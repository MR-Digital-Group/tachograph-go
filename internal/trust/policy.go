package trust

import (
	"bytes"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/way-platform/tachograph-go/internal/security"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

// Window bounds when data was signed: an exact signing time made by At (a VU overview's current
// date and time), a card's signing window, which is never exact even when From equals To, or the
// zero Window when nothing dates the signing.
type Window struct {
	// From is the earliest time the data can have been signed; zero when unknown.
	From time.Time
	// To is the latest time the data can have been signed; zero when nothing dates the signing.
	To time.Time
	// exact marks a recorded signing time rather than a window.
	exact bool
}

// At is the window of an exact signing time.
func At(t time.Time) Window {
	return Window{From: t, To: t, exact: true}
}

func (w Window) String() string {
	switch {
	case w.exact:
		return "the signing time " + w.From.Format(time.RFC3339)
	case w.To.IsZero():
		return "no signing time"
	case w.From.IsZero():
		return "the signing window ending " + w.To.Format(time.RFC3339)
	default:
		return "the signing window " + w.From.Format(time.RFC3339) + " to " + w.To.Format(time.RFC3339)
	}
}

// report records w on auth: an exact signing time, or a window's start (when known) and end.
func (w Window) report(auth *securityv1.Authentication) {
	switch {
	case w.exact:
		auth.SetSignatureCreationTime(timestamppb.New(w.From))
		return
	case w.To.IsZero():
		return
	}
	if !w.From.IsZero() {
		auth.SetSigningWindowStart(timestamppb.New(w.From))
	}
	auth.SetSigningWindowEnd(timestamppb.New(w.To))
}

// Role is the equipment whose certificate signs a download.
type Role int

const (
	// VehicleUnit signs VU downloads.
	VehicleUnit Role = iota + 1
	// Card signs card downloads: a driver or a workshop card.
	Card
)

// equipmentTypes are the Gen1 and Gen2 equipment types whose certificate may sign a role's
// downloads (Data Dictionary 2.67, note 2; Appendix 11 CSM_234): Gen2 data is signed with the
// "(Sign)" certificate, 1, 2 and 6 mark mutual authentication certificates there.
var equipmentTypes = map[Role]struct{ gen1, gen2 []byte }{
	VehicleUnit: {gen1: []byte{0x06}, gen2: []byte{0x13}},
	Card:        {gen1: []byte{0x01, 0x02}, gen2: []byte{0x11, 0x12}},
}

const (
	equipmentMemberStateGen1 = 0x00
	equipmentMSCA            = 0x0E
)

var gen1ApplicationID = []byte{0xFF, 0x54, 0x41, 0x43, 0x48, 0x4F}

func gen1CHA(equipmentType byte) []byte {
	return append(bytes.Clone(gen1ApplicationID), equipmentType)
}

// checkRole checks that a holder authorisation is applicationID followed by one of the equipment types.
func checkRole(cha, applicationID, equipmentTypes []byte) error {
	if len(cha) != len(applicationID)+1 || !bytes.HasPrefix(cha, applicationID) || !slices.Contains(equipmentTypes, cha[len(applicationID)]) {
		return fmt.Errorf("holder authorisation %X, want %X followed by one of % X", cha, applicationID, equipmentTypes)
	}
	return nil
}

// failed is the status of a certificate whose signature, issuer reference, role or validity fails.
const failed = securityv1.Authentication_CERTIFICATE_VERIFICATION_FAILED

// Status is an authentication holding only a status and its detail.
func Status(status securityv1.Authentication_Status, detail string) *securityv1.Authentication {
	return conclude(&securityv1.Authentication{}, status, "%s", detail)
}

// WithStatus is a copy of a chain's authentication with another status and detail.
func WithStatus(chain *securityv1.Authentication, status securityv1.Authentication_Status, detail string) *securityv1.Authentication {
	return conclude(proto.CloneOf(chain), status, "%s", detail)
}

func conclude(auth *securityv1.Authentication, status securityv1.Authentication_Status, format string, args ...any) *securityv1.Authentication {
	auth.SetStatus(status)
	auth.SetDetail(fmt.Sprintf(format, args...))
	return auth
}

// Blank reports a certificate or signature slot that holds nothing: absent, or zeroed as anonymized
// downloads have it.
func Blank(slot []byte) bool {
	return len(slot) == 0 || bytes.Equal(slot, make([]byte, len(slot)))
}

func certificateInfo(chr, car string, from, to *timestamppb.Timestamp) *securityv1.CertificateInfo {
	info := &securityv1.CertificateInfo{}
	info.SetCertificateHolderReference(chr)
	info.SetCertificationAuthorityReference(car)
	if from != nil {
		info.SetValidFrom(from)
	}
	if to != nil {
		info.SetValidTo(to)
	}
	return info
}

func eccInfo(c *securityv1.EccCertificate) *securityv1.CertificateInfo {
	return certificateInfo(c.GetCertificateHolderReference(), c.GetCertificateAuthorityReference(), c.GetCertificateEffectiveDate(), c.GetCertificateExpirationDate())
}

func stamp(t *timestamppb.Timestamp) string {
	return t.AsTime().Format(time.RFC3339)
}

// validAt checks that c was valid at t.
func validAt(c *securityv1.EccCertificate, t *timestamppb.Timestamp) error {
	from, to := c.GetCertificateEffectiveDate(), c.GetCertificateExpirationDate()
	switch {
	case from == nil || to == nil:
		return fmt.Errorf("certificate %s has no validity period", c.GetCertificateHolderReference())
	case t == nil:
		return fmt.Errorf("no date to check certificate %s at", c.GetCertificateHolderReference())
	case t.AsTime().Before(from.AsTime()) || t.AsTime().After(to.AsTime()):
		return fmt.Errorf("certificate %s is valid from %s to %s, not at %s", c.GetCertificateHolderReference(), stamp(from), stamp(to), stamp(t))
	}
	return nil
}

// VerifyGen1Chain verifies the Gen1 chain ERCA key → MSCA certificate → equipment certificate
// (Appendix 11 part A) of data signed within w. The equipment certificate's end of validity must
// not precede w: on or after its end it is valid, before its known start it fails, otherwise its
// validity is unknown, as it is for any end when nothing dates the signing. The MSCA
// certificate's end of validity is not checked: a Gen1 certificate has no start date to place the
// equipment certificate in it. Whenever the certificates verify, with status VERIFIED or
// CERTIFICATE_VALIDITY_UNKNOWN, it also returns the equipment certificate and its recovered
// public key.
func VerifyGen1Chain(r Resolver, msca, equipment []byte, role Role, w Window) (*securityv1.Authentication, *securityv1.RsaCertificate) {
	auth := &securityv1.Authentication{}
	auth.SetSignatureAlgorithm(securityv1.SignatureAlgorithm_SHA1_WITH_RSA_ENCRYPTION)
	w.report(auth)
	if Blank(msca) || Blank(equipment) {
		return conclude(auth, securityv1.Authentication_CERTIFICATE_MISSING, "the file holds no Gen1 MSCA and equipment certificates"), nil
	}
	mscaCert, err := security.UnmarshalRsaCertificate(msca)
	if err != nil {
		return conclude(auth, failed, "MSCA certificate: %v", err), nil
	}
	equipmentCert, err := security.UnmarshalRsaCertificate(equipment)
	if err != nil {
		return conclude(auth, failed, "equipment certificate: %v", err), nil
	}
	keyID := mscaCert.GetCertificateAuthorityReference()
	root, ok := r.Gen1RootKey(keyID)
	if !ok {
		return conclude(auth, securityv1.Authentication_CERTIFICATE_UNTRUSTED, "no trusted Gen1 ERCA key %s issued the MSCA certificate", keyID), nil
	}
	auth.SetRootCertificate(certificateInfo(root.GetKeyId(), root.GetKeyId(), nil, nil))
	err = security.VerifyRsaCertificateWithRoot(mscaCert, root)
	auth.SetCaCertificate(certificateInfo(mscaCert.GetCertificateHolderReference(), mscaCert.GetCertificateAuthorityReference(), nil, mscaCert.GetEndOfValidity()))
	if err != nil {
		return conclude(auth, failed, "MSCA certificate: %v", err), nil
	}
	mscaCHR := mscaCert.GetCertificateHolderReference()
	if cha, want := mscaCert.GetCertificateHolderAuthorisation(), gen1CHA(equipmentMemberStateGen1); !bytes.Equal(cha, want) {
		return conclude(auth, failed, "MSCA certificate %s: holder authorisation %X, want %X", mscaCHR, cha, want), nil
	}
	if r.Gen1MSCARevoked(mscaCHR) {
		return conclude(auth, securityv1.Authentication_CERTIFICATE_REVOKED, "MSCA certificate %s is revoked", mscaCHR), nil
	}
	err = security.VerifyRsaCertificateWithCA(equipmentCert, mscaCert)
	auth.SetSignerCertificate(certificateInfo(equipmentCert.GetCertificateHolderReference(), equipmentCert.GetCertificateAuthorityReference(), nil, equipmentCert.GetEndOfValidity()))
	if err != nil {
		return conclude(auth, failed, "equipment certificate: %v", err), nil
	}
	equipmentCHR := equipmentCert.GetCertificateHolderReference()
	if err := checkRole(equipmentCert.GetCertificateHolderAuthorisation(), gen1ApplicationID, equipmentTypes[role].gen1); err != nil {
		return conclude(auth, failed, "equipment certificate %s: %v", equipmentCHR, err), nil
	}
	if end := equipmentCert.GetEndOfValidity(); end != nil && w.To.IsZero() {
		return conclude(auth, securityv1.Authentication_CERTIFICATE_VALIDITY_UNKNOWN, "equipment certificate %s ends %s, and nothing dates the signature", equipmentCHR, stamp(end)), equipmentCert
	}
	if end := equipmentCert.GetEndOfValidity(); end != nil && end.AsTime().Before(w.To) {
		if !w.From.IsZero() && end.AsTime().Before(w.From) {
			return conclude(auth, failed, "equipment certificate %s ended %s, before %s", equipmentCHR, stamp(end), w), nil
		}
		return conclude(auth, securityv1.Authentication_CERTIFICATE_VALIDITY_UNKNOWN, "equipment certificate %s ended %s, inside %s", equipmentCHR, stamp(end), w), equipmentCert
	}
	auth.SetStatus(securityv1.Authentication_VERIFIED)
	return auth, equipmentCert
}

// VerifyGen2Chain verifies the Gen2 chain ERCA root (→ link certificate) → MSCA certificate →
// equipment certificate (Appendix 11, CSM_136 to CSM_150) of data signed within w: issuer
// references, roles, revocation of the verified MSCA certificate's CHR, the root or link valid at
// the MSCA certificate's effective date, the MSCA certificate valid at the equipment
// certificate's, and the equipment certificate valid throughout w. A card's window starts no
// earlier than the equipment certificate's effective date, since a card signs nothing before it is
// personalised. Valid for none of w fails; valid for part of it, or when nothing dates the
// signing, is CERTIFICATE_VALIDITY_UNKNOWN. fileLinks are link certificates the file itself
// carries. Whenever the certificates verify, with status VERIFIED or CERTIFICATE_VALIDITY_UNKNOWN,
// it also returns the equipment certificate.
func VerifyGen2Chain(r Resolver, msca, equipment []byte, fileLinks [][]byte, role Role, w Window) (*securityv1.Authentication, *securityv1.EccCertificate) {
	auth := &securityv1.Authentication{}
	w.report(auth)
	if Blank(msca) || Blank(equipment) {
		return conclude(auth, securityv1.Authentication_CERTIFICATE_MISSING, "the file holds no Gen2 MSCA and equipment certificates"), nil
	}
	mscaCert, err := security.UnmarshalEccCertificate(msca)
	if err != nil {
		return conclude(auth, failed, "MSCA certificate: %v", err), nil
	}
	equipmentCert, err := security.UnmarshalEccCertificate(equipment)
	if err != nil {
		return conclude(auth, failed, "equipment certificate: %v", err), nil
	}
	if effective := equipmentCert.GetCertificateEffectiveDate(); !w.exact && effective != nil && !w.To.IsZero() && (w.From.IsZero() || effective.AsTime().After(w.From)) {
		w.From = effective.AsTime()
		auth.SetSigningWindowStart(effective)
	}
	auth.SetSignatureAlgorithm(security.EccSignatureAlgorithm(equipmentCert.GetPublicKey().GetDomainParametersOid()))
	auth.SetCaCertificate(eccInfo(mscaCert))
	auth.SetSignerCertificate(eccInfo(equipmentCert))
	mscaCHR, equipmentCHR := mscaCert.GetCertificateHolderReference(), equipmentCert.GetCertificateHolderReference()
	if car := equipmentCert.GetCertificateAuthorityReference(); car != mscaCHR {
		return conclude(auth, failed, "equipment certificate %s: CAR %s does not name the MSCA certificate %s", equipmentCHR, car, mscaCHR), nil
	}
	if cha, want := mscaCert.GetCertificateHolderAuthorisation(), gen2CHA(equipmentMSCA); !bytes.Equal(cha, want) {
		return conclude(auth, failed, "MSCA certificate %s: holder authorisation %X, want %X", mscaCHR, cha, want), nil
	}
	if err := checkRole(equipmentCert.GetCertificateHolderAuthorisation(), gen2ApplicationID, equipmentTypes[role].gen2); err != nil {
		return conclude(auth, failed, "equipment certificate %s: %v", equipmentCHR, err), nil
	}

	// The MSCA certificate's issuer: a trusted root its CAR names, or a link certificate from a trusted root to that CAR (CSM_140).
	car := mscaCert.GetCertificateAuthorityReference()
	var issuer *securityv1.EccCertificate
	if root, ok := r.Gen2RootCertificate(car); ok {
		issuer = root
		auth.SetRootCertificate(eccInfo(root))
	} else {
		links := r.Gen2LinkCertificates(car)
		for _, raw := range fileLinks {
			if link, err := security.UnmarshalEccCertificate(raw); err == nil && link.GetCertificateHolderReference() == car {
				links = append(links, link)
			}
		}
		var linkFailure error
		for _, link := range links {
			root, ok := r.Gen2RootCertificate(link.GetCertificateAuthorityReference())
			if !ok {
				continue
			}
			err := security.VerifyEccCertificateWithEccRoot(link, root)
			if cha := link.GetCertificateHolderAuthorisation(); err == nil && !bytes.Equal(cha, gen2CHA(equipmentERCA)) {
				err = fmt.Errorf("holder authorisation %X is not the ERCA's", cha)
			}
			if err == nil {
				err = validAt(root, link.GetCertificateEffectiveDate())
			}
			if err != nil {
				if linkFailure == nil {
					linkFailure = fmt.Errorf("link certificate %s from root %s: %w", car, root.GetCertificateHolderReference(), err)
				}
				continue
			}
			issuer = link
			auth.SetRootCertificate(eccInfo(root))
			auth.SetLinkCertificate(eccInfo(link))
			break
		}
		if issuer == nil && linkFailure != nil {
			return conclude(auth, failed, "%v", linkFailure), nil
		}
		if issuer == nil {
			return conclude(auth, securityv1.Authentication_CERTIFICATE_UNTRUSTED, "no trusted root or link certificate issued MSCA certificate %s, whose CAR is %s", mscaCHR, car), nil
		}
	}

	if err := security.VerifyEccCertificateWithEccRoot(mscaCert, issuer); err != nil {
		return conclude(auth, failed, "MSCA certificate %s: %v", mscaCHR, err), nil
	}
	if r.Gen2MSCARevoked(mscaCHR) {
		return conclude(auth, securityv1.Authentication_CERTIFICATE_REVOKED, "MSCA certificate %s is revoked", mscaCHR), nil
	}
	if err := security.VerifyEccCertificateWithCA(equipmentCert, mscaCert); err != nil {
		return conclude(auth, failed, "equipment certificate %s: %v", equipmentCHR, err), nil
	}
	if err := validAt(issuer, mscaCert.GetCertificateEffectiveDate()); err != nil {
		return conclude(auth, failed, "at the MSCA certificate's effective date: %v", err), nil
	}
	if err := validAt(mscaCert, equipmentCert.GetCertificateEffectiveDate()); err != nil {
		return conclude(auth, failed, "at the equipment certificate's effective date: %v", err), nil
	}
	from, to := equipmentCert.GetCertificateEffectiveDate(), equipmentCert.GetCertificateExpirationDate()
	if to == nil {
		return conclude(auth, failed, "equipment certificate %s has no expiration date", equipmentCHR), nil
	}
	if w.To.IsZero() {
		return conclude(auth, securityv1.Authentication_CERTIFICATE_VALIDITY_UNKNOWN, "equipment certificate %s is valid from %s to %s, and nothing dates the signature", equipmentCHR, stamp(from), stamp(to)), equipmentCert
	}
	effective, expiration := from.AsTime(), to.AsTime()
	if expiration.Before(w.From) || effective.After(w.To) {
		return conclude(auth, failed, "equipment certificate %s is valid from %s to %s, outside %s", equipmentCHR, stamp(from), stamp(to), w), nil
	}
	if effective.After(w.From) || expiration.Before(w.To) {
		return conclude(auth, securityv1.Authentication_CERTIFICATE_VALIDITY_UNKNOWN, "equipment certificate %s is valid from %s to %s, for only part of %s", equipmentCHR, stamp(from), stamp(to), w), equipmentCert
	}
	auth.SetStatus(securityv1.Authentication_VERIFIED)
	return auth, equipmentCert
}
