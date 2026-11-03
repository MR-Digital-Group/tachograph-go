// Package tachographtest generates test PKIs and signs tachograph downloads with them, so tests
// verify real certificate chains without committed private keys. It is for tests only: only a
// resolver built from a PKI's trust anchors trusts its roots.
package tachographtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/way-platform/tachograph-go"
	"github.com/way-platform/tachograph-go/internal/brainpool"
)

// Equipment types of a certificate holder authorisation (Data Dictionary 2.67).
const (
	// EquipmentMemberState is a Gen1 MSCA.
	EquipmentMemberState byte = 0x00
	// EquipmentDriverCard is a driver card; in Gen2, its mutual authentication certificate.
	EquipmentDriverCard byte = 0x01
	// EquipmentWorkshopCard is a workshop card; in Gen2, its mutual authentication certificate.
	EquipmentWorkshopCard byte = 0x02
	// EquipmentVehicleUnit is a VU; in Gen2, its mutual authentication certificate.
	EquipmentVehicleUnit byte = 0x06
	// EquipmentERCA is the European Root CA (Gen2).
	EquipmentERCA byte = 0x0D
	// EquipmentMSCA is a Gen2 Member State CA.
	EquipmentMSCA byte = 0x0E
	// EquipmentDriverCardSign is a Gen2 driver card's signing certificate.
	EquipmentDriverCardSign byte = 0x11
	// EquipmentWorkshopCardSign is a Gen2 workshop card's signing certificate.
	EquipmentWorkshopCardSign byte = 0x12
	// EquipmentVehicleUnitSign is a Gen2 VU's signing certificate.
	EquipmentVehicleUnitSign byte = 0x13
)

// Gen1CHA is a Gen1 certificate holder authorisation: the tachograph application ID and an equipment type.
func Gen1CHA(equipmentType byte) [7]byte {
	return [7]byte{0xFF, 0x54, 0x41, 0x43, 0x48, 0x4F, equipmentType}
}

// Gen2CHA is a Gen2 certificate holder authorisation: the tachograph application ID and an equipment type.
func Gen2CHA(equipmentType byte) [7]byte {
	return [7]byte{0xFF, 0x53, 0x4D, 0x52, 0x44, 0x54, equipmentType}
}

// Validity is a certificate validity period.
type Validity struct {
	From, To time.Time
}

func date(year int, month time.Month, day int) time.Time {
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

var (
	// RootValidity is the validity of the generated roots and link certificate.
	RootValidity = Validity{From: date(2010, 1, 1), To: date(2060, 1, 1)}
	// MSCAValidity is the validity of the generated MSCA certificates.
	MSCAValidity = Validity{From: date(2015, 1, 1), To: date(2045, 1, 1)}
	// EquipmentValidity is the validity of the generated equipment certificates; it covers the
	// signing times of the library's VU and card fixtures (2020 to 2026).
	EquipmentValidity = Validity{From: date(2019, 1, 1), To: date(2035, 1, 1)}
)

var serial atomic.Uint64

// nextCHR is a fresh certificate holder reference opening with prefix.
func nextCHR(prefix byte) [8]byte {
	var chr [8]byte
	binary.BigEndian.PutUint64(chr[:], serial.Add(1))
	chr[0] = prefix
	return chr
}

// Gen1Key is a Gen1 RSA-1024 key pair and its key identifier, the CHR of its certificate.
type Gen1Key struct {
	ID         [8]byte
	PrivateKey *rsa.PrivateKey
}

// NewGen1Key generates a Gen1 key with key identifier id.
func NewGen1Key(tb testing.TB, id [8]byte) *Gen1Key {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		tb.Fatalf("generate RSA-1024 key: %v", err)
	}
	return &Gen1Key{ID: id, PrivateKey: key}
}

// RootKey is k's public key in the 144-byte ERCA format: key identifier, modulus, exponent.
func (k *Gen1Key) RootKey() []byte {
	return slices.Concat(k.ID[:], k.modulus(), k.exponent())
}

func (k *Gen1Key) modulus() []byte {
	return k.PrivateKey.N.FillBytes(make([]byte, 128))
}

func (k *Gen1Key) exponent() []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(k.PrivateKey.E))
}

// sign signs data with PKCS#1 v1.5 and SHA-1, as Gen1 equipment signs downloads.
func (k *Gen1Key) sign(tb testing.TB, data []byte) []byte {
	tb.Helper()
	digest := sha1.Sum(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, k.PrivateKey, crypto.SHA1, digest[:])
	if err != nil {
		tb.Fatalf("sign: %v", err)
	}
	return signature
}

// Gen1Certificate is the content of a Gen1 certificate (Appendix 11 part A, 3.3).
type Gen1Certificate struct {
	// CAR names the issuer's key, inside the signed content and as the trailing CAR′.
	CAR [8]byte
	// TrailingCAR replaces the trailing CAR′ when it isn't zero.
	TrailingCAR [8]byte
	// CHA is the certificate holder authorisation, see Gen1CHA.
	CHA [7]byte
	// EndOfValidity is the end of validity; the zero time writes 'FF' padding, no end.
	EndOfValidity time.Time
	// Holder is the certified key; its ID is the CHR.
	Holder *Gen1Key
}

// Sign issues the 194-byte certificate under issuer with ISO/IEC 9796-2 partial message recovery.
func (c Gen1Certificate) Sign(tb testing.TB, issuer *Gen1Key) []byte {
	tb.Helper()
	endOfValidity := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	if !c.EndOfValidity.IsZero() {
		endOfValidity = binary.BigEndian.AppendUint32(nil, uint32(c.EndOfValidity.Unix()))
	}
	content := slices.Concat([]byte{0x01}, c.CAR[:], c.CHA[:], endOfValidity, c.Holder.ID[:], c.Holder.modulus(), c.Holder.exponent())
	digest := sha1.Sum(content)
	recovered := slices.Concat([]byte{0x6A}, content[:106], digest[:], []byte{0xBC})
	signature := new(big.Int).Exp(new(big.Int).SetBytes(recovered), issuer.PrivateKey.D, issuer.PrivateKey.N)
	trailing := c.CAR
	if c.TrailingCAR != ([8]byte{}) {
		trailing = c.TrailingCAR
	}
	return slices.Concat(signature.FillBytes(make([]byte, 128)), content[106:], trailing[:])
}

// Curve is an elliptic curve of Gen2 keys.
type Curve int

const (
	// BrainpoolP256r1 is the curve of the ERCA Gen2(1) root.
	BrainpoolP256r1 Curve = iota + 1
	// P256 is NIST P-256.
	P256
	// P521 is NIST P-521.
	P521
)

func (c Curve) params() (elliptic.Curve, asn1.ObjectIdentifier) {
	switch c {
	case BrainpoolP256r1:
		return brainpool.P256r1(), asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	case P521:
		return elliptic.P521(), asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	default:
		return elliptic.P256(), asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	}
}

// Gen2Key is a Gen2 ECC key pair and its CHR.
type Gen2Key struct {
	CHR        [8]byte
	Curve      Curve
	PrivateKey *ecdsa.PrivateKey
}

// NewGen2Key generates a Gen2 key on curve with CHR chr.
func NewGen2Key(tb testing.TB, curve Curve, chr [8]byte) *Gen2Key {
	tb.Helper()
	c, _ := curve.params()
	key, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		tb.Fatalf("generate %s key: %v", c.Params().Name, err)
	}
	return &Gen2Key{CHR: chr, Curve: curve, PrivateKey: key}
}

// sign signs data with ECDSA in plain format r || s, hashed with the SHA-2 function CSM_50 pairs
// with the key size.
func (k *Gen2Key) sign(tb testing.TB, data []byte) []byte {
	tb.Helper()
	bits := k.PrivateKey.Curve.Params().BitSize
	var digest []byte
	switch {
	case bits <= 256:
		h := sha256.Sum256(data)
		digest = h[:]
	case bits <= 384:
		h := sha512.Sum384(data)
		digest = h[:]
	default:
		h := sha512.Sum512(data)
		digest = h[:]
	}
	r, s, err := ecdsa.Sign(rand.Reader, k.PrivateKey, digest)
	if err != nil {
		tb.Fatalf("sign: %v", err)
	}
	size := (bits + 7) / 8
	return slices.Concat(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size)))
}

// Gen2Certificate is the body of a Gen2 certificate (Appendix 11, CSM_136).
type Gen2Certificate struct {
	CAR            [8]byte
	CHA            [7]byte
	EffectiveDate  time.Time
	ExpirationDate time.Time
	// Holder is the certified key; its CHR is the certificate's.
	Holder *Gen2Key
}

// Sign issues the certificate under issuer: tags 7F21, 7F4E, 5F29, 42, 5F4C, 7F49 (06, 86), 5F20,
// 5F25, 5F24 and 5F37 with minimal DER lengths.
func (c Gen2Certificate) Sign(tb testing.TB, issuer *Gen2Key) []byte {
	tb.Helper()
	curve, oid := c.Holder.Curve.params()
	encodedOID, err := asn1.Marshal(oid)
	if err != nil {
		tb.Fatalf("encode curve OID: %v", err)
	}
	size := (curve.Params().BitSize + 7) / 8
	point := slices.Concat([]byte{0x04}, c.Holder.PrivateKey.X.FillBytes(make([]byte, size)), c.Holder.PrivateKey.Y.FillBytes(make([]byte, size)))
	body := tlv([]byte{0x7F, 0x4E}, slices.Concat(
		tlv([]byte{0x5F, 0x29}, []byte{0x00}),
		tlv([]byte{0x42}, c.CAR[:]),
		tlv([]byte{0x5F, 0x4C}, c.CHA[:]),
		tlv([]byte{0x7F, 0x49}, slices.Concat(encodedOID, tlv([]byte{0x86}, point))),
		tlv([]byte{0x5F, 0x20}, c.Holder.CHR[:]),
		tlv([]byte{0x5F, 0x25}, binary.BigEndian.AppendUint32(nil, uint32(c.EffectiveDate.Unix()))),
		tlv([]byte{0x5F, 0x24}, binary.BigEndian.AppendUint32(nil, uint32(c.ExpirationDate.Unix()))),
	))
	return tlv([]byte{0x7F, 0x21}, slices.Concat(body, tlv([]byte{0x5F, 0x37}, issuer.sign(tb, body))))
}

func tlv(tag, value []byte) []byte {
	out := slices.Clone(tag)
	switch n := len(value); {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xFF:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, value...)
}

// NewGen2MSCA generates an MSCA key on curve and its certificate under root, valid over MSCAValidity.
func NewGen2MSCA(tb testing.TB, root *Gen2Key, curve Curve) (*Gen2Key, []byte) {
	tb.Helper()
	key := NewGen2Key(tb, curve, nextCHR(0x01))
	certificate := Gen2Certificate{
		CAR: root.CHR, CHA: Gen2CHA(EquipmentMSCA),
		EffectiveDate: MSCAValidity.From, ExpirationDate: MSCAValidity.To, Holder: key,
	}.Sign(tb, root)
	return key, certificate
}

// Gen1Chain is what a Gen1 VU or card signs a download with.
type Gen1Chain struct {
	MSCACertificate      []byte
	EquipmentCertificate []byte
	EquipmentKey         *Gen1Key
}

// Gen2Chain is what a Gen2 VU or card signs a download with.
type Gen2Chain struct {
	MSCACertificate      []byte
	EquipmentCertificate []byte
	EquipmentKey         *Gen2Key
	// LinkCertificate goes into a card's EF_Link_Certificate; a VU download carries none.
	LinkCertificate []byte
}

// Gen1Equipment issues an equipment key and its certificate under msca, valid to
// EquipmentValidity.To with the given equipment type; edits change the certificate before it is
// signed.
func Gen1Equipment(tb testing.TB, msca *Gen1Key, mscaCertificate []byte, equipmentType byte, edits ...func(*Gen1Certificate)) *Gen1Chain {
	tb.Helper()
	certificate := Gen1Certificate{CAR: msca.ID, CHA: Gen1CHA(equipmentType), EndOfValidity: EquipmentValidity.To, Holder: NewGen1Key(tb, nextCHR(0x02))}
	for _, edit := range edits {
		edit(&certificate)
	}
	return &Gen1Chain{MSCACertificate: mscaCertificate, EquipmentCertificate: certificate.Sign(tb, msca), EquipmentKey: certificate.Holder}
}

// Gen2Equipment issues an equipment key on curve and its certificate under msca, valid over
// EquipmentValidity with the given equipment type; edits change the certificate before it is
// signed.
func Gen2Equipment(tb testing.TB, msca *Gen2Key, mscaCertificate []byte, curve Curve, equipmentType byte, edits ...func(*Gen2Certificate)) *Gen2Chain {
	tb.Helper()
	certificate := Gen2Certificate{
		CAR: msca.CHR, CHA: Gen2CHA(equipmentType),
		EffectiveDate: EquipmentValidity.From, ExpirationDate: EquipmentValidity.To,
		Holder: NewGen2Key(tb, curve, nextCHR(0x02)),
	}
	for _, edit := range edits {
		edit(&certificate)
	}
	return &Gen2Chain{MSCACertificate: mscaCertificate, EquipmentCertificate: certificate.Sign(tb, msca), EquipmentKey: certificate.Holder}
}

// PKI is a generated test PKI for both generations: an RSA-1024 Gen1 root key and MSCA,
// brainpoolP256r1 Gen2 roots and P-256 MSCAs.
type PKI struct {
	Gen1Root            *Gen1Key
	Gen1MSCA            *Gen1Key
	Gen1MSCACertificate []byte

	Gen2Root            *Gen2Key
	Gen2RootCertificate []byte
	Gen2MSCA            *Gen2Key
	Gen2MSCACertificate []byte

	// Gen2NextRoot follows Gen2Root: Gen2LinkCertificate, signed by Gen2Root, certifies it.
	Gen2NextRoot            *Gen2Key
	Gen2NextRootCertificate []byte
	Gen2LinkCertificate     []byte
	// Gen2NextMSCA is certified by Gen2NextRoot, so only the link leads to it from Gen2Root.
	Gen2NextMSCA            *Gen2Key
	Gen2NextMSCACertificate []byte
}

// NewPKI generates a PKI.
func NewPKI(tb testing.TB) *PKI {
	tb.Helper()
	p := &PKI{
		Gen1Root:     NewGen1Key(tb, nextCHR(0xFD)),
		Gen1MSCA:     NewGen1Key(tb, nextCHR(0x01)),
		Gen2Root:     NewGen2Key(tb, BrainpoolP256r1, nextCHR(0xFD)),
		Gen2NextRoot: NewGen2Key(tb, BrainpoolP256r1, nextCHR(0xFD)),
	}
	p.Gen1MSCACertificate = Gen1Certificate{
		CAR: p.Gen1Root.ID, CHA: Gen1CHA(EquipmentMemberState), EndOfValidity: MSCAValidity.To, Holder: p.Gen1MSCA,
	}.Sign(tb, p.Gen1Root)
	root := func(holder, issuer *Gen2Key) []byte {
		return Gen2Certificate{
			CAR: issuer.CHR, CHA: Gen2CHA(EquipmentERCA),
			EffectiveDate: RootValidity.From, ExpirationDate: RootValidity.To, Holder: holder,
		}.Sign(tb, issuer)
	}
	p.Gen2RootCertificate = root(p.Gen2Root, p.Gen2Root)
	p.Gen2NextRootCertificate = root(p.Gen2NextRoot, p.Gen2NextRoot)
	p.Gen2LinkCertificate = root(p.Gen2NextRoot, p.Gen2Root)
	p.Gen2MSCA, p.Gen2MSCACertificate = NewGen2MSCA(tb, p.Gen2Root, P256)
	p.Gen2NextMSCA, p.Gen2NextMSCACertificate = NewGen2MSCA(tb, p.Gen2NextRoot, P256)
	return p
}

// Gen1VehicleUnit issues a Gen1 VU key and certificate (type 6) under Gen1MSCA.
func (p *PKI) Gen1VehicleUnit(tb testing.TB, edits ...func(*Gen1Certificate)) *Gen1Chain {
	tb.Helper()
	return Gen1Equipment(tb, p.Gen1MSCA, p.Gen1MSCACertificate, EquipmentVehicleUnit, edits...)
}

// Gen1DriverCard issues a Gen1 driver card key and certificate (type 1) under Gen1MSCA.
func (p *PKI) Gen1DriverCard(tb testing.TB, edits ...func(*Gen1Certificate)) *Gen1Chain {
	tb.Helper()
	return Gen1Equipment(tb, p.Gen1MSCA, p.Gen1MSCACertificate, EquipmentDriverCard, edits...)
}

// Gen2VehicleUnit issues a Gen2 VU signing key and certificate (type 19) on P-256 under Gen2MSCA.
func (p *PKI) Gen2VehicleUnit(tb testing.TB, edits ...func(*Gen2Certificate)) *Gen2Chain {
	tb.Helper()
	return Gen2Equipment(tb, p.Gen2MSCA, p.Gen2MSCACertificate, P256, EquipmentVehicleUnitSign, edits...)
}

// Gen2DriverCard issues a Gen2 driver card signing key and certificate (type 17) on P-256 under Gen2MSCA.
func (p *PKI) Gen2DriverCard(tb testing.TB, edits ...func(*Gen2Certificate)) *Gen2Chain {
	tb.Helper()
	return Gen2Equipment(tb, p.Gen2MSCA, p.Gen2MSCACertificate, P256, EquipmentDriverCardSign, edits...)
}

// TrustStore trusts the PKI's Gen1 root key and Gen2Root, with no link certificates and no revocations.
func (p *PKI) TrustStore() tachograph.TrustStore {
	return tachograph.TrustStore{
		Gen1RootKeys:         [][]byte{p.Gen1Root.RootKey()},
		Gen2RootCertificates: [][]byte{p.Gen2RootCertificate},
	}
}

// Resolver builds a resolver from store, failing tb when store is malformed.
func Resolver(tb testing.TB, store tachograph.TrustStore) tachograph.CertificateResolver {
	tb.Helper()
	resolver, err := tachograph.NewCertificateResolver(store)
	if err != nil {
		tb.Fatalf("certificate resolver: %v", err)
	}
	return resolver
}
