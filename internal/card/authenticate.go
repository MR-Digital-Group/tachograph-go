package card

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/way-platform/tachograph-go/internal/security"
	"github.com/way-platform/tachograph-go/internal/trust"
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

// AuthenticateOptions configures the card authentication process.
type AuthenticateOptions struct {
	// CertificateResolver supplies the trusted roots, link certificates and revocations.
	CertificateResolver trust.Resolver
	// ReceivedAt is when the download was received; it ends the window in which the card signed.
	ReceivedAt time.Time
}

// cardChain is a DF's certificate chain, verified once per download. It holds the equipment
// certificate whenever the certificates verify, even when their validity is unknown.
type cardChain struct {
	auth *securityv1.Authentication
	gen1 *securityv1.RsaCertificate
	gen2 *securityv1.EccCertificate
}

// AuthenticateRawCardFile sets an authentication on every record of rawFile; a signature record
// carries the authentication of the EF it follows. It fails only when rawFile is nil or the
// options lack a resolver or a receipt time.
func (opts AuthenticateOptions) AuthenticateRawCardFile(rawFile *cardv1.RawCardFile) error {
	switch {
	case rawFile == nil:
		return errors.New("rawFile cannot be nil")
	case opts.CertificateResolver == nil:
		return errors.New("a certificate resolver is required")
	case opts.ReceivedAt.IsZero():
		return errors.New("the time the download was received is required")
	}
	records := rawFile.GetRecords()
	chains := make(map[ddv1.Generation]func() *cardChain)
	for _, generation := range []ddv1.Generation{ddv1.Generation_GENERATION_1, ddv1.Generation_GENERATION_2} {
		chains[generation] = sync.OnceValue(func() *cardChain { return opts.chain(records, generation) })
	}
	for i := 0; i < len(records); i++ {
		record := records[i]
		file := record.GetFile()
		if record.GetContentType() == cardv1.ContentType_SIGNATURE {
			record.SetAuthentication(trust.Status(securityv1.Authentication_UNSIGNED, fmt.Sprintf("a signature of %v without the data it signs", file)))
			continue
		}
		var signature *cardv1.RawCardFile_Record
		if i+1 < len(records) {
			next := records[i+1]
			if next.GetContentType() == cardv1.ContentType_SIGNATURE && next.GetFile() == file && next.GetGeneration() == record.GetGeneration() {
				signature = next
				i++
			}
		}
		chain := chains[record.GetGeneration()]
		var auth *securityv1.Authentication
		switch {
		case !IsSignedFile(file):
			auth = trust.Status(securityv1.Authentication_UNSIGNED, fmt.Sprintf("the regulation leaves %v unsigned", file))
		case chain == nil:
			auth = trust.Status(securityv1.Authentication_CERTIFICATE_VERIFICATION_FAILED, fmt.Sprintf("%v has no generation", file))
		case signature == nil || trust.Blank(signature.GetValue()):
			auth = trust.WithStatus(chain().auth, securityv1.Authentication_SIGNATURE_MISSING, fmt.Sprintf("%v has no signature, or a zeroed one", file))
		case chain().gen1 == nil && chain().gen2 == nil:
			auth = proto.CloneOf(chain().auth)
		default:
			c := chain()
			var err error
			if c.gen1 != nil {
				err = security.VerifyRsaDataSignature(record.GetValue(), signature.GetValue(), c.gen1)
			} else {
				err = security.VerifyEccDataSignature(record.GetValue(), signature.GetValue(), c.gen2)
			}
			auth = proto.CloneOf(c.auth)
			if err != nil {
				auth = trust.WithStatus(c.auth, securityv1.Authentication_DATA_SIGNATURE_INVALID, err.Error())
			}
		}
		record.SetAuthentication(auth)
		if signature != nil {
			signature.SetAuthentication(proto.CloneOf(auth))
		}
	}
	return nil
}

// chain verifies a DF's certificate chain over its signing window: from the newest timestamp in
// the DF's signed activity and event data to the receipt, never an exact signing time. A DF without
// timestamps, or whose newest one is after the receipt, leaves the start to VerifyGen2Chain's
// effective-date bound, or unknown for Gen1.
func (opts AuthenticateOptions) chain(records []*cardv1.RawCardFile_Record, generation ddv1.Generation) *cardChain {
	var newest time.Time
	for _, record := range records {
		if record.GetGeneration() != generation || record.GetContentType() != cardv1.ContentType_DATA {
			continue
		}
		var m proto.Message
		var err error
		switch record.GetFile() {
		case cardv1.ElementaryFileType_EF_DRIVER_ACTIVITY_DATA:
			m, err = UnmarshalOptions{}.unmarshalDriverActivityData(record.GetValue())
		case cardv1.ElementaryFileType_EF_EVENTS_DATA:
			m, err = UnmarshalOptions{}.unmarshalEventsData(record.GetValue())
		default:
			continue
		}
		if err != nil {
			continue
		}
		if t, ok := newestTimestamp(m.ProtoReflect()); ok && t.After(newest) {
			newest = t
		}
	}
	window := trust.Window{To: opts.ReceivedAt}
	if !newest.IsZero() && !newest.After(opts.ReceivedAt) {
		window.From = newest
	}
	ca := fileValue(records, generation, cardv1.ElementaryFileType_EF_CA_CERTIFICATE)
	if generation == ddv1.Generation_GENERATION_1 {
		auth, signer := trust.VerifyGen1Chain(opts.CertificateResolver, ca, fileValue(records, generation, cardv1.ElementaryFileType_EF_CARD_CERTIFICATE), trust.Card, window)
		return &cardChain{auth: auth, gen1: signer}
	}
	var links [][]byte
	if link := fileValue(records, generation, cardv1.ElementaryFileType_EF_LINK_CERTIFICATE); len(link) > 0 {
		links = append(links, link)
	}
	auth, signer := trust.VerifyGen2Chain(opts.CertificateResolver, ca, fileValue(records, generation, cardv1.ElementaryFileType_EF_CARD_SIGN_CERTIFICATE), links, trust.Card, window)
	return &cardChain{auth: auth, gen2: signer}
}

// fileValue is the value of the first data record of an EF in a generation's DF.
func fileValue(records []*cardv1.RawCardFile_Record, generation ddv1.Generation, file cardv1.ElementaryFileType) []byte {
	for _, record := range records {
		if record.GetGeneration() == generation && record.GetFile() == file && record.GetContentType() == cardv1.ContentType_DATA {
			return record.GetValue()
		}
	}
	return nil
}

// newestTimestamp is the latest google.protobuf.Timestamp anywhere in m.
func newestTimestamp(m protoreflect.Message) (time.Time, bool) {
	if ts, ok := m.Interface().(*timestamppb.Timestamp); ok {
		return ts.AsTime(), true
	}
	var newest time.Time
	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Message() == nil || fd.IsMap() {
			return true
		}
		var children []protoreflect.Message
		if fd.IsList() {
			list := v.List()
			for i := range list.Len() {
				children = append(children, list.Get(i).Message())
			}
		} else {
			children = append(children, v.Message())
		}
		for _, child := range children {
			if t, ok := newestTimestamp(child); ok && (!found || t.After(newest)) {
				newest, found = t, true
			}
		}
		return true
	})
	return newest, found
}

// IsSignedFile reports whether the regulation signs an EF of a card download (Appendix 7,
// DDP_035): EF_ICC, EF_IC, EF_Card_Download and the certificate EFs are downloaded unsigned.
func IsSignedFile(fileType cardv1.ElementaryFileType) bool {
	switch fileType {
	case cardv1.ElementaryFileType_EF_ICC,
		cardv1.ElementaryFileType_EF_IC,
		cardv1.ElementaryFileType_EF_CARD_CERTIFICATE,
		cardv1.ElementaryFileType_EF_CA_CERTIFICATE,
		cardv1.ElementaryFileType_EF_CARD_MA_CERTIFICATE,
		cardv1.ElementaryFileType_EF_CARD_SIGN_CERTIFICATE,
		cardv1.ElementaryFileType_EF_LINK_CERTIFICATE,
		cardv1.ElementaryFileType_EF_CARD_DOWNLOAD_DRIVER,
		cardv1.ElementaryFileType_EF_CARD_DOWNLOAD_WORKSHOP:
		return false
	default:
		return true
	}
}
