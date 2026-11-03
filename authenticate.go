package tachograph

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/way-platform/tachograph-go/internal/card"
	"github.com/way-platform/tachograph-go/internal/vu"
	tachographv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/v1"
)

// Authenticate verifies a raw file received at receivedAt against the ERCA anchors embedded in the
// library (DefaultCertificateResolver) and returns an authenticated copy.
func Authenticate(ctx context.Context, rawFile *tachographv1.RawFile, receivedAt time.Time) (*tachographv1.RawFile, error) {
	return AuthenticateOptions{CertificateResolver: DefaultCertificateResolver(), ReceivedAt: receivedAt}.Authenticate(ctx, rawFile)
}

// AuthenticateOptions configures the signature authentication process.
type AuthenticateOptions struct {
	// CertificateResolver supplies the trusted ERCA roots, link certificates and MSCA revocations.
	// Required: build one with NewCertificateResolver, or use DefaultCertificateResolver.
	CertificateResolver CertificateResolver

	// ReceivedAt is when the file was received. Required. A VU download's overview may be signed
	// at most a day later; a card download's signing window ends at it.
	ReceivedAt time.Time

	// Mutate controls whether authentication modifies the input RawFile in-place.
	//
	// If false (default), the input RawFile is deep cloned before authentication,
	// ensuring the original remains unchanged. This is the safe default for most use cases.
	//
	// If true, the input RawFile is modified in-place, which is more efficient
	// but requires the caller to be aware that the input will be mutated.
	Mutate bool
}

// Authenticate sets an Authentication on every record of a raw file: VERIFIED, UNSIGNED for a
// record the regulation leaves unsigned, or why the record isn't verified, with the chain's
// certificates and a detail. A record's status never fails the call: it returns an error only for
// input it can't process, a nil or unknown file, a missing resolver or receipt time.
func (o AuthenticateOptions) Authenticate(ctx context.Context, rawFile *tachographv1.RawFile) (*tachographv1.RawFile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch {
	case rawFile == nil:
		return nil, errors.New("rawFile cannot be nil")
	case o.CertificateResolver == nil:
		return nil, errors.New("AuthenticateOptions.CertificateResolver is required")
	case o.ReceivedAt.IsZero():
		return nil, errors.New("AuthenticateOptions.ReceivedAt is required")
	}
	target := rawFile
	if !o.Mutate {
		target = proto.CloneOf(rawFile)
	}
	switch target.GetType() {
	case tachographv1.RawFile_CARD:
		opts := card.AuthenticateOptions{CertificateResolver: o.CertificateResolver, ReceivedAt: o.ReceivedAt}
		if err := opts.AuthenticateRawCardFile(target.GetCard()); err != nil {
			return nil, err
		}
	case tachographv1.RawFile_VEHICLE_UNIT:
		opts := vu.AuthenticateOptions{CertificateResolver: o.CertificateResolver, ReceivedAt: o.ReceivedAt}
		if err := opts.AuthenticateRawVehicleUnitFile(target.GetVehicleUnit()); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported file type: %v", target.GetType())
	}
	return target, nil
}
