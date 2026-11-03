package security

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"math/big"
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/way-platform/tachograph-go/internal/cert/certcache"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

// gen1MemberState is a Gen1 MSCA's holder authorisation: the tachograph application ID and type 0.
var gen1MemberState = []byte{0xFF, 0x54, 0x41, 0x43, 0x48, 0x4F, 0x00}

func TestVerifyRsaCertificateRecoversTheHolderAuthorisation(t *testing.T) {
	root, err := UnmarshalRootCertificate(certcache.Root())
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	for _, file := range []string{"finland_tcc37.bin", "finland_tcc38.bin"} {
		data, err := os.ReadFile("testdata/certs/g1/" + file)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := UnmarshalRsaCertificate(data)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if err := VerifyRsaCertificateWithRoot(cert, root); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if got := cert.GetCertificateHolderAuthorisation(); !bytes.Equal(got, gen1MemberState) {
			t.Errorf("%s: holder authorisation = %X, want %X", file, got, gen1MemberState)
		}
	}
}

func TestVerifyRsaCertificateRequiresTheInnerCARToRepeatCARPrime(t *testing.T) {
	issuer, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	issuerID := []byte{0xFD, 0x54, 0x45, 0x53, 0x54, 0xFF, 0xFF, 0x01}
	root := &securityv1.RootCertificate{}
	root.SetKeyId(strconv.FormatUint(binary.BigEndian.Uint64(issuerID), 10))
	root.SetRsaModulus(issuer.N.FillBytes(make([]byte, 128)))
	root.SetRsaExponent(binary.BigEndian.AppendUint64(nil, uint64(issuer.E)))
	// certificate signs content naming car inside and issuerID as CAR′, ISO/IEC 9796-2 with recovery.
	certificate := func(car []byte) []byte {
		content := slices.Concat([]byte{0x01}, car, gen1MemberState, []byte{0xFF, 0xFF, 0xFF, 0xFF},
			[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, holder.N.FillBytes(make([]byte, 128)),
			binary.BigEndian.AppendUint64(nil, uint64(holder.E)))
		digest := sha1.Sum(content)
		recovered := slices.Concat([]byte{0x6A}, content[:106], digest[:], []byte{0xBC})
		signature := new(big.Int).Exp(new(big.Int).SetBytes(recovered), issuer.D, issuer.N)
		return slices.Concat(signature.FillBytes(make([]byte, 128)), content[106:], issuerID)
	}

	t.Run("inner CAR repeats CAR'", func(t *testing.T) {
		cert, err := UnmarshalRsaCertificate(certificate(issuerID))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyRsaCertificateWithRoot(cert, root); err != nil {
			t.Fatalf("VerifyRsaCertificateWithRoot() = %v", err)
		}
		if got := cert.GetCertificateHolderReference(); got != "72623859790382856" {
			t.Errorf("CHR = %s, want 72623859790382856 (0102030405060708)", got)
		}
		if cert.HasEndOfValidity() {
			t.Error("an 'FF'-padded end of validity was recorded")
		}
	})
	t.Run("inner CAR differs", func(t *testing.T) {
		cert, err := UnmarshalRsaCertificate(certificate([]byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyRsaCertificateWithRoot(cert, root); err == nil {
			t.Error("VerifyRsaCertificateWithRoot() accepted an inner CAR other than CAR'")
		}
		if cert.GetSignatureValid() {
			t.Error("signature_valid = true after a failed verification")
		}
	})
}
