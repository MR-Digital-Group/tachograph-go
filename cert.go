package tachograph

import (
	"github.com/way-platform/tachograph-go/internal/trust"
)

// CertificateResolver supplies the trust decisions of verification: the trusted Gen1 ERCA keys
// and Gen2 ERCA root certificates, the ERCA link certificates, and the revoked MSCA certificates.
// Equipment and MSCA certificates always come from the verified file.
type CertificateResolver = trust.Resolver

// TrustStore lists trust anchors in the encodings JRC publishes them in.
type TrustStore struct {
	// Gen1RootKeys are 144-byte Gen1 ERCA public keys (EC_PK.bin): key identifier, modulus, exponent.
	Gen1RootKeys [][]byte
	// Gen2RootCertificates are self-signed Gen2 ERCA root certificates.
	Gen2RootCertificates [][]byte
	// Gen2LinkCertificates are Gen2 ERCA link certificates, each certifying a new root under the previous one.
	Gen2LinkCertificates [][]byte
	// RevokedMSCACertificates are the MSCA certificates JRC marks revoked, as published: 194-byte
	// Gen1 certificates, recovered under the Gen1 ERCA key their CAR names, or Gen2 certificates.
	// Each revokes its CHR.
	RevokedMSCACertificates [][]byte
}

// NewCertificateResolver returns a resolver that trusts exactly what store lists. It fails when a
// Gen1 key isn't 144 bytes, a root isn't a self-signed ERCA certificate, a link certificate isn't
// an ERCA certificate, or a revoked certificate can't be read (a Gen1 one needs its ERCA key).
func NewCertificateResolver(store TrustStore) (CertificateResolver, error) {
	resolver, err := trust.NewStore(store.Gen1RootKeys, store.Gen2RootCertificates, store.Gen2LinkCertificates, store.RevokedMSCACertificates)
	if err != nil {
		return nil, err
	}
	return resolver, nil
}

// DefaultCertificateResolver trusts the Gen1 ERCA key and the Gen2(1) ERCA root certificate
// embedded in the library, with no link certificates and no revocations. It never uses the network.
func DefaultCertificateResolver() CertificateResolver {
	return trust.DefaultResolver()
}
