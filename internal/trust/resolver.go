// Package trust decides whether tachograph certificate chains lead to a trusted ERCA root.
package trust

import (
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

// Resolver supplies the trust anchors of signature verification. Equipment and MSCA certificates
// always come from the verified file; a resolver answers only for ERCA roots, ERCA link
// certificates and revoked MSCA certificates, with references as the decimal strings of their 8
// bytes. Each certificate it returns is a fresh copy the caller may modify. A lookup that reports
// false trusts nothing, whatever certificate or key it returns with it.
type Resolver interface {
	// Gen1RootKey returns the trusted Gen1 ERCA public key with key identifier keyID.
	Gen1RootKey(keyID string) (*securityv1.RootCertificate, bool)
	// Gen2RootCertificate returns the trusted Gen2 ERCA root certificate with CHR chr.
	Gen2RootCertificate(chr string) (*securityv1.EccCertificate, bool)
	// Gen2LinkCertificates returns the ERCA link certificates that certify the root with CHR chr.
	Gen2LinkCertificates(chr string) []*securityv1.EccCertificate
	// Gen1MSCARevoked reports whether the Gen1 MSCA certificate with CHR chr is revoked. Callers ask
	// only once the certificate has verified under its issuer, so the CHR is authenticated.
	Gen1MSCARevoked(chr string) bool
	// Gen2MSCARevoked is Gen1MSCARevoked for Gen2, whose MSCA CHRs are built like Gen1's.
	Gen2MSCARevoked(chr string) bool
}
