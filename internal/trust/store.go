package trust

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/way-platform/tachograph-go/internal/cert/certcache"
	"github.com/way-platform/tachograph-go/internal/security"
	securityv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/security/v1"
)

// Gen2 holder authorisations open with the tachograph application ID (Data Dictionary 2.43).
var gen2ApplicationID = []byte{0xFF, 0x53, 0x4D, 0x52, 0x44, 0x54}

// equipmentERCA is the European Root CA's equipment type (Data Dictionary 2.67).
const equipmentERCA = 0x0D

// lenGen1Certificate is the size of a Gen1 certificate (Appendix 11 part A).
const lenGen1Certificate = 194

func gen2CHA(equipmentType byte) []byte {
	return append(bytes.Clone(gen2ApplicationID), equipmentType)
}

// Store is a Resolver over a fixed set of trust anchors.
type Store struct {
	gen1Roots   map[string][]byte
	gen2Roots   map[string][]byte
	gen2Links   map[string][][]byte
	gen1Revoked map[string]bool
	gen2Revoked map[string]bool
}

var _ Resolver = (*Store)(nil)

// NewStore checks and indexes trust anchors in their published encodings: 144-byte Gen1 ERCA
// public keys, self-signed Gen2 ERCA root certificates, Gen2 ERCA link certificates, and revoked
// MSCA certificates (194-byte Gen1 ones, recovered under the Gen1 ERCA key their CAR names, or
// Gen2 ones), which revoke their CHR.
func NewStore(gen1RootKeys, gen2Roots, gen2Links, revokedMSCACertificates [][]byte) (*Store, error) {
	s := &Store{
		gen1Roots:   make(map[string][]byte),
		gen2Roots:   make(map[string][]byte),
		gen2Links:   make(map[string][][]byte),
		gen1Revoked: make(map[string]bool),
		gen2Revoked: make(map[string]bool),
	}
	erca := gen2CHA(equipmentERCA)
	for i, raw := range gen1RootKeys {
		key, err := security.UnmarshalRootCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("Gen1 root key %d: %w", i, err)
		}
		s.gen1Roots[key.GetKeyId()] = bytes.Clone(raw)
	}
	for i, raw := range gen2Roots {
		root, err := security.UnmarshalEccCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("Gen2 root certificate %d: %w", i, err)
		}
		if cha := root.GetCertificateHolderAuthorisation(); !bytes.Equal(cha, erca) {
			return nil, fmt.Errorf("Gen2 root certificate %d: holder authorisation %X, want the ERCA's %X", i, cha, erca)
		}
		if err := security.VerifyEccCertificateWithEccRoot(root, root); err != nil {
			return nil, fmt.Errorf("Gen2 root certificate %d is not self-signed: %w", i, err)
		}
		s.gen2Roots[root.GetCertificateHolderReference()] = bytes.Clone(raw)
	}
	for i, raw := range gen2Links {
		link, err := security.UnmarshalEccCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("Gen2 link certificate %d: %w", i, err)
		}
		if cha := link.GetCertificateHolderAuthorisation(); !bytes.Equal(cha, erca) {
			return nil, fmt.Errorf("Gen2 link certificate %d: holder authorisation %X, want the ERCA's %X", i, cha, erca)
		}
		chr := link.GetCertificateHolderReference()
		s.gen2Links[chr] = append(s.gen2Links[chr], bytes.Clone(raw))
	}
	for i, raw := range revokedMSCACertificates {
		if len(raw) != lenGen1Certificate {
			msca, err := security.UnmarshalEccCertificate(raw)
			if err != nil {
				return nil, fmt.Errorf("revoked MSCA certificate %d: %w", i, err)
			}
			s.gen2Revoked[msca.GetCertificateHolderReference()] = true
			continue
		}
		msca, err := security.UnmarshalRsaCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("revoked Gen1 MSCA certificate %d: %w", i, err)
		}
		key, ok := s.Gen1RootKey(msca.GetCertificateAuthorityReference())
		if !ok {
			return nil, fmt.Errorf("revoked Gen1 MSCA certificate %d: no Gen1 ERCA key %s to recover it", i, msca.GetCertificateAuthorityReference())
		}
		if err := security.VerifyRsaCertificateWithRoot(msca, key); err != nil {
			return nil, fmt.Errorf("revoked Gen1 MSCA certificate %d: %w", i, err)
		}
		s.gen1Revoked[msca.GetCertificateHolderReference()] = true
	}
	return s, nil
}

// Gen1RootKey implements Resolver.
func (s *Store) Gen1RootKey(keyID string) (*securityv1.RootCertificate, bool) {
	raw, ok := s.gen1Roots[keyID]
	if !ok {
		return nil, false
	}
	key, err := security.UnmarshalRootCertificate(raw)
	return key, err == nil
}

// Gen2RootCertificate implements Resolver.
func (s *Store) Gen2RootCertificate(chr string) (*securityv1.EccCertificate, bool) {
	raw, ok := s.gen2Roots[chr]
	if !ok {
		return nil, false
	}
	root, err := security.UnmarshalEccCertificate(raw)
	return root, err == nil
}

// Gen2LinkCertificates implements Resolver.
func (s *Store) Gen2LinkCertificates(chr string) []*securityv1.EccCertificate {
	var links []*securityv1.EccCertificate
	for _, raw := range s.gen2Links[chr] {
		if link, err := security.UnmarshalEccCertificate(raw); err == nil {
			links = append(links, link)
		}
	}
	return links
}

// Gen1MSCARevoked implements Resolver.
func (s *Store) Gen1MSCARevoked(chr string) bool {
	return s.gen1Revoked[chr]
}

// Gen2MSCARevoked implements Resolver.
func (s *Store) Gen2MSCARevoked(chr string) bool {
	return s.gen2Revoked[chr]
}

var defaultStore = sync.OnceValue(func() *Store {
	s, err := NewStore([][]byte{certcache.RootG1()}, [][]byte{certcache.RootG2()}, nil, nil)
	if err != nil {
		panic(fmt.Sprintf("trust: the embedded ERCA anchors: %v", err))
	}
	return s
})

// DefaultResolver trusts the Gen1 ERCA key and the Gen2(1) ERCA root certificate embedded in the
// library, with no link certificates and no revocations.
func DefaultResolver() Resolver {
	return defaultStore()
}
