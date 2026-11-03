package trust

import (
	"bytes"
	"os"
	"testing"

	"github.com/way-platform/tachograph-go/internal/cert/certcache"
)

func readCertificate(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDefaultResolverTrustsTheEmbeddedERCAAnchors(t *testing.T) {
	r := DefaultResolver()
	key, ok := r.Gen1RootKey("18250066869723594497") // FD45432000FFFF01
	if !ok || len(key.GetRsaModulus()) != 128 {
		t.Errorf("Gen1 ERCA key = %v, %v; want the embedded EC_PK", key, ok)
	}
	root, ok := r.Gen2RootCertificate("18250066869740371713") // FD45432001FFFF01
	if !ok {
		t.Fatal("the embedded Gen2(1) root does not resolve by its CHR")
	}
	if got := root.GetCertificateHolderAuthorisation(); !bytes.Equal(got, gen2CHA(equipmentERCA)) {
		t.Errorf("root holder authorisation = %X, want %X", got, gen2CHA(equipmentERCA))
	}
	if links := r.Gen2LinkCertificates("18250066869740371713"); len(links) != 0 {
		t.Errorf("%d link certificates, want none", len(links))
	}
	if _, ok := r.Gen2RootCertificate("1316820541130145537"); ok {
		t.Error("a Finnish MSCA CHR resolved as a root")
	}
	if r.Gen2MSCARevoked("1316820541130145537") {
		t.Error("the default resolver revokes a certificate")
	}
}

func TestNewStoreRejectsAnchorsOutsideTheirRole(t *testing.T) {
	msca := readCertificate(t, "../security/testdata/certs/g2/finland_msca_card42.bin")
	gen1MSCA := readCertificate(t, "../security/testdata/certs/g1/finland_tcc37.bin")
	tests := []struct {
		name                            string
		gen1Keys, roots, links, revoked [][]byte
	}{
		{name: "short Gen1 key", gen1Keys: [][]byte{certcache.RootG1()[:143]}},
		{name: "MSCA certificate as a root", roots: [][]byte{msca}},
		{name: "MSCA certificate as a link", links: [][]byte{msca}},
		{name: "revoked Gen1 certificate of an unknown ERCA key", revoked: [][]byte{gen1MSCA}},
		{name: "revoked certificate that is neither Gen1 nor Gen2", revoked: [][]byte{msca[:100]}},
	}
	for _, tt := range tests {
		if _, err := NewStore(tt.gen1Keys, tt.roots, tt.links, tt.revoked); err == nil {
			t.Errorf("%s: NewStore accepted it", tt.name)
		}
	}
}

func TestStoreRevokesTheCHROfEachRevokedCertificate(t *testing.T) {
	store, err := NewStore([][]byte{certcache.RootG1()}, nil, nil, [][]byte{
		readCertificate(t, "../security/testdata/certs/g1/finland_tcc37.bin"),
		readCertificate(t, "../security/testdata/certs/g2/finland_msca_card42.bin"),
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		revoked func(string) bool
		chr     string
		want    bool
	}{
		{"finland_tcc37, recovered under the Gen1 ERCA key", store.Gen1MSCARevoked, "1316820541096591105", true},
		{"finland_tcc38", store.Gen1MSCARevoked, "1316820541113368321", false},
		{"finland_msca_card42", store.Gen2MSCARevoked, "1316820541130145537", true},
		{"finland_msca_card43", store.Gen2MSCARevoked, "1316820541146922753", false},
		// Gen1 and Gen2 build MSCA CHRs alike, so a revocation names a CHR in its own generation only.
		{"Gen2 CHR of the revoked Gen1 certificate", store.Gen2MSCARevoked, "1316820541096591105", false},
		{"Gen1 CHR of the revoked Gen2 certificate", store.Gen1MSCARevoked, "1316820541130145537", false},
	}
	for _, tt := range tests {
		if got := tt.revoked(tt.chr); got != tt.want {
			t.Errorf("%s: revoked = %v, want %v", tt.name, got, tt.want)
		}
	}
}
