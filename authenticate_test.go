package tachograph_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/way-platform/tachograph-go"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	tachographv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/v1"
	"github.com/way-platform/tachograph-go/tachographtest"
)

func TestAuthenticateRejectsInputItCannotProcess(t *testing.T) {
	raw, err := tachograph.Unmarshal(cardFixture(t, "000-anonymized", ddv1.Generation_GENERATION_1))
	if err != nil {
		t.Fatal(err)
	}
	resolver := tachograph.DefaultCertificateResolver()
	tests := []struct {
		name string
		opts tachograph.AuthenticateOptions
		raw  *tachographv1.RawFile
	}{
		{"nil file", tachograph.AuthenticateOptions{CertificateResolver: resolver, ReceivedAt: receivedAt}, nil},
		{"no resolver", tachograph.AuthenticateOptions{ReceivedAt: receivedAt}, raw},
		{"no receipt time", tachograph.AuthenticateOptions{CertificateResolver: resolver}, raw},
		{"unknown file type", tachograph.AuthenticateOptions{CertificateResolver: resolver, ReceivedAt: receivedAt}, &tachographv1.RawFile{}},
	}
	for _, tt := range tests {
		if _, err := tt.opts.Authenticate(t.Context(), tt.raw); err == nil {
			t.Errorf("%s: Authenticate() succeeded, want an error", tt.name)
		}
	}
}

// TestLibraryNeverImportsTheNetwork lists every package the module's non-test packages import,
// directly or not: verification is offline by construction while neither net nor net/http is
// among them. No dependency imports net today.
func TestLibraryNeverImportsTheNetwork(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command to list the library's imports")
	}
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./...").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	importers := make(map[string][]string)
	for line := range strings.Lines(string(out)) {
		pkg, imports, _ := strings.Cut(strings.TrimSpace(line), " ")
		for imported := range strings.FieldsSeq(imports) {
			importers[imported] = append(importers[imported], pkg)
		}
	}
	for _, network := range []string{"net", "net/http"} {
		if len(importers[network]) > 0 {
			t.Errorf("the library depends on %s, which %s import", network, strings.Join(importers[network], ", "))
		}
	}
}

func TestDefaultCertificateResolverTrustsTheEmbeddedERCAAnchors(t *testing.T) {
	r := tachograph.DefaultCertificateResolver()
	if _, ok := r.Gen1RootKey("18250066869723594497"); !ok {
		t.Error("the Gen1 ERCA key FD45432000FFFF01 is not trusted")
	}
	if _, ok := r.Gen2RootCertificate("18250066869740371713"); !ok {
		t.Error("the Gen2(1) root FD45432001FFFF01 is not trusted")
	}
}

func TestNewCertificateResolverRejectsMalformedAnchors(t *testing.T) {
	pki := tachographtest.NewPKI(t)
	tests := []struct {
		name  string
		store tachograph.TrustStore
	}{
		{"short Gen1 key", tachograph.TrustStore{Gen1RootKeys: [][]byte{pki.Gen1Root.RootKey()[:143]}}},
		{"MSCA certificate as a root", tachograph.TrustStore{Gen2RootCertificates: [][]byte{pki.Gen2MSCACertificate}}},
		{"MSCA certificate as a link", tachograph.TrustStore{Gen2LinkCertificates: [][]byte{pki.Gen2MSCACertificate}}},
		{"revoked Gen1 certificate of an unknown ERCA key", tachograph.TrustStore{RevokedMSCACertificates: [][]byte{pki.Gen1MSCACertificate}}},
	}
	for _, tt := range tests {
		if _, err := tachograph.NewCertificateResolver(tt.store); err == nil {
			t.Errorf("%s: NewCertificateResolver accepted it", tt.name)
		}
	}
}
