package tachograph_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/way-platform/tachograph-go"
	"github.com/way-platform/tachograph-go/internal/hexdump"
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	tachographv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/v1"
	vuv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/vu/v1"
)

// receivedAt is when the tests' downloads arrived, after every fixture's signing time.
var receivedAt = time.Date(2026, 3, 12, 0, 0, 0, 0, time.UTC)

func readHexdump(t *testing.T, path string) []byte {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	data, err := hexdump.Unmarshal(text)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return data
}

// vuTransfer is a transfer behind its tag: 0x76 and the TREP (Appendix 7, 2.2.6).
func vuTransfer(t *testing.T, transferType vuv1.TransferType, value []byte) []byte {
	t.Helper()
	desc := transferType.Descriptor().Values().ByNumber(transferType.Number())
	if desc == nil || !proto.HasExtension(desc.Options(), vuv1.E_TrepValue) {
		t.Fatalf("transfer type %v has no TREP", transferType)
	}
	trep := proto.GetExtension(desc.Options(), vuv1.E_TrepValue).(int32)
	return append([]byte{0x76, byte(trep)}, value...)
}

// vuFixture is a VU record fixture directory as a download, its transfers in file order.
func vuFixture(t *testing.T, dir string) []byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("internal", "vu", "testdata", "records", dir, "*.hexdump"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no VU fixture in %s: %v", dir, err)
	}
	var out []byte
	for _, path := range paths {
		_, name, _ := strings.Cut(strings.TrimSuffix(filepath.Base(path), ".hexdump"), "-")
		number, ok := vuv1.TransferType_value[name]
		if !ok {
			t.Fatalf("%s: unknown transfer type %q", path, name)
		}
		out = append(out, vuTransfer(t, vuv1.TransferType(number), readHexdump(t, path))...)
	}
	return out
}

// cardDownloadTransfer is a TREP 06 transfer of a card's EF_ICC; it must end a download.
func cardDownloadTransfer(t *testing.T) []byte {
	t.Helper()
	return vuTransfer(t, vuv1.TransferType_CARD_DOWNLOAD, slices.Concat([]byte{0x00, 0x02, 0x00, 0x00, 0x19}, make([]byte, 25)))
}

// cardFixture is a card record fixture directory as a download without signatures: the MF's EFs
// and the data EFs of generation's DF, or of both DFs when generation is unspecified.
func cardFixture(t *testing.T, dir string, generation ddv1.Generation) []byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("internal", "card", "testdata", "records", dir, "*.hexdump"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no card fixture in %s: %v", dir, err)
	}
	var out []byte
	for _, path := range paths {
		parts := strings.Split(strings.TrimSuffix(filepath.Base(path), ".hexdump"), "-")
		if len(parts) != 4 {
			t.Fatalf("%s: unexpected fixture name", path)
		}
		file := cardv1.ElementaryFileType(cardv1.ElementaryFileType_value[parts[1]])
		gen := ddv1.Generation(ddv1.Generation_value[parts[2]])
		if file == cardv1.ElementaryFileType_ELEMENTARY_FILE_UNSPECIFIED {
			t.Fatalf("%s: unknown elementary file %q", path, parts[1])
		}
		mf := file == cardv1.ElementaryFileType_EF_ICC || file == cardv1.ElementaryFileType_EF_IC
		if parts[3] != "DATA" || (!mf && generation != ddv1.Generation_GENERATION_UNSPECIFIED && gen != generation) {
			continue
		}
		fid := proto.GetExtension(file.Descriptor().Values().ByNumber(file.Number()).Options(), cardv1.E_FileId).(int32)
		appendix := byte(0x00)
		if gen == ddv1.Generation_GENERATION_2 {
			appendix = 0x02
		}
		value := readHexdump(t, path)
		out = append(out, byte(fid>>8), byte(fid), appendix)
		out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
		out = append(out, value...)
	}
	return out
}

// vuKind is a VU download to sign: its generation, its unsigned body and its overview's signing time.
type vuKind struct {
	name       string
	generation ddv1.Generation
	body       func(*testing.T) []byte
	signedAt   time.Time
}

var vuKinds = []vuKind{
	{
		name:       "Gen1",
		generation: ddv1.Generation_GENERATION_1,
		body: func(t *testing.T) []byte {
			return slices.Concat(vuFixture(t, "000-anonymized"), cardDownloadTransfer(t))
		},
		signedAt: time.Date(2025, 9, 12, 13, 32, 45, 0, time.UTC),
	},
	{
		name:       "Gen2 v1",
		generation: ddv1.Generation_GENERATION_2,
		body:       gen2V1Download,
		signedAt:   time.Date(2026, 3, 11, 22, 52, 29, 0, time.UTC),
	},
	{
		name:       "Gen2 v2",
		generation: ddv1.Generation_GENERATION_2,
		body: func(t *testing.T) []byte {
			return slices.Concat(vuTransfer(t, vuv1.TransferType_DOWNLOAD_INTERFACE_VERSION, []byte{0x02, 0x02}), vuFixture(t, "004-anonymized"), cardDownloadTransfer(t))
		},
		signedAt: time.Date(2026, 3, 11, 22, 52, 29, 0, time.UTC),
	},
}

// gen2V1Download is a Gen2 v1 download: the Gen2 v2 fixture's overview with a 14-byte
// registration as TREP 21, and TREP 25 technical data holding only an identification.
func gen2V1Download(t *testing.T) []byte {
	t.Helper()
	v2 := readHexdump(t, "internal/vu/testdata/records/004-anonymized/000-OVERVIEW_GEN2_V2.hexdump")
	at := 0
	for range 3 {
		at += 5 + int(binary.BigEndian.Uint16(v2[at+1:]))*int(binary.BigEndian.Uint16(v2[at+3:]))
	}
	registration := slices.Concat([]byte{0x0B, 0x00, 0x0E, 0x00, 0x01, 0x01}, []byte("AB123        "))
	overview := slices.Concat(v2[:at], registration, v2[at+5+15:])
	technicalData := slices.Concat([]byte{0x19, 0x00, 0x7E, 0x00, 0x01}, make([]byte, 126), []byte{0x08, 0x00, 0x00, 0x00, 0x00})
	return slices.Concat(
		vuTransfer(t, vuv1.TransferType_DOWNLOAD_INTERFACE_VERSION, []byte{0x02, 0x01}),
		vuTransfer(t, vuv1.TransferType_OVERVIEW_GEN2_V1, overview),
		vuTransfer(t, vuv1.TransferType_TECHNICAL_DATA_GEN2_V1, technicalData),
		cardDownloadTransfer(t),
	)
}

// cardKind is a driver card download to sign: one DF, its unsigned body and the newest timestamp
// in that DF's activity and event data.
type cardKind struct {
	name       string
	generation ddv1.Generation
	body       func(*testing.T) []byte
	newest     time.Time
}

var cardKinds = []cardKind{
	{
		name:       "Gen1",
		generation: ddv1.Generation_GENERATION_1,
		body:       func(t *testing.T) []byte { return cardFixture(t, "000-anonymized", ddv1.Generation_GENERATION_1) },
		newest:     time.Date(2020, 7, 7, 0, 0, 0, 0, time.UTC),
	},
	{
		name:       "Gen2",
		generation: ddv1.Generation_GENERATION_2,
		body:       func(t *testing.T) []byte { return cardFixture(t, "004-anonymized", ddv1.Generation_GENERATION_2) },
		newest:     time.Date(2020, 7, 18, 0, 0, 0, 0, time.UTC),
	},
}

// rewriteVU re-encodes a VU download with each transfer's value replaced by edit's; nil drops the transfer.
func rewriteVU(t *testing.T, data []byte, edit func(*vuv1.RawVehicleUnitFile_Record) []byte) []byte {
	t.Helper()
	raw, err := tachograph.Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var out []byte
	for _, record := range raw.GetVehicleUnit().GetRecords() {
		value := edit(record)
		if value == nil {
			continue
		}
		out = binary.BigEndian.AppendUint16(out, uint16(record.GetTag()))
		out = append(out, value...)
	}
	return out
}

// rewriteCard re-encodes a card download as the records edit returns.
func rewriteCard(t *testing.T, data []byte, edit func([]*cardv1.RawCardFile_Record) []*cardv1.RawCardFile_Record) []byte {
	t.Helper()
	raw, err := tachograph.Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var out []byte
	for _, record := range edit(raw.GetCard().GetRecords()) {
		tag := record.GetTag()
		out = append(out, byte(tag>>16), byte(tag>>8), byte(tag))
		out = binary.BigEndian.AppendUint16(out, uint16(len(record.GetValue())))
		out = append(out, record.GetValue()...)
	}
	return out
}

// authenticate unmarshals a download and authenticates it as received at at.
func authenticate(t *testing.T, data []byte, resolver tachograph.CertificateResolver, at time.Time) *tachographv1.RawFile {
	t.Helper()
	raw, err := tachograph.Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	authenticated, err := tachograph.AuthenticateOptions{CertificateResolver: resolver, ReceivedAt: at}.Authenticate(t.Context(), raw)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return authenticated
}

// decimal is a certificate reference as Authentication reports it.
func decimal(reference [8]byte) string {
	return strconv.FormatUint(binary.BigEndian.Uint64(reference[:]), 10)
}
