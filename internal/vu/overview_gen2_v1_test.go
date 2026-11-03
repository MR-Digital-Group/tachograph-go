package vu

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"

	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	vuv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/vu/v1"
)

func TestOverview_Gen2V1(t *testing.T) {
	// Discover all matching hexdump files
	hexdumpFiles, err := findHexdumpFiles(vuv1.TransferType_OVERVIEW_GEN2_V1)
	if err != nil {
		t.Fatalf("Failed to discover hexdump files: %v", err)
	}
	if len(hexdumpFiles) == 0 {
		t.Skip("No hexdump files found for OVERVIEW_GEN2_V1")
	}

	// Run subtest for each discovered file
	for _, hexdumpPath := range hexdumpFiles {
		// Use relative path from testdata as subtest name
		relPath := strings.TrimPrefix(hexdumpPath, "testdata/records/")
		testName := strings.TrimSuffix(relPath, ".data.hexdump")

		t.Run(testName, func(t *testing.T) {
			// Read hexdump
			data, err := readHexdump(hexdumpPath)
			if err != nil {
				t.Fatalf("Failed to read hexdump: %v", err)
			}

			// Unmarshal
			overview, err := unmarshalOverviewGen2V1(data)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if overview == nil {
				t.Fatal("Unmarshal returned nil")
			}

			// Golden JSON comparison
			goldenPath := goldenJSONPath(hexdumpPath)
			loadOrCreateGolden(t, overview, goldenPath)

			// Round-trip test - marshal
			marshalOpts := MarshalOptions{}
			marshaled, err := marshalOpts.MarshalOverviewGen2V1(overview)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			if diff := cmp.Diff(data, marshaled); diff != "" {
				t.Errorf("Binary round-trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestParseVehicleRegistrationRecordArrayGen2V1 reads the overview's registration by its record
// size: a Gen2 V1 VU writes a 14-byte VehicleRegistrationNumber without the nation (Data
// Dictionary 2.168), and a 15-byte VehicleRegistrationIdentification carries the nation (2.166a).
func TestParseVehicleRegistrationRecordArrayGen2V1(t *testing.T) {
	number := []byte{0x01, 'A', 'B', '1', '2', '3', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '} // code page + 13 bytes
	tests := []struct {
		name       string
		array      []byte
		wantNation ddv1.NationNumeric
		wantErr    bool
	}{
		{
			name:       "VehicleRegistrationNumber, 14 bytes",
			array:      append([]byte{0x0B, 0x00, 0x0E, 0x00, 0x01}, number...),
			wantNation: ddv1.NationNumeric_NATION_NUMERIC_UNSPECIFIED,
		},
		{
			name:       "VehicleRegistrationIdentification, 15 bytes",
			array:      append([]byte{0x24, 0x00, 0x0F, 0x00, 0x01, 0x25}, number...), // 0x25 = Norway
			wantNation: ddv1.NationNumeric_NORWAY,
		},
		{
			name:    "13 bytes",
			array:   append([]byte{0x0B, 0x00, 0x0D, 0x00, 0x01}, number[:13]...),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vrn, n, err := parseVehicleRegistrationIdentificationRecordArray(tt.array, 0)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n != len(tt.array) {
				t.Errorf("bytes read = %d, want %d", n, len(tt.array))
			}
			if got := vrn.GetNation(); got != tt.wantNation {
				t.Errorf("nation = %v, want %v", got, tt.wantNation)
			}
			if got := vrn.GetNumber().GetValue(); got != "AB123" {
				t.Errorf("number = %q, want %q", got, "AB123")
			}
		})
	}
}

// TestOverviewGen2V1WritesTheRegistrationAsRead builds Gen2 V1 overviews from the Gen2 V2
// overview hexdump, whose layout differs only in the registration, and checks that a 14-byte
// VehicleRegistrationNumber and a 15-byte VehicleRegistrationIdentification are each written
// back at their own size, from the parsed fields and after anonymization.
func TestOverviewGen2V1WritesTheRegistrationAsRead(t *testing.T) {
	v2, err := readHexdump("testdata/records/004-anonymized/000-OVERVIEW_GEN2_V2.hexdump")
	if err != nil {
		t.Fatalf("read hexdump: %v", err)
	}
	// registrationAt walks past the certificate and VIN record arrays to the registration.
	registrationAt := func(data []byte) int {
		at := 0
		for range 3 {
			size, err := sizeOfRecordArray(data, at)
			if err != nil {
				t.Fatalf("record array at %d: %v", at, err)
			}
			at += size
		}
		return at
	}
	at := registrationAt(v2)
	end := at + 5 + 15
	number := []byte{0x01, 'A', 'B', '1', '2', '3', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '} // code page + 13 bytes
	tests := []struct {
		name       string
		array      []byte
		recordType byte
		size       int
		hasNation  bool
	}{
		{"VehicleRegistrationNumber", append([]byte{0x0B, 0x00, 0x0E, 0x00, 0x01}, number...), 0x0B, 14, false},
		{"VehicleRegistrationIdentification", append([]byte{0x24, 0x00, 0x0F, 0x00, 0x01, 0x25}, number...), 0x24, 15, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := append(append(append([]byte{}, v2[:at]...), tt.array...), v2[end:]...)
			overview, err := unmarshalOverviewGen2V1(data)
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			parsed := proto.CloneOf(overview)
			parsed.SetRawData(nil)
			for name, o := range map[string]*vuv1.OverviewGen2V1{
				"parsed":     parsed,
				"anonymized": AnonymizeOptions{}.anonymizeOverviewGen2V1(overview),
			} {
				marshaled, err := MarshalOptions{}.MarshalOverviewGen2V1(o)
				if err != nil {
					t.Fatalf("%s: marshal: %v", name, err)
				}
				recordType, size, count, _, err := parseRecordArrayHeader(marshaled, registrationAt(marshaled))
				if err != nil {
					t.Fatalf("%s: registration header: %v", name, err)
				}
				if recordType != tt.recordType || int(size) != tt.size || count != 1 {
					t.Errorf("%s: registration written as type 0x%02X, %d × %d bytes; want type 0x%02X, 1 × %d bytes", name, recordType, count, size, tt.recordType, tt.size)
				}
				again, err := unmarshalOverviewGen2V1(marshaled)
				if err != nil {
					t.Fatalf("%s: unmarshal the written overview: %v", name, err)
				}
				if got := again.GetVehicleRegistrationWithNation().HasNation(); got != tt.hasNation {
					t.Errorf("%s: nation present = %v, want %v", name, got, tt.hasNation)
				}
			}
		})
	}
}
