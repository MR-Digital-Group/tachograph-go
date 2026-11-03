package vu

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	vuv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/vu/v1"
)

func TestTechnicalData_Gen2V2(t *testing.T) {
	// Discover all matching hexdump files
	hexdumpFiles, err := findHexdumpFiles(vuv1.TransferType_TECHNICAL_DATA_GEN2_V2)
	if err != nil {
		t.Fatalf("Failed to discover hexdump files: %v", err)
	}
	if len(hexdumpFiles) == 0 {
		t.Skip("No hexdump files found for TECHNICAL_DATA_GEN2_V2")
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
			technicalData, err := unmarshalTechnicalDataGen2V2(data)
			if err != nil {
				t.Fatalf("Failed to unmarshal TechnicalData Gen2V2: %v", err)
			}
			if technicalData == nil {
				t.Fatal("Unmarshal returned nil")
			}

			// Golden JSON comparison
			goldenPath := goldenJSONPath(hexdumpPath)
			loadOrCreateGolden(t, technicalData, goldenPath)

			// Round-trip test - marshal
			marshalOpts := MarshalOptions{}
			marshaled, err := marshalOpts.MarshalTechnicalDataGen2V2(technicalData)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			if diff := cmp.Diff(data, marshaled); diff != "" {
				t.Errorf("Binary round-trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestTechnicalDataGen2V2ReadsTheWholeLayout sizes and parses a synthetic TREP 35 transfer whose
// record arrays carry Data Dictionary 2.120 record types, with the VuCardRecordArray between the
// calibrations and the ITS consents, then a 64-byte signature (upstream issue 39).
func TestTechnicalDataGen2V2ReadsTheWholeLayout(t *testing.T) {
	text := func(s string, n int) []byte { return []byte(fmt.Sprintf("%-*s", n, s)) }
	array := func(recordType byte, size int, records ...[]byte) []byte {
		b := []byte{recordType, byte(size >> 8), byte(size), 0, byte(len(records))}
		for _, r := range records {
			if len(r) != size {
				t.Fatalf("record type 0x%02X: record of %d bytes, want %d", recordType, len(r), size)
			}
			b = append(b, r...)
		}
		return b
	}
	serial := []byte{0x00, 0xBC, 0x61, 0x4E, 0x09, 0x25, 0x06, 0xA1} // 12345678, 09/25, vehicle unit, manufacturer A1
	timeReal := []byte{0x68, 0x00, 0x00, 0x00}
	identification := slices.Concat(
		[]byte{0x01}, text("MANUFACTURER", 35), []byte{0x01}, text("ADDRESS", 35), text("PART0001", 16),
		serial, text("0100", 4), timeReal, timeReal, text("e1-0001", 16), []byte{0x02, 0x00},
	)
	cardNumber := slices.Concat([]byte{0x01, 0x25}, text("DRIVER0000000100", 16), []byte{0x02})
	data := slices.Concat(
		array(0x19, 126, identification),
		array(0x20, 28),
		array(0x21, 28),
		array(0x0C, 252),
		array(0x0E, 28, slices.Concat(serial, []byte{0x01, 0x01, 0x00, 0x01}, text("DRIVER0000000100", 16))),
		array(0x17, 20, append(slices.Clone(cardNumber), 0x01)),
		array(0x1F, 87, slices.Concat([]byte{0x1A, 0x01}, timeReal, timeReal, cardNumber, cardNumber, cardNumber, cardNumber, []byte{0x00})),
	)
	signature := array(0x08, 64, make([]byte, 64))
	value := slices.Concat(data, signature)

	total, signatureSize, err := sizeOfTechnicalData(value, vuv1.TransferType_TECHNICAL_DATA_GEN2_V2)
	if err != nil {
		t.Fatalf("size: %v", err)
	}
	if total != len(value) || signatureSize != len(signature) {
		t.Fatalf("size = %d with a %d-byte signature, want %d with %d", total, signatureSize, len(value), len(signature))
	}
	td, err := unmarshalTechnicalDataGen2V2(value)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := td.GetVuIdentification().GetSerialNumber(); got.GetSerialNumber() != 12345678 {
		t.Errorf("VU serial = %d, want 12345678", got.GetSerialNumber())
	}
	if its := td.GetItsConsentRecords(); len(its) != 1 || !its[0].GetConsentStatus() {
		t.Errorf("ITS consents = %v, want one granted consent", its)
	}
	if got := len(td.GetPowerSupplyInterruptions()); got != 1 {
		t.Errorf("power supply interruptions = %d, want 1", got)
	}
	if diff := cmp.Diff(signature, td.GetSignature()); diff != "" {
		t.Errorf("signature (-want +got):\n%s", diff)
	}
	if _, err := unmarshalTechnicalDataGen2V2(data); err == nil {
		t.Error("a transfer without a signature array was accepted")
	}
}
