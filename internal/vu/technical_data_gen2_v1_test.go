package vu

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	vuv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/vu/v1"
)

func TestTechnicalData_Gen2V1(t *testing.T) {
	// Discover all matching hexdump files
	hexdumpFiles, err := findHexdumpFiles(vuv1.TransferType_TECHNICAL_DATA_GEN2_V1)
	if err != nil {
		t.Fatalf("Failed to discover hexdump files: %v", err)
	}
	if len(hexdumpFiles) == 0 {
		t.Skip("No hexdump files found for TECHNICAL_DATA_GEN2_V1")
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
			technicalData, err := unmarshalTechnicalDataGen2V1(data)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if technicalData == nil {
				t.Fatal("Unmarshal returned nil")
			}

			// Golden JSON comparison
			goldenPath := goldenJSONPath(hexdumpPath)
			loadOrCreateGolden(t, technicalData, goldenPath)

			// Round-trip test - marshal
			marshalOpts := MarshalOptions{}
			marshaled, err := marshalOpts.MarshalTechnicalDataGen2V1(technicalData)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			if diff := cmp.Diff(data, marshaled); diff != "" {
				t.Errorf("Binary round-trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestTechnicalDataGen2V1ReadsTheWholeLayout parses a synthetic TREP 25 transfer with every
// record array in the order of Appendix 7, record types from Data Dictionary 2.120 and record
// sizes from the data dictionary: VuIdentification 126, SensorPairedRecord and
// SensorExternalGNSSCoupledRecord 28, VuCalibrationRecord 222 (the 167-byte Gen1 layout plus
// SealDataVu, 5 × 11), VuCardRecord 28, VuITSConsentRecord 20, VuPowerSupplyInterruptionRecord
// 87, then a 64-byte signature.
func TestTechnicalDataGen2V1ReadsTheWholeLayout(t *testing.T) {
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
		serial, text("0100", 4), timeReal, timeReal, text("e1-0001", 16),
		[]byte{0x02, 0x00}, // vuGeneration, vuAbility
	)
	seal := func(equipmentType byte, id string) []byte {
		return slices.Concat([]byte{equipmentType, 0x00, 0xA1}, text(id, 8))
	}
	calibration := slices.Concat(
		[]byte{0x01},                       // calibrationPurpose
		[]byte{0x01}, text("WORKSHOP", 35), // workshopName
		[]byte{0x01}, text("STREET 1", 35), // workshopAddress
		[]byte{0x02, 0x25}, text("W000000000001011", 16), // workshopCardNumber: workshop card, Norway
		timeReal,                                // workshopCardExpiryDate
		text("VIN00000000000001", 17),           // vehicleIdentificationNumber
		[]byte{0x25, 0x01}, text("JD91529", 13), // vehicleRegistrationIdentification: Norway
		[]byte{0x1F, 0x40, 0x1F, 0x40, 0x0C, 0x80}, // w, k, l
		text("315/80 R22.5", 15),                   // tyreSize
		[]byte{0x5A},                               // authorisedSpeed
		[]byte{0, 0, 1, 0, 0, 2},                   // old and new odometer
		timeReal, timeReal, timeReal,               // old and new time, next calibration
		seal(0x06, "SEAL0001"), seal(0x10, ""), seal(0x10, ""), seal(0x10, ""), seal(0x10, ""), // sealDataVu
	)
	cardNumber := slices.Concat([]byte{0x01, 0x25}, text("DRIVER0000000100", 16), []byte{0x02}) // FullCardNumberAndGeneration
	data := slices.Concat(
		array(0x19, 126, identification),
		array(0x20, 28, slices.Concat(serial, text("e1-S001", 16), timeReal)),
		array(0x21, 28, slices.Concat(serial, text("e1-G001", 16), timeReal)),
		array(0x0C, 222, calibration),
		array(0x0E, 28, slices.Concat(serial, []byte{0x01, 0x01, 0x00, 0x01}, text("DRIVER0000000100", 16))),
		array(0x17, 20, append(slices.Clone(cardNumber), 0x01)),
		array(0x1F, 87, slices.Concat([]byte{0x1A, 0x01}, timeReal, timeReal, cardNumber, cardNumber, cardNumber, cardNumber, []byte{0x00})),
	)
	signature := array(0x08, 64, make([]byte, 64))
	value := slices.Concat(data, signature)

	total, signatureSize, err := sizeOfTechnicalDataGen2V1(value)
	if err != nil {
		t.Fatalf("size: %v", err)
	}
	if total != len(value) || signatureSize != len(signature) {
		t.Errorf("size = %d with a %d-byte signature, want %d with %d", total, signatureSize, len(value), len(signature))
	}
	td, err := unmarshalTechnicalDataGen2V1(value)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := td.GetVuIdentification().GetSerialNumber(); got.GetSerialNumber() != 12345678 || got.GetManufacturerCode() != 0xA1 {
		t.Errorf("VU serial = %d by %02X, want 12345678 by A1", got.GetSerialNumber(), got.GetManufacturerCode())
	}
	if got := len(td.GetPairedSensors()); got != 1 {
		t.Errorf("paired sensors = %d, want 1", got)
	}
	if got := len(td.GetCalibrationRecords()); got != 1 {
		t.Fatalf("calibration records = %d, want 1", got)
	}
	cal := td.GetCalibrationRecords()[0]
	if got := cal.GetWorkshopCardNumber().GetCardIssuingMemberState(); got != ddv1.NationNumeric_NORWAY {
		t.Errorf("workshop card nation = %v, want NORWAY", got)
	}
	if got := cal.GetVin().GetValue(); got != "VIN00000000000001" {
		t.Errorf("calibration VIN = %q", got)
	}
	if got := cal.GetVehicleRegistration(); got.GetNation() != ddv1.NationNumeric_NORWAY || got.GetNumber().GetValue() != "JD91529" {
		t.Errorf("calibration registration = %v %q, want NORWAY JD91529", got.GetNation(), got.GetNumber().GetValue())
	}
	if got := cal.GetTyreSize().GetValue(); got != "315/80 R22.5" {
		t.Errorf("calibration tyre size = %q", got)
	}
	if diff := cmp.Diff(signature, td.GetSignature()); diff != "" {
		t.Errorf("signature (-want +got):\n%s", diff)
	}
	marshaled, err := MarshalOptions{}.MarshalTechnicalDataGen2V1(td)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if diff := cmp.Diff(value, marshaled); diff != "" {
		t.Errorf("round trip (-want +got):\n%s", diff)
	}

	// the signature array ends the transfer
	if _, err := unmarshalTechnicalDataGen2V1(slices.Concat(value, array(0x0E, 28))); err == nil {
		t.Error("a record array after the signature was accepted")
	}
	if _, err := unmarshalTechnicalDataGen2V1(data); err == nil {
		t.Error("a transfer without a signature array was accepted")
	}
}
