package tachograph

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/way-platform/tachograph-go/internal/card"
	"github.com/way-platform/tachograph-go/internal/dd"
	"github.com/way-platform/tachograph-go/internal/vu"
	tachographv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/v1"
)

// Unmarshal parses a tachograph file from its binary representation into a raw,
// unparsed format with default options. The returned RawFile is suitable for
// authentication.
//
// This is a convenience function that uses default options:
// - Strict: true (error on unrecognized tags)
//
// For custom options, use UnmarshalOptions directly:
//
//	opts := UnmarshalOptions{Strict: false}
//	rawFile, err := opts.Unmarshal(data)
func Unmarshal(data []byte) (*tachographv1.RawFile, error) {
	opts := UnmarshalOptions{
		Strict: true,
	}
	return opts.Unmarshal(data)
}

// UnmarshalOptions configures the unmarshaling process for tachograph files.
type UnmarshalOptions struct {
	// Strict controls how the unmarshaler handles unrecognized tags or
	// structural inconsistencies.
	//
	// If true (default), the unmarshaler will return an error on any
	// unrecognized tags or structural inconsistencies.
	//
	// If false, the unmarshaler will attempt to skip over unrecognized
	// parts of the file and continue parsing.
	Strict bool
}

// Unmarshal parses a tachograph file from its binary representation into a raw,
// unparsed format. The returned RawFile is suitable for authentication via
// AuthenticateOptions.Authenticate.
func (o UnmarshalOptions) Unmarshal(data []byte) (*tachographv1.RawFile, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("insufficient data for tachograph file: %w", io.ErrUnexpectedEOF)
	}

	var rawFile tachographv1.RawFile

	switch {
	// Vehicle unit file (starts with TREP prefix 0x76).
	case data[0] == 0x76:
		vuRaw, err := o.vu().UnmarshalRawVehicleUnitFile(data)
		if err != nil {
			return nil, err
		}
		rawFile.SetType(tachographv1.RawFile_VEHICLE_UNIT)
		rawFile.SetVehicleUnit(vuRaw)

	// Card file (starts with EF_ICC 0x0002, or the TLV header of another card EF).
	case binary.BigEndian.Uint16(data[0:2]) == 0x0002 || card.StartsCardFile(data):
		cardRaw, err := o.card().UnmarshalRawCardFile(data)
		if err != nil {
			return nil, err
		}
		rawFile.SetType(tachographv1.RawFile_CARD)
		rawFile.SetCard(cardRaw)

	default:
		return nil, errors.New("unknown or unsupported file type")
	}

	return &rawFile, nil
}

// card returns card.UnmarshalOptions configured from UnmarshalOptions.
func (o UnmarshalOptions) card() card.UnmarshalOptions {
	return card.UnmarshalOptions{
		UnmarshalOptions: dd.UnmarshalOptions{
			// PreserveRawData NOT set - unmarshal produces RawFile, not semantic messages
		},
		Strict: o.Strict,
	}
}

// vu returns vu.UnmarshalOptions configured from UnmarshalOptions.
func (o UnmarshalOptions) vu() vu.UnmarshalOptions {
	return vu.UnmarshalOptions{
		UnmarshalOptions: dd.UnmarshalOptions{
			// PreserveRawData NOT set - unmarshal produces RawFile, not semantic messages
		},
		Strict: o.Strict,
	}
}
