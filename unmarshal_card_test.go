package tachograph_test

import (
	"slices"
	"testing"

	tachograph "github.com/way-platform/tachograph-go"
	cardv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/card/v1"
	ddv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/dd/v1"
	tachographv1 "github.com/way-platform/tachograph-go/proto/gen/go/wayplatform/connect/tachograph/v1"
	"google.golang.org/protobuf/proto"
)

func TestUnmarshalReadsACardDownloadWithoutTheOptionalMFFiles(t *testing.T) {
	for _, tc := range []struct{ name, dir string }{{"Gen1", "000-anonymized"}, {"Gen1 and Gen2", "004-anonymized"}} {
		whole := cardFixture(t, tc.dir, ddv1.Generation_GENERATION_UNSPECIFIED)
		want := parse(t, whole)
		for name, omitted := range map[string][]cardv1.ElementaryFileType{
			"EF_ICC":           {cardv1.ElementaryFileType_EF_ICC},
			"EF_ICC and EF_IC": {cardv1.ElementaryFileType_EF_ICC, cardv1.ElementaryFileType_EF_IC},
		} {
			t.Run(tc.name+" without "+name, func(t *testing.T) {
				data := rewriteCard(t, whole, func(records []*cardv1.RawCardFile_Record) []*cardv1.RawCardFile_Record {
					return slices.DeleteFunc(records, func(r *cardv1.RawCardFile_Record) bool { return slices.Contains(omitted, r.GetFile()) })
				})
				got := parse(t, data)
				if got.GetType() != tachographv1.File_DRIVER_CARD {
					t.Fatalf("type = %v, want DRIVER_CARD", got.GetType())
				}
				if got.GetDriverCard().GetIcc() != nil || (len(omitted) > 1 && got.GetDriverCard().GetIc() != nil) {
					t.Error("an MF file the download left out was parsed")
				}
				gotCard, wantCard := proto.CloneOf(got.GetDriverCard()), proto.CloneOf(want.GetDriverCard())
				for _, c := range []*cardv1.DriverCardFile{gotCard, wantCard} {
					c.ClearIcc()
					if slices.Contains(omitted, cardv1.ElementaryFileType_EF_IC) {
						c.ClearIc()
					}
				}
				if !proto.Equal(gotCard, wantCard) {
					t.Error("the card's application data differs from the whole download's")
				}
			})
		}
	}
}

func TestUnmarshalTakesAnEFICCFirstFileForACardInEitherMode(t *testing.T) {
	odd := slices.Clone(cardFixture(t, "000-anonymized", ddv1.Generation_GENERATION_UNSPECIFIED))
	if odd[0] != 0x00 || odd[1] != 0x02 {
		t.Fatalf("the fixture opens with % X, not EF_ICC", odd[:2])
	}
	odd[2] = 0x04
	raw, err := tachograph.UnmarshalOptions{Strict: false}.Unmarshal(odd)
	if err != nil || raw.GetType() != tachographv1.RawFile_CARD {
		t.Fatalf("non-strict Unmarshal() = %v, %v; want a card, as before EF_ICC became optional", raw.GetType(), err)
	}
	if _, err := tachograph.Unmarshal(odd); err == nil {
		t.Error("strict Unmarshal() took EF_ICC with an appendix beyond the two DFs")
	}
}

func TestUnmarshalRejectsWhatNoCardEFOpens(t *testing.T) {
	card := cardFixture(t, "000-anonymized", ddv1.Generation_GENERATION_UNSPECIFIED)
	for name, data := range map[string][]byte{
		"an unknown file ID":                  {0x12, 0x34, 0x00, 0x00, 0x01, 0xFF},
		"an appendix beyond the two DFs":      {0x05, 0x01, 0x04, 0x00, 0x01, 0xFF},
		"a card EF header cut short":          {0x05, 0x01, 0x00, 0x00},
		"a later record cut short":            card[:len(card)-3],
		"a card EF with an unknown one":       slices.Concat(card, []byte{0x12, 0x34, 0x00, 0x00, 0x01, 0xFF}),
		"a later appendix beyond the two DFs": slices.Concat(card, []byte{0x05, 0x01, 0x04, 0x00, 0x01, 0xFF}),
	} {
		t.Run(name, func(t *testing.T) {
			if raw, err := tachograph.Unmarshal(data); err == nil {
				t.Fatalf("Unmarshal() = %v, want an error", raw.GetType())
			}
		})
	}

	raw, err := tachograph.Unmarshal(vuFixture(t, "000-anonymized"))
	if err != nil {
		t.Fatalf("unmarshal VU: %v", err)
	}
	if raw.GetType() != tachographv1.RawFile_VEHICLE_UNIT {
		t.Errorf("a VU download read as %v", raw.GetType())
	}
}

func parse(t *testing.T, data []byte) *tachographv1.File {
	t.Helper()
	raw, err := tachograph.Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if raw.GetType() != tachographv1.RawFile_CARD {
		t.Fatalf("raw type = %v, want CARD", raw.GetType())
	}
	file, err := tachograph.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return file
}
