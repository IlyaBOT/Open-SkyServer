package server

import (
	"strings"
	"testing"
)

func TestDetailedDebugConfigFlag(t *testing.T) {
	cfg, err := ParseConfig([]string{"--detailed-debug"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DetailedDebug {
		t.Fatal("--detailed-debug did not enable detailed diagnostics")
	}

	cfg, err = ParseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DetailedDebug {
		t.Fatal("detailed diagnostics enabled by default")
	}
}

func TestSignedRecordEndpointsDecodeNestedIPv4(t *testing.T) {
	fields := []Field{
		{Type: 5, ID: 0x20, Children: []Field{
			{Type: 2, ID: 0x11, Bytes: []byte{192, 0, 2, 10, 0x52, 0xae}},
			{Type: 5, ID: 0x21, Children: []Field{
				{Type: 2, ID: 3, Bytes: []byte{203, 0, 113, 53, 0xec, 0x45}},
			}},
		}},
	}

	got := signedRecordEndpoints(fields)
	if len(got) != 2 {
		t.Fatalf("endpoint count=%d want=2: %+v", len(got), got)
	}
	if got[0].Path != "5:20/2:11" || got[0].Kind != "type2" || got[0].Address != "192.0.2.10:21166" {
		t.Fatalf("first endpoint=%+v", got[0])
	}
	if got[1].Path != "5:20/5:21/2:3" || got[1].Kind != "type2" || got[1].Address != "203.0.113.53:60485" {
		t.Fatalf("second endpoint=%+v", got[1])
	}

	detail := describeSignedRecordFields(fields)
	if !strings.Contains(detail, "192.0.2.10:21166") ||
		!strings.Contains(detail, "203.0.113.53:60485") {
		t.Fatalf("detailed field description omitted endpoints: %s", detail)
	}
}

func TestSignedRecordVCardEndpoints(t *testing.T) {
	vcard := []byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x01,
		192, 0, 2, 10, 0x52, 0xae,
		198, 51, 100, 7, 0x9c, 0x40,
		203, 0, 113, 53, 0xec, 0x45,
	}
	card, ok := decodeSignedRecordVCard(vcard)
	if !ok {
		t.Fatal("27-byte vCard was not decoded")
	}
	if card.NodeID != "1122334455667788" || card.Flag != 1 {
		t.Fatalf("unexpected vCard identity: %+v", card)
	}
	if card.Internal != "192.0.2.10:21166" {
		t.Fatalf("internal=%s", card.Internal)
	}
	if card.External != "198.51.100.7:40000" {
		t.Fatalf("external=%s", card.External)
	}
	if card.Additional != "203.0.113.53:60485" {
		t.Fatalf("additional=%s", card.Additional)
	}

	fields := []Field{{Type: 4, ID: 3, Bytes: vcard}}
	got := signedRecordEndpoints(fields)
	if len(got) != 3 {
		t.Fatalf("vCard endpoint count=%d want=3: %+v", len(got), got)
	}
	if got[0].Kind != "vcard-internal" || got[0].Address != card.Internal {
		t.Fatalf("internal endpoint=%+v", got[0])
	}
	if got[1].Kind != "vcard-external" || got[1].Address != card.External {
		t.Fatalf("external endpoint=%+v", got[1])
	}
	if got[2].Kind != "vcard-additional" || got[2].Address != card.Additional {
		t.Fatalf("additional endpoint=%+v", got[2])
	}

	detail := describeSignedRecordFields(fields)
	for _, want := range []string{
		"node=1122334455667788",
		"flag=0x01",
		"internal=192.0.2.10:21166",
		"external=198.51.100.7:40000",
		"additional=203.0.113.53:60485",
	} {
		if !strings.Contains(detail, want) {
			t.Fatalf("vCard detail missing %q: %s", want, detail)
		}
	}
}
