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
	if got[0].Path != "5:20/2:11" || got[0].Address != "192.0.2.10:21166" {
		t.Fatalf("first endpoint=%+v", got[0])
	}
	if got[1].Path != "5:20/5:21/2:3" || got[1].Address != "203.0.113.53:60485" {
		t.Fatalf("second endpoint=%+v", got[1])
	}

	detail := describeSignedRecordFields(fields)
	if !strings.Contains(detail, "192.0.2.10:21166") ||
		!strings.Contains(detail, "203.0.113.53:60485") {
		t.Fatalf("detailed field description omitted endpoints: %s", detail)
	}
}
