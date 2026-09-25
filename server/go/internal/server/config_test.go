package server

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestStage41ConfigParity(t *testing.T) {
	cfg, err := ParseConfig([]string{"--host", "0.0.0.0"})
	if err != nil { t.Fatal(err) }
	if cfg.APIHost != "127.0.0.1" { t.Fatalf("--host exposed API: %s", cfg.APIHost) }

	cfg, err = ParseConfig([]string{"--mode", "global", "--advertise-ip", "203.0.113.8"})
	if err != nil { t.Fatal(err) }
	if cfg.Host != "0.0.0.0" || cfg.APIHost != "127.0.0.1" { t.Fatalf("global binds: %+v", cfg) }

	reject := [][]string{
		{"--mode", "global"},
		{"--closed"},
		{"--port", "65536"},
		{"--port", "33034"},
		{"--host", "not-an-ip"},
		{"--api-host", "not-an-ip"},
		{"--advertise-ip", "not-an-ip"},
		{"--advertise-ip", "0.0.0.0"},
		{"--advertise-ip", "224.0.0.1"},
		{"--mode", "global", "--advertise-ip", "127.0.0.1"},
		{"--mode", "global", "--advertise-ip", "203.0.113.8", "--api-host", "0.0.0.0"},
	}
	for _, args := range reject {
		if _, err := ParseConfig(args); err == nil { t.Fatalf("accepted invalid config: %v", args) }
	}
}

func TestAccessPolicyParity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.txt")
	if err := os.WriteFile(path, []byte("# exact and subnet\n127.0.0.1\n203.0.113.128/25 # friends\n"), 0600); err != nil { t.Fatal(err) }
	p, err := LoadAccess(path)
	if err != nil { t.Fatal(err) }
	if !p.Allows(net.ParseIP("127.0.0.1")) || !p.Allows(net.ParseIP("203.0.113.255")) || p.Allows(net.ParseIP("203.0.113.127")) || p.Allows(net.ParseIP("::1")) {
		t.Fatal("allowlist CIDR behavior differs from C#")
	}
	if err := os.WriteFile(path, nil, 0600); err != nil { t.Fatal(err) }
	p, err = LoadAccess(path)
	if err != nil { t.Fatal(err) }
	if p.Allows(net.ParseIP("127.0.0.1")) { t.Fatal("empty closed allowlist must deny localhost") }
	if err := os.WriteFile(path, []byte("203.0.113.1/33\n"), 0600); err != nil { t.Fatal(err) }
	if _, err := LoadAccess(path); err == nil { t.Fatal("invalid CIDR accepted") }
}
