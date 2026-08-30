package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay-opensource/Vouchsafe/internal/policy"
)

func TestParseServeFlags_Defaults(t *testing.T) {
	cfg, err := parseServeFlags(nil)
	if err != nil {
		t.Fatalf("parseServeFlags: %v", err)
	}
	if cfg.listen != "127.0.0.1:8080" {
		t.Fatalf("listen = %q", cfg.listen)
	}
	if len(cfg.origins) != 1 || cfg.origins[0] != "http://127.0.0.1:8080" {
		t.Fatalf("origins = %v", cfg.origins)
	}
	if cfg.rpID != "127.0.0.1" {
		t.Fatalf("rpID = %q", cfg.rpID)
	}
	if cfg.uvPolicy != policy.UVPreferred {
		t.Fatalf("uvPolicy = %q", cfg.uvPolicy)
	}
	if cfg.storePath != "./vouchsafe.json" {
		t.Fatalf("storePath = %q", cfg.storePath)
	}
}

func TestParseServeFlags_OriginDerivesRPID(t *testing.T) {
	cfg, err := parseServeFlags([]string{"--origin", "https://example.com"})
	if err != nil {
		t.Fatalf("parseServeFlags: %v", err)
	}
	if cfg.rpID != "example.com" {
		t.Fatalf("rpID = %q, want example.com", cfg.rpID)
	}
}

func TestParseServeFlags_ExplicitRPIDOverridesDerived(t *testing.T) {
	cfg, err := parseServeFlags([]string{"--origin", "https://example.com", "--rp-id", "custom.example"})
	if err != nil {
		t.Fatalf("parseServeFlags: %v", err)
	}
	if cfg.rpID != "custom.example" {
		t.Fatalf("rpID = %q, want custom.example", cfg.rpID)
	}
}

func TestParseServeFlags_RepeatedOrigin(t *testing.T) {
	cfg, err := parseServeFlags([]string{"--origin", "https://a.example", "--origin", "https://b.example"})
	if err != nil {
		t.Fatalf("parseServeFlags: %v", err)
	}
	if len(cfg.origins) != 2 || cfg.origins[0] != "https://a.example" || cfg.origins[1] != "https://b.example" {
		t.Fatalf("origins = %v", cfg.origins)
	}
}

func TestParseServeFlags_ValidUVValues(t *testing.T) {
	for _, v := range []string{"required", "preferred", "discouraged"} {
		cfg, err := parseServeFlags([]string{"--uv", v})
		if err != nil {
			t.Fatalf("uv=%s: %v", v, err)
		}
		if string(cfg.uvPolicy) != v {
			t.Fatalf("uv=%s: got %q", v, cfg.uvPolicy)
		}
	}
}

func TestParseServeFlags_InvalidUVRejected(t *testing.T) {
	if _, err := parseServeFlags([]string{"--uv", "bogus"}); err == nil {
		t.Fatalf("expected an error for an invalid --uv value")
	}
}

func TestLoopbackWarning(t *testing.T) {
	cases := []struct {
		listen    string
		wantEmpty bool
	}{
		{"127.0.0.1:8080", true},
		{"localhost:8080", true},
		{"[::1]:8080", true},
		{"0.0.0.0:8080", false},
		{"192.168.1.5:8080", false},
	}
	for _, c := range cases {
		got := loopbackWarning(c.listen)
		if c.wantEmpty && got != "" {
			t.Fatalf("listen=%s: got warning %q, want none", c.listen, got)
		}
		if !c.wantEmpty && got == "" {
			t.Fatalf("listen=%s: got no warning, want one", c.listen)
		}
	}
}

func TestLoadOrCreateSessionKey_EmptyPathGeneratesEphemeral(t *testing.T) {
	key, err := loadOrCreateSessionKey("")
	if err != nil {
		t.Fatalf("loadOrCreateSessionKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}

func TestLoadOrCreateSessionKey_CreatesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.key")
	key1, err := loadOrCreateSessionKey(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("key length = %d, want 32", len(key1))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	_ = info

	key2, err := loadOrCreateSessionKey(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatalf("session key was regenerated instead of persisted")
	}
}

func TestLoadOrCreateSessionKey_LoadsExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.key")
	want := []byte("this-is-a-preexisting-32-byte-key")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := loadOrCreateSessionKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateSessionKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
