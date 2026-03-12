package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadInternalDestinationAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.txt")
	content := "\n# entries\nlocalhost\napi.internal.local\n.tenant.svc.cluster.local\n127.0.0.1\n10.0.0.0/8\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	allowlist, err := LoadInternalDestinationAllowlist(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, d := range []string{"localhost", "api.internal.local", "tenant.svc.cluster.local"} {
		if _, ok := allowlist.Domains[d]; !ok {
			t.Fatalf("expected domain %q to be loaded", d)
		}
	}
	if _, ok := allowlist.IPs["127.0.0.1"]; !ok {
		t.Fatal("expected ip 127.0.0.1 to be loaded")
	}
	if len(allowlist.CIDRs) != 1 || allowlist.CIDRs[0].String() != "10.0.0.0/8" {
		t.Fatalf("unexpected cidrs: %+v", allowlist.CIDRs)
	}
}

func TestLoadInternalDestinationAllowlistInvalidEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.txt")
	if err := os.WriteFile(path, []byte("no/slash.com\n"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	if _, err := LoadInternalDestinationAllowlist(path); err == nil {
		t.Fatal("expected error for invalid allowlist entry")
	}
}
