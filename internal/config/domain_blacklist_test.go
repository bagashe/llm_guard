package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDomainBlacklist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.txt")
	content := "\n# blocked domains\nEvil.com\nwww.malware.test\nsub.bad-domain.io # inline comment\n12.12.12.12\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	blocked, err := LoadDomainBlacklist(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, d := range []string{"evil.com", "malware.test", "sub.bad-domain.io", "12.12.12.12"} {
		if _, ok := blocked[d]; !ok {
			t.Fatalf("expected domain %q to be loaded", d)
		}
	}
}

func TestLoadDomainBlacklistNormalizesIPv6(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte("2001:0db8::0001\n"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	blocked, err := LoadDomainBlacklist(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := blocked["2001:db8::1"]; !ok {
		t.Fatalf("expected normalized ipv6 entry, got: %+v", blocked)
	}
}

func TestLoadDomainBlacklistInvalidDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte("not_a_domain\n"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	if _, err := LoadDomainBlacklist(path); err == nil {
		t.Fatal("expected error for invalid domain")
	}
}
