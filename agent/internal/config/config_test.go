package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestLoad_NoFile(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(empty): %v", err)
	}
	want := Default()
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("Load(empty) = %#v, want %#v", cfg, want)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "no-such-file.yaml"))
	if err != nil {
		t.Fatalf("Load(missing): %v", err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("Load(missing) = %#v, want defaults", cfg)
	}
}

func TestLoad_PartialOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `upstream_dns: "1.1.1.1:53"
api_listen: "127.0.0.1:9090"
rule_paths:
  - /tmp/a.txt
  - /tmp/b.txt
stats_flush_interval: 30s
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.UpstreamDNS != "1.1.1.1:53" {
		t.Errorf("UpstreamDNS = %q", cfg.UpstreamDNS)
	}
	if cfg.APIListen != "127.0.0.1:9090" {
		t.Errorf("APIListen = %q", cfg.APIListen)
	}
	if cfg.DNSListen != "127.0.0.1:53" {
		t.Errorf("DNSListen = %q, want default", cfg.DNSListen)
	}
	if cfg.DBPath != "secure-edge.db" {
		t.Errorf("DBPath = %q, want default", cfg.DBPath)
	}
	if cfg.StatsFlushInterval != 30*time.Second {
		t.Errorf("StatsFlushInterval = %v", cfg.StatsFlushInterval)
	}
	if len(cfg.RulePaths) != 2 {
		t.Errorf("RulePaths = %v", cfg.RulePaths)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("not: [valid"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load(bad yaml): expected error")
	}
}

func TestLoad_InvalidValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	// Negative durations fail validation; an empty upstream is rejected too.
	if err := os.WriteFile(path, []byte("stats_flush_interval: -1s\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load(invalid): expected error")
	}
}
