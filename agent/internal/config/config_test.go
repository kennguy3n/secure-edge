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

// TestLoad_DLPIntFields_ExplicitZeroDisables locks in the Phase 6
// "zero disables" semantics for the four DLP int fields. Writing an
// explicit `0` in YAML must override the built-in default — a previous
// implementation used `!= 0` merge guards that silently dropped the
// override and kept the operator on the default value.
func TestLoad_DLPIntFields_ExplicitZeroDisables(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zero.yaml")
	content := `large_content_threshold: 0
dlp_cache_ttl_seconds: 0
dlp_cache_capacity: 0
dlp_rate_limit_per_sec: 0
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LargeContentThreshold != 0 {
		t.Errorf("LargeContentThreshold = %d, want explicit 0", cfg.LargeContentThreshold)
	}
	if cfg.DLPCacheTTLSeconds != 0 {
		t.Errorf("DLPCacheTTLSeconds = %d, want explicit 0", cfg.DLPCacheTTLSeconds)
	}
	if cfg.DLPCacheCapacity != 0 {
		t.Errorf("DLPCacheCapacity = %d, want explicit 0", cfg.DLPCacheCapacity)
	}
	if cfg.DLPRateLimitPerSec != 0 {
		t.Errorf("DLPRateLimitPerSec = %d, want explicit 0", cfg.DLPRateLimitPerSec)
	}
}

// TestLoad_DLPIntFields_OmittedKeepsDefault confirms the corollary:
// when the operator omits the fields entirely, the documented
// defaults survive. Together with the explicit-zero test above this
// pins down the "omitted vs explicit 0" distinction.
func TestLoad_DLPIntFields_OmittedKeepsDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "omit.yaml")
	// No Phase 6 keys at all.
	content := "upstream_dns: \"1.1.1.1:53\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defaults := Default()
	if cfg.LargeContentThreshold != defaults.LargeContentThreshold {
		t.Errorf("LargeContentThreshold = %d, want default %d",
			cfg.LargeContentThreshold, defaults.LargeContentThreshold)
	}
	if cfg.DLPCacheTTLSeconds != defaults.DLPCacheTTLSeconds {
		t.Errorf("DLPCacheTTLSeconds = %d, want default %d",
			cfg.DLPCacheTTLSeconds, defaults.DLPCacheTTLSeconds)
	}
	if cfg.DLPCacheCapacity != defaults.DLPCacheCapacity {
		t.Errorf("DLPCacheCapacity = %d, want default %d",
			cfg.DLPCacheCapacity, defaults.DLPCacheCapacity)
	}
	if cfg.DLPRateLimitPerSec != defaults.DLPRateLimitPerSec {
		t.Errorf("DLPRateLimitPerSec = %d, want default %d",
			cfg.DLPRateLimitPerSec, defaults.DLPRateLimitPerSec)
	}
}

// TestLoad_DLPIntFields_PartialOverride confirms that mixing
// explicit overrides with omitted fields keeps each independent: the
// set fields take the operator's value (including zero) while the
// rest fall back to defaults.
func TestLoad_DLPIntFields_PartialOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.yaml")
	content := "dlp_rate_limit_per_sec: 0\n" + // disable limiter
		"dlp_cache_ttl_seconds: 30\n" // longer cache
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defaults := Default()
	if cfg.DLPRateLimitPerSec != 0 {
		t.Errorf("DLPRateLimitPerSec = %d, want 0", cfg.DLPRateLimitPerSec)
	}
	if cfg.DLPCacheTTLSeconds != 30 {
		t.Errorf("DLPCacheTTLSeconds = %d, want 30", cfg.DLPCacheTTLSeconds)
	}
	if cfg.LargeContentThreshold != defaults.LargeContentThreshold {
		t.Errorf("LargeContentThreshold = %d, want default %d",
			cfg.LargeContentThreshold, defaults.LargeContentThreshold)
	}
	if cfg.DLPCacheCapacity != defaults.DLPCacheCapacity {
		t.Errorf("DLPCacheCapacity = %d, want default %d",
			cfg.DLPCacheCapacity, defaults.DLPCacheCapacity)
	}
}

// TestLoad_DLPIntFields_NegativeRejected confirms validation rejects
// negative values for the Phase 6 ints. They have no useful meaning
// — the consumer code branches on positive vs zero only — so a
// negative reaches no production code path.
func TestLoad_DLPIntFields_NegativeRejected(t *testing.T) {
	dir := t.TempDir()
	for _, key := range []string{
		"large_content_threshold",
		"dlp_cache_ttl_seconds",
		"dlp_cache_capacity",
		"dlp_rate_limit_per_sec",
	} {
		path := filepath.Join(dir, key+".yaml")
		if err := os.WriteFile(path, []byte(key+": -1\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", key, err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("Load(%s: -1): expected error", key)
		}
	}
}

// TestLoad_AllowedExtensionIDs confirms the new pinned-ID allowlist
// round-trips through YAML and survives merge() unchanged.
func TestLoad_AllowedExtensionIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `allowed_extension_ids:
  - abcdefghijklmnopabcdefghijklmnop
  - 01234567-89ab-cdef-0123-456789abcdef
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{
		"abcdefghijklmnopabcdefghijklmnop",
		"01234567-89ab-cdef-0123-456789abcdef",
	}
	if !reflect.DeepEqual(cfg.AllowedExtensionIDs, want) {
		t.Errorf("AllowedExtensionIDs = %#v, want %#v", cfg.AllowedExtensionIDs, want)
	}
}

// TestLoad_APIToken confirms the api_token_path and api_token_required
// fields round-trip cleanly. APITokenRequired is a bool so we cover
// both explicit values.
func TestLoad_APIToken(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name     string
		yaml     string
		path     string
		required bool
	}{
		{
			name:     "off (defaults)",
			yaml:     ``,
			path:     "",
			required: false,
		},
		{
			name: "staged (path set, enforce off)",
			yaml: `api_token_path: "/var/lib/secure-edge/api-token"
api_token_required: false
`,
			path:     "/var/lib/secure-edge/api-token",
			required: false,
		},
		{
			name: "enforced",
			yaml: `api_token_path: "/var/lib/secure-edge/api-token"
api_token_required: true
`,
			path:     "/var/lib/secure-edge/api-token",
			required: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".yaml")
			if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			cfg, err := Load(p)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.APITokenPath != tc.path {
				t.Errorf("APITokenPath = %q, want %q", cfg.APITokenPath, tc.path)
			}
			if cfg.APITokenRequired != tc.required {
				t.Errorf("APITokenRequired = %v, want %v", cfg.APITokenRequired, tc.required)
			}
		})
	}
}

// TestLoad_BridgeMACRequired confirms the C1 staged-rollout knob
// round-trips cleanly. Mirrors the api_token_required test above:
// default is false (lenient), explicit false is allowed, explicit
// true flips the agent into strict-MAC-enforcement mode.
func TestLoad_BridgeMACRequired(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		yaml string
		want bool
	}{
		{
			name: "off (defaults — lenient)",
			yaml: ``,
			want: false,
		},
		{
			name: "explicit lenient",
			yaml: `bridge_mac_required: false` + "\n",
			want: false,
		},
		{
			name: "strict",
			yaml: `bridge_mac_required: true` + "\n",
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".yaml")
			if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			cfg, err := Load(p)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.BridgeMACRequired != tc.want {
				t.Errorf("BridgeMACRequired = %v, want %v", cfg.BridgeMACRequired, tc.want)
			}
		})
	}
}

// TestLoad_EnforcementMode_AcceptsKnown confirms the four accepted
// inputs (empty + the three explicit modes) load without error.
// Empty is intentionally permitted at the YAML layer; the merge
// step falls back to the documented "personal" default so the
// effective value is never blank. The explicit modes pass through
// unchanged.
func TestLoad_EnforcementMode_AcceptsKnown(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "personal"}, // empty → default
		{"personal", "personal"},
		{"team", "team"},
		{"managed", "managed"},
	}
	dir := t.TempDir()
	for _, c := range cases {
		path := filepath.Join(dir, "mode-"+c.in+".yaml")
		body := "enforcement_mode: \"" + c.in + "\"\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %q: %v", c.in, err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load(%q): %v", c.in, err)
		}
		if cfg.EnforcementMode != c.want {
			t.Errorf("EnforcementMode(%q) = %q, want %q", c.in, cfg.EnforcementMode, c.want)
		}
	}
}

// TestLoad_EnforcementMode_RejectsUnknown locks in the validator:
// an operator typo such as "manaaged" must surface as a config
// error at boot, not silently fall back to "personal". Falling back
// silently would let a managed deployment behave as personal
// without anyone noticing.
func TestLoad_EnforcementMode_RejectsUnknown(t *testing.T) {
	cases := []string{"manaaged", "off", "strict", "PERSONAL"}
	dir := t.TempDir()
	for _, mode := range cases {
		path := filepath.Join(dir, "bad.yaml")
		body := "enforcement_mode: \"" + mode + "\"\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %q: %v", mode, err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("Load(enforcement_mode=%q): expected error", mode)
		}
	}
}

// TestDefault_EnforcementModeIsPersonal pins the default so callers
// can rely on it without having to set the field explicitly. The
// privacy-first product stance is fall-open by default — operators
// opt in to "managed" with full intent.
func TestDefault_EnforcementModeIsPersonal(t *testing.T) {
	if got := Default().EnforcementMode; got != "personal" {
		t.Errorf("Default().EnforcementMode = %q, want \"personal\"", got)
	}
}

// TestLoad_RuleUpdatePublicKey ensures the new opt-in field round-trips
// through the YAML loader. The value is hex-decoded by main.go before
// being passed to the rules updater; config-layer validation only
// confirms the key is parsed off the YAML at all.
func TestLoad_RuleUpdatePublicKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules-key.yaml")
	// 64 hex chars = 32 bytes = Ed25519 public key size. The
	// config layer doesn't actually verify length (main.go does);
	// pass a realistic value so the test mirrors real usage.
	content := `rule_update_public_key: "` +
		"deadbeef00000000000000000000000000000000000000000000000000000000" +
		"\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	const want = "deadbeef00000000000000000000000000000000000000000000000000000000"
	if cfg.RuleUpdatePublicKey != want {
		t.Errorf("RuleUpdatePublicKey = %q, want %q", cfg.RuleUpdatePublicKey, want)
	}
}

// TestLoad_RuleUpdatePublicKey_DefaultEmpty pins the backwards-compat
// default: a deployment that hasn't enabled manifest signing must see
// an empty key string, which the rules updater treats as "skip
// verification, log a warning".
func TestLoad_RuleUpdatePublicKey_DefaultEmpty(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RuleUpdatePublicKey != "" {
		t.Errorf("default RuleUpdatePublicKey = %q, want empty", cfg.RuleUpdatePublicKey)
	}
}
