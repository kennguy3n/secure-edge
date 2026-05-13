// Package config loads and validates the YAML configuration for the
// Secure Edge agent. Defaults are applied when fields are omitted, and a
// missing config file is treated as "use all defaults".
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the runtime configuration for the agent.
type Config struct {
	UpstreamDNS        string        `yaml:"upstream_dns"`
	DNSListen          string        `yaml:"dns_listen"`
	APIListen          string        `yaml:"api_listen"`
	RulePaths          []string      `yaml:"rule_paths"`
	DBPath             string        `yaml:"db_path"`
	StatsFlushInterval time.Duration `yaml:"stats_flush_interval"`

	// DLPPatternsPath is the path to the rules/dlp_patterns.json file.
	// Optional — leaving it blank disables DLP at agent startup.
	DLPPatternsPath string `yaml:"dlp_patterns"`

	// DLPExclusionsPath is the path to the rules/dlp_exclusions.json
	// file. Optional; when blank, no exclusions are loaded.
	DLPExclusionsPath string `yaml:"dlp_exclusions"`

	// RuleUpdateURL is the absolute HTTP(S) URL of a manifest.json
	// that the agent polls for rule-bundle updates. An empty value
	// disables the updater.
	RuleUpdateURL string `yaml:"rule_update_url"`

	// RuleUpdateInterval is the polling cadence. Defaults to 6h.
	RuleUpdateInterval time.Duration `yaml:"rule_update_interval"`

	// RulesDir is the on-disk directory the updater writes rule
	// files into. Defaults to the dirname of the first RulePaths
	// entry, or "./rules" when RulePaths is empty.
	RulesDir string `yaml:"rules_dir"`

	// ProxyListen is the local MITM proxy listen address. Defaults
	// to 127.0.0.1:8443. Always loopback only; binding a public
	// interface is unsupported.
	ProxyListen string `yaml:"proxy_listen"`

	// ProxyEnabled toggles whether the MITM proxy auto-starts with
	// the agent. Off by default; the Electron UI / API also flips it
	// at runtime via POST /api/proxy/enable.
	ProxyEnabled bool `yaml:"proxy_enabled"`

	// CACertPath / CAKeyPath are where the per-device Root CA is
	// persisted. Defaults to ~/.secure-edge/ca.crt and ca.key.
	CACertPath string `yaml:"ca_cert_path"`
	CAKeyPath  string `yaml:"ca_key_path"`

	// ProxyPinningBypass is the list of hostnames the proxy should
	// pass through opaquely even when the policy engine would
	// classify them as Tier 2 — used as an escape hatch for apps
	// that pin certificates and break under MITM.
	ProxyPinningBypass []string `yaml:"proxy_pinning_bypass"`

	// ProfilePath is the path to a local enterprise profile JSON
	// file. Optional — leave blank to skip local profile loading.
	ProfilePath string `yaml:"profile_path"`

	// ProfileURL is the URL of an enterprise profile JSON document.
	// When set, the agent fetches the profile on startup. ProfilePath
	// takes precedence over ProfileURL when both are set.
	ProfileURL string `yaml:"profile_url"`

	// HeartbeatURL is the URL the agent POSTs an aggregate heartbeat
	// to. Empty (default) disables the heartbeat. The payload is
	// strictly {agent_version, os_type, os_arch, aggregate_counters}
	// — no access data ever leaves the device.
	HeartbeatURL string `yaml:"heartbeat_url"`

	// HeartbeatInterval is the cadence at which heartbeats are sent
	// when HeartbeatURL is non-empty. Defaults to 1h.
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`

	// LocalRulesDir is the override directory for admin-managed
	// allow/block lists and DLP overrides. Defaults to RulesDir/local
	// when blank. Files in this directory are merged on top of the
	// bundled rules without modifying them.
	LocalRulesDir string `yaml:"local_rules_dir"`

	// LargeContentThreshold is the byte size above which the DLP
	// pipeline drops low/medium-severity patterns and only runs
	// critical/high. Defaults to 51200 (50 KiB). Set 0 to disable
	// the optimisation.
	LargeContentThreshold int `yaml:"large_content_threshold"`

	// DLPCacheTTLSeconds is the lifetime of the in-memory scan
	// result cache. Zero disables caching entirely. Defaults to 5s.
	DLPCacheTTLSeconds int `yaml:"dlp_cache_ttl_seconds"`

	// DLPCacheCapacity is the maximum number of entries the scan
	// cache holds. Defaults to 1024.
	DLPCacheCapacity int `yaml:"dlp_cache_capacity"`

	// DLPRateLimitPerSec is the per-process rate limit applied to
	// POST /api/dlp/scan. Defaults to 100 requests per second.
	// Zero disables the limiter entirely.
	DLPRateLimitPerSec int `yaml:"dlp_rate_limit_per_sec"`

	// DLPDisabledCategories is the list of pattern categories
	// (e.g. "pii", "code_secret") that should be ignored when
	// scanning. Empty by default — all categories are active.
	DLPDisabledCategories []string `yaml:"dlp_disabled_categories"`
}

// Default returns a Config populated with the documented defaults.
func Default() Config {
	return Config{
		UpstreamDNS:        "8.8.8.8:53",
		DNSListen:          "127.0.0.1:53",
		APIListen:          "127.0.0.1:8080",
		RulePaths:          nil,
		DBPath:             "secure-edge.db",
		StatsFlushInterval: 60 * time.Second,
		RuleUpdateURL:      "",
		RuleUpdateInterval: 6 * time.Hour,
		ProxyListen:        "127.0.0.1:8443",
		ProxyEnabled:       false,
		HeartbeatInterval:  time.Hour,
		LargeContentThreshold: 50 * 1024,
		DLPCacheTTLSeconds:    5,
		DLPCacheCapacity:      1024,
		DLPRateLimitPerSec:    100,
	}
}

// Load reads a YAML config file and applies defaults for any unset fields.
// If path is empty or the file does not exist, the returned config is the
// default configuration.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return cfg, nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var parsed Config
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	merged := merge(cfg, parsed)
	if err := merged.validate(); err != nil {
		return Config{}, err
	}
	return merged, nil
}

func merge(defaults, override Config) Config {
	out := defaults
	if override.UpstreamDNS != "" {
		out.UpstreamDNS = override.UpstreamDNS
	}
	if override.DNSListen != "" {
		out.DNSListen = override.DNSListen
	}
	if override.APIListen != "" {
		out.APIListen = override.APIListen
	}
	if len(override.RulePaths) > 0 {
		out.RulePaths = override.RulePaths
	}
	if override.DBPath != "" {
		out.DBPath = override.DBPath
	}
	if override.StatsFlushInterval != 0 {
		out.StatsFlushInterval = override.StatsFlushInterval
	}
	if override.DLPPatternsPath != "" {
		out.DLPPatternsPath = override.DLPPatternsPath
	}
	if override.DLPExclusionsPath != "" {
		out.DLPExclusionsPath = override.DLPExclusionsPath
	}
	if override.RuleUpdateURL != "" {
		out.RuleUpdateURL = override.RuleUpdateURL
	}
	if override.RuleUpdateInterval != 0 {
		out.RuleUpdateInterval = override.RuleUpdateInterval
	}
	if override.RulesDir != "" {
		out.RulesDir = override.RulesDir
	}
	if override.ProxyListen != "" {
		out.ProxyListen = override.ProxyListen
	}
	if override.ProxyEnabled {
		out.ProxyEnabled = true
	}
	if override.CACertPath != "" {
		out.CACertPath = override.CACertPath
	}
	if override.CAKeyPath != "" {
		out.CAKeyPath = override.CAKeyPath
	}
	if len(override.ProxyPinningBypass) > 0 {
		out.ProxyPinningBypass = override.ProxyPinningBypass
	}
	if override.ProfilePath != "" {
		out.ProfilePath = override.ProfilePath
	}
	if override.ProfileURL != "" {
		out.ProfileURL = override.ProfileURL
	}
	if override.HeartbeatURL != "" {
		out.HeartbeatURL = override.HeartbeatURL
	}
	if override.HeartbeatInterval != 0 {
		out.HeartbeatInterval = override.HeartbeatInterval
	}
	if override.LocalRulesDir != "" {
		out.LocalRulesDir = override.LocalRulesDir
	}
	if override.LargeContentThreshold != 0 {
		out.LargeContentThreshold = override.LargeContentThreshold
	}
	if override.DLPCacheTTLSeconds != 0 {
		out.DLPCacheTTLSeconds = override.DLPCacheTTLSeconds
	}
	if override.DLPCacheCapacity != 0 {
		out.DLPCacheCapacity = override.DLPCacheCapacity
	}
	if override.DLPRateLimitPerSec != 0 {
		out.DLPRateLimitPerSec = override.DLPRateLimitPerSec
	}
	if len(override.DLPDisabledCategories) > 0 {
		out.DLPDisabledCategories = override.DLPDisabledCategories
	}
	return out
}

func (c Config) validate() error {
	if c.UpstreamDNS == "" {
		return errors.New("upstream_dns must not be empty")
	}
	if c.DNSListen == "" {
		return errors.New("dns_listen must not be empty")
	}
	if c.APIListen == "" {
		return errors.New("api_listen must not be empty")
	}
	if c.DBPath == "" {
		return errors.New("db_path must not be empty")
	}
	if c.StatsFlushInterval <= 0 {
		return errors.New("stats_flush_interval must be positive")
	}
	if c.RuleUpdateInterval < 0 {
		return errors.New("rule_update_interval must not be negative")
	}
	if c.HeartbeatInterval < 0 {
		return errors.New("heartbeat_interval must not be negative")
	}
	if c.ProxyListen == "" {
		return errors.New("proxy_listen must not be empty")
	}
	return nil
}
