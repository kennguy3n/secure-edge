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
	return nil
}
