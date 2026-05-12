// Command agent runs the Secure Edge Phase 1 agent: DNS resolver +
// policy engine + SQLite-backed config/stats + local HTTP API.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kennguy3n/secure-edge/agent/internal/api"
	"github.com/kennguy3n/secure-edge/agent/internal/config"
	"github.com/kennguy3n/secure-edge/agent/internal/dlp"
	"github.com/kennguy3n/secure-edge/agent/internal/dns"
	"github.com/kennguy3n/secure-edge/agent/internal/policy"
	"github.com/kennguy3n/secure-edge/agent/internal/rules"
	"github.com/kennguy3n/secure-edge/agent/internal/stats"
	"github.com/kennguy3n/secure-edge/agent/internal/store"
)

// version is overridable at build time via -ldflags.
var version = "0.1.0"

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	nativeMode := flag.Bool("native-messaging", false,
		"run as a Chrome Native Messaging host on stdin/stdout instead of a daemon")
	flag.Parse()

	api.Version = version

	if *nativeMode {
		if err := runNativeMessaging(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "agent (native): %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := run(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "agent: %v\n", err)
		os.Exit(1)
	}
}

// runNativeMessaging serves the Chrome Native Messaging protocol on
// stdin/stdout. It loads the same DLP pipeline as the daemon mode (so
// scan results match the HTTP fallback) but skips the DNS / API
// servers entirely — Chrome spawns one host process per extension
// session and tears it down on disconnect.
func runNativeMessaging(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.DLPPatternsPath == "" {
		return fmt.Errorf("native messaging requires dlp_patterns in config")
	}
	patterns, err := dlp.LoadPatterns(cfg.DLPPatternsPath)
	if err != nil {
		return err
	}
	var exclusions []dlp.Exclusion
	if cfg.DLPExclusionsPath != "" {
		exclusions, err = dlp.LoadExclusions(cfg.DLPExclusionsPath)
		if err != nil {
			return err
		}
	}
	pipeline := dlp.NewPipeline(
		dlp.ScoreWeights{},
		dlp.NewThresholdEngine(dlp.DefaultThresholds()),
	)
	pipeline.Rebuild(patterns, exclusions)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return api.ServeNativeMessaging(ctx, pipeline, os.Stdin, os.Stdout)
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	s, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()

	// Build the rule sources from config. Each rule_path entry is taken
	// as the category file path; the category name is derived from the
	// basename for human-friendly display.
	var sources []rules.RuleSource
	for _, p := range cfg.RulePaths {
		sources = append(sources, rules.RuleSource{
			Category: categoryFromPath(p),
			Path:     p,
		})
	}
	engine, err := policy.New(s, sources)
	if err != nil {
		return fmt.Errorf("build policy engine: %w", err)
	}

	counter := stats.New(storeAdapter{s})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go counter.Run(ctx, cfg.StatsFlushInterval)

	forwarder := &dns.MiekgForwarder{Upstream: cfg.UpstreamDNS, Timeout: 3 * time.Second}
	resolver := dns.New(cfg.DNSListen, engine, counter, forwarder)
	if err := resolver.Start(); err != nil {
		return fmt.Errorf("start DNS: %w", err)
	}
	defer func() { _ = resolver.Shutdown() }()

	apiServer := api.NewServer(s, engine, counter)

	// Optional DLP pipeline: only stand it up when rules/dlp_patterns.json
	// is configured. Phase 1 deployments leave both DLP paths blank and
	// the /api/dlp/* endpoints return 503 service-unavailable.
	if cfg.DLPPatternsPath != "" {
		dlpCfg, err := s.GetDLPConfig(ctx)
		if err != nil {
			return fmt.Errorf("read dlp_config: %w", err)
		}
		thresholds := dlp.Thresholds{
			Critical: dlpCfg.ThresholdCritical,
			High:     dlpCfg.ThresholdHigh,
			Medium:   dlpCfg.ThresholdMedium,
			Low:      dlpCfg.ThresholdLow,
		}
		weights := dlp.ScoreWeights{
			HotwordBoost:     dlpCfg.HotwordBoost,
			EntropyBoost:     dlpCfg.EntropyBoost,
			EntropyPenalty:   dlpCfg.EntropyPenalty,
			ExclusionPenalty: dlpCfg.ExclusionPenalty,
			MultiMatchBoost:  dlpCfg.MultiMatchBoost,
		}
		patterns, err := dlp.LoadPatterns(cfg.DLPPatternsPath)
		if err != nil {
			return err
		}
		var exclusions []dlp.Exclusion
		if cfg.DLPExclusionsPath != "" {
			exclusions, err = dlp.LoadExclusions(cfg.DLPExclusionsPath)
			if err != nil {
				return err
			}
		}
		pipeline := dlp.NewPipeline(weights, dlp.NewThresholdEngine(thresholds))
		pipeline.Rebuild(patterns, exclusions)
		apiServer.SetDLP(pipeline)

		// Wire the rule updater after the pipeline so the reload
		// callback can refresh both the policy engine's lookup table
		// and the DLP automaton from the freshly-downloaded files.
		if cfg.RuleUpdateURL != "" {
			rulesDir := cfg.RulesDir
			if rulesDir == "" {
				rulesDir = defaultRulesDir(cfg.RulePaths)
			}
			updater, err := rules.New(rules.Options{
				ManifestURL:  cfg.RuleUpdateURL,
				PollInterval: cfg.RuleUpdateInterval,
				RulesDir:     rulesDir,
				Store:        s,
				Reload: func(ctx context.Context) error {
					if err := engine.Reload(ctx); err != nil {
						return err
					}
					p, err := dlp.LoadPatterns(cfg.DLPPatternsPath)
					if err != nil {
						return err
					}
					var ex []dlp.Exclusion
					if cfg.DLPExclusionsPath != "" {
						ex, err = dlp.LoadExclusions(cfg.DLPExclusionsPath)
						if err != nil {
							return err
						}
					}
					pipeline.Rebuild(p, ex)
					return nil
				},
			})
			if err != nil {
				return fmt.Errorf("build updater: %w", err)
			}
			apiServer.SetRuleUpdater(updater)
			go updater.Start(ctx)
		}
	}

	httpServer, err := apiServer.ListenAndServe(cfg.APIListen)
	if err != nil {
		return fmt.Errorf("start API: %w", err)
	}
	defer func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(os.Stderr, "agent: ready (dns=%s api=%s)\n", cfg.DNSListen, cfg.APIListen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(os.Stderr, "agent: shutting down")
	return nil
}

// defaultRulesDir derives the directory rule files live in when the
// caller did not set RulesDir explicitly. Each RulePaths entry is
// typically RulesDir/<category>.txt, so the parent of the first entry
// is a safe default. Returns "rules" if RulePaths is empty.
func defaultRulesDir(rulePaths []string) string {
	if len(rulePaths) == 0 {
		return "rules"
	}
	dir := rulePaths[0]
	for i := len(dir) - 1; i >= 0; i-- {
		if dir[i] == '/' || dir[i] == '\\' {
			return dir[:i]
		}
	}
	return "."
}

// categoryAcronyms lists rule-file words that should be emitted in all
// uppercase so the derived category name matches the seeded categories
// in store.seedDefaults. Keep this list in sync with that seed.
var categoryAcronyms = map[string]bool{
	"ai":  true,
	"dlp": true,
}

// categoryFromPath turns "rules/ai_chat_blocked.txt" into "AI Chat Blocked".
// Words are split on '_' / '-'; recognized acronyms are uppercased and other
// words are title-cased so the result matches store.seedDefaults entries.
func categoryFromPath(path string) string {
	base := path
	if idx := strings.LastIndexAny(base, "/\\"); idx >= 0 {
		base = base[idx+1:]
	}
	if idx := strings.LastIndexByte(base, '.'); idx >= 0 {
		base = base[:idx]
	}
	words := strings.FieldsFunc(base, func(r rune) bool {
		return r == '_' || r == '-'
	})
	for i, w := range words {
		lower := strings.ToLower(w)
		if categoryAcronyms[lower] {
			words[i] = strings.ToUpper(lower)
			continue
		}
		words[i] = strings.ToUpper(lower[:1]) + lower[1:]
	}
	return strings.Join(words, " ")
}

// storeAdapter bridges store.Store to stats.Store, converting between
// store.AggregateStats and stats.Snapshot (they have identical fields).
type storeAdapter struct{ s *store.Store }

func (a storeAdapter) GetStats(ctx context.Context) (stats.Snapshot, error) {
	v, err := a.s.GetStats(ctx)
	if err != nil {
		return stats.Snapshot{}, err
	}
	return stats.Snapshot{
		DNSQueriesTotal: v.DNSQueriesTotal,
		DNSBlocksTotal:  v.DNSBlocksTotal,
		DLPScansTotal:   v.DLPScansTotal,
		DLPBlocksTotal:  v.DLPBlocksTotal,
	}, nil
}

func (a storeAdapter) AddStats(ctx context.Context, delta stats.Snapshot) error {
	return a.s.AddStats(ctx, store.AggregateStats{
		DNSQueriesTotal: delta.DNSQueriesTotal,
		DNSBlocksTotal:  delta.DNSBlocksTotal,
		DLPScansTotal:   delta.DLPScansTotal,
		DLPBlocksTotal:  delta.DLPBlocksTotal,
	})
}

func (a storeAdapter) ResetStats(ctx context.Context) error { return a.s.ResetStats(ctx) }
