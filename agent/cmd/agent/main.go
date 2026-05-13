// Command agent runs the Secure Edge Phase 1 agent: DNS resolver +
// policy engine + SQLite-backed config/stats + local HTTP API.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kennguy3n/secure-edge/agent/internal/api"
	"github.com/kennguy3n/secure-edge/agent/internal/config"
	"github.com/kennguy3n/secure-edge/agent/internal/dlp"
	"github.com/kennguy3n/secure-edge/agent/internal/dns"
	"github.com/kennguy3n/secure-edge/agent/internal/heartbeat"
	"github.com/kennguy3n/secure-edge/agent/internal/policy"
	"github.com/kennguy3n/secure-edge/agent/internal/profile"
	"github.com/kennguy3n/secure-edge/agent/internal/proxy"
	"github.com/kennguy3n/secure-edge/agent/internal/rules"
	"github.com/kennguy3n/secure-edge/agent/internal/stats"
	"github.com/kennguy3n/secure-edge/agent/internal/store"
	"github.com/kennguy3n/secure-edge/agent/internal/tamper"
)

// version is overridable at build time via -ldflags.
var version = "0.1.0"

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	nativeMode := flag.Bool("native-messaging", false,
		"run as a Chrome Native Messaging host on stdin/stdout instead of a daemon")
	flag.Parse()

	api.Version = version

	// Chrome / Firefox launch the Native Messaging host with the
	// caller's chrome-extension:// (or moz-extension://) origin as the
	// first positional argument and no flags. Auto-detect that calling
	// convention so the same host manifest can point straight at the
	// agent binary without needing a wrapper script.
	if !*nativeMode && isNativeMessagingArgv(flag.Args()) {
		*nativeMode = true
	}

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

// isNativeMessagingArgv reports whether the positional arguments look
// like a browser Native Messaging invocation. Chrome passes the
// caller's extension origin as argv[1] (e.g.
// "chrome-extension://<id>/"); Firefox uses "moz-extension://<UUID>/"
// and additionally appends the extension ID on Windows. Returns true
// when the first positional arg matches either scheme.
func isNativeMessagingArgv(args []string) bool {
	if len(args) == 0 {
		return false
	}
	first := args[0]
	return strings.HasPrefix(first, "chrome-extension://") ||
		strings.HasPrefix(first, "moz-extension://")
}

// runNativeMessaging serves the Chrome Native Messaging protocol on
// stdin/stdout. It mirrors daemon mode's DLP setup so scan results
// match the HTTP fallback: configured ScoreWeights and Thresholds are
// loaded from the SQLite store (falling back to defaults when the
// store has no row yet) and the same pattern / exclusion files are
// rebuilt into the pipeline. DNS and API servers are intentionally
// skipped — Chrome spawns one host process per extension session and
// tears it down on disconnect.
func runNativeMessaging(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.DLPPatternsPath == "" {
		return fmt.Errorf("native messaging requires dlp_patterns in config")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	weights := dlp.DefaultScoreWeights()
	thresholds := dlp.DefaultThresholds()
	// The store, if available, is kept open for the lifetime of the
	// Native Messaging session so ServeNativeMessaging can bump the
	// shared dlp_scans_total / dlp_blocks_total counters after each
	// scan. Without this the Status page would silently undercount
	// whenever Chrome chose the NM transport over the HTTP fallback.
	var statsStore *store.Store
	if cfg.DBPath != "" {
		s, err := store.Open(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("open store: %w", err)
		}
		defer s.Close()
		dlpCfg, err := s.GetDLPConfig(ctx)
		if err != nil {
			return fmt.Errorf("read dlp_config: %w", err)
		}
		weights = dlp.ScoreWeights{
			HotwordBoost:     dlpCfg.HotwordBoost,
			EntropyBoost:     dlpCfg.EntropyBoost,
			EntropyPenalty:   dlpCfg.EntropyPenalty,
			ExclusionPenalty: dlpCfg.ExclusionPenalty,
			MultiMatchBoost:  dlpCfg.MultiMatchBoost,
		}
		thresholds = dlp.Thresholds{
			Critical: dlpCfg.ThresholdCritical,
			High:     dlpCfg.ThresholdHigh,
			Medium:   dlpCfg.ThresholdMedium,
			Low:      dlpCfg.ThresholdLow,
		}
		statsStore = s
	}

	patterns, err := dlp.MergePatternsFromDir(cfg.DLPPatternsPath, cfg.LocalRulesDir)
	if err != nil {
		return err
	}
	var exclusions []dlp.Exclusion
	if cfg.DLPExclusionsPath != "" {
		exclusions, err = dlp.MergeExclusionsFromDir(cfg.DLPExclusionsPath, cfg.LocalRulesDir)
		if err != nil {
			return err
		}
	}
	pipeline := dlp.NewPipeline(weights, dlp.NewThresholdEngine(thresholds))
	pipeline.Rebuild(patterns, exclusions)

	return api.ServeNativeMessaging(ctx, pipeline, statsStore, os.Stdin, os.Stdout)
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
		patterns, err := dlp.MergePatternsFromDir(cfg.DLPPatternsPath, cfg.LocalRulesDir)
		if err != nil {
			return err
		}
		var exclusions []dlp.Exclusion
		if cfg.DLPExclusionsPath != "" {
			exclusions, err = dlp.MergeExclusionsFromDir(cfg.DLPExclusionsPath, cfg.LocalRulesDir)
			if err != nil {
				return err
			}
		}
		pipeline := dlp.NewPipeline(weights, dlp.NewThresholdEngine(thresholds))
		pipeline.Rebuild(patterns, exclusions)
		apiServer.SetDLP(pipeline)

		// Wire the local MITM proxy. The controller is constructed
		// unconditionally so the API surface always has a real
		// implementation behind /api/proxy/*; the listener itself
		// only starts when proxy_enabled=true (auto-start) or the
		// caller hits POST /api/proxy/enable.
		caCertPath, caKeyPath := resolveCAPaths(cfg)
		pinning := buildPinningSet(cfg.ProxyPinningBypass)
		controller, err := proxy.NewController(proxy.ControllerConfig{
			ListenAddr: cfg.ProxyListen,
			CertPath:   caCertPath,
			KeyPath:    caKeyPath,
			Policy: proxy.PolicyCheckerFunc(func(host string) bool {
				if _, bypass := pinning[strings.ToLower(host)]; bypass {
					return false
				}
				return engine.CheckDomain(host) == policy.AllowWithDLP
			}),
			Scanner: pipeline,
			Stats:   proxyStats{s},
		})
		if err != nil {
			return fmt.Errorf("build proxy controller: %w", err)
		}
		apiServer.SetProxyController(&proxyAdapter{c: controller})
		if cfg.ProxyEnabled {
			if _, err := controller.Enable(ctx); err != nil {
				return fmt.Errorf("auto-enable proxy: %w", err)
			}
			defer func() {
				shutdownCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
				defer c()
				_ = controller.Disable(shutdownCtx, false)
			}()
		}

		// Wire the rule updater after the pipeline so the reload
		// callback can refresh both the policy engine's lookup table
		// and the DLP automaton from the freshly-downloaded files.
		if cfg.RuleUpdateURL != "" {
			rulesDir := cfg.RulesDir
			if rulesDir == "" {
				rulesDir = defaultRulesDir(cfg.RulePaths)
			}
			// The updater writes downloads as rulesDir/<basename>; the
			// reload callback below reads cfg.DLPPatternsPath /
			// cfg.RulePaths verbatim. If any of those paths point
			// outside rulesDir we'd download new bytes that the live
			// pipeline never reads — a silent staleness bug. Fail loud
			// at startup instead of letting POST /api/rules/update lie.
			if err := validateRulesAlignment(rulesDir, cfg.RulePaths,
				cfg.DLPPatternsPath, cfg.DLPExclusionsPath); err != nil {
				return fmt.Errorf("rule_update_url is set but %w", err)
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
					p, err := dlp.MergePatternsFromDir(cfg.DLPPatternsPath, cfg.LocalRulesDir)
					if err != nil {
						return err
					}
					var ex []dlp.Exclusion
					if cfg.DLPExclusionsPath != "" {
						ex, err = dlp.MergeExclusionsFromDir(cfg.DLPExclusionsPath, cfg.LocalRulesDir)
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

	// Phase 5: admin rule override store. An empty
	// local_rules_dir disables overrides.
	overrideStore, err := rules.NewOverrideStore(cfg.LocalRulesDir)
	if err != nil {
		return fmt.Errorf("init override store: %w", err)
	}
	apiServer.SetRuleOverride(overrideStore)
	if overrides := overrideStore.Sources(); len(overrides) > 0 {
		engine.SetSources(append(append([]rules.RuleSource(nil), sources...), overrides...))
		if err := engine.Reload(ctx); err != nil {
			return fmt.Errorf("reload with overrides: %w", err)
		}
	}

	// Phase 5: enterprise profile holder. Profiles arrive
	// via /api/profile/import or are loaded eagerly from
	// cfg.ProfilePath / cfg.ProfileURL on startup.
	holder := profile.NewHolder(nil)
	applyStore := &profileApplyAdapter{store: s}
	apiServer.SetProfile(holder, applyStore)
	if err := loadProfileOnStartup(ctx, cfg, holder, applyStore, engine); err != nil {
		fmt.Fprintf(os.Stderr, "agent: profile load failed: %v\n", err)
	}

	// Phase 5: tamper detector goroutine.
	if cfg.DNSListen != "" {
		expectedDNS, _ := splitHostPort(cfg.DNSListen)
		// Only assert the system proxy is wired through us when the MITM
		// proxy is actually enabled. Otherwise the detector would
		// transition from its initialised ProxyOK=true to false on the
		// first tick and increment tamper_detections_total on every
		// agent startup that doesn't enable the proxy.
		expectedProxy := ""
		if cfg.ProxyEnabled {
			expectedProxy = cfg.ProxyListen
		}
		detector := tamper.New(tamper.Options{
			ExpectedDNSServer: expectedDNS,
			ExpectedProxyAddr: expectedProxy,
			Reporter:          counter,
		})
		apiServer.SetTamperReporter(tamperAdapter{detector: detector})
		go detector.Start(ctx)
	}

	// Phase 5: optional heartbeat. URL=="" disables it.
	hb, err := heartbeat.New(heartbeat.Options{
		URL:          cfg.HeartbeatURL,
		AgentVersion: version,
		Interval:     cfg.HeartbeatInterval,
		Stats:        counter,
	})
	if err != nil {
		return fmt.Errorf("init heartbeat: %w", err)
	}
	if hb != nil {
		go hb.Start(ctx, func(format string, args ...interface{}) {
			fmt.Fprintf(os.Stderr, "agent: "+format+"\n", args...)
		})
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

// validateRulesAlignment checks that every rule file the live agent
// reads at runtime resolves to a sibling of rulesDir. The updater
// writes downloaded bytes to rulesDir/<basename>, then calls the
// reload callback which re-reads cfg.DLPPatternsPath /
// cfg.DLPExclusionsPath / cfg.RulePaths verbatim. Misaligned paths
// therefore land in a directory the pipeline never reads, so
// POST /api/rules/update would happily return {updated: true} while
// every scan keeps using the on-disk file from the original install.
//
// Comparison is against the absolute-cleaned form of rulesDir so
// "./rules" and "/etc/secure-edge/rules/" with a trailing slash both
// behave the same way as canonical paths.
func validateRulesAlignment(rulesDir string, rulePaths []string, dlpPatternsPath, dlpExclusionsPath string) error {
	absDir, err := filepath.Abs(rulesDir)
	if err != nil {
		return fmt.Errorf("resolve rules_dir %q: %w", rulesDir, err)
	}
	absDir = filepath.Clean(absDir)
	check := func(field, p string) error {
		if p == "" {
			return nil
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return fmt.Errorf("resolve %s %q: %w", field, p, err)
		}
		if filepath.Dir(filepath.Clean(abs)) != absDir {
			return fmt.Errorf("%s = %q is not directly inside rules_dir = %q; "+
				"the rule updater writes downloaded files into rules_dir but the "+
				"live pipeline keeps reading the original path, so updates would "+
				"silently never take effect. Move the file into rules_dir, or set "+
				"rules_dir to the file's parent directory",
				field, p, rulesDir)
		}
		return nil
	}
	for _, p := range rulePaths {
		if err := check("rule_paths entry", p); err != nil {
			return err
		}
	}
	if err := check("dlp_patterns", dlpPatternsPath); err != nil {
		return err
	}
	if err := check("dlp_exclusions", dlpExclusionsPath); err != nil {
		return err
	}
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
		DNSQueriesTotal:       v.DNSQueriesTotal,
		DNSBlocksTotal:        v.DNSBlocksTotal,
		DLPScansTotal:         v.DLPScansTotal,
		DLPBlocksTotal:        v.DLPBlocksTotal,
		TamperDetectionsTotal: v.TamperDetectionsTotal,
	}, nil
}

func (a storeAdapter) AddStats(ctx context.Context, delta stats.Snapshot) error {
	return a.s.AddStats(ctx, store.AggregateStats{
		DNSQueriesTotal:       delta.DNSQueriesTotal,
		DNSBlocksTotal:        delta.DNSBlocksTotal,
		DLPScansTotal:         delta.DLPScansTotal,
		DLPBlocksTotal:        delta.DLPBlocksTotal,
		TamperDetectionsTotal: delta.TamperDetectionsTotal,
	})
}

// proxyStats adapts store.Store to proxy.StatsBumper. The proxy can't
// import store directly without inflating the package's dependency
// graph; this tiny adapter keeps the wiring private to main.
type proxyStats struct{ s *store.Store }

func (p proxyStats) BumpDLP(ctx context.Context, blocked bool) error {
	if p.s == nil {
		return nil
	}
	delta := store.AggregateStats{DLPScansTotal: 1}
	if blocked {
		delta.DLPBlocksTotal = 1
	}
	return p.s.AddStats(ctx, delta)
}

// proxyAdapter bridges the proxy.Controller's StatusSnapshot to the
// api.ProxyController interface. Keeping the wire shape in the api
// package (not the proxy package) avoids the proxy package having to
// import api just to produce its own JSON.
type proxyAdapter struct{ c *proxy.Controller }

func (p *proxyAdapter) Enable(ctx context.Context) (string, error) {
	return p.c.Enable(ctx)
}

func (p *proxyAdapter) Disable(ctx context.Context, removeCA bool) error {
	return p.c.Disable(ctx, removeCA)
}

func (p *proxyAdapter) Status() api.ProxyStatus {
	snap := p.c.Status()
	return api.ProxyStatus{
		Running:         snap.Running,
		CAInstalled:     snap.CAInstalled,
		ProxyConfigured: snap.ProxyConfigured,
		ListenAddr:      snap.ListenAddr,
		CACertPath:      snap.CACertPath,
		DLPScansTotal:   snap.DLPScansTotal,
		DLPBlocksTotal:  snap.DLPBlocksTotal,
	}
}

// resolveCAPaths returns the CA cert / key paths, falling back to
// ~/.secure-edge/ca.{crt,key} when the config leaves them blank.
// When HOME cannot be resolved (rare on CI containers) the fallback
// is "./secure-edge-ca.{crt,key}" relative to the agent's working
// directory.
func resolveCAPaths(cfg config.Config) (string, string) {
	cert := cfg.CACertPath
	key := cfg.CAKeyPath
	if cert != "" && key != "" {
		return cert, key
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		if cert == "" {
			cert = "secure-edge-ca.crt"
		}
		if key == "" {
			key = "secure-edge-ca.key"
		}
		return cert, key
	}
	dir := filepath.Join(home, ".secure-edge")
	if cert == "" {
		cert = filepath.Join(dir, "ca.crt")
	}
	if key == "" {
		key = filepath.Join(dir, "ca.key")
	}
	return cert, key
}

// buildPinningSet turns the configured proxy_pinning_bypass list into
// a lowercased lookup set for O(1) hostname checks on the proxy hot
// path.
func buildPinningSet(hosts []string) map[string]struct{} {
	if len(hosts) == 0 {
		return map[string]struct{}{}
	}
	out := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			out[h] = struct{}{}
		}
	}
	return out
}

func (a storeAdapter) ResetStats(ctx context.Context) error { return a.s.ResetStats(ctx) }

// profileApplyAdapter adapts *store.Store to profile.PolicyStore.
// The interface uses profile.DLPConfigSnapshot for layering reasons —
// profile/ cannot import store/ without an import cycle once the
// store consumes the profile package.
type profileApplyAdapter struct{ store *store.Store }

func (a *profileApplyAdapter) SetPolicy(ctx context.Context, category, action string) error {
	return a.store.SetPolicy(ctx, category, action)
}

func (a *profileApplyAdapter) GetDLPConfig(ctx context.Context) (profile.DLPConfigSnapshot, error) {
	cfg, err := a.store.GetDLPConfig(ctx)
	if err != nil {
		return profile.DLPConfigSnapshot{}, err
	}
	return profile.DLPConfigSnapshot{
		ThresholdCritical: cfg.ThresholdCritical,
		ThresholdHigh:     cfg.ThresholdHigh,
		ThresholdMedium:   cfg.ThresholdMedium,
		ThresholdLow:      cfg.ThresholdLow,
		HotwordBoost:      cfg.HotwordBoost,
		EntropyBoost:      cfg.EntropyBoost,
		EntropyPenalty:    cfg.EntropyPenalty,
		ExclusionPenalty:  cfg.ExclusionPenalty,
		MultiMatchBoost:   cfg.MultiMatchBoost,
	}, nil
}

func (a *profileApplyAdapter) SetDLPConfig(ctx context.Context, c profile.DLPConfigSnapshot) error {
	return a.store.SetDLPConfig(ctx, store.DLPConfig{
		ThresholdCritical: c.ThresholdCritical,
		ThresholdHigh:     c.ThresholdHigh,
		ThresholdMedium:   c.ThresholdMedium,
		ThresholdLow:      c.ThresholdLow,
		HotwordBoost:      c.HotwordBoost,
		EntropyBoost:      c.EntropyBoost,
		EntropyPenalty:    c.EntropyPenalty,
		ExclusionPenalty:  c.ExclusionPenalty,
		MultiMatchBoost:   c.MultiMatchBoost,
	})
}

// tamperAdapter bridges the *tamper.Detector to the api.TamperReporter
// interface, mapping tamper.Status field-for-field to api.TamperStatus.
type tamperAdapter struct{ detector *tamper.Detector }

func (a tamperAdapter) Status() api.TamperStatus {
	st := a.detector.Status()
	return api.TamperStatus{
		DNSOK:           st.DNSOK,
		ProxyOK:         st.ProxyOK,
		LastCheck:       st.LastCheck,
		DetectionsTotal: st.DetectionsTotal,
	}
}

// loadProfileOnStartup applies cfg.ProfilePath or cfg.ProfileURL if
// either is set. ProfilePath takes precedence over ProfileURL when
// both are configured (per the config.Config doc comment) — an
// operator-supplied local file overrides any server-distributed
// profile. Errors are propagated so the caller can decide whether to
// fail the boot.
func loadProfileOnStartup(ctx context.Context, cfg config.Config, h *profile.Holder, ps profile.PolicyStore, engine *policy.Engine) error {
	var p *profile.Profile
	var err error
	switch {
	case cfg.ProfilePath != "":
		p, err = profile.LoadFromFile(cfg.ProfilePath)
	case cfg.ProfileURL != "":
		p, err = profile.LoadFromURL(ctx, nil, cfg.ProfileURL)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	if err := p.Apply(ctx, profile.ApplyOptions{PolicyStore: ps, Reloader: engine}); err != nil {
		return err
	}
	return h.Set(p)
}

// splitHostPort returns the host portion of an addr like "127.0.0.1:53".
// Falls back to addr unchanged when no port is present.
func splitHostPort(addr string) (string, string) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, ""
	}
	return addr[:idx], addr[idx+1:]
}
