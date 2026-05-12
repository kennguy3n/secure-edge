// Command agent runs the Secure Edge Phase 1 agent: DNS resolver +
// policy engine + SQLite-backed config/stats + local HTTP API.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kennguy3n/secure-edge/agent/internal/api"
	"github.com/kennguy3n/secure-edge/agent/internal/config"
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
	flag.Parse()

	api.Version = version

	if err := run(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "agent: %v\n", err)
		os.Exit(1)
	}
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

// categoryFromPath turns "rules/ai_chat_blocked.txt" into "AI Chat Blocked".
func categoryFromPath(path string) string {
	base := path
	if idx := lastIndex(base, '/'); idx >= 0 {
		base = base[idx+1:]
	}
	if idx := lastIndex(base, '\\'); idx >= 0 {
		base = base[idx+1:]
	}
	if idx := lastIndex(base, '.'); idx >= 0 {
		base = base[:idx]
	}
	out := make([]byte, 0, len(base))
	upper := true
	for i := 0; i < len(base); i++ {
		c := base[i]
		if c == '_' || c == '-' {
			out = append(out, ' ')
			upper = true
			continue
		}
		if upper && c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		out = append(out, c)
		upper = false
	}
	return string(out)
}

func lastIndex(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
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
