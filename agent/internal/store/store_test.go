package store

import (
	"context"
	"path/filepath"
	"sort"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpen_SchemaAndSeeds(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Migrations create five tables and no access/alert tables.
	rows, err := s.DB().QueryContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		names = append(names, n)
	}
	sort.Strings(names)
	want := []string{"aggregate_stats", "category_policies", "dlp_config", "rule_versions", "rulesets"}
	if len(names) != len(want) {
		t.Fatalf("tables = %v, want %v", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("table[%d] = %q, want %q", i, names[i], w)
		}
	}

	// Singleton rows are seeded.
	st, err := s.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if st != (AggregateStats{}) {
		t.Fatalf("seeded stats not zero: %+v", st)
	}

	pols, err := s.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(pols) == 0 {
		t.Fatal("expected default policies")
	}
}

func TestSetPolicy(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.SetPolicy(ctx, "AI Chat Blocked", ActionAllow); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	pols, err := s.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	var found bool
	for _, p := range pols {
		if p.Category == "AI Chat Blocked" {
			if p.Action != ActionAllow {
				t.Errorf("action = %q, want %q", p.Action, ActionAllow)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("policy not found")
	}

	if err := s.SetPolicy(ctx, "AI Chat Blocked", "bogus"); err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestStatsAddAndReset(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.AddStats(ctx, AggregateStats{
		DNSQueriesTotal: 5,
		DNSBlocksTotal:  2,
		DLPScansTotal:   1,
		DLPBlocksTotal:  1,
	}); err != nil {
		t.Fatalf("AddStats: %v", err)
	}
	got, err := s.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	want := AggregateStats{DNSQueriesTotal: 5, DNSBlocksTotal: 2, DLPScansTotal: 1, DLPBlocksTotal: 1}
	if got != want {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}

	if err := s.ResetStats(ctx); err != nil {
		t.Fatalf("ResetStats: %v", err)
	}
	got, err = s.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if got != (AggregateStats{}) {
		t.Fatalf("after reset = %+v", got)
	}
}

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "twice.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatalf("Open 2: %v", err)
	}
	defer s.Close()

	// Operations should still succeed; counters preserved.
	if _, err := s.GetStats(context.Background()); err != nil {
		t.Fatalf("GetStats after reopen: %v", err)
	}
}
