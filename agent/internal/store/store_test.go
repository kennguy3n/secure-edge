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

	// Bug regression: rules/local/ admin overrides assign domains
	// to the "allow_admin" and "block_admin" categories. Without
	// matching category_policies rows the policy engine falls
	// through to Deny, silently blocking admin-allowed domains.
	// Keep these category strings in sync with
	// rules.OverrideAllowCategory / OverrideBlockCategory.
	wantCats := map[string]string{
		"allow_admin": ActionAllow,
		"block_admin": ActionDeny,
	}
	got := map[string]string{}
	for _, p := range pols {
		got[p.Category] = p.Action
	}
	for cat, wantAct := range wantCats {
		gotAct, ok := got[cat]
		if !ok {
			t.Errorf("expected seeded admin category %q in category_policies", cat)
			continue
		}
		if gotAct != wantAct {
			t.Errorf("category %q action = %q, want %q", cat, gotAct, wantAct)
		}
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

func TestOpen_PragmasApplied(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// busy_timeout matters when the daemon and the Native Messaging
	// host both write to aggregate_stats. The DSN sets it to 5000 ms;
	// drift here would re-introduce silent counter loss.
	var busy int
	if err := s.DB().QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatalf("read busy_timeout: %v", err)
	}
	if busy != 5000 {
		t.Errorf("busy_timeout = %d ms, want 5000 ms", busy)
	}

	var mode string
	if err := s.DB().QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want %q", mode, "wal")
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

// TestMigrations_UserVersionTracksSchema pins the contract Task 1
// added: PRAGMA user_version is bumped to schemaVersion after the
// initial migration, every expected column is present, and re-opening
// the same on-disk database is a no-op (no migration step re-runs).
func TestMigrations_UserVersionTracksSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migrations.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()

	var v int
	if err := s.DB().QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if v != schemaVersion {
		t.Fatalf("user_version after Open = %d, want %d", v, schemaVersion)
	}

	// The v1→v2 migration added tamper_detections_total; assert
	// it is present so a future migration that drops the column
	// surfaces here.
	has, err := columnExists(ctx, s.DB(), "aggregate_stats", "tamper_detections_total")
	if err != nil {
		t.Fatalf("columnExists: %v", err)
	}
	if !has {
		t.Fatal("aggregate_stats.tamper_detections_total missing")
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open the same DB. user_version must already be at
	// schemaVersion, so migrate() walks zero steps. We assert by
	// reading the pragma value out again.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("Open 2: %v", err)
	}
	defer s2.Close()
	var v2 int
	if err := s2.DB().QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v2); err != nil {
		t.Fatalf("read user_version after reopen: %v", err)
	}
	if v2 != schemaVersion {
		t.Fatalf("user_version after reopen = %d, want %d", v2, schemaVersion)
	}
}

// TestSetPolicy_RejectsUnknownCategory locks in Task 7's category
// validation. A profile or admin override that names a category the
// agent does not know about must fail at the store boundary rather
// than land an orphaned row policy code later ignores.
func TestSetPolicy_RejectsUnknownCategory(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if err := s.SetPolicy(ctx, "Made Up Category", ActionAllow); err == nil {
		t.Fatal("expected error for unknown category")
	}
}

// TestSetPolicy_AcceptsAdminOverride confirms the *_admin override
// namespace (allow_admin, block_admin, …) keeps working. The agent's
// rules-override file uses these to grant per-domain allow/deny that
// trump category policies; rejecting them here would lock operators
// out of their own override file.
func TestSetPolicy_AcceptsAdminOverride(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for _, cat := range []string{"allow_admin", "block_admin", "team_admin"} {
		if err := s.SetPolicy(ctx, cat, ActionAllow); err != nil {
			t.Errorf("SetPolicy(%q): %v", cat, err)
		}
	}
}

// TestSetDLPConfig_RejectsInvalidThreshold guards the threshold
// half of Task 7's DLP validation. A profile that ships a zero or
// negative threshold is rejected at the store boundary; left alone,
// such a value would let every scan match (threshold=0) or never
// match (negative), and the operator would see the symptom only at
// scan time.
func TestSetDLPConfig_RejectsInvalidThreshold(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	base := DLPConfig{
		ThresholdCritical: 10, ThresholdHigh: 8, ThresholdMedium: 5, ThresholdLow: 2,
	}
	bad := base
	bad.ThresholdCritical = 0
	if err := s.SetDLPConfig(ctx, bad); err == nil {
		t.Error("expected error for ThresholdCritical=0")
	}
	bad = base
	bad.ThresholdHigh = -1
	if err := s.SetDLPConfig(ctx, bad); err == nil {
		t.Error("expected error for ThresholdHigh=-1")
	}
}

// TestSetDLPConfig_RejectsOutOfBoundsWeight guards the weight half
// of Task 7's DLP validation. Weights live in [-100, +100] so a
// profile cannot dominate the scorer with a single feature that
// drowns out everyone else's signal.
func TestSetDLPConfig_RejectsOutOfBoundsWeight(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	base := DLPConfig{
		ThresholdCritical: 10, ThresholdHigh: 8, ThresholdMedium: 5, ThresholdLow: 2,
	}
	bad := base
	bad.HotwordBoost = 200
	if err := s.SetDLPConfig(ctx, bad); err == nil {
		t.Error("expected error for HotwordBoost=200")
	}
	bad = base
	bad.ExclusionPenalty = -200
	if err := s.SetDLPConfig(ctx, bad); err == nil {
		t.Error("expected error for ExclusionPenalty=-200")
	}
}

// TestApplyProfileTx_RollsBackOnValidationFailure is the regression
// test for the bug Task 2 fixes: a profile import that fails halfway
// through must leave the store untouched. Without ApplyProfileTx the
// first N-1 SetPolicy calls would commit individually and a later
// failure would land the agent on a half-applied profile.
func TestApplyProfileTx_RollsBackOnValidationFailure(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Snapshot the current policy for "AI Chat Blocked" so we can
	// assert the failed import did not move it.
	before, err := s.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	beforeMap := map[string]string{}
	for _, p := range before {
		beforeMap[p.Category] = p.Action
	}

	// The third policy is invalid (unknown category). Validation
	// runs before BEGIN, so none of the preceding two writes can
	// have made it to disk.
	cats := []CategoryPolicy{
		{Category: "AI Chat Blocked", Action: ActionDeny},
		{Category: "AI Allowed", Action: ActionDeny},
		{Category: "Made Up Category", Action: ActionAllow}, // rejects
	}
	err = s.ApplyProfileTx(ctx, cats, nil)
	if err == nil {
		t.Fatal("expected error from invalid third category")
	}

	after, err := s.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies after: %v", err)
	}
	afterMap := map[string]string{}
	for _, p := range after {
		afterMap[p.Category] = p.Action
	}
	for cat, want := range beforeMap {
		if got := afterMap[cat]; got != want {
			t.Errorf("category %q drifted: was %q, now %q (partial commit)", cat, want, got)
		}
	}
}

// TestApplyProfileTx_HappyPath confirms the all-or-nothing path
// does in fact persist both the categories AND the DLP config when
// every input validates.
func TestApplyProfileTx_HappyPath(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	cats := []CategoryPolicy{
		{Category: "AI Chat Blocked", Action: ActionDeny},
		{Category: "AI Allowed", Action: ActionAllow},
	}
	dlp := &DLPConfig{
		ThresholdCritical: 12, ThresholdHigh: 9, ThresholdMedium: 6, ThresholdLow: 3,
		HotwordBoost: 5,
	}
	if err := s.ApplyProfileTx(ctx, cats, dlp); err != nil {
		t.Fatalf("ApplyProfileTx: %v", err)
	}
	pols, err := s.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	got := map[string]string{}
	for _, p := range pols {
		got[p.Category] = p.Action
	}
	for _, c := range cats {
		if got[c.Category] != c.Action {
			t.Errorf("category %q action = %q, want %q", c.Category, got[c.Category], c.Action)
		}
	}
	cur, err := s.GetDLPConfig(ctx)
	if err != nil {
		t.Fatalf("GetDLPConfig: %v", err)
	}
	if cur.ThresholdCritical != 12 || cur.HotwordBoost != 5 {
		t.Errorf("dlp_config not persisted: got %+v", cur)
	}
}

// TestRegisterCategories_AcceptsCustomNames pins the follow-up fix
// for the post-merge review finding: operators ship custom rule
// files via cfg.RulePaths (categoryFromPath turns a `gaming.txt`
// entry into the category "Gaming"), and the store must accept
// SetPolicy writes against those custom categories. Without
// RegisterCategories the closed-set check rejects them as
// ErrInvalidCategory and the operator-visible /api/policies surface
// returns 400 on every write.
func TestRegisterCategories_AcceptsCustomNames(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Baseline: an unregistered custom category is rejected.
	if err := s.SetPolicy(ctx, "Gaming", ActionDeny); err == nil {
		t.Fatal("expected ErrInvalidCategory for unregistered custom category")
	}

	// Register and retry.
	s.RegisterCategories([]string{"Gaming"})
	if err := s.SetPolicy(ctx, "Gaming", ActionDeny); err != nil {
		t.Fatalf("registered custom category should be accepted, got %v", err)
	}

	// The closed-set known names still flow through.
	if err := s.SetPolicy(ctx, "AI Chat Blocked", ActionDeny); err != nil {
		t.Fatalf("known closed-set category rejected: %v", err)
	}

	// An admin-pattern category still works without registration.
	if err := s.SetPolicy(ctx, "allow_admin", ActionAllow); err != nil {
		t.Fatalf("admin-pattern category rejected: %v", err)
	}
}

// TestRegisterCategories_TrimsAndIgnoresBlanks is the input-hygiene
// half of RegisterCategories. The boot-time helper that derives
// names from cfg.RulePaths could pass through whitespace if the
// path contained a trailing space (or a future caller passes raw
// YAML values), and a blank entry would otherwise widen the
// acceptable-category set to include the empty string.
func TestRegisterCategories_TrimsAndIgnoresBlanks(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	s.RegisterCategories([]string{"  ", "", "\t", "  Gaming  ", "Reading"})

	// The empty string and pure whitespace must NOT have been added.
	if err := s.SetPolicy(ctx, "", ActionDeny); err == nil {
		t.Error("empty-string category should be rejected")
	}
	if err := s.SetPolicy(ctx, "   ", ActionDeny); err == nil {
		t.Error("whitespace-only category should be rejected")
	}

	// The trimmed forms succeed.
	if err := s.SetPolicy(ctx, "Gaming", ActionDeny); err != nil {
		t.Errorf("trimmed Gaming rejected: %v", err)
	}
	if err := s.SetPolicy(ctx, "Reading", ActionAllow); err != nil {
		t.Errorf("Reading rejected: %v", err)
	}
}

// TestRegisterCategories_AppliesToApplyProfileTx confirms the
// ApplyProfileTx code path also consults the registered set —
// otherwise an enterprise profile that names a custom category
// would still be rejected wholesale during import.
func TestRegisterCategories_AppliesToApplyProfileTx(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	s.RegisterCategories([]string{"Gaming"})

	cats := []CategoryPolicy{
		{Category: "AI Chat Blocked", Action: ActionDeny},
		{Category: "Gaming", Action: ActionDeny},
	}
	if err := s.ApplyProfileTx(ctx, cats, nil); err != nil {
		t.Fatalf("ApplyProfileTx with registered custom: %v", err)
	}

	// And the negative case still fires for unregistered names.
	bad := []CategoryPolicy{{Category: "Cooking", Action: ActionDeny}}
	if err := s.ApplyProfileTx(ctx, bad, nil); err == nil {
		t.Fatal("expected ApplyProfileTx to reject unregistered Cooking")
	}
}

// TestRegisterCategories_NilSafeAndIdempotent covers the two
// degenerate inputs (nil receiver, repeated registrations) so a
// caller can re-derive the list on every reload without worrying
// about emptying or wiping the existing set.
func TestRegisterCategories_NilSafeAndIdempotent(t *testing.T) {
	var nilStore *Store
	nilStore.RegisterCategories([]string{"Gaming"}) // must not panic

	s := openTestStore(t)
	ctx := context.Background()

	s.RegisterCategories([]string{"Gaming"})
	s.RegisterCategories(nil)
	s.RegisterCategories([]string{}) // explicit empty
	s.RegisterCategories([]string{"Reading"})

	// First registration survived the subsequent no-ops.
	if err := s.SetPolicy(ctx, "Gaming", ActionDeny); err != nil {
		t.Errorf("Gaming survived idempotent calls: %v", err)
	}
	// Second registration unioned in.
	if err := s.SetPolicy(ctx, "Reading", ActionAllow); err != nil {
		t.Errorf("Reading added on second call: %v", err)
	}
}
