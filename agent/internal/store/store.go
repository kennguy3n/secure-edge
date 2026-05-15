// Package store wraps the SQLite persistence layer for the Secure Edge
// agent. Only configuration and anonymous aggregate counters are
// persisted — no domain names, IP addresses, URLs, or per-event timestamps.
//
// The schema mirrors ARCHITECTURE.md section 6:
//
//	rulesets
//	category_policies
//	aggregate_stats         -- singleton, id = 1
//	rule_versions
//	dlp_config              -- singleton, id = 1
//
// There is intentionally NO alert_events table and NO access_log table.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	_ "modernc.org/sqlite" // SQLite driver (pure Go, no CGO).
)

// schemaVersion is the target user_version for a freshly-opened DB.
// Versioned migrations (see migrate) replay every step between the
// DB's current PRAGMA user_version and this value. Bump this whenever
// you add a new migrateVN step and append the corresponding case to
// the switch in migrate().
const schemaVersion = 2

// Action values stored in category_policies.action.
const (
	ActionAllow        = "allow"
	ActionAllowWithDLP = "allow_with_dlp"
	ActionDeny         = "deny"
)

// knownCategories is the closed set of rule categories the store
// accepts via SetPolicy. The list intentionally mirrors the seeded
// defaults in seedDefaults so any operator who wants to add a new
// category has to update this set as well — a write through SetPolicy
// is the load-bearing gate, so an unknown category here means an
// unknown category in the policy engine.
//
// Categories outside this set are accepted only when they match the
// admin-override namespace pattern (see isAdminCategory). Together
// the two checks bound SetPolicy's writable space to (a) the known
// fixed categories produced by categoryFromPath in cmd/agent and
// (b) the `<verb>_admin` rows seeded for rules.OverrideStore.
var knownCategories = map[string]bool{
	"AI Chat Blocked": true,
	"AI Code Blocked": true,
	"AI Allowed":      true,
	"AI Chat DLP":     true,
	"Phishing":        true,
	"Social":          true,
	"News":            true,
}

// adminCategoryPattern matches the admin-override namespace used by
// rules.OverrideStore (allow_admin, block_admin). Any category that
// matches this pattern is accepted by SetPolicy even if it isn't in
// knownCategories. The verb prefix must be a non-empty lowercase
// identifier so callers can't smuggle in arbitrary names by adding a
// trailing `_admin` substring.
var adminCategoryPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*_admin$`)

// isKnownCategory reports whether cat is acceptable as a SetPolicy
// target — either a hard-coded fixed category or an admin-override.
func isKnownCategory(cat string) bool {
	if knownCategories[cat] {
		return true
	}
	return adminCategoryPattern.MatchString(cat)
}

// CategoryPolicy is a row in the category_policies table.
type CategoryPolicy struct {
	Category string `json:"category"`
	Action   string `json:"action"`
}

// AggregateStats is the singleton row in aggregate_stats.
type AggregateStats struct {
	DNSQueriesTotal       int64 `json:"dns_queries_total"`
	DNSBlocksTotal        int64 `json:"dns_blocks_total"`
	DLPScansTotal         int64 `json:"dlp_scans_total"`
	DLPBlocksTotal        int64 `json:"dlp_blocks_total"`
	TamperDetectionsTotal int64 `json:"tamper_detections_total"`
}

// Store is the persistence handle. Methods are safe for concurrent use.
type Store struct {
	db *sql.DB

	mu sync.Mutex
}

// Open connects to the SQLite database at path (creating it if needed)
// in WAL mode and applies all required migrations.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: db path is empty")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		// Caller is responsible for creating parent directories; we don't
		// silently create directories here to keep behaviour predictable.
		_ = dir
	}

	// busy_timeout matters when more than one process holds the DB
	// open concurrently — e.g. the long-lived daemon and a transient
	// Native Messaging host instance both bumping aggregate_stats. WAL
	// keeps reads non-blocking but writers still serialise; without
	// busy_timeout SQLite returns SQLITE_BUSY immediately and the
	// caller has to retry. We retry for up to 5s inside the driver so
	// callers (and ultimately the stats counters) don't have to.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)",
		url.QueryEscape(path))

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer; serialise via the pool.

	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.seedDefaults(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the raw handle for callers that need it (e.g. the privacy
// audit test). External users should treat this as a read-only view.
func (s *Store) DB() *sql.DB { return s.db }

// migrate replays every versioned migration step between the DB's
// current PRAGMA user_version and schemaVersion. Each step is
// idempotent on its own: re-running migrate against an up-to-date DB
// is a no-op and never fails. Steps are wrapped individually so a
// partial run leaves a coherent user_version pointing at the highest
// successfully-applied step.
//
// Each case must set PRAGMA user_version = N at the end so a crash
// between steps does not silently leave the DB at the lower version
// — the next Open call would otherwise re-apply the step. Migrations
// MUST also avoid string-matching SQLite error strings (e.g.
// "duplicate column name"): every conditional schema change goes
// through columnExists / tableExists instead.
func (s *Store) migrate(ctx context.Context) error {
	current, err := s.currentUserVersion(ctx)
	if err != nil {
		return err
	}
	for current < schemaVersion {
		next := current + 1
		switch current {
		case 0:
			if err := s.migrateV1(ctx); err != nil {
				return fmt.Errorf("migrate v0->v1: %w", err)
			}
		case 1:
			if err := s.migrateV2(ctx); err != nil {
				return fmt.Errorf("migrate v1->v2: %w", err)
			}
		default:
			return fmt.Errorf("migrate: no step registered for user_version=%d", current)
		}
		if _, err := s.db.ExecContext(ctx,
			fmt.Sprintf("PRAGMA user_version = %d", next)); err != nil {
			return fmt.Errorf("set user_version=%d: %w", next, err)
		}
		current = next
	}
	return nil
}

// currentUserVersion reads PRAGMA user_version. A fresh DB returns 0.
func (s *Store) currentUserVersion(ctx context.Context) (int, error) {
	var v int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return 0, fmt.Errorf("read user_version: %w", err)
	}
	return v, nil
}

// migrateV1 creates the five baseline tables at their pre-Phase-5
// shape (aggregate_stats does NOT yet include tamper_detections_total
// — migrateV2 adds it). The CREATE TABLE IF NOT EXISTS forms keep the
// step idempotent against an older install that already has these
// tables from a pre-versioned migrate() call.
func (s *Store) migrateV1(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS rulesets (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid        TEXT UNIQUE NOT NULL,
			name        TEXT NOT NULL,
			rule_type   TEXT NOT NULL DEFAULT 'dstdomain',
			file_path   TEXT NOT NULL,
			category    TEXT NOT NULL,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS category_policies (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			category    TEXT UNIQUE NOT NULL,
			action      TEXT NOT NULL DEFAULT 'deny',
			updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS aggregate_stats (
			id                       INTEGER PRIMARY KEY CHECK (id = 1),
			dns_queries_total        INTEGER NOT NULL DEFAULT 0,
			dns_blocks_total         INTEGER NOT NULL DEFAULT 0,
			dlp_scans_total          INTEGER NOT NULL DEFAULT 0,
			dlp_blocks_total         INTEGER NOT NULL DEFAULT 0,
			last_reset_at            DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS rule_versions (
			id               INTEGER PRIMARY KEY AUTOINCREMENT,
			manifest_version TEXT NOT NULL,
			updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS dlp_config (
			id                      INTEGER PRIMARY KEY CHECK (id = 1),
			threshold_critical      INTEGER NOT NULL DEFAULT 1,
			threshold_high          INTEGER NOT NULL DEFAULT 2,
			threshold_medium        INTEGER NOT NULL DEFAULT 3,
			threshold_low           INTEGER NOT NULL DEFAULT 4,
			hotword_boost           INTEGER NOT NULL DEFAULT 2,
			entropy_boost           INTEGER NOT NULL DEFAULT 1,
			entropy_penalty         INTEGER NOT NULL DEFAULT -2,
			exclusion_penalty       INTEGER NOT NULL DEFAULT -3,
			multi_match_boost       INTEGER NOT NULL DEFAULT 1,
			updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("migrate v1: %w (stmt=%s)", err, q[:30])
		}
	}
	return nil
}

// migrateV2 adds tamper_detections_total to aggregate_stats. Phase 5
// introduced the column; before versioned migrations existed the
// agent ran an ALTER TABLE on every Open and sniffed the SQLite
// error string to make it idempotent. The columnExists check below
// is the structural replacement for that error-string sniff.
func (s *Store) migrateV2(ctx context.Context) error {
	has, err := columnExists(ctx, s.db, "aggregate_stats", "tamper_detections_total")
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE aggregate_stats ADD COLUMN tamper_detections_total INTEGER NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("add tamper_detections_total: %w", err)
	}
	return nil
}

// columnExists reports whether the named column is present in the
// table according to PRAGMA table_info. Returns (false, nil) when the
// table itself does not exist — callers that need to distinguish
// "missing column" from "missing table" should use tableExists first.
func columnExists(ctx context.Context, db *sql.DB, table, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", quoteIdent(table)))
	if err != nil {
		return false, fmt.Errorf("columnExists pragma: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, fmt.Errorf("columnExists scan: %w", err)
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// quoteIdent wraps an SQLite identifier in double-quotes after
// doubling any embedded double-quote characters. PRAGMA table_info
// accepts a quoted identifier inside its parens, which is the only
// safe way to embed a Go-side string into the statement (we can't
// bind a parameter inside a PRAGMA argument).
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func (s *Store) seedDefaults(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO aggregate_stats (id) VALUES (1)`); err != nil {
		return fmt.Errorf("seed aggregate_stats: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO dlp_config (id) VALUES (1)`); err != nil {
		return fmt.Errorf("seed dlp_config: %w", err)
	}

	// Default Phase 1 category policies. These can be updated via the API.
	// The list must cover every category produced by categoryFromPath
	// for a rule file shipped under rules/, otherwise the policy engine
	// falls back to its default-Deny rule and silently blocks a whole
	// category (e.g. news domains).
	defaults := []CategoryPolicy{
		{Category: "AI Chat Blocked", Action: ActionDeny},
		{Category: "AI Code Blocked", Action: ActionDeny},
		{Category: "AI Allowed", Action: ActionAllow},
		{Category: "AI Chat DLP", Action: ActionAllowWithDLP},
		{Category: "Phishing", Action: ActionDeny},
		{Category: "Social", Action: ActionAllow},
		{Category: "News", Action: ActionAllow},
		// Admin override categories produced by rules.OverrideStore.
		// Without these rows the engine's lookup map falls through to
		// Deny (see policy/engine.go), so admin-allowed domains would
		// be silently blocked. Keep these category strings in sync
		// with rules.OverrideAllowCategory / OverrideBlockCategory.
		{Category: "allow_admin", Action: ActionAllow},
		{Category: "block_admin", Action: ActionDeny},
	}
	for _, p := range defaults {
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO category_policies (category, action) VALUES (?, ?)`,
			p.Category, p.Action); err != nil {
			return fmt.Errorf("seed category_policies: %w", err)
		}
	}
	return nil
}

// ListPolicies returns all category policies.
func (s *Store) ListPolicies(ctx context.Context) ([]CategoryPolicy, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT category, action FROM category_policies ORDER BY category`)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	var out []CategoryPolicy
	for rows.Next() {
		var p CategoryPolicy
		if err := rows.Scan(&p.Category, &p.Action); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ErrInvalidAction is returned by SetPolicy when the action value
// isn't one of the three supported strings.
var ErrInvalidAction = errors.New("invalid action")

// ErrInvalidCategory is returned by SetPolicy when the category
// name is neither a known fixed category nor an admin-override.
var ErrInvalidCategory = errors.New("invalid category")

// ErrInvalidDLPConfig is returned by SetDLPConfig when one of the
// thresholds or weights falls outside its sane envelope. Wrapped
// with %w so callers can errors.Is against it.
var ErrInvalidDLPConfig = errors.New("invalid dlp_config")

// dlpWeightMax bounds the absolute value of every DLPConfig weight
// (hotword_boost, entropy_boost, entropy_penalty, exclusion_penalty,
// multi_match_boost). The scoring path adds these per match; without
// a bound a single pathological config value could push a benign
// payload into Critical and trigger a block.
const dlpWeightMax = 100

// validateDLPConfig enforces the sane-envelope contract on a
// DLPConfig before it's persisted. Returns an ErrInvalidDLPConfig-
// wrapped error pointing at the offending field on the first
// failure; callers use this from both SetDLPConfig and
// ApplyProfileTx so the API surface and the profile-import path
// share one validator.
func validateDLPConfig(c DLPConfig) error {
	if c.ThresholdCritical <= 0 {
		return fmt.Errorf("%w: threshold_critical must be positive", ErrInvalidDLPConfig)
	}
	if c.ThresholdHigh <= 0 {
		return fmt.Errorf("%w: threshold_high must be positive", ErrInvalidDLPConfig)
	}
	if c.ThresholdMedium <= 0 {
		return fmt.Errorf("%w: threshold_medium must be positive", ErrInvalidDLPConfig)
	}
	if c.ThresholdLow <= 0 {
		return fmt.Errorf("%w: threshold_low must be positive", ErrInvalidDLPConfig)
	}
	weights := []struct {
		name string
		v    int
	}{
		{"hotword_boost", c.HotwordBoost},
		{"entropy_boost", c.EntropyBoost},
		{"entropy_penalty", c.EntropyPenalty},
		{"exclusion_penalty", c.ExclusionPenalty},
		{"multi_match_boost", c.MultiMatchBoost},
	}
	for _, w := range weights {
		if w.v < -dlpWeightMax || w.v > dlpWeightMax {
			return fmt.Errorf("%w: %s=%d outside [-%d,%d]",
				ErrInvalidDLPConfig, w.name, w.v, dlpWeightMax, dlpWeightMax)
		}
	}
	return nil
}

// validatePolicyInputs runs the closed-set checks that gate every
// SetPolicy / ApplyProfileTx write. Splitting it out from SetPolicy
// lets ApplyProfileTx pre-flight the entire batch before opening a
// transaction (so the partial-write regression test in store_test.go
// can drive the failure mode without depending on SQLite's own
// rollback semantics).
func validatePolicyInputs(category, action string) error {
	switch action {
	case ActionAllow, ActionAllowWithDLP, ActionDeny:
	default:
		return ErrInvalidAction
	}
	if !isKnownCategory(category) {
		return fmt.Errorf("%w: %q", ErrInvalidCategory, category)
	}
	return nil
}

// SetPolicy upserts the action for a category. Validates both the
// action (ErrInvalidAction) and the category name (ErrInvalidCategory)
// before touching the DB so an out-of-set category never lands on disk.
func (s *Store) SetPolicy(ctx context.Context, category, action string) error {
	if err := validatePolicyInputs(category, action); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO category_policies (category, action) VALUES (?, ?)
		ON CONFLICT(category) DO UPDATE SET action = excluded.action, updated_at = CURRENT_TIMESTAMP
	`, category, action)
	if err != nil {
		return fmt.Errorf("set policy: %w", err)
	}
	return nil
}

// GetStats reads the singleton aggregate_stats row.
func (s *Store) GetStats(ctx context.Context) (AggregateStats, error) {
	var st AggregateStats
	err := s.db.QueryRowContext(ctx, `
		SELECT dns_queries_total, dns_blocks_total, dlp_scans_total, dlp_blocks_total, tamper_detections_total
		FROM aggregate_stats WHERE id = 1
	`).Scan(&st.DNSQueriesTotal, &st.DNSBlocksTotal, &st.DLPScansTotal, &st.DLPBlocksTotal, &st.TamperDetectionsTotal)
	if err != nil {
		return AggregateStats{}, fmt.Errorf("get stats: %w", err)
	}
	return st, nil
}

// AddStats atomically adds deltas to the aggregate_stats counters.
func (s *Store) AddStats(ctx context.Context, delta AggregateStats) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, `
		UPDATE aggregate_stats SET
			dns_queries_total        = dns_queries_total        + ?,
			dns_blocks_total         = dns_blocks_total         + ?,
			dlp_scans_total          = dlp_scans_total          + ?,
			dlp_blocks_total         = dlp_blocks_total         + ?,
			tamper_detections_total  = tamper_detections_total  + ?
		WHERE id = 1
	`, delta.DNSQueriesTotal, delta.DNSBlocksTotal, delta.DLPScansTotal, delta.DLPBlocksTotal, delta.TamperDetectionsTotal)
	if err != nil {
		return fmt.Errorf("add stats: %w", err)
	}
	return nil
}

// DLPConfig is the singleton row in dlp_config.
type DLPConfig struct {
	ThresholdCritical int `json:"threshold_critical"`
	ThresholdHigh     int `json:"threshold_high"`
	ThresholdMedium   int `json:"threshold_medium"`
	ThresholdLow      int `json:"threshold_low"`
	HotwordBoost      int `json:"hotword_boost"`
	EntropyBoost      int `json:"entropy_boost"`
	EntropyPenalty    int `json:"entropy_penalty"`
	ExclusionPenalty  int `json:"exclusion_penalty"`
	MultiMatchBoost   int `json:"multi_match_boost"`
}

// GetDLPConfig reads the singleton dlp_config row.
func (s *Store) GetDLPConfig(ctx context.Context) (DLPConfig, error) {
	var c DLPConfig
	err := s.db.QueryRowContext(ctx, `
		SELECT threshold_critical, threshold_high, threshold_medium, threshold_low,
		       hotword_boost, entropy_boost, entropy_penalty, exclusion_penalty,
		       multi_match_boost
		FROM dlp_config WHERE id = 1
	`).Scan(
		&c.ThresholdCritical, &c.ThresholdHigh, &c.ThresholdMedium, &c.ThresholdLow,
		&c.HotwordBoost, &c.EntropyBoost, &c.EntropyPenalty, &c.ExclusionPenalty,
		&c.MultiMatchBoost,
	)
	if err != nil {
		return DLPConfig{}, fmt.Errorf("get dlp_config: %w", err)
	}
	return c, nil
}

// SetDLPConfig overwrites the singleton dlp_config row. Validates the
// thresholds (must be positive) and weights (must be within
// [-dlpWeightMax, +dlpWeightMax]) before touching the DB.
func (s *Store) SetDLPConfig(ctx context.Context, c DLPConfig) error {
	if err := validateDLPConfig(c); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, `
		UPDATE dlp_config SET
			threshold_critical = ?,
			threshold_high     = ?,
			threshold_medium   = ?,
			threshold_low      = ?,
			hotword_boost      = ?,
			entropy_boost      = ?,
			entropy_penalty    = ?,
			exclusion_penalty  = ?,
			multi_match_boost  = ?,
			updated_at         = CURRENT_TIMESTAMP
		WHERE id = 1
	`,
		c.ThresholdCritical, c.ThresholdHigh, c.ThresholdMedium, c.ThresholdLow,
		c.HotwordBoost, c.EntropyBoost, c.EntropyPenalty, c.ExclusionPenalty,
		c.MultiMatchBoost,
	)
	if err != nil {
		return fmt.Errorf("set dlp_config: %w", err)
	}
	return nil
}

// ApplyProfileTx atomically writes a batch of category policies and
// (optionally) a new DLP config inside a single SQLite transaction.
// Validation runs first against every input; if any value fails the
// closed-set / sane-envelope checks the transaction is never opened
// and the existing rows are left untouched.
//
// This is the load-bearing alternative to issuing N SetPolicy calls
// followed by a SetDLPConfig: the per-call SetPolicy path runs each
// upsert as its own implicit transaction, so the Nth failure leaves
// the first N-1 writes already committed and the agent ends up in a
// half-applied state (some categories at the new profile's values,
// others at the old). ApplyProfileTx makes that impossible by design
// — the profile loader in cmd/agent and POST /api/profile/import
// both route through this method, so the on-disk picture either
// reflects the entire incoming profile or none of it.
//
// dlpConfig may be nil; when nil the dlp_config row is left
// untouched. A nil-or-empty categories slice with a nil dlpConfig is
// a no-op and returns without opening a transaction.
func (s *Store) ApplyProfileTx(ctx context.Context, categories []CategoryPolicy, dlpConfig *DLPConfig) error {
	for _, p := range categories {
		if err := validatePolicyInputs(p.Category, p.Action); err != nil {
			return fmt.Errorf("apply_profile_tx: %w", err)
		}
	}
	if dlpConfig != nil {
		if err := validateDLPConfig(*dlpConfig); err != nil {
			return fmt.Errorf("apply_profile_tx: %w", err)
		}
	}
	if len(categories) == 0 && dlpConfig == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("apply_profile_tx: begin: %w", err)
	}
	// Defer a rollback that is a no-op after a successful Commit:
	// sql.Tx.Rollback() on a committed tx returns sql.ErrTxDone,
	// which we intentionally swallow so the success path stays
	// quiet but a panic / early return still rolls back cleanly.
	defer func() { _ = tx.Rollback() }()

	for _, p := range categories {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO category_policies (category, action) VALUES (?, ?)
			ON CONFLICT(category) DO UPDATE SET action = excluded.action, updated_at = CURRENT_TIMESTAMP
		`, p.Category, p.Action); err != nil {
			return fmt.Errorf("apply_profile_tx: set %q=%q: %w", p.Category, p.Action, err)
		}
	}
	if dlpConfig != nil {
		c := *dlpConfig
		if _, err := tx.ExecContext(ctx, `
			UPDATE dlp_config SET
				threshold_critical = ?,
				threshold_high     = ?,
				threshold_medium   = ?,
				threshold_low      = ?,
				hotword_boost      = ?,
				entropy_boost      = ?,
				entropy_penalty    = ?,
				exclusion_penalty  = ?,
				multi_match_boost  = ?,
				updated_at         = CURRENT_TIMESTAMP
			WHERE id = 1
		`,
			c.ThresholdCritical, c.ThresholdHigh, c.ThresholdMedium, c.ThresholdLow,
			c.HotwordBoost, c.EntropyBoost, c.EntropyPenalty, c.ExclusionPenalty,
			c.MultiMatchBoost,
		); err != nil {
			return fmt.Errorf("apply_profile_tx: set dlp_config: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("apply_profile_tx: commit: %w", err)
	}
	return nil
}

// ResetStats zeroes the aggregate counters.
func (s *Store) ResetStats(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE aggregate_stats SET
			dns_queries_total        = 0,
			dns_blocks_total         = 0,
			dlp_scans_total          = 0,
			dlp_blocks_total         = 0,
			tamper_detections_total  = 0,
			last_reset_at            = CURRENT_TIMESTAMP
		WHERE id = 1
	`)
	if err != nil {
		return fmt.Errorf("reset stats: %w", err)
	}
	return nil
}

// CurrentRuleVersion returns the most recent rule manifest version
// recorded in rule_versions. An empty string is returned when no
// version has been written yet (fresh install).
func (s *Store) CurrentRuleVersion(ctx context.Context) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `
SELECT manifest_version FROM rule_versions ORDER BY id DESC LIMIT 1
`).Scan(&v)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("current rule_version: %w", err)
	}
	return v, nil
}

// AppendRuleVersion records that the agent successfully synced rules
// to the given manifest version. The append-only history preserves an
// audit trail; CurrentRuleVersion always returns the newest row.
func (s *Store) AppendRuleVersion(ctx context.Context, version string) error {
	if version == "" {
		return errors.New("append rule_version: version is empty")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rule_versions (manifest_version) VALUES (?)`, version)
	if err != nil {
		return fmt.Errorf("append rule_version: %w", err)
	}
	return nil
}
