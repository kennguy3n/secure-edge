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
	"sync"

	_ "modernc.org/sqlite" // SQLite driver (pure Go, no CGO).
)

// schemaVersion is bumped when the schema changes in a non-additive way.
// Pragmatic migrations should be additive (CREATE TABLE IF NOT EXISTS,
// ALTER TABLE ADD COLUMN). The user_version pragma is updated to this
// value after a successful migration run.
const schemaVersion = 1

// Action values stored in category_policies.action.
const (
	ActionAllow        = "allow"
	ActionAllowWithDLP = "allow_with_dlp"
	ActionDeny         = "deny"
)

// CategoryPolicy is a row in the category_policies table.
type CategoryPolicy struct {
	Category string `json:"category"`
	Action   string `json:"action"`
}

// AggregateStats is the singleton row in aggregate_stats.
type AggregateStats struct {
	DNSQueriesTotal int64 `json:"dns_queries_total"`
	DNSBlocksTotal  int64 `json:"dns_blocks_total"`
	DLPScansTotal   int64 `json:"dlp_scans_total"`
	DLPBlocksTotal  int64 `json:"dlp_blocks_total"`
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

	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)",
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

func (s *Store) migrate(ctx context.Context) error {
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
			id                  INTEGER PRIMARY KEY CHECK (id = 1),
			dns_queries_total   INTEGER NOT NULL DEFAULT 0,
			dns_blocks_total    INTEGER NOT NULL DEFAULT 0,
			dlp_scans_total     INTEGER NOT NULL DEFAULT 0,
			dlp_blocks_total    INTEGER NOT NULL DEFAULT 0,
			last_reset_at       DATETIME DEFAULT CURRENT_TIMESTAMP
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
			return fmt.Errorf("migrate: %w (stmt=%s)", err, q[:30])
		}
	}
	if _, err := s.db.ExecContext(ctx,
		fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	return nil
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
	defaults := []CategoryPolicy{
		{Category: "AI Chat Blocked", Action: ActionDeny},
		{Category: "AI Code Blocked", Action: ActionDeny},
		{Category: "AI Allowed", Action: ActionAllow},
		{Category: "AI Chat DLP", Action: ActionAllowWithDLP},
		{Category: "Phishing", Action: ActionDeny},
		{Category: "Social", Action: ActionAllow},
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

// SetPolicy upserts the action for a category. Returns ErrInvalidAction
// when the action is not one of the supported values.
var ErrInvalidAction = errors.New("invalid action")

// SetPolicy upserts the action for a category.
func (s *Store) SetPolicy(ctx context.Context, category, action string) error {
	switch action {
	case ActionAllow, ActionAllowWithDLP, ActionDeny:
	default:
		return ErrInvalidAction
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
		SELECT dns_queries_total, dns_blocks_total, dlp_scans_total, dlp_blocks_total
		FROM aggregate_stats WHERE id = 1
	`).Scan(&st.DNSQueriesTotal, &st.DNSBlocksTotal, &st.DLPScansTotal, &st.DLPBlocksTotal)
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
			dns_queries_total = dns_queries_total + ?,
			dns_blocks_total  = dns_blocks_total  + ?,
			dlp_scans_total   = dlp_scans_total   + ?,
			dlp_blocks_total  = dlp_blocks_total  + ?
		WHERE id = 1
	`, delta.DNSQueriesTotal, delta.DNSBlocksTotal, delta.DLPScansTotal, delta.DLPBlocksTotal)
	if err != nil {
		return fmt.Errorf("add stats: %w", err)
	}
	return nil
}

// ResetStats zeroes the aggregate counters.
func (s *Store) ResetStats(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE aggregate_stats SET
			dns_queries_total = 0,
			dns_blocks_total  = 0,
			dlp_scans_total   = 0,
			dlp_blocks_total  = 0,
			last_reset_at     = CURRENT_TIMESTAMP
		WHERE id = 1
	`)
	if err != nil {
		return fmt.Errorf("reset stats: %w", err)
	}
	return nil
}
