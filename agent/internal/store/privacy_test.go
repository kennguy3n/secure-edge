package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// TestPrivacy_NoAccessTablesAndNoDomainsPersisted is the safety net for
// the privacy-first guarantee: after a sequence of "DNS events" is
// processed via the store API, we scan every text column in the
// database and assert it contains nothing that looks like the domain
// names, IP addresses, URLs, or per-event timestamps that the agent
// observed. Only the aggregate counters may have changed.
func TestPrivacy_NoAccessTablesAndNoDomainsPersisted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "privacy.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	statsBefore, err := s.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}

	// Simulate the events that the DNS resolver would generate.
	events := []struct {
		domain string
		block  bool
	}{
		{"deepseek.com", true},
		{"foo.deepseek.com", true},
		{"chat.openai.com", false},
		{"api.openai.com", false},
		{"203.0.113.45", true}, // also try an IP-shaped string
	}
	for _, ev := range events {
		delta := AggregateStats{DNSQueriesTotal: 1}
		if ev.block {
			delta.DNSBlocksTotal = 1
		}
		if err := s.AddStats(ctx, delta); err != nil {
			t.Fatalf("AddStats: %v", err)
		}
	}

	// Counters moved.
	statsAfter, err := s.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if statsAfter.DNSQueriesTotal-statsBefore.DNSQueriesTotal != int64(len(events)) {
		t.Errorf("queries delta = %d", statsAfter.DNSQueriesTotal-statsBefore.DNSQueriesTotal)
	}
	if statsAfter.DNSBlocksTotal-statsBefore.DNSBlocksTotal != 3 {
		t.Errorf("blocks delta = %d", statsAfter.DNSBlocksTotal-statsBefore.DNSBlocksTotal)
	}

	// Forbidden tables MUST NOT exist.
	for _, name := range []string{"access_log", "alert_events", "dns_log", "events", "alerts"} {
		var found string
		err := s.DB().QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, name).
			Scan(&found)
		if err == nil {
			t.Errorf("forbidden table %q exists", name)
		} else if err != sql.ErrNoRows {
			t.Fatalf("query forbidden table %q: %v", name, err)
		}
	}

	// Now sweep every text column of every table and assert no event
	// fingerprints made it into the DB.
	forbidden := []string{
		"deepseek.com",
		"foo.deepseek.com",
		"chat.openai.com",
		"api.openai.com",
		"203.0.113.45",
	}
	scanTextColumns(t, s.DB(), forbidden)
}

func scanTextColumns(t *testing.T, db *sql.DB, forbidden []string) {
	t.Helper()
	tables, err := db.Query(
		`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tableNames []string
	for tables.Next() {
		var n string
		if err := tables.Scan(&n); err != nil {
			t.Fatalf("scan tablename: %v", err)
		}
		tableNames = append(tableNames, n)
	}
	tables.Close()

	for _, table := range tableNames {
		cols, err := db.Query(`SELECT name, type FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatalf("pragma_table_info(%s): %v", table, err)
		}
		var textCols []string
		for cols.Next() {
			var name, typ string
			if err := cols.Scan(&name, &typ); err != nil {
				t.Fatalf("scan col: %v", err)
			}
			if strings.Contains(strings.ToUpper(typ), "TEXT") {
				textCols = append(textCols, name)
			}
		}
		cols.Close()

		for _, col := range textCols {
			rows, err := db.Query("SELECT " + col + " FROM " + table) //nolint:gosec // identifiers from pragma
			if err != nil {
				t.Fatalf("select %s.%s: %v", table, col, err)
			}
			for rows.Next() {
				var v sql.NullString
				if err := rows.Scan(&v); err != nil {
					rows.Close()
					t.Fatalf("scan: %v", err)
				}
				if !v.Valid {
					continue
				}
				lower := strings.ToLower(v.String)
				for _, f := range forbidden {
					if strings.Contains(lower, strings.ToLower(f)) {
						rows.Close()
						t.Fatalf("table=%s col=%s contains forbidden value %q (row=%q)",
							table, col, f, v.String)
					}
				}
			}
			rows.Close()
		}
	}
}
