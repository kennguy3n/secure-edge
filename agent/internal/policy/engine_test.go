package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kennguy3n/secure-edge/agent/internal/rules"
	"github.com/kennguy3n/secure-edge/agent/internal/store"
)

func newTestEnv(t *testing.T) (*store.Store, []rules.RuleSource) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	chatBlocked := filepath.Join(dir, "chat_blocked.txt")
	if err := os.WriteFile(chatBlocked, []byte(".deepseek.com\n"), 0o600); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	chatDLP := filepath.Join(dir, "chat_dlp.txt")
	if err := os.WriteFile(chatDLP, []byte(".chat.openai.com\n"), 0o600); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	allowed := filepath.Join(dir, "allowed.txt")
	if err := os.WriteFile(allowed, []byte(".api.openai.com\n"), 0o600); err != nil {
		t.Fatalf("write rule: %v", err)
	}

	sources := []rules.RuleSource{
		{Category: "AI Chat Blocked", Path: chatBlocked},
		{Category: "AI Chat DLP", Path: chatDLP},
		{Category: "AI Allowed", Path: allowed},
	}
	return s, sources
}

func TestEngineActions(t *testing.T) {
	s, sources := newTestEnv(t)
	e, err := New(s, sources)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		domain string
		want   Action
	}{
		{"deepseek.com", Deny},
		{"foo.deepseek.com", Deny},
		{"chat.openai.com", AllowWithDLP},
		{"api.openai.com", Allow},
		{"unrelated.example.com", DefaultAction},
		{"", DefaultAction},
	}
	for _, c := range cases {
		if got := e.CheckDomain(c.domain); got != c.want {
			t.Errorf("CheckDomain(%q) = %q, want %q", c.domain, got, c.want)
		}
	}
}

func TestEngineReloadPicksUpPolicyChange(t *testing.T) {
	s, sources := newTestEnv(t)
	e, err := New(s, sources)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := e.CheckDomain("foo.deepseek.com"); got != Deny {
		t.Fatalf("initial = %q", got)
	}

	ctx := context.Background()
	if err := s.SetPolicy(ctx, "AI Chat Blocked", store.ActionAllow); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if got := e.CheckDomain("foo.deepseek.com"); got != Deny {
		t.Fatalf("before reload = %q (cached)", got)
	}
	if err := e.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := e.CheckDomain("foo.deepseek.com"); got != Allow {
		t.Fatalf("after reload = %q, want %q", got, Allow)
	}
}

func TestEngineSetSourcesAndReload(t *testing.T) {
	s, sources := newTestEnv(t)
	e, err := New(s, sources)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	dir := t.TempDir()
	swapped := filepath.Join(dir, "swap.txt")
	if err := os.WriteFile(swapped, []byte(".badnewdomain.com\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	e.SetSources([]rules.RuleSource{{Category: "AI Chat Blocked", Path: swapped}})
	if err := e.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := e.CheckDomain("foo.deepseek.com"); got != DefaultAction {
		t.Fatalf("old rule still active: %q", got)
	}
	if got := e.CheckDomain("foo.badnewdomain.com"); got != Deny {
		t.Fatalf("new rule not active: %q", got)
	}
}
