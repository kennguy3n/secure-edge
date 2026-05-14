package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestIsNativeMessagingArgv(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"empty", nil, false},
		{"no extension origin", []string{"--config", "config.yaml"}, false},
		{"chrome extension origin", []string{"chrome-extension://abcdefghijklmnopabcdefghijklmnop/"}, true},
		{"firefox extension origin", []string{"moz-extension://01234567-89ab-cdef-0123-456789abcdef/"}, true},
		{"firefox windows extra arg", []string{"moz-extension://01234567-89ab-cdef-0123-456789abcdef/", "secure-edge@example.com"}, true},
		{"unrelated url", []string{"https://example.com"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNativeMessagingArgv(tc.args); got != tc.want {
				t.Errorf("isNativeMessagingArgv(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestValidateRulesAlignment(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()

	t.Run("everything inside rules_dir", func(t *testing.T) {
		err := validateRulesAlignment(dir,
			[]string{filepath.Join(dir, "ai_chat_blocked.txt"), filepath.Join(dir, "phishing.txt")},
			filepath.Join(dir, "dlp_patterns.json"),
			filepath.Join(dir, "dlp_exclusions.json"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rule_paths outside rules_dir", func(t *testing.T) {
		err := validateRulesAlignment(dir,
			[]string{filepath.Join(other, "phishing.txt")},
			filepath.Join(dir, "dlp_patterns.json"), "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "rule_paths entry") {
			t.Errorf("error should name the offending field: %v", err)
		}
	})

	t.Run("dlp_patterns outside rules_dir", func(t *testing.T) {
		err := validateRulesAlignment(dir, nil,
			filepath.Join(other, "dlp_patterns.json"), "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "dlp_patterns") {
			t.Errorf("error should name the offending field: %v", err)
		}
	})

	t.Run("dlp_exclusions outside rules_dir", func(t *testing.T) {
		err := validateRulesAlignment(dir, nil,
			filepath.Join(dir, "dlp_patterns.json"),
			filepath.Join(other, "dlp_exclusions.json"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "dlp_exclusions") {
			t.Errorf("error should name the offending field: %v", err)
		}
	})

	t.Run("blank optional dlp paths are allowed", func(t *testing.T) {
		if err := validateRulesAlignment(dir,
			[]string{filepath.Join(dir, "phishing.txt")}, "", ""); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("trailing slash on rules_dir is normalised", func(t *testing.T) {
		if err := validateRulesAlignment(dir+string(filepath.Separator),
			[]string{filepath.Join(dir, "phishing.txt")},
			filepath.Join(dir, "dlp_patterns.json"), ""); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("subdirectory of rules_dir is rejected", func(t *testing.T) {
		// rule files must be direct children: rulesDir/foo.txt, not
		// rulesDir/sub/foo.txt — the updater downloads to the former
		// only.
		err := validateRulesAlignment(dir,
			[]string{filepath.Join(dir, "sub", "phishing.txt")}, "", "")
		if err == nil {
			t.Fatal("expected error for nested file, got nil")
		}
	})
}

func TestCategoryFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"rules/ai_chat_blocked.txt", "AI Chat Blocked"},
		{"rules/ai_code_blocked.txt", "AI Code Blocked"},
		{"rules/ai_allowed.txt", "AI Allowed"},
		{"rules/ai_chat_dlp.txt", "AI Chat DLP"},
		{"rules/phishing.txt", "Phishing"},
		{"rules/social.txt", "Social"},
		{"rules\\ai_allowed.txt", "AI Allowed"},
		{"ai-chat-dlp.txt", "AI Chat DLP"},
		{"AI_Chat_DLP.txt", "AI Chat DLP"},
		{"plain", "Plain"},
	}
	for _, tc := range cases {
		got := categoryFromPath(tc.path)
		if got != tc.want {
			t.Errorf("categoryFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestOrphanedRulePublicKeyWarning covers the misconfiguration
// nudge that fires when an operator sets `rule_update_public_key`
// but leaves `rule_update_url` empty. Reviewers flagged the silent-
// ignore on PR #20 as an operator footgun: a partial rollout
// (deploy the key first, plumb the URL second) would leave the
// signature verification code path inert with no visible signal.
//
// The helper is pure (returns the warning message, or "") so the
// real test surface stays decoupled from os.Stderr and the rest
// of run().
func TestOrphanedRulePublicKeyWarning(t *testing.T) {
	const wellFormedKey = "00112233445566778899aabbccddeeff" +
		"00112233445566778899aabbccddeeff"

	cases := []struct {
		name string
		url  string
		key  string
		want string // "" means no warning
	}{
		{
			name: "both empty: no warning",
			url:  "",
			key:  "",
			want: "",
		},
		{
			name: "url set, key empty: no warning",
			url:  "https://example.com/manifest.json",
			key:  "",
			want: "",
		},
		{
			name: "both set: well-formed rollout, no warning",
			url:  "https://example.com/manifest.json",
			key:  wellFormedKey,
			want: "",
		},
		{
			name: "url empty, key set: WARN (this is the case the helper exists for)",
			url:  "",
			key:  wellFormedKey,
			want: "agent: rule_update_public_key is set but rule_update_url is empty; " +
				"the configured key will be ignored. Set rule_update_url to enable signature verification, " +
				"or remove rule_update_public_key to silence this warning.",
		},
		{
			name: "url empty, key is whitespace-only: treat as unset, no warning",
			url:  "",
			key:  "   \t\n  ",
			want: "",
		},
		{
			name: "url empty, key has surrounding whitespace: still warn (matches trimmed-decode path)",
			url:  "",
			key:  "   " + wellFormedKey + "   ",
			want: "agent: rule_update_public_key is set but rule_update_url is empty; " +
				"the configured key will be ignored. Set rule_update_url to enable signature verification, " +
				"or remove rule_update_public_key to silence this warning.",
		},
		{
			name: "url set, key whitespace-only: no warning (mirror of the no-rollout case)",
			url:  "https://example.com/manifest.json",
			key:  "   ",
			want: "",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := orphanedRulePublicKeyWarning(tc.url, tc.key)
			if got != tc.want {
				t.Fatalf("orphanedRulePublicKeyWarning(%q, %q):\n  got:  %q\n  want: %q",
					tc.url, tc.key, got, tc.want)
			}
		})
	}
}
