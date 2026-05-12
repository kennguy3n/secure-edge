package main

import "testing"

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
