package main

import "testing"

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
