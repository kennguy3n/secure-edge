package dlp

import "testing"

func TestValidateCandidates_NoCompiled(t *testing.T) {
	// Pattern without Compiled is silently skipped.
	p := &Pattern{Name: "x", Prefix: "AKIA", Regex: "AKIA[A-Z0-9]{16}"}
	cs := []Candidate{{Offset: 0, Pattern: p}}
	if got := ValidateCandidates("AKIAABCDEFGHIJKLMNOP", cs); len(got) != 0 {
		t.Fatalf("ValidateCandidates returned matches for uncompiled pattern: %#v", got)
	}
}

func TestValidateCandidates_RealHit(t *testing.T) {
	p := mustPattern("AWS", "AKIA", `AKIA[A-Z0-9]{16}`)
	content := "leak: AKIAABCDEFGHIJKLMNOP end"
	cs := []Candidate{{Offset: 6, Pattern: p}}
	got := ValidateCandidates(content, cs)
	if len(got) != 1 {
		t.Fatalf("ValidateCandidates returned %d matches, want 1: %#v", len(got), got)
	}
	if got[0].Value != "AKIAABCDEFGHIJKLMNOP" {
		t.Fatalf("got value %q, want %q", got[0].Value, "AKIAABCDEFGHIJKLMNOP")
	}
}

func TestValidateCandidates_NoSpuriousMatch(t *testing.T) {
	p := mustPattern("AWS", "AKIA", `AKIA[A-Z0-9]{16}`)
	cs := []Candidate{{Offset: 0, Pattern: p}}
	if got := ValidateCandidates("AKIAxxxx", cs); len(got) != 0 {
		t.Fatalf("ValidateCandidates returned %d matches for non-matching content", len(got))
	}
}

func TestValidateCandidates_DedupesByPattern(t *testing.T) {
	p := mustPattern("AWS", "AKIA", `AKIA[A-Z0-9]{16}`)
	content := "AKIA0000000000000000 and AKIA1111111111111111"
	cs := []Candidate{
		{Offset: 0, Pattern: p},
		{Offset: 25, Pattern: p}, // same pattern twice
	}
	got := ValidateCandidates(content, cs)
	if len(got) != 2 {
		t.Fatalf("want 2 dedup'd matches, got %d", len(got))
	}
}

func TestValidateCandidates_LongContentWindow(t *testing.T) {
	p := mustPattern("AWS", "AKIA", `AKIA[A-Z0-9]{16}`)
	prefix := make([]byte, regexWindow*4)
	for i := range prefix {
		prefix[i] = 'x'
	}
	content := string(prefix) + "AKIAABCDEFGHIJKLMNOP"
	offset := len(prefix)
	got := ValidateCandidates(content, []Candidate{{Offset: offset, Pattern: p}})
	if len(got) != 1 {
		t.Fatalf("expected window-bound regex to find match, got %d", len(got))
	}
}

func TestValidateCandidates_EmptyInputs(t *testing.T) {
	if got := ValidateCandidates("", nil); got != nil {
		t.Fatalf("empty inputs should yield nil, got %#v", got)
	}
	if got := ValidateCandidates("x", nil); got != nil {
		t.Fatalf("nil candidates should yield nil, got %#v", got)
	}
}

// TestValidateCandidates_PrefixlessLargeContent guards against a class
// of DLP bypass where a prefix-less pattern (e.g. SSN, credit card)
// gets hidden in long pastes — the Aho-Corasick offset is a sentinel
// (0) for prefix-less patterns, so the validator must scan the full
// content rather than a window starting at byte 0.
func TestValidateCandidates_PrefixlessLargeContent(t *testing.T) {
	p := mustPattern("SSN", "", `\d{3}-\d{2}-\d{4}`)
	// Build a paste that's well past the regexWindow*2 cutoff and
	// puts the secret far away from byte 0 so a windowed scan
	// starting at offset=0 would miss it.
	pad := make([]byte, regexWindow*4)
	for i := range pad {
		pad[i] = 'x'
	}
	content := string(pad) + "ssn 123-45-6789 end"
	got := ValidateCandidates(content, []Candidate{{Offset: 0, Pattern: p}})
	if len(got) != 1 {
		t.Fatalf("prefix-less pattern in large content: got %d matches, want 1", len(got))
	}
	if got[0].Value != "123-45-6789" {
		t.Fatalf("got value %q, want %q", got[0].Value, "123-45-6789")
	}
}
