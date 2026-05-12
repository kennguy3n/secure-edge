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
