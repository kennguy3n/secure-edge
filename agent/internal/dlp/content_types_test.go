// Tests for the Pattern.ContentTypes wiring that hooks the
// ClassifyContent verdict into filterCandidates. The mechanism is
// defense-in-depth: patterns with a non-empty ContentTypes list are
// dropped at the AC filter step when ClassifyContent returns a verdict
// not in the list. Patterns with an empty ContentTypes list continue
// to match every classification (backwards compatible).
//
// These tests intentionally use a tiny inline pattern set rather than
// the production rules/dlp_patterns.json so the assertions stay
// independent of any specific real-world pattern's tagging.

package dlp

import (
	"context"
	"testing"
)

// contentTypePipeline builds a pipeline whose pattern set spans the
// three interesting cases:
//
//   - a code-scoped pattern (ContentTypes=["code"]) — should fire on
//     source code, must NOT fire on prose or env-style credentials.
//   - a structured-scoped pattern (ContentTypes=["structured"]).
//   - an untagged pattern (ContentTypes=nil) — must fire regardless of
//     classification.
//
// Hotwords are widened and require_hotword is false so the assertions
// here measure the classifier filter and nothing else.
func contentTypePipeline(t testing.TB) *Pipeline {
	t.Helper()
	patternsJSON := []byte(`{
"patterns": [
  {
    "name": "Code-Scoped Demo Token",
    "regex": "CODEDEMO[A-Z0-9]{20}",
    "prefix": "CODEDEMO",
    "severity": "critical",
    "score_weight": 1,
    "hotwords": ["demo", "secret"],
    "hotword_window": 400,
    "hotword_boost": 2,
    "require_hotword": false,
    "entropy_min": 0,
    "category": "test_code_only",
    "content_types": ["code"]
  },
  {
    "name": "Structured-Scoped Demo Token",
    "regex": "STRUCTDEMO[A-Z0-9]{20}",
    "prefix": "STRUCTDEMO",
    "severity": "critical",
    "score_weight": 1,
    "hotwords": ["demo", "secret"],
    "hotword_window": 400,
    "hotword_boost": 2,
    "require_hotword": false,
    "entropy_min": 0,
    "category": "test_structured_only",
    "content_types": ["structured"]
  },
  {
    "name": "Any-Type Demo Token",
    "regex": "ANYDEMO[A-Z0-9]{20}",
    "prefix": "ANYDEMO",
    "severity": "critical",
    "score_weight": 1,
    "hotwords": ["demo", "secret"],
    "hotword_window": 400,
    "hotword_boost": 2,
    "require_hotword": false,
    "entropy_min": 0,
    "category": "test_any"
  }
]
}`)

	patterns, err := ParsePatterns(patternsJSON)
	if err != nil {
		t.Fatalf("ParsePatterns: %v", err)
	}

	p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(DefaultThresholds()))
	p.Rebuild(patterns, nil)
	return p
}

// codeContext is a Java source-file snippet that the classifier should
// report as CodeContent (≥2 import/class/package lines).
const codeContext = `package com.example.demo;

import java.util.List;
import java.util.Map;

public class DemoService {
    private final String demoSecret = "CODEDEMOABCDEFGHIJKLMNOPQRST";
    private final String anyMarker  = "ANYDEMOABCDEFGHIJKLMNOPQRST";
    private final String structMark = "STRUCTDEMOABCDEFGHIJKLMNOPQRST";
}`

// structuredContext is a JSON blob that the classifier should report
// as StructuredData (contains { and } and the "key": pattern).
const structuredContext = `{
  "demo": "secret",
  "code_token": "CODEDEMOABCDEFGHIJKLMNOPQRST",
  "struct_token": "STRUCTDEMOABCDEFGHIJKLMNOPQRST",
  "any_token": "ANYDEMOABCDEFGHIJKLMNOPQRST"
}`

// naturalContext is plain English prose with no code or structured
// markers — should classify as NaturalLanguage.
const naturalContext = "Here is the demo secret string CODEDEMOABCDEFGHIJKLMNOPQRST " +
	"alongside STRUCTDEMOABCDEFGHIJKLMNOPQRST and ANYDEMOABCDEFGHIJKLMNOPQRST " +
	"embedded in this paragraph of ordinary English text that has many spaces " +
	"and ordinary words and sentences ending in periods."

func TestContentTypes_CodeScopedFiresOnCode(t *testing.T) {
	if ct := ClassifyContent(codeContext); ct != CodeContent {
		t.Fatalf("test fixture invariant: codeContext classified as %q, want %q", ct, CodeContent)
	}
	p := contentTypePipeline(t)

	res := p.Scan(context.Background(), codeContext)
	if !res.Blocked {
		t.Fatalf("expected a block on code context, got %+v", res)
	}
	// Either code-scoped or any-type can win; both are valid TPs here.
	switch res.PatternName {
	case "Code-Scoped Demo Token", "Any-Type Demo Token":
		// ok
	default:
		t.Fatalf("unexpected winning pattern %q", res.PatternName)
	}
}

func TestContentTypes_CodeScopedDoesNotFireOnProse(t *testing.T) {
	if ct := ClassifyContent(naturalContext); ct != NaturalLanguage {
		t.Fatalf("test fixture invariant: naturalContext classified as %q, want %q", ct, NaturalLanguage)
	}
	p := contentTypePipeline(t)

	// The code-scoped pattern shape is present in the prose, but the
	// classifier filter must drop the candidate before regex/scoring.
	// Disable the untagged "Any-Type Demo Token" so it cannot rescue
	// the block — we want to observe that the code-scoped pattern by
	// itself is suppressed.
	original := p.Patterns()
	filtered := make([]*Pattern, 0, len(original))
	for _, pat := range original {
		if pat.Name == "Any-Type Demo Token" || pat.Name == "Structured-Scoped Demo Token" {
			continue
		}
		filtered = append(filtered, pat)
	}
	p.Rebuild(filtered, nil)

	res := p.Scan(context.Background(), naturalContext)
	if res.Blocked {
		t.Fatalf("code-scoped pattern must not fire on prose, got %+v", res)
	}
}

func TestContentTypes_StructuredScopedDoesNotFireOnCode(t *testing.T) {
	if ct := ClassifyContent(codeContext); ct != CodeContent {
		t.Fatalf("test fixture invariant: codeContext classified as %q, want %q", ct, CodeContent)
	}
	p := contentTypePipeline(t)

	// Drop the code-scoped + any-type patterns so the only candidate
	// reaching the AC is the structured-scoped one.
	original := p.Patterns()
	filtered := make([]*Pattern, 0, len(original))
	for _, pat := range original {
		if pat.Name == "Structured-Scoped Demo Token" {
			filtered = append(filtered, pat)
		}
	}
	p.Rebuild(filtered, nil)

	res := p.Scan(context.Background(), codeContext)
	if res.Blocked {
		t.Fatalf("structured-scoped pattern must not fire on code, got %+v", res)
	}
}

func TestContentTypes_AnyTypeFiresEverywhere(t *testing.T) {
	p := contentTypePipeline(t)

	// Keep only the untagged "Any-Type Demo Token" so the other two
	// scoped patterns cannot mask the assertion.
	original := p.Patterns()
	filtered := make([]*Pattern, 0, len(original))
	for _, pat := range original {
		if pat.Name == "Any-Type Demo Token" {
			filtered = append(filtered, pat)
		}
	}
	p.Rebuild(filtered, nil)

	cases := []struct {
		label   string
		content string
		wantCT  ContentType
	}{
		{"code", codeContext, CodeContent},
		{"structured", structuredContext, StructuredData},
		{"natural", naturalContext, NaturalLanguage},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			if ct := ClassifyContent(tc.content); ct != tc.wantCT {
				t.Fatalf("fixture %q classified as %q, want %q", tc.label, ct, tc.wantCT)
			}
			res := p.Scan(context.Background(), tc.content)
			if !res.Blocked {
				t.Fatalf("untagged pattern must fire on %s, got %+v", tc.label, res)
			}
			if res.PatternName != "Any-Type Demo Token" {
				t.Fatalf("unexpected pattern %q", res.PatternName)
			}
		})
	}
}

func TestContentTypes_LoaderParsesField(t *testing.T) {
	raw := []byte(`{"patterns": [
  {
    "name": "P1",
    "regex": "ABCDEF[A-Z]{10}",
    "prefix": "ABCDEF",
    "severity": "critical",
    "score_weight": 1,
    "hotwords": [],
    "hotword_window": 0,
    "hotword_boost": 0,
    "require_hotword": false,
    "entropy_min": 0,
    "content_types": ["code", "structured"]
  },
  {
    "name": "P2",
    "regex": "GHIJKL[A-Z]{10}",
    "prefix": "GHIJKL",
    "severity": "critical",
    "score_weight": 1,
    "hotwords": [],
    "hotword_window": 0,
    "hotword_boost": 0,
    "require_hotword": false,
    "entropy_min": 0
  }
]}`)
	pats, err := ParsePatterns(raw)
	if err != nil {
		t.Fatalf("ParsePatterns: %v", err)
	}
	if len(pats) != 2 {
		t.Fatalf("got %d patterns, want 2", len(pats))
	}
	if got := pats[0].ContentTypes; len(got) != 2 || got[0] != CodeContent || got[1] != StructuredData {
		t.Fatalf("P1.ContentTypes = %v, want [code structured]", got)
	}
	if len(pats[1].ContentTypes) != 0 {
		t.Fatalf("P2.ContentTypes = %v, want empty/nil", pats[1].ContentTypes)
	}
}

func TestFilterCandidates_RespectsContentTypeAndPreservesCategoryFilter(t *testing.T) {
	patternsJSON := []byte(`{"patterns": [
  {
    "name": "P-code",
    "regex": "PCODE[A-Z0-9]{10}",
    "prefix": "PCODE",
    "severity": "high",
    "score_weight": 1,
    "hotwords": [],
    "hotword_window": 0,
    "hotword_boost": 0,
    "require_hotword": false,
    "entropy_min": 0,
    "category": "demo_code",
    "content_types": ["code"]
  },
  {
    "name": "P-any-low",
    "regex": "PLOW[A-Z0-9]{10}",
    "prefix": "PLOW",
    "severity": "low",
    "score_weight": 1,
    "hotwords": [],
    "hotword_window": 0,
    "hotword_boost": 0,
    "require_hotword": false,
    "entropy_min": 0,
    "category": "demo_low"
  }
]}`)
	pats, err := ParsePatterns(patternsJSON)
	if err != nil {
		t.Fatalf("ParsePatterns: %v", err)
	}
	auto := BuildAutomaton(pats)

	// filterCandidates reuses the backing array (in[:0]) so each
	// scenario calls auto.Scan again to get a fresh candidate slice.
	// Feeds AC a content blob that hits both prefixes, then exercises
	// the classifier filter, the large-content severity filter, and
	// the disabledCategories set.
	mix := "PCODEAAAAAAAAAA PLOWBBBBBBBBBB"

	// Case 1: NaturalLanguage drops the code-scoped pattern; the
	// untagged P-any-low survives.
	out := filterCandidates(auto.Scan(mix), len(mix), 1<<30, nil, NaturalLanguage)
	names := candidateNames(out)
	if contains(names, "P-code") {
		t.Fatalf("expected P-code dropped under NaturalLanguage, got %v", names)
	}
	if !contains(names, "P-any-low") {
		t.Fatalf("expected P-any-low preserved under NaturalLanguage, got %v", names)
	}

	// Case 2: CodeContent keeps both.
	out = filterCandidates(auto.Scan(mix), len(mix), 1<<30, nil, CodeContent)
	names = candidateNames(out)
	if !contains(names, "P-code") || !contains(names, "P-any-low") {
		t.Fatalf("expected both candidates under CodeContent, got %v", names)
	}

	// Case 3: "Large" payload drops low-severity (P-any-low) even
	// though the code-scoped is allowed.
	out = filterCandidates(auto.Scan(mix), 1, 1, nil, CodeContent)
	names = candidateNames(out)
	if contains(names, "P-any-low") {
		t.Fatalf("expected P-any-low dropped on large content, got %v", names)
	}

	// Case 4: disabledCategories drops by category regardless of
	// classifier verdict.
	disabled := map[string]struct{}{"demo_code": {}}
	out = filterCandidates(auto.Scan(mix), len(mix), 1<<30, disabled, CodeContent)
	names = candidateNames(out)
	if contains(names, "P-code") {
		t.Fatalf("expected P-code dropped via disabledCategories, got %v", names)
	}

	// Case 5: empty contentType (e.g. classifier disabled at the
	// call site) must NOT drop ContentTypes-tagged patterns —
	// backwards compatible behaviour for callers that bypass the
	// classifier.
	out = filterCandidates(auto.Scan(mix), len(mix), 1<<30, nil, ContentType(""))
	names = candidateNames(out)
	if !contains(names, "P-code") || !contains(names, "P-any-low") {
		t.Fatalf("expected both candidates with empty contentType, got %v", names)
	}
}

// TestContentTypes_LoaderRejectsUnknownValue locks the contract that
// ParsePatterns refuses to load a pattern whose content_types contains
// a value that is not one of the four ContentType constants. The risk
// the validation defends against: a misspelled or wrong-case value
// like "Code" or "natual" would deserialise into a string that never
// matches any ClassifyContent verdict, which would silently disable
// the owning pattern for every scan instead of failing loudly. The
// behaviour is part of the loader's API and any change here is a
// rule-format change that needs to be deliberate.
func TestContentTypes_LoaderRejectsUnknownValue(t *testing.T) {
	cases := []struct {
		label string
		body  string
	}{
		{
			label: "wrong case",
			body: `{"patterns":[{"name":"P","regex":"A[A-Z]{5}",` +
				`"prefix":"A","severity":"low","score_weight":1,` +
				`"hotwords":[],"hotword_window":0,"hotword_boost":0,` +
				`"require_hotword":false,"entropy_min":0,` +
				`"content_types":["Code"]}]}`,
		},
		{
			label: "typo",
			body: `{"patterns":[{"name":"P","regex":"A[A-Z]{5}",` +
				`"prefix":"A","severity":"low","score_weight":1,` +
				`"hotwords":[],"hotword_window":0,"hotword_boost":0,` +
				`"require_hotword":false,"entropy_min":0,` +
				`"content_types":["natual"]}]}`,
		},
		{
			label: "mixed valid+invalid",
			body: `{"patterns":[{"name":"P","regex":"A[A-Z]{5}",` +
				`"prefix":"A","severity":"low","score_weight":1,` +
				`"hotwords":[],"hotword_window":0,"hotword_boost":0,` +
				`"require_hotword":false,"entropy_min":0,` +
				`"content_types":["code","credentialz"]}]}`,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			pats, err := ParsePatterns([]byte(tc.body))
			if err == nil {
				t.Fatalf("expected ParsePatterns to fail on %q, got patterns=%+v", tc.label, pats)
			}
		})
	}
}

// TestContentTypes_PipelineSkipsClassifierWhenNoPatternTagged guards
// the fast-path optimisation: when no loaded pattern has a non-empty
// ContentTypes, Pipeline.Rebuild precomputes hasContentTypeFilter as
// false and Scan must skip ClassifyContent entirely. The contract we
// pin here is the externally visible one: an untagged pattern fires
// on prose content (which the classifier would label NaturalLanguage)
// exactly as it did before the wiring landed. The "skipped" part is
// not directly observable from outside the pipeline, but the
// behaviour assertion is the one that actually matters for
// correctness, and the unit test for filterCandidates above already
// covers the contentType=="" sentinel path.
func TestContentTypes_PipelineSkipsClassifierWhenNoPatternTagged(t *testing.T) {
	raw := []byte(`{"patterns":[
{"name":"Untagged Demo","regex":"UNTAGDEMO[A-Z0-9]{15}","prefix":"UNTAGDEMO",
 "severity":"critical","score_weight":1,"hotwords":[],"hotword_window":0,
 "hotword_boost":0,"require_hotword":false,"entropy_min":0}
]}`)
	pats, err := ParsePatterns(raw)
	if err != nil {
		t.Fatalf("ParsePatterns: %v", err)
	}
	p := NewPipeline(DefaultScoreWeights(), nil)
	p.Rebuild(pats, nil)
	prose := "Yesterday afternoon we caught an UNTAGDEMOABCDEFGHIJKLMNO " +
		"floating in the activity feed of the platform; please rotate it."
	if ct := ClassifyContent(prose); ct != NaturalLanguage {
		t.Fatalf("fixture classified as %q, want natural", ct)
	}
	res := p.Scan(context.Background(), prose)
	if !res.Blocked {
		t.Fatalf("untagged pattern must fire on prose with hasContentTypeFilter=false, got %+v", res)
	}
}

// TestContentTypes_MixedContentDocumentsTradeoff pins the known
// limitation of the document-level classifier raised in the PR #41
// review: ClassifyContent operates on the whole content string, so a
// pattern scoped to ContentTypes=["structured"] is dropped when the
// dominant content shape is natural-language prose even though the
// pattern's regex matches a substring of it. The test exists so the
// tradeoff is visible to future contributors and so any change to it
// (e.g. a future window-based classifier) is deliberate.
//
// Note for production-pattern authors: the classifier's looksLikeJSON
// check fires on any document that contains both `{` and `}` plus a
// `":` token, so paste-style patterns whose own regex captures the
// surrounding JSON braces (AWS Secrets Manager SecretString, Azure
// Key Vault GetSecret, GCR JSON key, …) effectively force the
// document to classify as structured by virtue of their own match —
// the FN documented here only bites patterns whose regex does NOT
// require enclosing JSON shape, which is why the W2 PR shipped with
// the structured-scoped paste patterns un-tagged.
func TestContentTypes_MixedContentDocumentsTradeoff(t *testing.T) {
	patternsJSON := []byte(`{"patterns":[
{"name":"Structured-Only Demo","regex":"MIXDEMO[A-Z0-9]{12}","prefix":"MIXDEMO",
 "severity":"critical","score_weight":1,"hotwords":[],"hotword_window":400,
 "hotword_boost":2,"require_hotword":false,"entropy_min":0,
 "content_types":["structured"]}
]}`)
	pats, err := ParsePatterns(patternsJSON)
	if err != nil {
		t.Fatalf("ParsePatterns: %v", err)
	}
	p := NewPipeline(DefaultScoreWeights(), nil)
	p.Rebuild(pats, nil)

	purelyStructured := `{"token": "MIXDEMOABCDEF123456", "scope": "prod"}`
	if ct := ClassifyContent(purelyStructured); ct != StructuredData {
		t.Fatalf("pure JSON classified as %q, want structured", ct)
	}
	if res := p.Scan(context.Background(), purelyStructured); !res.Blocked {
		t.Fatalf("structured-scoped pattern must fire on pure JSON, got %+v", res)
	}

	// The fixture below is deliberately a prose paragraph that
	// quotes the token without enclosing JSON braces or any `":`
	// sequence, so looksLikeJSON, looksLikeCSV, and the kv-line gate
	// all decline and ClassifyContent falls through to
	// NaturalLanguage. Adding `{`, `}`, or `":` here would flip the
	// verdict to structured and the FN below would no longer
	// reproduce.
	mixed := "Hello team. During the migration window today we noticed " +
		"an unexpected error from the upstream rotation service. The " +
		"on-call engineer shared the token (MIXDEMOABCDEF123456) from " +
		"the incident ticket; please verify it lands in vault before " +
		"we close the bridge. Let me know once you have rotated it."
	if ct := ClassifyContent(mixed); ct != NaturalLanguage {
		t.Fatalf("mixed-content fixture classified as %q, want natural "+
			"(test depends on this so the FN documented below is observable)", ct)
	}
	res := p.Scan(context.Background(), mixed)
	if res.Blocked {
		t.Fatalf("documented tradeoff: structured-scoped pattern is "+
			"DROPPED in a prose-dominant document, but Scan returned "+
			"Blocked=true with %+v — either the classifier got smarter "+
			"or the filterCandidates contract changed; revisit which "+
			"production patterns are tagged ['structured'] in light of "+
			"the new behaviour", res)
	}
}

func candidateNames(cs []Candidate) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		if c.Pattern == nil {
			continue
		}
		out = append(out, c.Pattern.Name)
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

