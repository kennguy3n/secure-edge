// Candidate-only regex validation (pipeline step 3).
//
// For each (offset, pattern) candidate emitted by the Aho-Corasick
// scanner we run only that pattern's compiled regex on a bounded
// window around the offset. This keeps regex work O(candidates) instead
// of O(content_length × patterns).

package dlp

import "regexp"

// regexWindow is the byte radius around each Aho-Corasick candidate
// over which the per-pattern regex is run. The constant is generous so
// that patterns whose regex matches material both before and after the
// prefix (e.g. "api_key = AKIA...") still hit, while staying far below
// "scan the whole content" cost.
const regexWindow = 1024

// ValidateCandidates runs each candidate pattern's compiled regex over
// a window around its Aho-Corasick offset and returns deduplicated
// Match results. Patterns whose Compiled field is nil are silently
// skipped — callers are expected to have run LoadPatterns first.
//
// Match values reference the original content slice and must NOT be
// persisted; they live only for the duration of the scan call.
func ValidateCandidates(content string, candidates []Candidate) []Match {
	if content == "" || len(candidates) == 0 {
		return nil
	}
	// Run each pattern's regex at most once per scan so that a
	// pattern with multiple Aho-Corasick hits (e.g. several emails)
	// doesn't generate duplicate Match values.
	seenPattern := make(map[*Pattern]bool)
	var out []Match
	for _, cand := range candidates {
		if cand.Pattern == nil || cand.Pattern.Compiled == nil {
			continue
		}
		if seenPattern[cand.Pattern] {
			continue
		}
		seenPattern[cand.Pattern] = true

		var ms [][]int
		if cand.Pattern.Prefix == "" {
			// Prefix-less patterns (e.g. SSN, credit card) have no
			// real Aho-Corasick offset; cand.Offset is a sentinel.
			// Scan the entire content so we don't miss matches past
			// the regexWindow boundary.
			ms = cand.Pattern.Compiled.FindAllStringIndex(content, -1)
		} else {
			ms = findAllInWindow(content, cand.Pattern.Compiled, cand.Offset)
		}
		if len(ms) == 0 {
			continue
		}
		for _, m := range ms {
			out = append(out, Match{
				Pattern: cand.Pattern,
				Start:   m[0],
				End:     m[1],
				Value:   content[m[0]:m[1]],
			})
		}
	}
	return out
}

// findAllInWindow finds all matches of re over content, biased to a
// window around offset. When the window would cover the whole content,
// we just scan the full content. This is still O(n) per call but
// avoids missing matches that span the window boundary.
//
// Callers must invoke this only for prefixed patterns. Prefix-less
// patterns have no real Aho-Corasick offset (the sentinel 0 is not a
// location) and must be scanned over the full content directly.
func findAllInWindow(content string, re *regexp.Regexp, offset int) [][]int {
	if len(content) <= regexWindow*2 {
		return re.FindAllStringIndex(content, -1)
	}

	start := offset - regexWindow
	if start < 0 {
		start = 0
	}
	end := offset + regexWindow
	if end > len(content) {
		end = len(content)
	}
	window := content[start:end]
	rel := re.FindAllStringIndex(window, -1)
	if len(rel) == 0 {
		return nil
	}
	abs := make([][]int, 0, len(rel))
	for _, m := range rel {
		abs = append(abs, []int{m[0] + start, m[1] + start})
	}
	return abs
}
