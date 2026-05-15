// Pattern / exclusion loader.
//
// Reads rules/dlp_patterns.json and rules/dlp_exclusions.json from disk
// and returns slices ready to feed into Pipeline.Rebuild. Failure to
// compile a regex aborts the load — corrupted rule files should fail
// loudly rather than silently disabling patterns.

package dlp

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// LoadPatterns reads patterns from path and compiles each pattern's
// regex. The slice is shared by the Aho-Corasick scanner and the regex
// validator — every Pattern.Compiled is non-nil on return.
func LoadPatterns(path string) ([]*Pattern, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dlp: read patterns: %w", err)
	}
	return ParsePatterns(raw)
}

// ParsePatterns is the in-memory equivalent of LoadPatterns.
func ParsePatterns(raw []byte) ([]*Pattern, error) {
	var body struct {
		Patterns []*Pattern `json:"patterns"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("dlp: parse patterns: %w", err)
	}
	for _, p := range body.Patterns {
		if p == nil {
			continue
		}
		if p.Regex == "" {
			return nil, fmt.Errorf("dlp: pattern %q has empty regex", p.Name)
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("dlp: compile %q: %w", p.Name, err)
		}
		p.Compiled = re
		if p.Category == "" {
			p.Category = CategoryUncategorized
		}
		for _, ct := range p.ContentTypes {
			if !isKnownContentType(ct) {
				return nil, fmt.Errorf(
					"dlp: pattern %q: unknown content_type %q "+
						"(must be one of %q, %q, %q, %q)",
					p.Name, ct,
					CodeContent, StructuredData,
					CredentialsBlock, NaturalLanguage,
				)
			}
		}
	}
	return body.Patterns, nil
}

// isKnownContentType reports whether ct is one of the four classifier
// verdicts. ContentTypes is parsed from JSON, so a typo like "Code" or
// "natual" would deserialise cleanly into a string that never matches
// any classifier output and silently disables the owning pattern for
// every scan. We reject such values at load time instead so misspelled
// content_types fail loudly.
func isKnownContentType(ct ContentType) bool {
	switch ct {
	case CodeContent, StructuredData, CredentialsBlock, NaturalLanguage:
		return true
	default:
		return false
	}
}

// LoadExclusions reads exclusions from path and compiles each regex
// exclusion. Dictionary exclusions need no compilation.
func LoadExclusions(path string) ([]Exclusion, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dlp: read exclusions: %w", err)
	}
	return ParseExclusions(raw)
}

// ParseExclusions is the in-memory equivalent of LoadExclusions.
func ParseExclusions(raw []byte) ([]Exclusion, error) {
	var body struct {
		Exclusions []Exclusion `json:"exclusions"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("dlp: parse exclusions: %w", err)
	}
	for i := range body.Exclusions {
		x := &body.Exclusions[i]
		if x.Type == ExclusionRegex {
			if x.Pattern == "" {
				return nil, fmt.Errorf("dlp: regex exclusion for %q has empty pattern", x.AppliesTo)
			}
			re, err := regexp.Compile(x.Pattern)
			if err != nil {
				return nil, fmt.Errorf("dlp: compile exclusion %q: %w", x.AppliesTo, err)
			}
			x.Compiled = re
		}
	}
	return body.Exclusions, nil
}
