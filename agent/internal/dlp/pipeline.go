// DLP pipeline orchestrator.
//
// The Pipeline owns the compiled patterns, exclusions, Aho-Corasick
// automaton, scoring weights, and threshold engine. Scan(content) runs
// every step from classification through the threshold check and
// returns the final block decision plus the pattern responsible.
//
// Privacy invariant: the only state held by Pipeline that depends on
// the scanned content is local to Scan — it returns to the caller and
// is then garbage-collected. Nothing about the scanned content is
// persisted to disk or logged.

package dlp

import (
	"context"
	"sync"
)

// ScanResult is what Pipeline.Scan returns. PatternName is empty when
// Blocked is false. Score is the highest score across all matches.
type ScanResult struct {
	Blocked     bool   `json:"blocked"`
	PatternName string `json:"pattern_name"`
	Score       int    `json:"score"`
}

// Pipeline ties all the DLP pipeline steps together.
type Pipeline struct {
	mu sync.RWMutex

	patterns   []*Pattern
	automaton  *Automaton
	exclusions []Exclusion
	weights    ScoreWeights
	threshold  *ThresholdEngine
}

// NewPipeline returns an empty pipeline. Callers must call Rebuild
// before Scan returns useful results — Scan on an empty pipeline always
// returns Blocked=false.
func NewPipeline(weights ScoreWeights, threshold *ThresholdEngine) *Pipeline {
	if threshold == nil {
		threshold = NewThresholdEngine(DefaultThresholds())
	}
	return &Pipeline{
		weights:   weights,
		threshold: threshold,
	}
}

// Rebuild atomically swaps in a new pattern set, automaton, and
// exclusion list. Called on agent startup and whenever rule files are
// updated (POST /api/rules/update or future automatic rule sync).
func (p *Pipeline) Rebuild(patterns []*Pattern, exclusions []Exclusion) {
	auto := BuildAutomaton(patterns)
	p.mu.Lock()
	p.patterns = patterns
	p.automaton = auto
	p.exclusions = exclusions
	p.mu.Unlock()
}

// SetWeights atomically updates the scoring weights.
func (p *Pipeline) SetWeights(w ScoreWeights) {
	p.mu.Lock()
	p.weights = w
	p.mu.Unlock()
}

// Threshold returns the threshold engine. Used by the API to expose
// GET /api/dlp/config and PUT /api/dlp/config.
func (p *Pipeline) Threshold() *ThresholdEngine { return p.threshold }

// Patterns returns a snapshot of the loaded patterns. Used for tests
// and introspection only — callers must not mutate the slice.
func (p *Pipeline) Patterns() []*Pattern {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*Pattern, len(p.patterns))
	copy(out, p.patterns)
	return out
}

// Scan runs the full DLP pipeline on content and returns the highest
// scoring match's decision. ctx is honoured at the entry point only;
// individual pipeline steps are bounded and complete quickly.
func (p *Pipeline) Scan(ctx context.Context, content string) ScanResult {
	if err := ctx.Err(); err != nil {
		return ScanResult{}
	}

	p.mu.RLock()
	auto := p.automaton
	exclusions := p.exclusions
	weights := p.weights
	threshold := p.threshold
	p.mu.RUnlock()

	if auto == nil || threshold == nil {
		return ScanResult{}
	}

	// Step 1: classify content — currently used to short-circuit
	// scans of obviously-empty input and to label the result for
	// future per-class pattern subsets.
	_ = ClassifyContent(content)

	// Step 2: Aho-Corasick prefix scan.
	candidates := auto.Scan(content)

	// Step 3: regex validation of candidates.
	matches := ValidateCandidates(content, candidates)
	if len(matches) == 0 {
		return ScanResult{}
	}

	// Group by pattern for the multi_match_boost.
	perPattern := make(map[*Pattern][]Match)
	for _, m := range matches {
		perPattern[m.Pattern] = append(perPattern[m.Pattern], m)
	}

	best := ScanResult{}

	for pat, ms := range perPattern {
		if pat.MinMatches > 0 && len(ms) < pat.MinMatches {
			continue
		}

		var (
			hotwordSeenForPattern bool
			topScore              int
			haveScored            bool
		)
		for _, m := range ms {
			// Step 4a: hotword proximity.
			hotword := CheckHotwords(content, m, *pat)

			// Step 4c: exclusion — possibly suppress entirely.
			excl := CheckExclusion(content, m, exclusions)
			if excl.SuppressEntirely {
				continue
			}

			// Step 4b: entropy.
			ent := ShannonEntropy(m.Value)

			// Step 4d: aggregate score.
			score := ScoreMatch(ScoreInput{
				Pattern:        *pat,
				Match:          m,
				HotwordPresent: hotword,
				Entropy:        ent,
				NumMatches:     len(ms),
				ExclusionHit:   excl.Hit,
				Weights:        weights,
			})

			if !haveScored || score > topScore {
				topScore = score
				haveScored = true
			}
			if hotword {
				hotwordSeenForPattern = true
			}
		}

		if !haveScored {
			continue
		}
		if pat.RequireHotword && !hotwordSeenForPattern {
			continue
		}

		// Step 5: threshold check.
		if threshold.ShouldBlock(topScore, string(pat.Severity)) {
			if !best.Blocked || topScore > best.Score {
				best = ScanResult{
					Blocked:     true,
					PatternName: pat.Name,
					Score:       topScore,
				}
			}
		}
	}

	return best
}
