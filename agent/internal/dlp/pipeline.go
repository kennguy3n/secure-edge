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
	"runtime"
	"sort"
	"sync"

	"github.com/kennguy3n/secure-edge/agent/internal/dlp/ml"
)

// LargeContentThreshold is the byte threshold above which Pipeline
// drops low-severity patterns from the candidate set. Configurable per
// pipeline via SetLargeContentThreshold; the default matches the
// `large_content_threshold` setting in config.yaml.
const LargeContentThreshold = 50 * 1024

// ConcurrentEvalThreshold is the byte threshold above which the
// pipeline evaluates per-pattern groups concurrently. Below this the
// sequential path is cheaper because of goroutine setup overhead.
const ConcurrentEvalThreshold = 10 * 1024

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

	patterns       []*Pattern
	automaton      *Automaton
	exclusions     []Exclusion
	weights        ScoreWeights
	threshold      *ThresholdEngine
	largeThreshold int

	// disabledCategories holds the set of pattern categories that
	// should be skipped at scan time. Empty by default (all
	// categories active).
	disabledCategories map[string]struct{}

	// hasContentTypeFilter is true iff at least one loaded pattern
	// has a non-empty Pattern.ContentTypes. Cached at Rebuild time so
	// the hot per-scan path does not need to walk the entire pattern
	// set to discover that nobody uses the content_types field. When
	// false, Scan skips ClassifyContent entirely and filterCandidates
	// reaches its original fast-path early return when no other
	// adaptive filter (large payload, disabled categories) is active.
	hasContentTypeFilter bool

	// mlLayer is the optional ML-augmented detection layer (W3,
	// draft). Nil or non-Ready means the pipeline is fully
	// deterministic and behaves exactly as before. SetMLLayer
	// installs a Layer at runtime; the pipeline guarantees no
	// observable behaviour change until SetMLLayer is called with
	// a Ready layer AND ScoreWeights.MLBoost > 0.
	mlLayer *ml.Layer

	// cache deduplicates identical pastes that arrive in rapid
	// succession (paste + form-submit + fetch interceptors).
	cache *ScanCache
}

// NewPipeline returns an empty pipeline. Callers must call Rebuild
// before Scan returns useful results — Scan on an empty pipeline always
// returns Blocked=false.
func NewPipeline(weights ScoreWeights, threshold *ThresholdEngine) *Pipeline {
	if threshold == nil {
		threshold = NewThresholdEngine(DefaultThresholds())
	}
	return &Pipeline{
		weights:        weights,
		threshold:      threshold,
		largeThreshold: LargeContentThreshold,
	}
}

// SetLargeContentThreshold updates the byte threshold above which the
// pipeline switches to "critical/high only" scanning. Zero or negative
// values restore the default LargeContentThreshold. Safe to call
// concurrently with Scan. The scan cache is reset alongside the
// update so cached verdicts produced under the previous threshold
// cannot leak past the change.
func (p *Pipeline) SetLargeContentThreshold(n int) {
	if n <= 0 {
		n = LargeContentThreshold
	}
	p.mu.Lock()
	p.largeThreshold = n
	cache := p.cache
	p.mu.Unlock()
	cache.Reset()
}

// LargeContentThreshold returns the current threshold in bytes.
func (p *Pipeline) LargeContentThreshold() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.largeThreshold <= 0 {
		return LargeContentThreshold
	}
	return p.largeThreshold
}

// SetDisabledCategories replaces the set of disabled pattern
// categories. Pass an empty slice to re-enable all categories. The
// agent UI uses this to let operators turn off PII or low-severity
// pattern groups without editing the rule file. The scan cache is
// reset alongside the update so verdicts produced before a category
// was disabled (or re-enabled) cannot survive the change.
func (p *Pipeline) SetDisabledCategories(categories []string) {
	disabled := make(map[string]struct{}, len(categories))
	for _, c := range categories {
		if c == "" {
			continue
		}
		disabled[c] = struct{}{}
	}
	p.mu.Lock()
	p.disabledCategories = disabled
	cache := p.cache
	p.mu.Unlock()
	cache.Reset()
}

// DisabledCategories returns the current set of disabled categories.
// The returned slice is a snapshot and safe for the caller to mutate.
func (p *Pipeline) DisabledCategories() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.disabledCategories))
	for c := range p.disabledCategories {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Categories returns the sorted list of distinct pattern categories
// currently loaded. Used by the Electron UI's Rules page.
func (p *Pipeline) Categories() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	seen := make(map[string]struct{}, 16)
	for _, pat := range p.patterns {
		c := pat.Category
		if c == "" {
			c = CategoryUncategorized
		}
		seen[c] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Rebuild atomically swaps in a new pattern set, automaton, and
// exclusion list. Called on agent startup and whenever rule files are
// updated (POST /api/rules/update or future automatic rule sync).
func (p *Pipeline) Rebuild(patterns []*Pattern, exclusions []Exclusion) {
	auto := BuildAutomaton(patterns)
	hasContentTypeFilter := false
	for _, pat := range patterns {
		if pat != nil && len(pat.ContentTypes) > 0 {
			hasContentTypeFilter = true
			break
		}
	}
	p.mu.Lock()
	p.patterns = patterns
	p.automaton = auto
	p.exclusions = exclusions
	p.hasContentTypeFilter = hasContentTypeFilter
	cache := p.cache
	p.mu.Unlock()
	cache.Reset()
}

// EnableCache attaches a ScanCache to the pipeline. Passing nil
// disables caching (useful for tests). Safe to call concurrently with
// Scan.
func (p *Pipeline) EnableCache(c *ScanCache) {
	p.mu.Lock()
	p.cache = c
	p.mu.Unlock()
}

// SetMLLayer installs (or removes) the optional ML-augmented
// detection layer. Passing nil restores fully-deterministic
// behaviour. The scan cache is reset alongside the swap so
// verdicts produced under the previous layer (or with no layer)
// cannot leak past the change. Safe to call concurrently with Scan.
//
// Privacy note: the Layer owns its own embedder lifecycle. Pipeline
// only holds the pointer and never touches the underlying model
// artefacts.
func (p *Pipeline) SetMLLayer(l *ml.Layer) {
	p.mu.Lock()
	p.mlLayer = l
	cache := p.cache
	p.mu.Unlock()
	cache.Reset()
}

// MLLayer returns the currently installed ML layer, or nil if none.
// Useful for /api/dlp/config inspection.
func (p *Pipeline) MLLayer() *ml.Layer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.mlLayer
}

// Cache returns the attached ScanCache, or nil if caching is disabled.
func (p *Pipeline) Cache() *ScanCache {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cache
}

// Weights returns a snapshot of the currently active scoring
// weights. Used by main.go to reapply MLBoost after a hot-reload
// (POST /api/profile/import) and by /api/dlp/config GET to surface
// the live MLBoost alongside the persisted database value.
func (p *Pipeline) Weights() ScoreWeights {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.weights
}

// SetWeights atomically updates the scoring weights. The scan cache
// is reset alongside the update so verdicts produced under the
// previous weights cannot leak past the change — otherwise a PUT
// /api/dlp/config that raises a hotword/entropy boost would only
// take effect after the cache TTL expired.
func (p *Pipeline) SetWeights(w ScoreWeights) {
	p.mu.Lock()
	p.weights = w
	cache := p.cache
	p.mu.Unlock()
	cache.Reset()
}

// ResetCache drops every cached scan result. Exposed so callers that
// mutate state outside the pipeline's setters — most notably
// Threshold().Set() on the embedded ThresholdEngine — can keep the
// cache in sync with the live policy. A nil cache is a no-op.
func (p *Pipeline) ResetCache() {
	p.mu.RLock()
	cache := p.cache
	p.mu.RUnlock()
	cache.Reset()
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
	largeThreshold := p.largeThreshold
	disabledCats := p.disabledCategories
	hasContentTypeFilter := p.hasContentTypeFilter
	mlLayer := p.mlLayer
	cache := p.cache
	p.mu.RUnlock()

	if cache != nil {
		if cached, ok := cache.Lookup(content); ok {
			return cached
		}
	}

	if auto == nil || threshold == nil {
		return ScanResult{}
	}
	if largeThreshold <= 0 {
		largeThreshold = LargeContentThreshold
	}

	// Step 1: classify content — but only when at least one loaded
	// pattern actually declares a content_types restriction. The flag
	// is precomputed at Rebuild time so the common case (no pattern
	// scoped to a classifier verdict) skips the classifier entirely
	// and lets filterCandidates take its existing fast-path early
	// return. ClassifyContent is documented to never return "", so we
	// use the empty value here as a sentinel for "no content-type
	// filtering requested".
	var contentType ContentType
	if hasContentTypeFilter {
		contentType = ClassifyContent(content)
	}

	// Step 2: Aho-Corasick prefix scan.
	candidates := auto.Scan(content)

	// Adaptive scanning + category filter + content-type filter: drop
	// candidates whose patterns are disabled by category, are
	// de-prioritised for very large payloads, or are scoped to a
	// classifier verdict that does not match contentType.
	candidates = filterCandidates(candidates, len(content), largeThreshold, disabledCats, contentType)

	// When filterCandidates drops every candidate, the
	// deterministic pipeline already produces ScanResult{} —
	// running the ML pre-filter just to return the same answer
	// would waste an embedder call (~5-8 ms on the production
	// MiniLM-L12 build). Short-circuit before reaching the ML
	// block so the no-candidate fast path stays fast.
	if len(candidates) == 0 {
		if cache != nil {
			cache.Put(content, ScanResult{})
		}
		return ScanResult{}
	}

	// W3 embed-once optimisation. When the ML layer is active
	// (Ready + MLBoost > 0) both the pre-filter (this block) and
	// the disambiguator (a few lines further down) embed the same
	// content string — historically that was two independent
	// Embed calls per scan, costing ~10-16 ms on the production
	// MiniLM-L12 build. Computing the vector once here and feeding
	// it to both stages via *Vec methods halves the ML-active
	// latency budget. Embed failures fall through to the legacy
	// per-call PreFilter / DisambiguatorScore methods (which
	// embed independently and short-circuit on errors), so the
	// optimisation is a pure latency win and never changes the
	// pipeline's verdict.
	mlActive := mlLayer != nil && mlLayer.Ready() && weights.MLBoost > 0
	var mlVec []float32
	if mlActive {
		if v, err := mlLayer.Embed(ctx, content); err == nil && len(v) > 0 {
			mlVec = v
		}
	}

	// Optional ML pre-filter (W3). Runs after the AC scan so we
	// know the candidate severity distribution, and only short-
	// circuits when ALL of the following hold:
	//
	//   - mlLayer is Ready (model + centroids loaded),
	//   - the embedder thinks the content is much closer to the TN
	//     centroid than to the TP centroid (VerdictLikelyBenign),
	//   - no surviving candidate has Critical or High severity.
	//
	// The severity guard is what keeps the deterministic pipeline
	// in charge of every confident block: a Critical/High AC
	// candidate ALWAYS goes through regex + scoring + threshold,
	// regardless of what the ML pre-filter says. The pre-filter is
	// a *latency* shortcut for low-severity noise, never a recall
	// hazard for high-severity secrets.
	//
	// Gating on weights.MLBoost > 0 mirrors the disambiguator
	// branch below. ScoreWeights.MLBoost is the documented kill
	// switch ("Zero or negative disables ML scoring for this
	// Pipeline"); enforcing it at both ML entry points means a
	// future caller cannot install a Ready layer + MLBoost=0 and
	// have the pre-filter surprise them by silently skipping
	// medium/low-severity patterns.
	if mlActive && !candidatesIncludeHighSeverity(candidates) {
		var verdict ml.Verdict
		if mlVec != nil {
			verdict = mlLayer.PreFilterVec(mlVec)
		} else {
			verdict = mlLayer.PreFilter(ctx, content)
		}
		if verdict == ml.VerdictLikelyBenign {
			if cache != nil {
				cache.Put(content, ScanResult{})
			}
			return ScanResult{}
		}
	}

	// Step 3: regex validation of candidates.
	matches := ValidateCandidates(content, candidates)
	if len(matches) == 0 {
		if cache != nil {
			cache.Put(content, ScanResult{})
		}
		return ScanResult{}
	}

	// Group by pattern for the multi_match_boost.
	perPattern := make(map[*Pattern][]Match)
	for _, m := range matches {
		perPattern[m.Pattern] = append(perPattern[m.Pattern], m)
	}

	// Optional ML disambiguator score for the *scan content* as a
	// whole. Computed once and applied to every borderline
	// per-pattern evaluation below — calling the embedder per
	// pattern would blow the latency budget for content with many
	// matches. Zero (and a no-op nudge in ScoreMatch) when the ML
	// layer is disabled.
	//
	// Reuses the embedding vector cached at the top of the ML
	// block when present; falls back to DisambiguatorScore (which
	// re-embeds internally) when the cache is empty — e.g. the
	// Embed call failed transiently. The mlActive guard is the
	// same boolean computed for the pre-filter block; recomputing
	// it here would be redundant.
	var mlScore float32
	if mlActive {
		if mlVec != nil {
			mlScore = mlLayer.DisambiguatorScoreVec(mlVec)
		} else {
			mlScore = mlLayer.DisambiguatorScore(ctx, content)
		}
	}

	// For large payloads we evaluate the per-pattern groups in
	// parallel. The pipeline state we read above is captured by value
	// so each worker can run without further locking.
	var best ScanResult
	if len(content) >= ConcurrentEvalThreshold && len(perPattern) > 1 {
		best = scanConcurrent(content, perPattern, exclusions, weights, threshold, mlScore)
	} else {
		for pat, ms := range perPattern {
			res := evaluatePattern(content, pat, ms, exclusions, weights, threshold, mlScore)
			if res.Blocked && (!best.Blocked || res.Score > best.Score) {
				best = res
			}
		}
	}

	if cache != nil {
		cache.Put(content, best)
	}
	return best
}

// evaluatePattern runs steps 4a-4d and the threshold check for a
// single pattern group. Pure function with no shared state — safe to
// invoke from worker goroutines in the concurrent path.
//
// mlScore is the ML disambiguator output for the entire scan content
// (0 when ML is disabled). The scorer only applies it when this
// pattern's deterministic score lands within mlBorderlineWidth of
// the per-severity block threshold.
func evaluatePattern(
	content string,
	pat *Pattern,
	ms []Match,
	exclusions []Exclusion,
	weights ScoreWeights,
	threshold *ThresholdEngine,
	mlScore float32,
) ScanResult {
	if pat.MinMatches > 0 && len(ms) < pat.MinMatches {
		return ScanResult{}
	}

	var (
		hotwordSeen bool
		topScore    int
		haveScored  bool
	)
	for _, m := range ms {
		hotword := CheckHotwords(content, m, *pat)
		excl := CheckExclusion(content, m, exclusions)
		if excl.SuppressEntirely {
			continue
		}
		ent := ShannonEntropy(m.Value)
		score := ScoreMatch(ScoreInput{
			Pattern:           *pat,
			Match:             m,
			HotwordPresent:    hotword,
			Entropy:           ent,
			NumMatches:        len(ms),
			ExclusionHit:      excl.Hit,
			Weights:           weights,
			MLScore:           mlScore,
			SeverityThreshold: threshold.Lookup(string(pat.Severity)),
		})
		if !haveScored || score > topScore {
			topScore = score
			haveScored = true
		}
		if hotword {
			hotwordSeen = true
		}
	}
	if !haveScored {
		return ScanResult{}
	}
	if pat.RequireHotword && !hotwordSeen {
		return ScanResult{}
	}
	if !threshold.ShouldBlock(topScore, string(pat.Severity)) {
		return ScanResult{}
	}
	return ScanResult{Blocked: true, PatternName: pat.Name, Score: topScore}
}

// scanConcurrent fans the per-pattern groups out to a small worker
// pool and reduces the per-group results into the single best block
// decision. The number of workers is bounded by GOMAXPROCS so we never
// oversubscribe the CPU.
//
// mlScore is the per-scan ML disambiguator output (0 when ML is
// disabled). Forwarded unchanged to every worker so the per-pattern
// scoring sees the same ML signal.
func scanConcurrent(
	content string,
	perPattern map[*Pattern][]Match,
	exclusions []Exclusion,
	weights ScoreWeights,
	threshold *ThresholdEngine,
	mlScore float32,
) ScanResult {
	type job struct {
		pat *Pattern
		ms  []Match
	}
	jobs := make([]job, 0, len(perPattern))
	for pat, ms := range perPattern {
		jobs = append(jobs, job{pat: pat, ms: ms})
	}

	workers := runtime.GOMAXPROCS(0)
	if workers > len(jobs) {
		workers = len(jobs)
	}
	if workers < 1 {
		workers = 1
	}

	results := make(chan ScanResult, len(jobs))
	jobCh := make(chan job, len(jobs))
	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := range jobCh {
				results <- evaluatePattern(content, j.pat, j.ms, exclusions, weights, threshold, mlScore)
			}
		}()
	}
	wg.Wait()
	close(results)

	best := ScanResult{}
	for r := range results {
		if r.Blocked && (!best.Blocked || r.Score > best.Score) {
			best = r
		}
	}
	return best
}

// filterCandidates implements adaptive scanning, category filtering,
// and content-type filtering. For payloads larger than largeThreshold
// we drop candidates whose Pattern severity is "low" or "medium" —
// large pastes pay the per-candidate regex cost on critical/high
// patterns only. A pattern with a non-empty ContentTypes list is
// dropped when contentType is not in that list; patterns with an
// empty ContentTypes list match every classification (backwards
// compatible).
//
// A zero-value contentType is the caller's signal that no
// content-type filtering should be applied — e.g. when the owning
// Pipeline detected at Rebuild time that no loaded pattern declares a
// ContentTypes list, Scan skips ClassifyContent entirely and passes
// the empty value here so the fast-path early return below (no large
// payload, no disabled categories, no content-type filter) can fire
// just like it did before the classifier wiring landed.
func filterCandidates(
	in []Candidate,
	contentLen int,
	largeThreshold int,
	disabledCategories map[string]struct{},
	contentType ContentType,
) []Candidate {
	if len(in) == 0 {
		return in
	}
	large := contentLen >= largeThreshold
	hasContentType := contentType != ""
	if !large && len(disabledCategories) == 0 && !hasContentType {
		return in
	}
	out := in[:0]
	for _, c := range in {
		pat := c.Pattern
		if pat == nil {
			continue
		}
		if len(disabledCategories) > 0 {
			cat := pat.Category
			if cat == "" {
				cat = CategoryUncategorized
			}
			if _, off := disabledCategories[cat]; off {
				continue
			}
		}
		if hasContentType && len(pat.ContentTypes) > 0 && !contentTypeAllowed(pat.ContentTypes, contentType) {
			continue
		}
		if large {
			switch pat.Severity {
			case SeverityCritical, SeverityHigh:
				// keep
			default:
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// contentTypeAllowed reports whether ct appears in allowed. Tiny
// helper kept separate from filterCandidates so the per-candidate
// loop stays readable.
func contentTypeAllowed(allowed []ContentType, ct ContentType) bool {
	for _, a := range allowed {
		if a == ct {
			return true
		}
	}
	return false
}

// candidatesIncludeHighSeverity reports whether the supplied
// AC-candidate slice contains at least one pattern of Critical or
// High severity. Used by the ML pre-filter as a recall guard: if
// a high-severity candidate is in flight, the pre-filter is not
// allowed to short-circuit the regex pass.
func candidatesIncludeHighSeverity(cs []Candidate) bool {
	for _, c := range cs {
		if c.Pattern == nil {
			continue
		}
		switch c.Pattern.Severity {
		case SeverityCritical, SeverityHigh:
			return true
		}
	}
	return false
}
