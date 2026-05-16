package ml

import (
	"context"
	"errors"
	"math"
)

// Centroids holds the two reference vectors the pre-filter compares
// content against. tpCentroid is the mean embedding of the synthetic
// true-positive corpus (samples that *should* block); tnCentroid is
// the mean embedding of the synthetic true-negative corpus.
//
// Both vectors have the same length, equal to Embedder.Dim() for
// the Embedder that produced them. Loading is deferred to a JSON
// sidecar (see corpus_centroids.json) so the in-process state stays
// small and the centroids can be regenerated without rebuilding
// the agent.
type Centroids struct {
	TP []float32
	TN []float32
}

// ErrNoCentroids is returned by NewPreFilter when the supplied
// centroids slice is empty or the dimensions disagree with the
// supplied embedder. The pipeline treats this the same as the
// embedder being unavailable — pre-filter becomes a no-op.
var ErrNoCentroids = errors.New("ml: no centroids configured")

// Verdict is the pre-filter's recommendation to the pipeline.
type Verdict int

const (
	// VerdictUnknown means the pre-filter cannot make a confident
	// call — the pipeline should run the full deterministic
	// pipeline and ignore the pre-filter signal.
	VerdictUnknown Verdict = iota
	// VerdictLikelyBenign means the content is much closer to the
	// TN centroid than the TP centroid. The pipeline may skip the
	// expensive regex + AC steps and return a fast no-block
	// verdict — but only when the deterministic pipeline does not
	// have *any* high-severity pattern that would have fired
	// anyway. The pre-filter is a *latency* win, never a *recall*
	// loss: the threshold is conservative.
	VerdictLikelyBenign
)

// PreFilter classifies content as VerdictLikelyBenign when its
// embedding is significantly closer to the TN centroid than to the
// TP centroid. The margin is configurable via Threshold — a higher
// threshold means the pre-filter is more reluctant to skip the
// deterministic pipeline.
type PreFilter struct {
	emb       Embedder
	tp        []float32
	tn        []float32
	threshold float32
}

// DefaultPreFilterThreshold is the default cosine-similarity margin
// the pre-filter requires before it returns VerdictLikelyBenign.
// Picked conservatively to favour recall over latency — at this
// margin, less than 1 % of the synthetic TP corpus is at risk of a
// false skip (measured during corpus regeneration; see
// agent/internal/dlp/testdata/cmd/build_centroids/).
const DefaultPreFilterThreshold = 0.35

// NewPreFilter wires an Embedder and a pair of centroids together
// into a PreFilter. The embedder.Dim() must equal the centroid
// length. When the embedder is not Ready, or the centroids are
// missing / malformed, NewPreFilter returns (nil, ErrNoCentroids /
// ErrEmbedderUnavailable). Callers should treat any such error as
// "ML pre-filter disabled" and proceed with the deterministic
// pipeline.
func NewPreFilter(emb Embedder, c Centroids, threshold float32) (*PreFilter, error) {
	if emb == nil || !emb.Ready() {
		return nil, ErrEmbedderUnavailable
	}
	if len(c.TP) == 0 || len(c.TN) == 0 {
		return nil, ErrNoCentroids
	}
	if len(c.TP) != len(c.TN) || len(c.TP) != emb.Dim() {
		return nil, ErrNoCentroids
	}
	if threshold <= 0 {
		threshold = DefaultPreFilterThreshold
	}
	// Defensive copy. Callers retain ownership of the supplied
	// Centroids slices; the PreFilter must remain immune to any
	// post-construction mutation of those slices (e.g. a reload
	// path that reuses the same backing array). The copies are
	// ~3 KB per slice for the 384-dim MiniLM-L12 model, so the
	// allocation is negligible compared with the in-process
	// model footprint.
	tp := append([]float32(nil), c.TP...)
	tn := append([]float32(nil), c.TN...)
	return &PreFilter{emb: emb, tp: tp, tn: tn, threshold: threshold}, nil
}

// Classify computes the embedding for content and returns the
// pre-filter verdict. Returns VerdictUnknown on any embedder error
// (including ErrEmbedderUnavailable) so callers can keep their
// single-line "fast path? then return" wiring simple.
//
// Callers that have already embedded the same content (e.g. the
// DLP pipeline's embed-once optimisation between the pre-filter
// and the disambiguator) should call ClassifyVec directly to
// avoid a redundant Embed call.
func (p *PreFilter) Classify(ctx context.Context, content string) Verdict {
	if p == nil {
		return VerdictUnknown
	}
	vec, err := p.emb.Embed(ctx, content)
	if err != nil {
		return VerdictUnknown
	}
	return p.ClassifyVec(vec)
}

// ClassifyVec returns the pre-filter verdict for a pre-computed
// embedding vector. Returns VerdictUnknown when the supplied
// vector's length does not match the centroid length — the same
// "no signal" fall-through Classify uses on embedder errors. The
// vector must come from the same Embedder that built the
// centroids; mixing embedding spaces produces meaningless cosine
// distances.
//
// ClassifyVec is the cache-companion to Classify: it lets the DLP
// pipeline embed once and feed the same vector to both the pre-
// filter and the disambiguator, halving the ML-active scan
// latency on the production MiniLM-L12 build.
func (p *PreFilter) ClassifyVec(vec []float32) Verdict {
	if p == nil || len(vec) != len(p.tp) {
		return VerdictUnknown
	}
	tpSim := cosine(vec, p.tp)
	tnSim := cosine(vec, p.tn)
	if tnSim-tpSim >= p.threshold {
		return VerdictLikelyBenign
	}
	return VerdictUnknown
}

// cosine returns the cosine similarity between two vectors of equal
// length. Returns 0 when either input is the zero vector — that
// matches the convention used by the centroid-building tool.
func cosine(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		ai := float64(a[i])
		bi := float64(b[i])
		dot += ai * bi
		na += ai * ai
		nb += bi * bi
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return float32(dot / (math.Sqrt(na) * math.Sqrt(nb)))
}
