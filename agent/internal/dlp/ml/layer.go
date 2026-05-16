package ml

import (
	"context"
	"errors"
)

// Layer bundles the embedder, pre-filter, and disambiguator into a
// single object that the DLP pipeline can hold. The pipeline calls
// PreFilter and DisambiguatorScore directly — Layer owns the
// embedder so the pipeline does not need to know whether ML is
// enabled, disabled, partially loaded, or fully loaded.
//
// All entry points are safe for concurrent calls and complete in
// bounded time. When the underlying embedder is the NullEmbedder,
// every entry point returns the "no signal" value (VerdictUnknown
// or score 0) without invoking the embedder.
type Layer struct {
	emb       Embedder
	preFilter *PreFilter
	disamb    *Disambiguator
}

// NewLayer wires the supplied embedder and artefacts into a Layer.
// A nil emb is replaced by NullEmbedder so callers never have to
// nil-check the result.
//
// Initialisation is best-effort: failures to wire the pre-filter or
// disambiguator are not propagated as errors — they degrade those
// specific features to no-ops while leaving the rest of the layer
// functional. This matches the design intent that ML is *additive*
// and never blocks the deterministic pipeline.
//
// NewLayer returns (*Layer, nil) in every case where the supplied
// arguments are well-formed. The error return is reserved for
// future use (e.g. when a stricter initialisation contract is
// added) and is always nil today.
func NewLayer(emb Embedder, art *Artefacts, preFilterThreshold float32) (*Layer, error) {
	if emb == nil {
		emb = NullEmbedder{}
	}
	l := &Layer{emb: emb}

	if art != nil && art.Centroids != nil {
		if pf, err := NewPreFilter(emb, *art.Centroids, preFilterThreshold); err == nil {
			l.preFilter = pf
		} else if !errors.Is(err, ErrEmbedderUnavailable) && !errors.Is(err, ErrNoCentroids) {
			// Unknown init failure — return it so the caller
			// can surface a one-time log line. Pre-filter
			// stays nil so the pipeline path degrades.
			return l, err
		}
	}

	if art != nil && art.Linear != nil {
		if d, err := NewDisambiguator(emb, *art.Linear); err == nil {
			l.disamb = d
		} else if !errors.Is(err, ErrEmbedderUnavailable) && !errors.Is(err, ErrNoDisambiguatorWeights) {
			return l, err
		}
	}

	return l, nil
}

// Ready reports whether the embedder is loaded and at least one of
// pre-filter / disambiguator is wired. False means the Layer is a
// no-op and the pipeline can skip every ML call site.
func (l *Layer) Ready() bool {
	if l == nil || l.emb == nil || !l.emb.Ready() {
		return false
	}
	return l.preFilter != nil || l.disamb != nil
}

// PreFilter classifies content. Returns VerdictUnknown when the
// pre-filter is not configured. The pipeline calls this early in
// Scan and can short-circuit when the verdict is VerdictLikelyBenign
// *and* no high-severity pattern would have fired anyway. The
// "high-severity guard" lives in the pipeline, not here — this
// layer must not have any knowledge of pattern severities.
//
// Callers that already have an embedding for the same content
// (e.g. the DLP pipeline's embed-once optimisation between the
// pre-filter and disambiguator stages) should use PreFilterVec
// instead to avoid re-embedding.
func (l *Layer) PreFilter(ctx context.Context, content string) Verdict {
	if l == nil || l.preFilter == nil {
		return VerdictUnknown
	}
	return l.preFilter.Classify(ctx, content)
}

// DisambiguatorScore returns the ML score for content. Returns 0
// when the disambiguator is not configured or the embedder errors.
// Callers in the DLP pipeline scale this float into an integer
// score adjustment via ScoreWeights.MLBoost.
//
// Callers that already have an embedding for the same content
// (e.g. the DLP pipeline's embed-once optimisation between the
// pre-filter and disambiguator stages) should use
// DisambiguatorScoreVec instead to avoid re-embedding.
func (l *Layer) DisambiguatorScore(ctx context.Context, content string) float32 {
	if l == nil || l.disamb == nil {
		return 0
	}
	return l.disamb.Score(ctx, content)
}

// Embed returns the sentence-embedding vector for content. The
// DLP pipeline calls Embed once per scan when both ML stages are
// active and reuses the resulting vector with PreFilterVec and
// DisambiguatorScoreVec, halving the per-scan ML latency budget
// (~10-16 ms → ~5-8 ms on the production MiniLM-L12 build) by
// avoiding two Embed calls on identical content.
//
// Returns ErrEmbedderUnavailable on a nil Layer or when the
// underlying embedder is the NullEmbedder. Returns context
// errors verbatim from the embedder so the caller's outer ctx
// management still works. Any other non-nil error means the
// embedder failed transiently — callers should treat it the
// same as "no ML signal for this scan" and fall through to the
// legacy PreFilter / DisambiguatorScore call sites, which each
// embed independently and short-circuit on the same errors.
//
// Embed exposes only the *vector*, never the embedder itself —
// the Layer remains the sole owner of the embedder's lifecycle.
func (l *Layer) Embed(ctx context.Context, content string) ([]float32, error) {
	if l == nil || l.emb == nil {
		return nil, ErrEmbedderUnavailable
	}
	return l.emb.Embed(ctx, content)
}

// PreFilterVec is the embed-cached companion to PreFilter:
// classifies a pre-computed embedding vector instead of re-
// embedding content. Returns VerdictUnknown when the pre-filter
// is not configured or the supplied vector's length does not
// match the centroid length. The vector must come from the same
// Embedder that built the pre-filter's centroids — callers in
// the DLP pipeline guarantee this by obtaining the vector via
// Layer.Embed on the same Layer.
func (l *Layer) PreFilterVec(vec []float32) Verdict {
	if l == nil || l.preFilter == nil {
		return VerdictUnknown
	}
	return l.preFilter.ClassifyVec(vec)
}

// DisambiguatorScoreVec is the embed-cached companion to
// DisambiguatorScore: scores a pre-computed embedding vector
// instead of re-embedding content. Returns 0 when the
// disambiguator is not configured or the supplied vector's
// length does not match the linear-head weight length. The
// vector must come from the same Embedder that produced the
// disambiguator's training embeddings — callers in the DLP
// pipeline guarantee this by obtaining the vector via
// Layer.Embed on the same Layer.
func (l *Layer) DisambiguatorScoreVec(vec []float32) float32 {
	if l == nil || l.disamb == nil {
		return 0
	}
	return l.disamb.ScoreVec(vec)
}

// Close releases the embedder. Safe to call on a nil Layer.
func (l *Layer) Close() error {
	if l == nil || l.emb == nil {
		return nil
	}
	return l.emb.Close()
}
