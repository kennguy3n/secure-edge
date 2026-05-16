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
func (l *Layer) DisambiguatorScore(ctx context.Context, content string) float32 {
	if l == nil || l.disamb == nil {
		return 0
	}
	return l.disamb.Score(ctx, content)
}

// Close releases the embedder. Safe to call on a nil Layer.
func (l *Layer) Close() error {
	if l == nil || l.emb == nil {
		return nil
	}
	return l.emb.Close()
}
