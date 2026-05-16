package ml

import (
	"context"
	"errors"
	"math"
)

// Disambiguator is a tiny classifier head that turns a content
// embedding into a single scalar in [-1, 1] expressing how confident
// the model is that the content contains a real secret / PII match.
// Positive values lean "real match"; negative values lean "false
// positive"; zero means "no signal".
//
// The disambiguator is only consulted for *borderline* deterministic
// scores (per-severity threshold ± MLBorderlineWidth). High-confidence
// blocks and high-confidence non-blocks are unchanged regardless of
// what the disambiguator says — this is by design and is what makes
// the ML layer reviewable: the deterministic pipeline retains
// veto power on every confident decision.
//
// The default implementation is a frozen linear head over the
// sentence-embedding vector (one weight per dimension, plus a bias).
// Weights are loaded from a small JSON sidecar alongside the
// centroids. The architecture is intentionally minimal so the
// per-scan cost is bounded by the embedder itself: a dot product on
// a 384-dim vector takes ~1 μs.
type Disambiguator struct {
	emb  Embedder
	w    []float32
	bias float32
}

// LinearHead is the on-disk representation of the disambiguator
// weights. Loaded from a JSON sidecar at agent startup; produced by
// agent/internal/dlp/testdata/cmd/build_disambiguator/ during
// corpus regeneration. The struct is intentionally small so
// reviewers can verify the entire ML-influenced surface in one
// glance.
type LinearHead struct {
	// Weights is the per-dimension weight vector. Length must
	// equal Embedder.Dim().
	Weights []float32 `json:"weights"`
	// Bias is added to the dot product before squashing.
	Bias float32 `json:"bias"`
}

// ErrNoDisambiguatorWeights is returned by NewDisambiguator when no
// weight vector is supplied or the dimensions disagree with the
// embedder. Treated by the pipeline the same as the embedder being
// unavailable.
var ErrNoDisambiguatorWeights = errors.New("ml: no disambiguator weights configured")

// NewDisambiguator wires an Embedder and a LinearHead into a
// Disambiguator. The embedder.Dim() must equal len(head.Weights).
// Callers should treat a non-nil error as "ML disambiguator
// disabled" and proceed with the deterministic score.
func NewDisambiguator(emb Embedder, head LinearHead) (*Disambiguator, error) {
	if emb == nil || !emb.Ready() {
		return nil, ErrEmbedderUnavailable
	}
	if len(head.Weights) == 0 || len(head.Weights) != emb.Dim() {
		return nil, ErrNoDisambiguatorWeights
	}
	// Defensive copy of the weight vector so callers cannot
	// silently re-write the linear head after construction. Matches
	// PreFilter's centroid copying — both surfaces accept loader-
	// owned slices and freeze them at construction.
	w := append([]float32(nil), head.Weights...)
	return &Disambiguator{emb: emb, w: w, bias: head.Bias}, nil
}

// Score returns a scalar in [-1, 1] for content. The embedder is
// invoked once per call; callers that already have an embedding
// from the pre-filter step should use ScoreVec to avoid re-embedding.
// Any embedder error is treated as "no signal" and surfaces as 0.
func (d *Disambiguator) Score(ctx context.Context, content string) float32 {
	if d == nil {
		return 0
	}
	vec, err := d.emb.Embed(ctx, content)
	if err != nil || len(vec) != len(d.w) {
		return 0
	}
	return d.ScoreVec(vec)
}

// ScoreVec returns the disambiguator score for a pre-computed
// embedding vector. Used by the pipeline to avoid embedding the
// same content twice (once in pre-filter, once here).
func (d *Disambiguator) ScoreVec(vec []float32) float32 {
	if d == nil || len(vec) != len(d.w) {
		return 0
	}
	var dot float32
	for i := range vec {
		dot += vec[i] * d.w[i]
	}
	return tanh(dot + d.bias)
}

// tanh squashes the linear-head output into [-1, 1]. We use math.Tanh
// for numerical stability rather than rolling our own approximation —
// the per-scan cost is dominated by the embedder, not by this.
func tanh(x float32) float32 {
	return float32(math.Tanh(float64(x)))
}
