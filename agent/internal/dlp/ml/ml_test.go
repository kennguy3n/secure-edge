package ml

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// stubEmbedder is a deterministic Embedder for tests. It returns a
// vector keyed off the *first byte* of the content so tests can
// pin specific inputs to specific vectors without inventing a
// real model. Ready() / Dim() reflect the configured state.
type stubEmbedder struct {
	dim      int
	ready    bool
	vectors  map[byte][]float32
	embedErr error
}

func (s *stubEmbedder) Embed(ctx context.Context, content string) ([]float32, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.embedErr != nil {
		return nil, s.embedErr
	}
	if !s.ready {
		return nil, ErrEmbedderUnavailable
	}
	if content == "" {
		return make([]float32, s.dim), nil
	}
	if v, ok := s.vectors[content[0]]; ok {
		return v, nil
	}
	return make([]float32, s.dim), nil
}

func (s *stubEmbedder) Dim() int     { return s.dim }
func (s *stubEmbedder) Ready() bool  { return s.ready }
func (s *stubEmbedder) Close() error { return nil }

func TestNullEmbedder_AlwaysUnavailable(t *testing.T) {
	e := NewNullEmbedder()
	if e.Ready() {
		t.Fatalf("NullEmbedder.Ready() = true, want false")
	}
	if d := e.Dim(); d != 0 {
		t.Fatalf("NullEmbedder.Dim() = %d, want 0", d)
	}
	v, err := e.Embed(context.Background(), "anything")
	if v != nil {
		t.Fatalf("NullEmbedder.Embed() returned a non-nil vector")
	}
	if !errors.Is(err, ErrEmbedderUnavailable) {
		t.Fatalf("NullEmbedder.Embed() err = %v, want ErrEmbedderUnavailable", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("NullEmbedder.Close() err = %v", err)
	}
}

func TestNullEmbedder_RespectsContextCancel(t *testing.T) {
	e := NewNullEmbedder()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Embed(ctx, "anything"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Embed on cancelled ctx returned %v, want context.Canceled", err)
	}
}

func TestNewPreFilter_RejectsBadInputs(t *testing.T) {
	ready := &stubEmbedder{dim: 3, ready: true}
	notReady := &stubEmbedder{dim: 3, ready: false}

	cases := []struct {
		name string
		emb  Embedder
		c    Centroids
		want error
	}{
		{"nil embedder", nil, Centroids{TP: []float32{1, 0, 0}, TN: []float32{0, 1, 0}}, ErrEmbedderUnavailable},
		{"not ready embedder", notReady, Centroids{TP: []float32{1, 0, 0}, TN: []float32{0, 1, 0}}, ErrEmbedderUnavailable},
		{"empty tp", ready, Centroids{TP: nil, TN: []float32{0, 1, 0}}, ErrNoCentroids},
		{"empty tn", ready, Centroids{TP: []float32{1, 0, 0}, TN: nil}, ErrNoCentroids},
		{"mismatched dims tp/tn", ready, Centroids{TP: []float32{1, 0, 0}, TN: []float32{0, 1}}, ErrNoCentroids},
		{"dim mismatch with embedder", ready, Centroids{TP: []float32{1, 0}, TN: []float32{0, 1}}, ErrNoCentroids},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pf, err := NewPreFilter(tc.emb, tc.c, 0)
			if pf != nil {
				t.Fatalf("expected nil PreFilter, got %v", pf)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPreFilter_VerdictLikelyBenignWhenTNClose(t *testing.T) {
	// "b" content => vector close to TN; "t" content => vector close
	// to TP. Confirms the verdict logic responds to the geometry.
	emb := &stubEmbedder{
		dim:   3,
		ready: true,
		vectors: map[byte][]float32{
			't': {1, 0, 0},     // identical to TP centroid
			'b': {0, 1, 0},     // identical to TN centroid
			'm': {0.5, 0.5, 0}, // midway between TP and TN — no clear winner
		},
	}
	pf, err := NewPreFilter(emb, Centroids{TP: []float32{1, 0, 0}, TN: []float32{0, 1, 0}}, 0.1)
	if err != nil {
		t.Fatalf("NewPreFilter: %v", err)
	}

	ctx := context.Background()
	if v := pf.Classify(ctx, "benign content"); v != VerdictLikelyBenign {
		t.Errorf("Classify benign: verdict = %v, want VerdictLikelyBenign", v)
	}
	if v := pf.Classify(ctx, "true-positive content"); v != VerdictUnknown {
		t.Errorf("Classify TP: verdict = %v, want VerdictUnknown", v)
	}
	if v := pf.Classify(ctx, "midpoint content"); v != VerdictUnknown {
		t.Errorf("Classify midpoint: verdict = %v, want VerdictUnknown", v)
	}
}

func TestPreFilter_UnknownOnEmbedderError(t *testing.T) {
	emb := &stubEmbedder{dim: 3, ready: true, embedErr: errors.New("boom")}
	pf, err := NewPreFilter(emb, Centroids{TP: []float32{1, 0, 0}, TN: []float32{0, 1, 0}}, 0.1)
	if err != nil {
		t.Fatalf("NewPreFilter: %v", err)
	}
	if v := pf.Classify(context.Background(), "x"); v != VerdictUnknown {
		t.Errorf("verdict = %v, want VerdictUnknown when embedder errors", v)
	}
}

func TestPreFilter_NilReceiver(t *testing.T) {
	var pf *PreFilter
	if v := pf.Classify(context.Background(), "x"); v != VerdictUnknown {
		t.Errorf("nil PreFilter.Classify = %v, want VerdictUnknown", v)
	}
}

func TestDisambiguator_ScoreInBounds(t *testing.T) {
	emb := &stubEmbedder{
		dim:   3,
		ready: true,
		vectors: map[byte][]float32{
			'p': {3, 0, 0},  // strong positive
			'n': {-3, 0, 0}, // strong negative
			'z': {0, 0, 0},  // zero
		},
	}
	head := LinearHead{Weights: []float32{1, 0, 0}, Bias: 0}
	d, err := NewDisambiguator(emb, head)
	if err != nil {
		t.Fatalf("NewDisambiguator: %v", err)
	}

	ctx := context.Background()
	pos := d.Score(ctx, "positive content")
	neg := d.Score(ctx, "negative content")
	zero := d.Score(ctx, "zero content")

	if pos <= 0 {
		t.Errorf("positive score = %v, want > 0", pos)
	}
	if neg >= 0 {
		t.Errorf("negative score = %v, want < 0", neg)
	}
	if math.Abs(float64(zero)) > 1e-6 {
		t.Errorf("zero score = %v, want ~0", zero)
	}
	// tanh range guarantees [-1, 1].
	for name, s := range map[string]float32{"pos": pos, "neg": neg, "zero": zero} {
		if s < -1 || s > 1 {
			t.Errorf("%s score = %v, outside [-1, 1]", name, s)
		}
	}
}

func TestDisambiguator_NilOrMissingReturnsZero(t *testing.T) {
	var d *Disambiguator
	if s := d.Score(context.Background(), "x"); s != 0 {
		t.Errorf("nil Disambiguator score = %v, want 0", s)
	}
	if s := d.ScoreVec([]float32{1, 2, 3}); s != 0 {
		t.Errorf("nil Disambiguator ScoreVec = %v, want 0", s)
	}
}

func TestNewDisambiguator_RejectsBadInputs(t *testing.T) {
	ready := &stubEmbedder{dim: 3, ready: true}
	notReady := &stubEmbedder{dim: 3, ready: false}
	cases := []struct {
		name string
		emb  Embedder
		head LinearHead
		want error
	}{
		{"nil embedder", nil, LinearHead{Weights: []float32{1, 0, 0}}, ErrEmbedderUnavailable},
		{"not ready embedder", notReady, LinearHead{Weights: []float32{1, 0, 0}}, ErrEmbedderUnavailable},
		{"empty weights", ready, LinearHead{}, ErrNoDisambiguatorWeights},
		{"dim mismatch", ready, LinearHead{Weights: []float32{1, 0}}, ErrNoDisambiguatorWeights},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewDisambiguator(tc.emb, tc.head)
			if d != nil {
				t.Fatalf("expected nil Disambiguator")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestLoadArtefacts_AllMissing(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadArtefacts(dir)
	if err != nil {
		t.Fatalf("LoadArtefacts: %v", err)
	}
	if a == nil {
		t.Fatalf("LoadArtefacts returned nil Artefacts")
	}
	if a.Centroids != nil || a.Linear != nil || a.ModelDir != "" {
		t.Errorf("expected all-nil artefacts, got %+v", a)
	}
}

func TestLoadArtefacts_EmptyBase(t *testing.T) {
	a, err := LoadArtefacts("")
	if err != nil {
		t.Fatalf("LoadArtefacts(\"\"): %v", err)
	}
	if a == nil {
		t.Fatalf("LoadArtefacts returned nil")
	}
	if a.Centroids != nil || a.Linear != nil || a.ModelDir != "" {
		t.Errorf("expected empty Artefacts for empty base, got %+v", a)
	}
}

func TestLoadArtefacts_RealFiles(t *testing.T) {
	dir := t.TempDir()
	cPath := filepath.Join(dir, "centroids.json")
	dPath := filepath.Join(dir, "disambiguator.json")
	if err := os.WriteFile(cPath, []byte(`{"tp":[1,0,0],"tn":[0,1,0]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dPath, []byte(`{"weights":[0.1,0.2,0.3],"bias":-0.1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := LoadArtefacts(dir)
	if err != nil {
		t.Fatalf("LoadArtefacts: %v", err)
	}
	if a.Centroids == nil || len(a.Centroids.TP) != 3 || len(a.Centroids.TN) != 3 {
		t.Errorf("centroids not loaded correctly: %+v", a.Centroids)
	}
	if a.Linear == nil || len(a.Linear.Weights) != 3 {
		t.Errorf("linear head not loaded correctly: %+v", a.Linear)
	}
}

func TestLoadArtefacts_RejectsMalformedCentroids(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "centroids.json"), []byte(`{"tp":[1,0,0],"tn":[0,1]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadArtefacts(dir)
	if err == nil {
		t.Fatalf("expected dimension-mismatch error, got nil")
	}
}

func TestLayer_NoOpWhenEmbedderNotReady(t *testing.T) {
	// NullEmbedder => Layer not Ready => every entry point returns
	// the no-signal value.
	l, err := NewLayer(NullEmbedder{}, &Artefacts{}, 0)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	if l.Ready() {
		t.Errorf("Layer.Ready() = true with NullEmbedder, want false")
	}
	if v := l.PreFilter(context.Background(), "x"); v != VerdictUnknown {
		t.Errorf("PreFilter on null layer = %v, want VerdictUnknown", v)
	}
	if s := l.DisambiguatorScore(context.Background(), "x"); s != 0 {
		t.Errorf("DisambiguatorScore on null layer = %v, want 0", s)
	}
	if err := l.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestLayer_NilSafe(t *testing.T) {
	var l *Layer
	if l.Ready() {
		t.Errorf("nil Layer.Ready() = true, want false")
	}
	if v := l.PreFilter(context.Background(), "x"); v != VerdictUnknown {
		t.Errorf("nil PreFilter = %v, want VerdictUnknown", v)
	}
	if s := l.DisambiguatorScore(context.Background(), "x"); s != 0 {
		t.Errorf("nil DisambiguatorScore = %v, want 0", s)
	}
	if err := l.Close(); err != nil {
		t.Errorf("nil Close: %v", err)
	}
}

func TestLayer_WiresPreFilterAndDisambiguatorWhenArtefactsPresent(t *testing.T) {
	emb := &stubEmbedder{
		dim:   3,
		ready: true,
		vectors: map[byte][]float32{
			'b': {0, 1, 0},
			't': {1, 0, 0},
		},
	}
	art := &Artefacts{
		Centroids: &Centroids{TP: []float32{1, 0, 0}, TN: []float32{0, 1, 0}},
		Linear:    &LinearHead{Weights: []float32{1, 0, 0}, Bias: 0},
	}
	l, err := NewLayer(emb, art, 0.1)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	if !l.Ready() {
		t.Fatalf("Layer.Ready() = false with both artefacts present")
	}
	if v := l.PreFilter(context.Background(), "benign"); v != VerdictLikelyBenign {
		t.Errorf("PreFilter benign = %v, want VerdictLikelyBenign", v)
	}
	if s := l.DisambiguatorScore(context.Background(), "true-positive"); s <= 0 {
		t.Errorf("DisambiguatorScore TP = %v, want > 0", s)
	}
}

func TestCosine_KnownValues(t *testing.T) {
	cases := []struct {
		a, b []float32
		want float32
	}{
		{[]float32{1, 0}, []float32{1, 0}, 1},
		{[]float32{1, 0}, []float32{0, 1}, 0},
		{[]float32{1, 0}, []float32{-1, 0}, -1},
		{[]float32{}, []float32{}, 0},
		{[]float32{0, 0}, []float32{1, 0}, 0},
	}
	for _, tc := range cases {
		got := cosine(tc.a, tc.b)
		if math.Abs(float64(got-tc.want)) > 1e-6 {
			t.Errorf("cosine(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
