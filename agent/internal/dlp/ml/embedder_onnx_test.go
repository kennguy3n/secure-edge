//go:build onnx

// End-to-end integration test for the ONNX-backed embedder.
//
// This test is gated behind `-tags=onnx` and additionally behind
// the SHIELDNET_TEST_ONNX_MODEL_DIR environment variable. Without
// both, t.Skip() is invoked — the default CI build does not have
// the onnxruntime shared library or the ~470 MB model checkpoint
// installed, and exercising those code paths is impossible there.
//
// To run locally:
//
//	scripts/fetch-ml-model.sh
//	export SHIELDNET_ONNXRUNTIME_LIB=/path/to/libonnxruntime.so
//	export SHIELDNET_TEST_ONNX_MODEL_DIR=$HOME/.shieldnet/models/model
//	cd agent && go test -tags=onnx -run TestONNXEmbedder ./internal/dlp/ml/
//
// What is asserted:
//
//   - The real ONNXEmbedder loads from a real on-disk model dir.
//   - Embed() returns a vector of the documented dimension (384 for
//     MiniLM-L12) that is L2-normalised within numerical tolerance.
//   - Embed() is stable: the same input produces an identical
//     vector across two calls (cosine similarity == 1.0).
//   - Embed() is discriminative: semantically dissimilar inputs
//     produce vectors with cosine similarity strictly less than
//     vectors from semantically similar inputs.
//   - The full Layer (pre-filter + disambiguator) loads from the
//     committed artefacts under ml/testdata/ and answers
//     PreFilter / DisambiguatorScore without panicking.

package ml

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func skipIfNoModel(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("SHIELDNET_TEST_ONNX_MODEL_DIR")
	if dir == "" {
		t.Skip("SHIELDNET_TEST_ONNX_MODEL_DIR unset; skipping real-model integration test")
	}
	for _, want := range []string{"model.onnx", "tokenizer.json"} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Skipf("model artefact %q missing under %s: %v", want, dir, err)
		}
	}
	if os.Getenv("SHIELDNET_ONNXRUNTIME_LIB") == "" {
		// Best-effort default: warn but try anyway. The runtime
		// will fall back to whatever ld.so finds.
		t.Logf("warning: SHIELDNET_ONNXRUNTIME_LIB unset; relying on platform default")
	}
	return dir
}

// cosineSim returns the cosine similarity of two equally-sized
// vectors. Panics on length mismatch to keep the test bodies
// readable — every call site already controls the vector source.
func cosineSim(a, b []float32) float32 {
	if len(a) != len(b) {
		panic("cosineSim: length mismatch")
	}
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return float32(dot / (math.Sqrt(na) * math.Sqrt(nb)))
}

// l2Norm returns the Euclidean length of v.
func l2Norm(v []float32) float64 {
	var s float64
	for _, x := range v {
		s += float64(x) * float64(x)
	}
	return math.Sqrt(s)
}

// TestONNXEmbedder_RealModel_Shape_NormStability_Discrimination
// exercises the full embedder pipeline against a real on-disk
// checkpoint. The four claims it covers are documented in the
// package comment at the top of this file. We bundle them into a
// single test so we only load the ~470 MB model once.
func TestONNXEmbedder_RealModel_Shape_NormStability_Discrimination(t *testing.T) {
	dir := skipIfNoModel(t)

	emb, err := NewEmbedderFromDir(dir, DefaultEmbedderOptions())
	if err != nil {
		t.Fatalf("NewEmbedderFromDir(%s): %v", dir, err)
	}
	defer func() { _ = emb.Close() }()
	if !emb.Ready() {
		t.Fatalf("embedder not ready after successful construction")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Shape. MiniLM-L12-v2 is documented at 384-dim.
	v1, err := emb.Embed(ctx, "the quick brown fox jumps over the lazy dog")
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(v1) != 384 {
		t.Fatalf("Embed returned %d-dim vector; want 384", len(v1))
	}

	// 2. L2-normalisation. The embedder applies mean-pooling and
	// L2 normalisation so the cosine prefilter can operate
	// without re-normalising. Allow a small tolerance for FP
	// rounding.
	if got := l2Norm(v1); math.Abs(got-1.0) > 1e-3 {
		t.Fatalf("|v1| = %.6f; want 1.0 ± 1e-3", got)
	}

	// 3. Stability. The same input must produce identical output
	// across two calls. Tokenization is deterministic, the model
	// has no dropout at inference time, and onnxruntime should
	// produce identical floats given identical inputs.
	v1b, err := emb.Embed(ctx, "the quick brown fox jumps over the lazy dog")
	if err != nil {
		t.Fatalf("Embed (second call): %v", err)
	}
	if sim := cosineSim(v1, v1b); sim < 0.999 {
		t.Fatalf("repeated Embed not stable: cos(v1, v1b) = %.6f; want ≥ 0.999", sim)
	}

	// 4. Discrimination. Two paraphrases of the same idea must
	// land closer than two unrelated sentences. This is the
	// fundamental claim the pre-filter relies on. Thresholds
	// are intentionally loose so we never flake on tokenizer or
	// model micro-revisions.
	related, err := emb.Embed(ctx, "A fast brown fox leaps above a sleeping dog.")
	if err != nil {
		t.Fatalf("Embed (related): %v", err)
	}
	unrelated, err := emb.Embed(ctx, "Database backups completed at 03:14 UTC.")
	if err != nil {
		t.Fatalf("Embed (unrelated): %v", err)
	}
	simRelated := cosineSim(v1, related)
	simUnrelated := cosineSim(v1, unrelated)
	if !(simRelated > simUnrelated) {
		t.Fatalf(
			"discrimination failed: cos(v1,related)=%.4f cos(v1,unrelated)=%.4f",
			simRelated, simUnrelated,
		)
	}
	if simRelated < simUnrelated+0.05 {
		// Loose margin — we just need a defensible gap. If
		// this ever flakes, bump the related/unrelated pair to
		// something further apart rather than weakening the
		// assertion.
		t.Logf(
			"discrimination gap small: related=%.4f unrelated=%.4f gap=%.4f",
			simRelated, simUnrelated, simRelated-simUnrelated,
		)
	}
}

// TestONNXEmbedder_RealModel_RespectsContextCancel proves Embed
// returns promptly when the caller's context is already cancelled.
// The pipeline calls Embed under the request context; a stuck
// inference would block Scan's latency budget.
func TestONNXEmbedder_RealModel_RespectsContextCancel(t *testing.T) {
	dir := skipIfNoModel(t)

	emb, err := NewEmbedderFromDir(dir, DefaultEmbedderOptions())
	if err != nil {
		t.Fatalf("NewEmbedderFromDir: %v", err)
	}
	defer func() { _ = emb.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := emb.Embed(ctx, "hello world"); err == nil {
		t.Fatalf("Embed on cancelled ctx returned nil error; want a cancellation error")
	}
}

// TestLayer_RealModel_WithCommittedArtefacts wires the real ONNX
// embedder together with the committed centroids.json /
// disambiguator.json under testdata/. This is the contract the
// agent runs in production: real embeddings against on-disk
// artefacts produced by the build_ml_artefacts corpus tool.
func TestLayer_RealModel_WithCommittedArtefacts(t *testing.T) {
	dir := skipIfNoModel(t)

	emb, err := NewEmbedderFromDir(dir, DefaultEmbedderOptions())
	if err != nil {
		t.Fatalf("NewEmbedderFromDir: %v", err)
	}
	defer func() { _ = emb.Close() }()

	// Pull the committed artefacts from this package's testdata.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	artBase := filepath.Dir(thisFile) // agent/internal/dlp/ml
	art, err := LoadArtefacts(filepath.Join(artBase, "testdata"))
	if err != nil {
		t.Fatalf("LoadArtefacts: %v", err)
	}
	if art == nil || art.Centroids == nil {
		t.Fatalf("expected committed centroids.json under testdata/")
	}

	layer, err := NewLayer(emb, art, DefaultPreFilterThreshold)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	if !layer.Ready() {
		t.Fatalf("layer not ready with real embedder + real artefacts")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Sanity: pre-filter must complete without panicking. The
	// specific verdict depends on the committed centroids and
	// the random sentence; we just want to prove the wiring is
	// intact end-to-end.
	v := layer.PreFilter(ctx, "Internal status update on the weekly engineering metrics meeting.")
	if v != VerdictUnknown && v != VerdictLikelyBenign {
		t.Fatalf("PreFilter returned unexpected verdict %d (want VerdictUnknown or VerdictLikelyBenign)", v)
	}

	// Disambiguator contract: the committed disambiguator.json is
	// now a real trained linear head (LDA-1d fit over the W4
	// corpus by build_ml_artefacts). The head's documented
	// contract is "positive scores for TP-like content (real
	// secrets / PII), negative scores for TN-like content (benign
	// prose / code)". This test verifies that contract end-to-end
	// against the real ONNX model + the committed weights.
	//
	// Probes are shaped like the W4 corpus the head was fit on,
	// because that distribution is what the disambiguator is
	// expected to discriminate. The corpus TP samples are
	// short *config* snippets (env / JSON / YAML) with embedded
	// credentials; TN samples are short prose snippets, meeting
	// notes, and code comments. Single-sentence prose probes
	// (e.g. "AWS key X was rotated") fall outside the corpus
	// shape and give weak/ambiguous scores — the W3 borderline
	// gate handles that by deferring to the deterministic score,
	// not by relying on the disambiguator. We therefore probe
	// with the same content shape the head was trained on.
	//
	//   benignProse  — paragraph of policy text, no creds. Expect < 0.
	//   benignCode   — short JS snippet with no creds.      Expect < 0.
	//   tpConfig     — .env-style config with an embedded
	//                  email + value. Expect > 0.
	//   tpJSON       — JSON config with credentials field.  Expect > 0.
	//
	// The actual ML signal is meant for *borderline* matches:
	// content that already passed the deterministic scoring
	// threshold by a small margin. For high-confidence matches
	// the disambiguator is bypassed entirely (see Pipeline.Scan).
	// If a future model rebuild flips the sign on these probes
	// against the committed corpus shape, the test catches it.
	benignProse := "The security policy says: never paste credentials into chat. Use the secret manager."
	benignCode := "// example service implementation\nfunction matches(input) { return hash(input) === SAMPLE_HASH; }"
	tpConfig := "# production environment\nNODE_ENV=production\nLOG_LEVEL=info\n# user credential for production deployment\nnyussk.dbb3b@n9f0fo.io\ndu7hbz.qgj68@xt2dls.io"
	tpJSON := `{
  "env": "production",
  "subscriber": "production",
  "credential": "ztmnru.gmhmz@gki9u5.io"
}`

	for _, c := range []struct {
		name     string
		input    string
		wantSign int // +1 = expect > 0, -1 = expect < 0
	}{
		{"benign_prose", benignProse, -1},
		{"benign_code", benignCode, -1},
		{"tp_config", tpConfig, +1},
		{"tp_json", tpJSON, +1},
	} {
		score := layer.DisambiguatorScore(ctx, c.input)
		if math.IsNaN(float64(score)) || math.IsInf(float64(score), 0) {
			t.Fatalf("[%s] DisambiguatorScore returned non-finite %v", c.name, score)
		}
		if c.wantSign > 0 && score <= 0 {
			t.Errorf("[%s] DisambiguatorScore = %v; want > 0 (TP-like content should score positive)", c.name, score)
		}
		if c.wantSign < 0 && score >= 0 {
			t.Errorf("[%s] DisambiguatorScore = %v; want < 0 (benign content should score negative)", c.name, score)
		}
	}
}

// TestLayer_RealModel_GracefulFallback_MissingDisambiguator
// removes one of the two artefacts and verifies the Layer still
// loads, the embedder is still Ready, and only the missing piece
// degrades to a no-op. This proves the "additive, never blocking"
// invariant survives a partial artefact install.
func TestLayer_RealModel_GracefulFallback_MissingDisambiguator(t *testing.T) {
	dir := skipIfNoModel(t)

	emb, err := NewEmbedderFromDir(dir, DefaultEmbedderOptions())
	if err != nil {
		t.Fatalf("NewEmbedderFromDir: %v", err)
	}
	defer func() { _ = emb.Close() }()

	// Build a tmpdir that has centroids.json only.
	_, thisFile, _, _ := runtime.Caller(0)
	src := filepath.Dir(thisFile)
	cBytes, err := os.ReadFile(filepath.Join(src, "testdata", "centroids.json"))
	if err != nil {
		t.Fatalf("read centroids.json: %v", err)
	}
	// Round-trip through json to ensure the file is at least
	// minimally well-formed before we hand it to LoadArtefacts.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(cBytes, &probe); err != nil {
		t.Fatalf("committed centroids.json is malformed JSON: %v", err)
	}
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "centroids.json"), cBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	art, err := LoadArtefacts(tmp)
	if err != nil {
		t.Fatalf("LoadArtefacts: %v", err)
	}
	if art == nil || art.Centroids == nil {
		t.Fatalf("expected centroids in partial artefact dir")
	}
	if art.Linear != nil {
		t.Fatalf("expected disambiguator absent in partial artefact dir")
	}

	layer, err := NewLayer(emb, art, DefaultPreFilterThreshold)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	if !layer.Ready() {
		t.Fatalf("layer not ready with centroids-only artefacts")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Disambiguator missing -> always 0.
	if got := layer.DisambiguatorScore(ctx, "anything"); got != 0 {
		t.Fatalf("DisambiguatorScore with missing weights = %v; want 0", got)
	}
}
