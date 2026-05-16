//go:build onnx

// build_ml_artefacts reads the synthetic TP/TN corpus under
// agent/internal/dlp/testdata/corpus/ and writes the two sidecar
// files the ML layer expects under
// agent/internal/dlp/ml/testdata/:
//
//	centroids.json       — mean-embedding for TP and TN samples
//	disambiguator.json   — linear head (zero-initialised; pure
//	                       cosine pre-filter signal until offline
//	                       training ships)
//
// The tool requires a fully-loaded ONNX model at
// ~/.shieldnet/models/model (or the directory passed as -model).
// It is intended to be run by maintainers once per model release
// — the resulting JSON files are committed to the repo so the test
// suite and the agent's default install path always have a
// reasonable starting set of artefacts.
//
// Usage:
//
//	# default in/out paths, default model directory
//	go run -tags=onnx ./internal/dlp/cmd/build_ml_artefacts
//
//	# explicit overrides
//	go run -tags=onnx ./internal/dlp/cmd/build_ml_artefacts \
//	    -corpus agent/internal/dlp/testdata/corpus \
//	    -out    agent/internal/dlp/ml/testdata \
//	    -model  ~/.shieldnet/models/model \
//	    -max-samples 200
//
// Privacy invariant: this tool only reads the test corpus and the
// configured model directory. It does not phone home, does not log
// scan content (only counts), and writes outputs exclusively to
// the configured output directory.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kennguy3n/secure-edge/agent/internal/dlp/ml"
)

func main() {
	var (
		corpusDir  = flag.String("corpus", "agent/internal/dlp/testdata/corpus", "Corpus root containing true_positives/ and true_negatives/")
		outDir     = flag.String("out", "agent/internal/dlp/ml/testdata", "Output directory for centroids.json + disambiguator.json")
		modelDir   = flag.String("model", "", "ONNX model directory (default: ~/.shieldnet/models/model)")
		maxSamples = flag.Int("max-samples", 0, "Cap per-side sample count (0 = use everything)")
		threads    = flag.Int("threads", 1, "ONNX intra-op thread count")
	)
	flag.Parse()

	if *modelDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fatal("locate home dir: %v", err)
		}
		*modelDir = filepath.Join(home, ".shieldnet", "models", "model")
	}

	// Resolve corpusDir / outDir to absolute paths anchored at the
	// repo root if the caller passed a relative path.
	absCorpus, err := filepath.Abs(*corpusDir)
	if err != nil {
		fatal("abs corpus: %v", err)
	}
	absOut, err := filepath.Abs(*outDir)
	if err != nil {
		fatal("abs out: %v", err)
	}

	fmt.Printf("build_ml_artefacts:\n  corpus: %s\n  out:    %s\n  model:  %s\n", absCorpus, absOut, *modelDir)

	emb, err := ml.NewEmbedderFromDir(*modelDir, ml.EmbedderOption{MaxSeqLen: 128, Threads: *threads})
	if err != nil {
		fatal("load embedder: %v", err)
	}
	defer emb.Close()
	if !emb.Ready() {
		fatal("embedder not ready (model files missing under %q?)", *modelDir)
	}
	dim := emb.Dim()
	fmt.Printf("  embedder ready: dim=%d\n\n", dim)

	tpSamples, err := collectSamples(filepath.Join(absCorpus, "true_positives"), *maxSamples)
	if err != nil {
		fatal("collect TP samples: %v", err)
	}
	tnSamples, err := collectSamples(filepath.Join(absCorpus, "true_negatives"), *maxSamples)
	if err != nil {
		fatal("collect TN samples: %v", err)
	}
	fmt.Printf("  collected: TP=%d  TN=%d\n", len(tpSamples), len(tnSamples))
	if len(tpSamples) == 0 || len(tnSamples) == 0 {
		fatal("empty TP or TN sample set; corpus path correct?")
	}

	t0 := time.Now()
	tpCentroid, err := computeCentroid(emb, tpSamples, dim, "TP")
	if err != nil {
		fatal("TP centroid: %v", err)
	}
	tnCentroid, err := computeCentroid(emb, tnSamples, dim, "TN")
	if err != nil {
		fatal("TN centroid: %v", err)
	}
	fmt.Printf("  centroids computed in %s\n", time.Since(t0).Round(time.Millisecond))

	cosTPTN := cosineSimilarity(tpCentroid, tnCentroid)
	fmt.Printf("  centroid cos(TP, TN) = %+.4f (lower is better; this is the gap the pre-filter exploits)\n", cosTPTN)

	if err := writeCentroids(filepath.Join(absOut, "centroids.json"), tpCentroid, tnCentroid); err != nil {
		fatal("write centroids: %v", err)
	}
	if err := writeDisambiguator(filepath.Join(absOut, "disambiguator.json"), dim); err != nil {
		fatal("write disambiguator: %v", err)
	}
	fmt.Printf("  wrote %s\n  wrote %s\n", filepath.Join(absOut, "centroids.json"), filepath.Join(absOut, "disambiguator.json"))
}

// collectSamples walks root looking for *.jsonl files and returns
// the `content` field from each line. The corpus generator emits
// lines like
//
//	{"category":"pii_eu","content":"IBAN: GB29NWBK60161331926819","expect_blocked":true,...}
//
// We do not retain anything else; only the raw content is needed
// for embedding.
func collectSamples(root string, maxPerSide int) ([]string, error) {
	var samples []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
		for sc.Scan() {
			// The corpus generator writes either `content`
			// (plain UTF-8) or `content_b64` (base64 of the
			// payload bytes — used so embedded NULs and
			// binary blobs round-trip cleanly through JSON).
			// Read both.
			var rec struct {
				Content    string `json:"content"`
				ContentB64 string `json:"content_b64"`
			}
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				continue
			}
			content := rec.Content
			if content == "" && rec.ContentB64 != "" {
				raw, err := base64.StdEncoding.DecodeString(rec.ContentB64)
				if err != nil {
					continue
				}
				content = string(raw)
			}
			if content == "" {
				continue
			}
			samples = append(samples, content)
		}
		return sc.Err()
	})
	if err != nil {
		return nil, err
	}
	// Sort for determinism so identical corpus + identical model
	// always produces identical centroids.
	sort.Strings(samples)
	if maxPerSide > 0 && len(samples) > maxPerSide {
		samples = samples[:maxPerSide]
	}
	return samples, nil
}

// computeCentroid embeds every sample and returns the L2-normalised
// mean. Logs a progress line every 500 samples so a maintainer can
// see the tool is alive on a large corpus.
func computeCentroid(emb ml.Embedder, samples []string, dim int, label string) ([]float32, error) {
	mean := make([]float64, dim)
	ctx := context.Background()
	var counted int
	for i, s := range samples {
		v, err := emb.Embed(ctx, s)
		if err != nil {
			// Skip pathological inputs (tokeniser returns
			// nothing, runtime errors). Centroid is robust
			// to losing a few samples.
			continue
		}
		if len(v) != dim {
			return nil, fmt.Errorf("sample %d: embedding dim %d, want %d", i, len(v), dim)
		}
		for h := 0; h < dim; h++ {
			mean[h] += float64(v[h])
		}
		counted++
		if (i+1)%500 == 0 {
			fmt.Printf("    %s: %d/%d (%.1f%%)\n", label, i+1, len(samples), 100*float64(i+1)/float64(len(samples)))
		}
	}
	if counted == 0 {
		return nil, fmt.Errorf("no samples produced embeddings")
	}
	out := make([]float32, dim)
	inv := 1.0 / float64(counted)
	for h := 0; h < dim; h++ {
		out[h] = float32(mean[h] * inv)
	}
	// L2-normalise the centroid so cosine-similarity against
	// other L2-normalised embeddings reduces to a dot product.
	var sq float64
	for _, x := range out {
		sq += float64(x) * float64(x)
	}
	if sq > 0 {
		inv := 1.0 / math.Sqrt(sq)
		for h := range out {
			out[h] = float32(float64(out[h]) * inv)
		}
	}
	fmt.Printf("    %s centroid: counted=%d/%d  ||c||=1.0\n", label, counted, len(samples))
	return out, nil
}

// cosineSimilarity assumes both vectors are unit-norm and returns
// the dot product (== cosine similarity for unit vectors). Defined
// here, rather than reusing the ml package's helper, to keep the
// command independent of the package's internal contract.
func cosineSimilarity(a, b []float32) float32 {
	var s float64
	for i := range a {
		s += float64(a[i]) * float64(b[i])
	}
	return float32(s)
}

// writeCentroids serialises the centroids in the JSON shape the ml
// package's loader expects.
func writeCentroids(path string, tp, tn []float32) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	doc := struct {
		Dim int       `json:"dim"`
		TP  []float32 `json:"tp"`
		TN  []float32 `json:"tn"`
	}{
		Dim: len(tp),
		TP:  tp,
		TN:  tn,
	}
	return writeJSON(path, doc)
}

// writeDisambiguator writes a zero-initialised linear head. Pure
// cosine pre-filter signal until an offline trainer ships real
// weights. Using zeros (rather than omitting the file) means the
// loader exercises the same code path in tests as it will in
// production after the head is trained.
func writeDisambiguator(path string, dim int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	doc := struct {
		Weights []float32 `json:"weights"`
		Bias    float32   `json:"bias"`
	}{
		Weights: make([]float32, dim),
		Bias:    0,
	}
	return writeJSON(path, doc)
}

// writeJSON marshals doc with a stable 2-space indent so the
// committed artefacts diff cleanly across runs.
func writeJSON(path string, doc any) error {
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "build_ml_artefacts: "+format+"\n", args...)
	os.Exit(1)
}
