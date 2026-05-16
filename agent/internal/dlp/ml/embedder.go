package ml

import (
	"context"
	"errors"
)

// Embedder produces a fixed-size sentence-embedding vector for a
// piece of text. Implementations must be safe for concurrent calls;
// the DLP pipeline invokes the embedder from inside Scan and Scan is
// already called concurrently from multiple goroutines (paste hook,
// form-submit hook, fetch hook).
//
// Implementations must complete within a small bounded latency
// budget (default 10 ms on commodity CPU for the L12 model). If the
// model is missing, the runtime libraries are not loaded, or any
// other initialisation step fails, NewEmbedder must return a
// non-nil Null implementation whose Embed always returns
// ErrEmbedderUnavailable. Callers rely on this to fall back to the
// deterministic pipeline without further error handling.
type Embedder interface {
	// Embed returns the sentence-embedding vector for content.
	// The returned slice length is implementation-defined but
	// must be stable across a single Embedder instance (callers
	// cache centroids of the same length).
	//
	// Returns ErrEmbedderUnavailable when the underlying model
	// is not loaded. Returns context.Canceled / context.DeadlineExceeded
	// when ctx is done. All other errors mean the call failed
	// for a transient reason — callers should treat the result
	// as "no signal" and skip ML augmentation for this scan.
	Embed(ctx context.Context, content string) ([]float32, error)

	// Dim returns the embedding dimension. Stable for the lifetime
	// of an Embedder. Implementations that have not loaded a model
	// (the Null embedder, or a failed-load real embedder) return 0.
	Dim() int

	// Ready reports whether the underlying model is loaded and
	// the embedder will produce real signal. The Null embedder
	// always returns false; a real embedder returns true after
	// successful model + tokenizer load.
	Ready() bool

	// Close releases any resources (memory-mapped weights, ONNX
	// session, tokenizer). Safe to call multiple times.
	Close() error
}

// ErrEmbedderUnavailable is returned by the Null embedder's Embed
// (and by a real embedder whose model failed to load). Callers in
// the DLP pipeline check errors.Is(err, ErrEmbedderUnavailable) to
// distinguish "ML layer not active" from "ML layer crashed".
var ErrEmbedderUnavailable = errors.New("ml: embedder unavailable")

// NullEmbedder is an Embedder that never produces signal. It is the
// default Embedder for the DLP pipeline; the ONNX-backed embedder
// replaces it only when:
//
//  1. the agent was built with `-tags onnx`, and
//  2. the ONNX runtime shared library can be loaded, and
//  3. the configured model and tokenizer artefacts are present.
//
// When any of those conditions fails, the pipeline keeps the
// NullEmbedder and the ML augmentation layer becomes a no-op.
type NullEmbedder struct{}

// NewNullEmbedder returns a NullEmbedder. The constructor exists so
// callers do not have to know about the concrete type.
func NewNullEmbedder() *NullEmbedder { return &NullEmbedder{} }

// Embed always returns ErrEmbedderUnavailable.
func (NullEmbedder) Embed(ctx context.Context, _ string) ([]float32, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrEmbedderUnavailable
}

// Dim returns 0 — the Null embedder does not produce vectors.
func (NullEmbedder) Dim() int { return 0 }

// Ready returns false — the Null embedder is never "ready".
func (NullEmbedder) Ready() bool { return false }

// Close is a no-op for the NullEmbedder.
func (NullEmbedder) Close() error { return nil }
