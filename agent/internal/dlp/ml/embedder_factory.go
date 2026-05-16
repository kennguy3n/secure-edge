// Cross-build embedder factory.
//
// The ml package exposes a single entry point — NewEmbedderFromDir
// — so callers do not have to know whether the agent was built with
// the `onnx` tag. Without the tag the factory returns NullEmbedder
// unconditionally; with the tag it tries to wire a real
// ONNXEmbedder against the artefacts in modelDir and falls back to
// NullEmbedder on any failure (missing files, runtime not present,
// tokenizer parse error, …).
//
// Splitting the factory across embedder_default.go (no tag) and
// embedder_onnx.go (`//go:build onnx`) lets the default agent
// binary stay CGO-free and dependency-light while the onnx-tagged
// build pulls in onnxruntime_go and the SentencePiece tokenizer.

package ml

// EmbedderOption tweaks how NewEmbedderFromDir builds the embedder.
// All zero-valued fields mean "use the package defaults".
//
// MaxSeqLen caps the number of tokens the embedder will pass to the
// underlying model. The XLM-RoBERTa family is trained at 512 tokens;
// the DLP pipeline does not benefit from longer contexts because
// the scan content is already chunked. Truncation is applied after
// tokenization, before model inference.
//
// Threads, when > 0, sets the ONNX runtime intra-op thread count.
// Zero leaves the default ("use all available cores"). The agent
// runs inside a constrained process and operators may want to cap
// parallelism so the ML layer cannot starve the rest of the agent;
// the documented default is 1 to keep tail-latency predictable.
type EmbedderOption struct {
	MaxSeqLen int
	Threads   int
}

// DefaultEmbedderOptions returns the option set the agent's
// production path uses.
func DefaultEmbedderOptions() EmbedderOption {
	return EmbedderOption{
		MaxSeqLen: 128, // DLP scans are short snippets; 128 is plenty.
		Threads:   1,   // Bounded latency over peak throughput.
	}
}
