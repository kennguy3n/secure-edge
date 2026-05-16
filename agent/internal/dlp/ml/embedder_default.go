//go:build !onnx

// Default (CGO-free) embedder factory.
//
// Without the `onnx` build tag the agent never links the ONNX
// runtime or the SentencePiece tokenizer. NewEmbedderFromDir
// always returns the NullEmbedder so the rest of the ML layer
// degrades cleanly to "no signal".

package ml

// NewEmbedderFromDir returns NullEmbedder on the default build.
//
// modelDir and opts are accepted for API compatibility with the
// onnx-tagged variant; they are ignored on this build. The
// returned Embedder is always ready=false, dim=0, and Embed
// always returns ErrEmbedderUnavailable.
func NewEmbedderFromDir(modelDir string, opts EmbedderOption) (Embedder, error) {
	_ = modelDir
	_ = opts
	return NullEmbedder{}, nil
}

// BuildTagONNX is false on the default build. The agent uses this
// to short-circuit ML setup logging — there is no point asking the
// operator about a missing model file when the binary cannot use
// one anyway.
const BuildTagONNX = false
