//go:build onnx

// ONNX-backed multilingual sentence-embedder.
//
// This file is compiled only when the agent is built with
// `-tags onnx`. It wires the `paraphrase-multilingual-MiniLM-L12-v2`
// model (or any other XLM-RoBERTa-class model with the same input
// signature) to the DLP pipeline via the package-public Embedder
// interface.
//
// On-disk layout under modelDir:
//
//	<modelDir>/model.onnx        — int8-quantised ONNX export
//	<modelDir>/tokenizer.json    — HuggingFace fast tokenizer JSON
//	<modelDir>/sentencepiece.bpe.model (optional, future use)
//
// At runtime the ONNX shared library is loaded via
// onnxruntime_go.SetSharedLibraryPath(). The path is resolved in
// this order:
//
//   1. The environment variable SHIELDNET_ONNXRUNTIME_LIB, if set.
//   2. <modelDir>/onnxruntime.so / .dylib / .dll, if present.
//   3. The platform default (libonnxruntime.so / .dylib /
//      onnxruntime.dll) located by the dynamic loader.
//
// Failure to load the library, the model, or the tokenizer
// degrades to NullEmbedder — the pipeline must not crash when the
// operator drops only some artefacts into ~/.shieldnet/models/.
//
// Privacy invariant: the embedder runs in-process. No tokens, no
// hidden states, no normalised vectors leave this file. The
// onnxruntime_go library wraps onnxruntime via purego/dlopen so
// the agent does not require CGO; cf. agent/go.mod.

package ml

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	ort "github.com/yalue/onnxruntime_go"

	"github.com/sugarme/tokenizer"
	"github.com/sugarme/tokenizer/pretrained"
)

// onnxInitOnce guards the global onnxruntime environment. The
// onnxruntime C++ library expects InitializeEnvironment() / Destroy
// to be called once per process; the Go wrapper enforces that with
// a global flag. Using sync.Once means concurrent NewONNXEmbedder
// callers see a single, deterministic initialisation.
var (
	onnxInitOnce sync.Once
	onnxInitErr  error
)

// initONNX initialises the global onnxruntime environment, loading
// the shared library from modelDir or the package defaults.
func initONNX(modelDir string) error {
	onnxInitOnce.Do(func() {
		if libPath := resolveSharedLibrary(modelDir); libPath != "" {
			ort.SetSharedLibraryPath(libPath)
		}
		if err := ort.InitializeEnvironment(); err != nil {
			onnxInitErr = fmt.Errorf("ml: onnxruntime init: %w", err)
		}
	})
	return onnxInitErr
}

// resolveSharedLibrary returns the absolute path to the
// onnxruntime shared library, or "" to let onnxruntime_go fall
// back to its platform default. See package doc for the resolution
// order.
func resolveSharedLibrary(modelDir string) string {
	if envPath := os.Getenv("SHIELDNET_ONNXRUNTIME_LIB"); envPath != "" {
		return envPath
	}
	if modelDir == "" {
		return ""
	}
	switch runtime.GOOS {
	case "linux":
		if p := filepath.Join(modelDir, "onnxruntime.so"); fileExists(p) {
			return p
		}
		if p := filepath.Join(modelDir, "libonnxruntime.so"); fileExists(p) {
			return p
		}
	case "darwin":
		if p := filepath.Join(modelDir, "onnxruntime.dylib"); fileExists(p) {
			return p
		}
		if p := filepath.Join(modelDir, "libonnxruntime.dylib"); fileExists(p) {
			return p
		}
	case "windows":
		if p := filepath.Join(modelDir, "onnxruntime.dll"); fileExists(p) {
			return p
		}
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// ONNXEmbedder is the real Embedder implementation backed by
// onnxruntime + a SentencePiece tokenizer. It satisfies the
// Embedder interface and is safe for concurrent calls (an internal
// mutex serialises tensor mutation on the single bound session).
//
// The embedder uses XLM-RoBERTa-compatible inputs:
//
//	input_ids       int64 [1, seq_len]
//	attention_mask  int64 [1, seq_len]
//
// And produces a mean-pooled, L2-normalised embedding from the
// model's last_hidden_state output. Mean pooling is masked by the
// attention mask so padding tokens never contribute. Normalisation
// makes the vector directly comparable with the centroids stored in
// centroids.json via plain cosine similarity (which becomes a dot
// product on unit vectors).
type ONNXEmbedder struct {
	tk        *tokenizer.Tokenizer
	session   *ort.DynamicAdvancedSession
	maxSeqLen int
	hidden    int // embedding dimension
	inputName string
	maskName  string
	typeName  string // token_type_ids name, or "" when the model does not declare it
	outName   string

	mu sync.Mutex // serialises session.Run
}

// NewEmbedderFromDir wires a real ONNXEmbedder if modelDir holds
// the required artefacts, or NullEmbedder otherwise. This is the
// onnx-tagged variant of the package-public factory; the
// !onnx build always returns NullEmbedder.
//
// Returning (NullEmbedder, nil) on missing artefacts is
// intentional: the agent's startup logs the degraded mode once but
// does not exit, so a deployment that ships the agent without the
// model still runs the deterministic pipeline.
func NewEmbedderFromDir(modelDir string, opts EmbedderOption) (Embedder, error) {
	if modelDir == "" {
		return NullEmbedder{}, nil
	}
	modelPath := filepath.Join(modelDir, "model.onnx")
	tokenizerPath := filepath.Join(modelDir, "tokenizer.json")
	if !fileExists(modelPath) || !fileExists(tokenizerPath) {
		return NullEmbedder{}, nil
	}
	if opts.MaxSeqLen <= 0 {
		opts = DefaultEmbedderOptions()
	}

	if err := initONNX(modelDir); err != nil {
		return NullEmbedder{}, err
	}

	tk, err := pretrained.FromFile(tokenizerPath)
	if err != nil {
		return NullEmbedder{}, fmt.Errorf("ml: load tokenizer: %w", err)
	}

	// Discover the model's input / output names + hidden dim via
	// onnxruntime's metadata reflection. The MiniLM/XLM-R export
	// always has input_ids + attention_mask as inputs and
	// last_hidden_state (or sentence_embedding) as the output,
	// but we reflect rather than hard-code to keep the embedder
	// model-agnostic — operators may ship a fine-tuned export.
	inputInfos, outputInfos, err := ort.GetInputOutputInfo(modelPath)
	if err != nil {
		return NullEmbedder{}, fmt.Errorf("ml: inspect model: %w", err)
	}
	inputNames := infoNames(inputInfos)
	outputNames := infoNames(outputInfos)

	inputName := pickInput(inputNames, "input_ids")
	maskName := pickInput(inputNames, "attention_mask")
	// token_type_ids is optional: present in BERT/XLM-R fp32
	// exports, often missing in distilled / quantised exports.
	// We pass it (zero-filled) only when the model declares it.
	typeName := pickOptionalInput(inputNames, "token_type_ids")
	outName := pickInput(outputNames, "last_hidden_state", "sentence_embedding", "embeddings")
	if inputName == "" || maskName == "" || outName == "" {
		return NullEmbedder{}, fmt.Errorf("ml: unrecognised model inputs/outputs (have inputs=%v outputs=%v)",
			inputNames, outputNames)
	}
	inputs := []string{inputName, maskName}
	if typeName != "" {
		inputs = append(inputs, typeName)
	}

	sessOpts, err := ort.NewSessionOptions()
	if err != nil {
		return NullEmbedder{}, fmt.Errorf("ml: session options: %w", err)
	}
	defer sessOpts.Destroy()
	if opts.Threads > 0 {
		// Bounded intra-op threads so the ML layer does not
		// starve the rest of the agent.
		_ = sessOpts.SetIntraOpNumThreads(opts.Threads)
		_ = sessOpts.SetInterOpNumThreads(1)
	}

	session, err := ort.NewDynamicAdvancedSession(
		modelPath,
		inputs,
		[]string{outName},
		sessOpts,
	)
	if err != nil {
		return NullEmbedder{}, fmt.Errorf("ml: create session: %w", err)
	}

	// Probe the output shape with a 1-token input so we know the
	// hidden dimension up front. Without this Dim() would lie.
	hidden, err := probeHiddenDim(session, typeName != "")
	if err != nil {
		_ = session.Destroy()
		return NullEmbedder{}, fmt.Errorf("ml: probe hidden dim: %w", err)
	}

	return &ONNXEmbedder{
		tk:        tk,
		session:   session,
		maxSeqLen: opts.MaxSeqLen,
		hidden:    hidden,
		inputName: inputName,
		maskName:  maskName,
		typeName:  typeName,
		outName:   outName,
	}, nil
}

// infoNames extracts the Name field from each InputOutputInfo so
// downstream lookups can use a single []string instead of carrying
// the full info struct.
func infoNames(items []ort.InputOutputInfo) []string {
	out := make([]string, len(items))
	for i := range items {
		out[i] = items[i].Name
	}
	return out
}

// pickInput returns the first name in names that matches any of
// the supplied preferred labels (case-sensitive). If none match,
// returns the first name when there is exactly one input — the
// fall-back for single-input/output models with non-standard names.
func pickInput(names []string, preferred ...string) string {
	for _, want := range preferred {
		for _, n := range names {
			if n == want {
				return n
			}
		}
	}
	if len(names) == 1 {
		return names[0]
	}
	return ""
}

// pickOptionalInput returns the matching name or "" when no name
// matches. Used for inputs that are not required by every export
// (e.g. token_type_ids).
func pickOptionalInput(names []string, want string) string {
	for _, n := range names {
		if n == want {
			return n
		}
	}
	return ""
}

// probeHiddenDim runs a one-token forward pass to learn the
// model's hidden dimension. Cheap (a handful of milliseconds) and
// avoids the embarrassment of reporting Dim()==0 from a real
// embedder. withTokenTypeIds adds a zero-filled token_type_ids
// input for models that declare it.
func probeHiddenDim(session *ort.DynamicAdvancedSession, withTokenTypeIds bool) (int, error) {
	idsShape := ort.NewShape(1, 1)
	maskShape := ort.NewShape(1, 1)
	ids, err := ort.NewTensor(idsShape, []int64{0})
	if err != nil {
		return 0, err
	}
	defer ids.Destroy()
	mask, err := ort.NewTensor(maskShape, []int64{1})
	if err != nil {
		return 0, err
	}
	defer mask.Destroy()

	inputs := []ort.Value{ids, mask}
	if withTokenTypeIds {
		typeIds, err := ort.NewTensor(ort.NewShape(1, 1), []int64{0})
		if err != nil {
			return 0, err
		}
		defer typeIds.Destroy()
		inputs = append(inputs, typeIds)
	}

	outputs := make([]ort.Value, 1)
	if err := session.Run(inputs, outputs); err != nil {
		return 0, err
	}
	defer func() {
		if outputs[0] != nil {
			_ = outputs[0].Destroy()
		}
	}()

	tensor, ok := outputs[0].(*ort.Tensor[float32])
	if !ok {
		return 0, fmt.Errorf("ml: unexpected output tensor type %T", outputs[0])
	}
	shape := tensor.GetShape()
	if len(shape) == 0 {
		return 0, errors.New("ml: empty output shape")
	}
	return int(shape[len(shape)-1]), nil
}

// Embed implements Embedder.
func (e *ONNXEmbedder) Embed(ctx context.Context, content string) ([]float32, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e == nil || e.session == nil {
		return nil, ErrEmbedderUnavailable
	}

	// Tokenise. AddSpecialTokens=true so the XLM-R CLS / SEP
	// tokens are inserted; the model is trained with them.
	encInput := tokenizer.NewSingleEncodeInput(tokenizer.NewInputSequence(content))
	enc, err := e.tk.Encode(encInput, true)
	if err != nil {
		return nil, fmt.Errorf("ml: tokenize: %w", err)
	}

	ids := truncateInt64(enc.GetIds(), e.maxSeqLen)
	mask := truncateInt64(enc.GetAttentionMask(), e.maxSeqLen)
	if len(ids) == 0 {
		return nil, ErrEmbedderUnavailable
	}

	// Build input tensors. Shape: [1, seq_len].
	idsTensor, err := ort.NewTensor(ort.NewShape(1, int64(len(ids))), ids)
	if err != nil {
		return nil, fmt.Errorf("ml: ids tensor: %w", err)
	}
	defer idsTensor.Destroy()
	maskTensor, err := ort.NewTensor(ort.NewShape(1, int64(len(mask))), mask)
	if err != nil {
		return nil, fmt.Errorf("ml: mask tensor: %w", err)
	}
	defer maskTensor.Destroy()

	inputTensors := []ort.Value{idsTensor, maskTensor}
	var typeIdsTensor *ort.Tensor[int64]
	if e.typeName != "" {
		typeIds := make([]int64, len(ids)) // zero-filled
		var tErr error
		typeIdsTensor, tErr = ort.NewTensor(ort.NewShape(1, int64(len(ids))), typeIds)
		if tErr != nil {
			return nil, fmt.Errorf("ml: type_ids tensor: %w", tErr)
		}
		defer typeIdsTensor.Destroy()
		inputTensors = append(inputTensors, typeIdsTensor)
	}

	outputs := make([]ort.Value, 1)
	e.mu.Lock()
	runErr := e.session.Run(inputTensors, outputs)
	e.mu.Unlock()
	if runErr != nil {
		return nil, fmt.Errorf("ml: session run: %w", runErr)
	}
	defer func() {
		if outputs[0] != nil {
			_ = outputs[0].Destroy()
		}
	}()

	tensor, ok := outputs[0].(*ort.Tensor[float32])
	if !ok {
		return nil, fmt.Errorf("ml: unexpected output tensor type %T", outputs[0])
	}

	// shape is [1, seq_len, hidden] for last_hidden_state, or
	// [1, hidden] for the (rarer) sentence_embedding output.
	shape := tensor.GetShape()
	data := tensor.GetData()

	switch len(shape) {
	case 2:
		// Already pooled by the model. Just L2-normalise.
		out := make([]float32, shape[1])
		copy(out, data)
		l2Normalize(out)
		return out, nil
	case 3:
		// [batch=1, seq_len, hidden]. Apply masked mean-pooling.
		seq := int(shape[1])
		hid := int(shape[2])
		if hid != e.hidden {
			// Model's hidden dim shifted under us — refuse
			// to mix dimensions. Caller will treat as no
			// signal.
			return nil, fmt.Errorf("ml: hidden dim mismatch: got %d want %d", hid, e.hidden)
		}
		return meanPool(data, mask, seq, hid), nil
	default:
		return nil, fmt.Errorf("ml: unexpected output shape %v", shape)
	}
}

// Dim implements Embedder.
func (e *ONNXEmbedder) Dim() int {
	if e == nil {
		return 0
	}
	return e.hidden
}

// Ready implements Embedder.
func (e *ONNXEmbedder) Ready() bool {
	return e != nil && e.session != nil && e.tk != nil
}

// Close implements Embedder. Safe to call multiple times.
func (e *ONNXEmbedder) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session != nil {
		_ = e.session.Destroy()
		e.session = nil
	}
	return nil
}

// truncateInt64 widens uint32 token ids / mask values to int64
// (the dtype the XLM-R ONNX export expects) and truncates to max.
// Tokenizers libraries vary in whether they return int or uint32;
// we accept []int and convert.
func truncateInt64(src []int, max int) []int64 {
	if max <= 0 || len(src) <= max {
		max = len(src)
	}
	out := make([]int64, max)
	for i := 0; i < max; i++ {
		out[i] = int64(src[i])
	}
	return out
}

// meanPool applies masked mean-pooling across the seq dimension
// and L2-normalises the resulting hidden-dim vector.
//
// data is laid out as [seq_len][hidden] in row-major order; mask
// is [seq_len]. Padding tokens (mask==0) are excluded from the
// average so the embedding represents the content only, not the
// padding distribution.
func meanPool(data []float32, mask []int64, seq, hidden int) []float32 {
	out := make([]float32, hidden)
	var denom float32
	for t := 0; t < seq; t++ {
		if t >= len(mask) {
			break
		}
		if mask[t] == 0 {
			continue
		}
		denom++
		base := t * hidden
		for h := 0; h < hidden; h++ {
			out[h] += data[base+h]
		}
	}
	if denom == 0 {
		return out
	}
	for h := 0; h < hidden; h++ {
		out[h] /= denom
	}
	l2Normalize(out)
	return out
}

// l2Normalize divides each element by the L2 norm of the vector,
// in place. Vectors whose norm is below a tiny epsilon are left
// untouched so we never divide by zero.
func l2Normalize(v []float32) {
	var sq float64
	for _, x := range v {
		sq += float64(x) * float64(x)
	}
	norm := math.Sqrt(sq)
	if norm < 1e-12 {
		return
	}
	inv := float32(1.0 / norm)
	for i := range v {
		v[i] *= inv
	}
}

// BuildTagONNX is true on the onnx build. The agent uses this to
// decide whether to log "ONNX runtime available but no model
// present" vs "ONNX runtime not built in".
const BuildTagONNX = true
