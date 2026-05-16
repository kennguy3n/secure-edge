// Package ml hosts the optional ML-augmented detection layer for the
// DLP pipeline (workstream W3, draft).
//
// The DLP pipeline is fully deterministic by default — classifier,
// Aho-Corasick prefix scan, regex validation, hotword proximity,
// entropy, exclusion, scoring, threshold — and stays that way even
// when this package is linked in: every entry point falls back to a
// no-op Null implementation when the ONNX runtime, model file, or
// tokenizer artefact is missing. ML is a *signal* layered on top of
// the deterministic pipeline, never a replacement for it.
//
// Two integration points:
//
//   - Pre-filter (Pipeline.Scan): the embedder produces a single
//     sentence vector for the scan content; the pre-filter compares
//     it to two centroids (true-positive / true-negative) built at
//     corpus-build time. When the cosine distance to the TN centroid
//     is much smaller than to the TP centroid the pipeline skips the
//     expensive regex + AC steps and returns a fast "not blocked"
//     verdict. The threshold is conservative — pre-filter never
//     skips on the basis of low confidence.
//
//   - Disambiguator (ScoreMatch): an optional ML score is added to
//     ScoreInput. The scorer only consults it for *borderline* hits
//     (per-severity threshold ± mlBorderlineWidth). High-confidence
//     deterministic verdicts are unchanged regardless of what the ML
//     classifier says. The disambiguator can lift a borderline match
//     above the threshold or pull it just under, never lift a clear
//     non-match across the line.
//
// Privacy invariant: all model artefacts are loaded from local disk
// (default ~/.shieldnet/models). The embedder runs in-process; no
// embedding vector, no model output, and no scanned content leaves
// the process. The package never opens a network socket, never
// writes to disk, and never logs the scan content. Counters exposed
// through the pipeline metrics surface are anonymous integers only.
//
// Multilingual coverage: the default model is
// paraphrase-multilingual-MiniLM-L12-v2 (int8 quantised, ~45 MB),
// distilled from XLM-RoBERTa; it covers the 50+ languages in the
// XLM-R training set, including all W4 jurisdictions (CJK, Arabic,
// Thai, Hindi, European). The interface is model-agnostic — any
// sentence-embedding ONNX export with a comparable hidden size will
// drop in.
//
// Build tags:
//
//   - Default build: only this package's Null implementation is
//     linked. Agent works exactly as before; the ML layer is a
//     no-op. CI builds without ONNX runtime libraries installed
//     hit this path.
//
//   - Build tag `onnx`: the ONNX-backed implementation in
//     ml_onnx.go is linked in. Requires the ONNX runtime C++
//     shared library to be present at link/load time (bundled by
//     release.yml per OS).
package ml
