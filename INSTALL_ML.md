# Installing the ML-augmented Detection Layer (W3)

The default ShieldNet Secure Edge build is fully functional **without
any ML artefacts** — every code path falls back to `NullEmbedder`
and the deterministic pipeline retains veto power on every block
decision. The optional ML layer (Workstream 3 / W3) bolts on top of
the deterministic pipeline as a *pre-filter* + *disambiguator*; it
can speed up clearly-benign content and resolve borderline cases,
but never overrides a confident deterministic decision.

This document describes the end-to-end install workflow for that
optional layer on Linux, macOS, and Windows.

## Quick start (Linux / macOS, x86_64 or arm64)

From the repo root:

```bash
cd agent
make install
```

That's it. The `install` target runs three steps:

1. **`install-onnx-runtime`** — downloads the official Microsoft
   `onnxruntime` CPU shared library for your OS/arch from
   <https://github.com/microsoft/onnxruntime/releases>, verifies its
   SHA-256 against `scripts/onnxruntime-manifest.txt`, and drops it
   at `~/.shieldnet/models/model/libonnxruntime.{so,dylib}`.
2. **`install-ml`** — downloads the int8-quantised
   [`paraphrase-multilingual-MiniLM-L12-v2`](https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2)
   sentence-embedder (118 MB) from Hugging Face, verifies its
   SHA-256 against `scripts/ml-model-manifest.txt`, and writes
   `model.onnx`, `tokenizer.json`, `sentencepiece.bpe.model` into
   the same directory.
3. **`build-onnx`** — builds `secure-edge-agent` with `-tags=onnx`,
   so it uses the real `ONNXEmbedder` instead of `NullEmbedder` at
   runtime. This build requires `CGO_ENABLED=1` and a system C
   toolchain (`gcc` on Linux, Xcode CLT on macOS, MSVC build tools
   or MinGW on Windows) — `onnxruntime_go` uses cgo for the dlopen /
   ABI shim. The default `make build` is unchanged and stays
   CGO-free; only the `-tags=onnx` path needs the C toolchain.
   At runtime, `libonnxruntime` is still loaded dynamically via
   dlopen, so the binary is portable across machines as long as the
   pinned shared library is reachable.

After the install completes, edit your `config.yaml` and set:

```yaml
dlp_ml_boost: 1                     # 0..3 inclusive; 0 disables ML
# dlp_ml_model_dir: ~/.shieldnet/models    # only if you used a custom path
```

That's the only flag that flips the ML layer on. With
`dlp_ml_boost: 0` (the default), the agent will not even load the
model — the deterministic pipeline runs exactly as it did pre-W3.

## What the install puts on disk

```
~/.shieldnet/models/
├── centroids.json                     # TP/TN mean embeddings (LDA-1d input)
├── disambiguator.json                 # 384-d linear head, fit from corpus
└── model/
    ├── libonnxruntime.so              # CPU shared library (Linux x64/arm64)
    │   (or libonnxruntime.dylib on macOS, onnxruntime.dll on Windows)
    ├── model.onnx                     # 118 MB int8-quantised MiniLM-L12
    ├── tokenizer.json                 # HuggingFace fast tokenizer JSON
    └── sentencepiece.bpe.model        # SentencePiece BPE model
```

`centroids.json` and `disambiguator.json` sit at the base level
because `ml.LoadArtefacts(base)` reads them from `<base>/`, not
`<base>/model/`. Without them the ONNX session still loads but
`Layer.Ready()` stays `false` (no pre-filter, no disambiguator).

Disk footprint: ~133 MB total (118 MB model + 9 MB tokenizer +
5 MB SentencePiece + ~1 MB onnxruntime + ~20 KB sidecars; the
runtime is small because it's the CPU build, not GPU/CUDA).

## Memory footprint at runtime

- Initial load: ~120–140 MB resident (model weights + onnxruntime
  arena).
- Per-scan: bounded by the embedder's mean-pool — the agent
  serialises tensor mutation through a single mutex so concurrent
  scans queue, they do not multiply memory.
- Inference latency: ~5–8 ms per 128-token sequence on a modern CPU.

## Privacy invariants

- **No content leaves the process.** The embedder runs entirely
  in-process via `dlopen` of the system-local onnxruntime library.
- **No vectors leave the process.** Embeddings are computed,
  consumed by the pre-filter / disambiguator, and discarded. No
  caching to disk, no telemetry, no analytics.
- **Pinned downloads.** Both the model and the onnxruntime archive
  are SHA-256-pinned via committed manifest files. A tampered
  upstream artefact triggers a hard failure during install.
- **Reversible.** `rm -rf ~/.shieldnet/models && go build
  ./cmd/agent` returns to the deterministic-only build.

## Manual install (Linux / macOS)

If you don't want to use `make install`, you can run each step by
hand:

```bash
# 1. onnxruntime shared library
./scripts/fetch-onnxruntime.sh

# 2. model + tokenizer
./scripts/fetch-ml-model.sh

# 3. agent build
cd agent && go build -tags=onnx ./cmd/agent
```

Both scripts accept `-d <path>` to install to a non-default
location, and `--no-pin` if you need to skip SHA-256 enforcement
(not recommended).

## Windows install

`fetch-onnxruntime.sh` does not currently install the Windows DLL
because it is distributed as a `.zip` rather than `.tar.gz`. For
Windows hosts:

1. Download
   <https://github.com/microsoft/onnxruntime/releases/download/v1.25.0/onnxruntime-win-x64-1.25.0.zip>.
2. Verify the SHA-256 matches the value in
   `scripts/onnxruntime-manifest.txt` (line ending in
   `onnxruntime-win-x64-1.25.0.zip`).
3. Extract `onnxruntime.dll` from the archive's `lib/` directory.
4. Place it at `%USERPROFILE%\.shieldnet\models\model\onnxruntime.dll`,
   or set the `SHIELDNET_ONNXRUNTIME_LIB` environment variable to
   the absolute path of `onnxruntime.dll`.
5. Run `scripts/fetch-ml-model.sh` from Git Bash / WSL, or download
   the three files manually from Hugging Face and verify them
   against `scripts/ml-model-manifest.txt`:

   - `onnx/model_qint8_avx512.onnx` → save as `model.onnx`
   - `tokenizer.json`
   - `sentencepiece.bpe.model`

6. Build the agent with the onnx tag:

   ```
   cd agent
   go build -tags=onnx -o secure-edge-agent.exe .\cmd\agent
   ```

## Custom install paths

```bash
# Linux/macOS — install to /opt/shieldnet/models
make install SHIELDNET_MODELS_DIR=/opt/shieldnet/models
```

Then in `config.yaml`:

```yaml
dlp_ml_boost: 1
dlp_ml_model_dir: /opt/shieldnet/models
```

The agent's startup logs will print one line documenting the
resolved model dir, whether the embedder loaded, and whether the
layer is ready — see `cmd/agent/main.go` `attachMLLayer`.

## Disabling the ML layer

Without uninstalling anything, set `dlp_ml_boost: 0` in `config.yaml`
(or omit the field — that's the default). The agent's `attachMLLayer`
helper exits early when `MLBoost <= 0` and never loads the model.

To remove the on-disk artefacts entirely:

```bash
rm -rf ~/.shieldnet/models/model
```

## Verifying the install end-to-end

```bash
# The agent emits one `dlp ml:` line at startup describing the
# resolved state. The format is fixed in cmd/agent/main.go's
# attachMLLayer and looks like:
#
#   dlp ml: layer ready=true  boost=1 configured_boost=1 threshold=0.180 base=/.../models build_tag_onnx=true
#   dlp ml: layer ready=false boost=0 configured_boost=1 threshold=0.180 base=/.../models build_tag_onnx=true
#   dlp ml: embedder init failed: ... (falling back to NullEmbedder)
#   dlp ml: model dir unresolved (HOME unset?); skipping
#
# `configured_boost` is what dlp_ml_boost is set to in config.yaml;
# `boost` is what the pipeline is actually using right now. When
# `ready=false` the agent forces `boost=0` so /api/dlp/config does
# not report a non-zero boost on a layer that cannot consume it.
#
# After `make install` you want `ready=true` with `build_tag_onnx=true`.
cd agent
./secure-edge-agent --config /path/to/config.yaml 2>&1 | grep "dlp ml:"
```

Or hit the live config endpoint:

```bash
curl -s http://localhost:8821/api/dlp/config | jq .ml
# {
#   "boost": 1,
#   "ready": true,
#   "build_tag_onnx": true
# }
```

If `ready: false` and `build_tag_onnx: true`, the binary is the
onnx build but the model dir / runtime lib failed to load — check
the agent log for the `dlp ml:` line.

## Rebuilding the corpus artefacts (developers only)

The committed `agent/internal/dlp/ml/testdata/centroids.json` and
`disambiguator.json` are produced by the offline tool:

```bash
cd agent
export SHIELDNET_ONNXRUNTIME_LIB=$HOME/.shieldnet/models/model/libonnxruntime.so
go run -tags=onnx ./internal/dlp/cmd/build_ml_artefacts \
  -corpus ./internal/dlp/testdata/corpus \
  -out    ./internal/dlp/ml/testdata \
  -max-samples 500
```

This re-runs the embedder over the corpus and emits fresh
centroids + a fresh LDA-1d linear head. The tool prints
sign-accuracy diagnostics so you can verify the produced head
separates the corpus before committing.
