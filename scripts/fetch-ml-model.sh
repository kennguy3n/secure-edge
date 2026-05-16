#!/usr/bin/env bash
# fetch-ml-model.sh — download the optional ML model for W3
# (multilingual MiniLM-L12-v2) into ~/.shieldnet/models/model.
#
# Usage:
#   scripts/fetch-ml-model.sh                            install to ~/.shieldnet/models
#   scripts/fetch-ml-model.sh -d /custom/path            install to /custom/path/model
#   scripts/fetch-ml-model.sh -d /custom/path -m PIN     pin model.onnx SHA-256 to PIN
#
# Privacy invariant:
#   - Downloads ONLY from huggingface.co under the documented
#     paraphrase-multilingual-MiniLM-L12-v2 repo.
#   - Each file's SHA-256 is computed AFTER download and printed to
#     stdout. The operator is expected to compare these against the
#     "Files and versions" page on Hugging Face (or against a
#     pre-shared manifest in their own deployment infra) before
#     pointing the agent at the model directory.
#   - When --model-sha256 / -m is passed, the script enforces a
#     pin: it refuses to leave the downloaded model.onnx in place
#     unless its SHA-256 matches the supplied value. Use this in
#     deployment automation where the upstream hash is known.
#   - No telemetry, no analytics, no user data leaves the box.
#
# The agent runs fine WITHOUT the model — every code path falls back
# to NullEmbedder. This script is only needed for operators who want
# the real pre-filter + disambiguator signal. The model is NOT
# bundled in the agent release artefacts to keep the binary small
# and to keep the optional ML dependency clearly separable from the
# deterministic pipeline.

set -euo pipefail

# Default to the HF "main" branch. Operators wanting deterministic
# behaviour should override MODEL_REV with a specific commit hash
# from the Hugging Face "Files and versions" UI.
MODEL_REPO="${SHIELDNET_MODEL_REPO:-sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2}"
MODEL_REV="${SHIELDNET_MODEL_REV:-main}"

ROOT_DIR="${HOME}/.shieldnet/models"
EXPECTED_MODEL_SHA=""

usage() {
    cat >&2 <<EOF
usage: $(basename "$0") [-d <models-root>] [-m <expected-sha256-of-model.onnx>] [-h]

    -d <dir>   Models root (default: \$HOME/.shieldnet/models).
               The model files land under \$dir/model/.
    -m <sha>   Pin the SHA-256 of model.onnx to <sha>. If the
               downloaded file's hash does not match, the script
               removes the file and exits non-zero.
    -h         Print this help and exit.

Environment overrides:
    SHIELDNET_MODEL_REPO   Hugging Face repo (default: ${MODEL_REPO})
    SHIELDNET_MODEL_REV    Git revision / branch    (default: ${MODEL_REV})
EOF
}

while getopts ":d:m:h" opt; do
    case "${opt}" in
        d) ROOT_DIR="${OPTARG}" ;;
        m) EXPECTED_MODEL_SHA="${OPTARG}" ;;
        h) usage; exit 0 ;;
        \?) echo "error: unknown option -${OPTARG}" >&2; usage; exit 2 ;;
        :)  echo "error: -${OPTARG} requires an argument" >&2; usage; exit 2 ;;
    esac
done

TARGET="${ROOT_DIR}/model"
mkdir -p "${TARGET}"

if command -v curl >/dev/null 2>&1; then
    DL_CMD=(curl --fail --location --silent --show-error --output)
elif command -v wget >/dev/null 2>&1; then
    DL_CMD=(wget --quiet --output-document)
else
    echo "error: need curl or wget on PATH" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    SHA256_CMD=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
    SHA256_CMD=(shasum -a 256)
else
    echo "error: need sha256sum or shasum on PATH" >&2
    exit 1
fi

# sha256 prints the hex digest of a file on stdout.
sha256() {
    "${SHA256_CMD[@]}" "$1" | awk '{print $1}'
}

# fetch <source-path-on-hf> <dst-on-disk>
# Downloads <source-path-on-hf> from the configured HF repo+rev to
# <dst-on-disk>, replacing any prior file. The temp-file dance keeps
# the on-disk model intact if the download is interrupted mid-flight.
fetch() {
    local src="$1"
    local dst="$2"
    local url="https://huggingface.co/${MODEL_REPO}/resolve/${MODEL_REV}/${src}"
    local tmp
    tmp="$(mktemp "${dst}.XXXXXX")"
    echo "  - GET ${url}"
    if ! "${DL_CMD[@]}" "${tmp}" "${url}"; then
        rm -f "${tmp}"
        echo "error: download failed for ${url}" >&2
        return 1
    fi
    mv "${tmp}" "${dst}"
}

echo "==> Downloading ${MODEL_REPO} @ ${MODEL_REV} into ${TARGET}"

# model.onnx is published under onnx/model.onnx on this repo.
# The int8-quantized variant lives at onnx/model_quantized.onnx; if
# you want the smaller / faster checkpoint, set:
#   SHIELDNET_MODEL_ONNX_PATH=onnx/model_quantized.onnx
MODEL_ONNX_PATH="${SHIELDNET_MODEL_ONNX_PATH:-onnx/model.onnx}"

fetch "${MODEL_ONNX_PATH}"       "${TARGET}/model.onnx"
fetch "tokenizer.json"           "${TARGET}/tokenizer.json"
fetch "sentencepiece.bpe.model"  "${TARGET}/sentencepiece.bpe.model"

echo "==> Computed SHA-256 of downloaded files:"
MODEL_SHA="$(sha256 "${TARGET}/model.onnx")"
TOK_SHA="$(sha256 "${TARGET}/tokenizer.json")"
SP_SHA="$(sha256 "${TARGET}/sentencepiece.bpe.model")"
printf '  model.onnx              %s\n' "${MODEL_SHA}"
printf '  tokenizer.json          %s\n' "${TOK_SHA}"
printf '  sentencepiece.bpe.model %s\n' "${SP_SHA}"

if [[ -n "${EXPECTED_MODEL_SHA}" ]]; then
    if [[ "${EXPECTED_MODEL_SHA}" != "${MODEL_SHA}" ]]; then
        echo "error: model.onnx SHA-256 mismatch" >&2
        echo "  expected: ${EXPECTED_MODEL_SHA}" >&2
        echo "  got:      ${MODEL_SHA}" >&2
        rm -f "${TARGET}/model.onnx"
        exit 1
    fi
    echo "==> model.onnx pin matches"
fi

cat <<INFO

ML model installed under ${TARGET}.

Compare the SHA-256 digests above against the Hugging Face
"Files and versions" page for ${MODEL_REPO}@${MODEL_REV}, or
against a pre-shared deployment manifest, before pointing the
agent at the model directory.

To enable ML augmentation in the agent's config.yaml, add:

  dlp_ml_boost: 1                  # 0..3 inclusive; 0 disables ML
  # dlp_ml_model_dir: "${ROOT_DIR}"  # only needed if you used a custom path

The default build does NOT load this model — you need the onnx
build tag to get a real embedder:

  cd agent && go build -tags=onnx ./cmd/agent

Without -tags=onnx, the agent falls back to NullEmbedder regardless
of what is on disk, which keeps the deterministic pipeline fully
functional. See ARCHITECTURE.md "Workstream 3 (W3): ML-augmented
detection" for the rationale.
INFO
