#!/usr/bin/env bash
# fetch-ml-model.sh — download the optional ML model for W3
# (multilingual MiniLM-L12-v2, int8-quantised) into
# ~/.shieldnet/models/model.
#
# Usage:
#   scripts/fetch-ml-model.sh                       install with pinned manifest
#   scripts/fetch-ml-model.sh -d /custom/path       install to /custom/path/model
#   scripts/fetch-ml-model.sh -m <sha256>           override pin (e.g. for FP32)
#   scripts/fetch-ml-model.sh --no-pin              skip pin enforcement (NOT recommended)
#   scripts/fetch-ml-model.sh -M <manifest-path>    use a different manifest file
#
# Privacy invariant:
#   - Downloads ONLY from huggingface.co under the documented
#     paraphrase-multilingual-MiniLM-L12-v2 repo.
#   - The committed manifest (scripts/ml-model-manifest.txt) pins
#     the upstream commit revision AND the SHA-256 of every file
#     before download. A SHA mismatch is a hard failure — the
#     downloaded file is removed and the script exits non-zero.
#   - Each file's SHA-256 is also printed to stdout after download
#     so the operator can cross-check against the Hugging Face
#     "Files and versions" page in an audit context.
#   - No telemetry, no analytics, no user data leaves the box.
#
# The agent runs fine WITHOUT the model — every code path falls back
# to NullEmbedder. This script is only needed for operators who want
# the real pre-filter + disambiguator signal. The model is NOT
# bundled in the agent release artefacts to keep the binary small
# and to keep the optional ML dependency clearly separable from the
# deterministic pipeline.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_PATH="${SCRIPT_DIR}/ml-model-manifest.txt"

ROOT_DIR="${HOME}/.shieldnet/models"
EXPECTED_MODEL_SHA=""
SKIP_PIN=0

usage() {
    cat >&2 <<EOF
usage: $(basename "$0") [-d <models-root>] [-m <model.onnx-sha256>] [-M <manifest>] [--no-pin] [-h]

    -d <dir>      Models root (default: \$HOME/.shieldnet/models).
                  The model files land under \$dir/model/.
    -m <sha>      Override the pinned SHA-256 for model.onnx. The
                  tokenizer / SPM pins still apply.
    -M <path>     Use a different manifest file. Defaults to:
                  ${MANIFEST_PATH}
    --no-pin      Skip ALL SHA-256 enforcement. NOT recommended; only
                  use when fetching a non-default checkpoint without
                  a corresponding manifest entry.
    -h            Print this help and exit.

Environment overrides (override values in the manifest):
    SHIELDNET_MODEL_REPO        Hugging Face repo
    SHIELDNET_MODEL_REV         Git revision / branch
    SHIELDNET_MODEL_ONNX_PATH   Path within the repo to model.onnx
EOF
}

# Manual long-option parsing for --no-pin alongside getopts.
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-pin) SKIP_PIN=1; shift ;;
        --) shift; ARGS+=("$@"); break ;;
        *) ARGS+=("$1"); shift ;;
    esac
done
set -- "${ARGS[@]:-}"

while getopts ":d:m:M:h" opt; do
    case "${opt}" in
        d) ROOT_DIR="${OPTARG}" ;;
        m) EXPECTED_MODEL_SHA="${OPTARG}" ;;
        M) MANIFEST_PATH="${OPTARG}" ;;
        h) usage; exit 0 ;;
        \?) echo "error: unknown option -${OPTARG}" >&2; usage; exit 2 ;;
        :)  echo "error: -${OPTARG} requires an argument" >&2; usage; exit 2 ;;
    esac
done

if [[ ! -f "${MANIFEST_PATH}" ]]; then
    echo "error: manifest not found at ${MANIFEST_PATH}" >&2
    exit 1
fi

# Defaults from the committed manifest. The env-var fallbacks let
# operators override individual fields without editing the file.
# shellcheck disable=SC1090
source "${MANIFEST_PATH}"
MODEL_REPO="${SHIELDNET_MODEL_REPO:-${MODEL_REPO}}"
MODEL_REV="${SHIELDNET_MODEL_REV:-${MODEL_REV}}"
MODEL_ONNX_PATH="${SHIELDNET_MODEL_ONNX_PATH:-${MODEL_ONNX_PATH}}"
EXPECTED_MODEL_SHA="${EXPECTED_MODEL_SHA:-${MODEL_ONNX_SHA}}"
EXPECTED_TOKENIZER_SHA="${TOKENIZER_SHA:-}"
EXPECTED_SPM_SHA="${SPM_SHA:-}"

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

# verify <dst> <expected-sha> <label>
# Re-computes the SHA of <dst>, compares to <expected-sha>, removes
# the file and exits non-zero on mismatch. When SKIP_PIN=1 or
# <expected-sha> is empty, the function still prints the computed
# digest but does not enforce the pin.
verify() {
    local dst="$1"
    local expected="$2"
    local label="$3"
    local got
    got="$(sha256 "${dst}")"
    printf '  %-24s %s\n' "${label}" "${got}"
    if [[ "${SKIP_PIN}" == "1" || -z "${expected}" ]]; then
        return 0
    fi
    if [[ "${expected}" != "${got}" ]]; then
        echo "error: ${label} SHA-256 mismatch" >&2
        echo "  expected: ${expected}" >&2
        echo "  got:      ${got}" >&2
        rm -f "${dst}"
        exit 1
    fi
}

echo "==> Downloading ${MODEL_REPO} @ ${MODEL_REV} into ${TARGET}"
echo "    model file: ${MODEL_ONNX_PATH}"

fetch "${MODEL_ONNX_PATH}"       "${TARGET}/model.onnx"
fetch "tokenizer.json"           "${TARGET}/tokenizer.json"
fetch "sentencepiece.bpe.model"  "${TARGET}/sentencepiece.bpe.model"

echo "==> SHA-256 of downloaded files:"
verify "${TARGET}/model.onnx"              "${EXPECTED_MODEL_SHA}"     "model.onnx"
verify "${TARGET}/tokenizer.json"          "${EXPECTED_TOKENIZER_SHA}" "tokenizer.json"
verify "${TARGET}/sentencepiece.bpe.model" "${EXPECTED_SPM_SHA}"       "sentencepiece.bpe.model"

if [[ "${SKIP_PIN}" == "1" ]]; then
    echo "==> Pin enforcement skipped (--no-pin)."
else
    echo "==> All SHA-256 pins matched."
fi

cat <<INFO

ML model installed under ${TARGET}.

To enable ML augmentation in the agent's config.yaml, add:

  dlp_ml_boost: 1                  # 0..3 inclusive; 0 disables ML
  # dlp_ml_model_dir: "${ROOT_DIR}"  # only needed if you used a custom path

The default agent build does NOT load this model — you need both the
onnx build tag AND a working onnxruntime shared library at runtime:

  cd agent && go build -tags=onnx ./cmd/agent

See INSTALL_ML.md (top-level) for the end-to-end install workflow,
including how to install the onnxruntime shared library on each
supported OS.
INFO
