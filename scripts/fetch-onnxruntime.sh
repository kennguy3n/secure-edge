#!/usr/bin/env bash
# fetch-onnxruntime.sh — download the official Microsoft onnxruntime
# CPU shared library that the agent's `-tags=onnx` build links
# against at runtime via purego/dlopen.
#
# The library is dropped into the same directory as the model files
# so the agent's `resolveSharedLibrary` helper picks it up without
# needing LD_LIBRARY_PATH:
#
#   <models-root>/model/libonnxruntime.so          (Linux)
#   <models-root>/model/libonnxruntime.dylib       (macOS)
#   <models-root>/model/onnxruntime.dll            (Windows)
#
# Usage:
#   scripts/fetch-onnxruntime.sh                       install into ~/.shieldnet
#   scripts/fetch-onnxruntime.sh -d /custom/path       install into /custom/path/model
#   scripts/fetch-onnxruntime.sh -v 1.25.0             pin onnxruntime version
#   scripts/fetch-onnxruntime.sh --no-pin              skip SHA-256 enforcement
#
# Pin enforcement:
#
# This script pins the *archive* (.tgz / .zip) SHA-256 the first time
# you install onnxruntime so a subsequent install from the same
# version cannot be silently replaced by a tampered tarball. The pin
# manifest lives under scripts/onnxruntime-manifest.txt and is
# committed alongside the model manifest. If you change ORT_VERSION
# and the manifest does not have a pin for the new version, the
# script refuses to install unless you pass --no-pin.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_PATH="${SCRIPT_DIR}/onnxruntime-manifest.txt"

ROOT_DIR="${HOME}/.shieldnet/models"
ORT_VERSION="${ORT_VERSION:-1.25.0}"
SKIP_PIN=0

usage() {
    cat >&2 <<EOF
usage: $(basename "$0") [-d <models-root>] [-v <ort-version>] [-M <manifest>] [--no-pin] [-h]

    -d <dir>      Models root (default: \$HOME/.shieldnet/models).
                  The shared library lands under \$dir/model/.
    -v <version>  onnxruntime version to install (default: ${ORT_VERSION}).
                  Must have a corresponding pin in the manifest unless
                  --no-pin is set.
    -M <path>     Use a different manifest file. Defaults to:
                  ${MANIFEST_PATH}
    --no-pin      Skip SHA-256 enforcement (NOT recommended).
    -h            Print this help and exit.
EOF
}

ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-pin) SKIP_PIN=1; shift ;;
        --) shift; ARGS+=("$@"); break ;;
        *) ARGS+=("$1"); shift ;;
    esac
done
set -- "${ARGS[@]:-}"

while getopts ":d:v:M:h" opt; do
    case "${opt}" in
        d) ROOT_DIR="${OPTARG}" ;;
        v) ORT_VERSION="${OPTARG}" ;;
        M) MANIFEST_PATH="${OPTARG}" ;;
        h) usage; exit 0 ;;
        \?) echo "error: unknown option -${OPTARG}" >&2; usage; exit 2 ;;
        :)  echo "error: -${OPTARG} requires an argument" >&2; usage; exit 2 ;;
    esac
done

# Detect platform.
OS="$(uname -s)"
ARCH="$(uname -m)"
case "${OS}-${ARCH}" in
    Linux-x86_64)  ARCHIVE="onnxruntime-linux-x64-${ORT_VERSION}.tgz"; LIB_REL="onnxruntime-linux-x64-${ORT_VERSION}/lib/libonnxruntime.so.${ORT_VERSION}"; LIB_NAME="libonnxruntime.so" ;;
    Linux-aarch64) ARCHIVE="onnxruntime-linux-aarch64-${ORT_VERSION}.tgz"; LIB_REL="onnxruntime-linux-aarch64-${ORT_VERSION}/lib/libonnxruntime.so.${ORT_VERSION}"; LIB_NAME="libonnxruntime.so" ;;
    Darwin-x86_64) ARCHIVE="onnxruntime-osx-x86_64-${ORT_VERSION}.tgz"; LIB_REL="onnxruntime-osx-x86_64-${ORT_VERSION}/lib/libonnxruntime.${ORT_VERSION}.dylib"; LIB_NAME="libonnxruntime.dylib" ;;
    Darwin-arm64)  ARCHIVE="onnxruntime-osx-arm64-${ORT_VERSION}.tgz"; LIB_REL="onnxruntime-osx-arm64-${ORT_VERSION}/lib/libonnxruntime.${ORT_VERSION}.dylib"; LIB_NAME="libonnxruntime.dylib" ;;
    *)
        echo "error: unsupported platform ${OS}-${ARCH}" >&2
        echo "  install onnxruntime manually from https://github.com/microsoft/onnxruntime/releases and set SHIELDNET_ONNXRUNTIME_LIB" >&2
        exit 1
        ;;
esac

URL="https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/${ARCHIVE}"

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

sha256() { "${SHA256_CMD[@]}" "$1" | awk '{print $1}'; }

# Load the pinned SHA for this (version, archive) pair from the
# manifest, if present. The manifest is a plain `<sha>  <name>` file
# (sha256sum format) so `sha256sum -c` could verify it directly.
EXPECTED_SHA=""
if [[ -f "${MANIFEST_PATH}" ]]; then
    EXPECTED_SHA="$(awk -v a="${ARCHIVE}" '$2==a {print $1; exit}' "${MANIFEST_PATH}")"
fi

if [[ "${SKIP_PIN}" != "1" && -z "${EXPECTED_SHA}" ]]; then
    echo "error: no SHA-256 pin for ${ARCHIVE} in ${MANIFEST_PATH}" >&2
    echo "  add the line:  <sha256>  ${ARCHIVE}" >&2
    echo "  or pass --no-pin to skip enforcement (NOT recommended)" >&2
    exit 1
fi

TARGET="${ROOT_DIR}/model"
mkdir -p "${TARGET}"

TMP_DIR="$(mktemp -d -t shieldnet-ort.XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "==> Downloading ${URL}"
"${DL_CMD[@]}" "${TMP_DIR}/${ARCHIVE}" "${URL}"

GOT_SHA="$(sha256 "${TMP_DIR}/${ARCHIVE}")"
echo "    archive SHA-256:  ${GOT_SHA}"
if [[ "${SKIP_PIN}" != "1" ]]; then
    if [[ "${EXPECTED_SHA}" != "${GOT_SHA}" ]]; then
        echo "error: ${ARCHIVE} SHA-256 mismatch" >&2
        echo "  expected: ${EXPECTED_SHA}" >&2
        echo "  got:      ${GOT_SHA}" >&2
        exit 1
    fi
    echo "    pin matches."
fi

echo "==> Extracting"
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}"

if [[ ! -f "${TMP_DIR}/${LIB_REL}" ]]; then
    echo "error: extracted archive does not contain ${LIB_REL}" >&2
    ls "${TMP_DIR}" >&2 || true
    exit 1
fi

cp "${TMP_DIR}/${LIB_REL}" "${TARGET}/${LIB_NAME}"
chmod +rx "${TARGET}/${LIB_NAME}"

echo "==> onnxruntime ${ORT_VERSION} installed to ${TARGET}/${LIB_NAME}"
echo

cat <<INFO
The agent's -tags=onnx build will pick this up automatically:

  cd agent && go build -tags=onnx ./cmd/agent

You may also set SHIELDNET_ONNXRUNTIME_LIB to point at an existing
system install — see INSTALL_ML.md for details.

Windows: this script does not install onnxruntime.dll on Windows.
Download onnxruntime-win-x64-${ORT_VERSION}.zip from the Microsoft
release page, extract onnxruntime.dll, and drop it at
%USERPROFILE%\.shieldnet\models\model\onnxruntime.dll, or set the
SHIELDNET_ONNXRUNTIME_LIB env var. See INSTALL_ML.md.
INFO
