AGENT_BINARY := secure-edge-agent
PKG := ./...

# Where the model artefacts + onnxruntime shared library live by
# default. The install-ml / install-onnx-runtime targets honour this
# variable so an operator can drop the install under any prefix.
SHIELDNET_MODELS_DIR ?= $(HOME)/.shieldnet/models

.PHONY: build
build:
	go build -o $(AGENT_BINARY) ./cmd/agent

# build-onnx produces an agent binary that activates the optional
# ONNX-backed embedder. Requires CGO_ENABLED=1 and a system C
# toolchain — onnxruntime_go uses cgo for the dlopen / ABI shim. The
# runtime library itself is still loaded dynamically via dlopen at
# start time, so the binary is portable across machines as long as
# $(SHIELDNET_MODELS_DIR)/model/libonnxruntime.{so,dylib} (or
# $SHIELDNET_ONNXRUNTIME_LIB) is reachable.
.PHONY: build-onnx
build-onnx:
	CGO_ENABLED=1 go build -tags=onnx -o $(AGENT_BINARY) ./cmd/agent

.PHONY: test
test:
	go test -race $(PKG)

.PHONY: lint
lint:
	go vet $(PKG)

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	rm -f $(AGENT_BINARY)

# install-ml downloads the int8-quantised MiniLM-L12 model into
# $(SHIELDNET_MODELS_DIR)/model and enforces the SHA-256 pin from
# scripts/ml-model-manifest.txt. Idempotent — re-running just
# re-downloads and re-verifies the same artefacts.
.PHONY: install-ml
install-ml:
	../scripts/fetch-ml-model.sh -d $(SHIELDNET_MODELS_DIR)

# install-artefacts deploys the centroids + disambiguator sidecars
# that ml.LoadArtefacts() reads at <base>/centroids.json and
# <base>/disambiguator.json. Without these two files Layer.Ready()
# returns false and the ML layer never activates, regardless of
# whether the ONNX model is present.
#
# The committed artefacts under internal/dlp/ml/testdata are real
# LDA-1d weights fit from the TP/TN corpus by build_ml_artefacts;
# they are not synthetic test fixtures. We ship them through the
# repo (rather than from a download) so a fresh clone + make install
# yields a working ML layer with no extra steps.
.PHONY: install-artefacts
install-artefacts:
	mkdir -p $(SHIELDNET_MODELS_DIR)
	cp internal/dlp/ml/testdata/centroids.json     $(SHIELDNET_MODELS_DIR)/centroids.json
	cp internal/dlp/ml/testdata/disambiguator.json $(SHIELDNET_MODELS_DIR)/disambiguator.json

# install-onnx-runtime downloads the official Microsoft onnxruntime
# CPU shared library for the current OS/arch and drops it next to
# the model so the -tags=onnx agent binary can dlopen() it without
# touching LD_LIBRARY_PATH. SHA-256 of the upstream archive is
# verified against scripts/onnxruntime-manifest.txt.
.PHONY: install-onnx-runtime
install-onnx-runtime:
	../scripts/fetch-onnxruntime.sh -d $(SHIELDNET_MODELS_DIR)

# install runs the full ML install on the current host: downloads the
# onnxruntime shared library, downloads + verifies the model,
# deploys the centroids + disambiguator sidecars, and builds the
# onnx-tagged agent binary. After this target the binary has a
# working, Ready() ML layer on first run.
.PHONY: install
install: install-onnx-runtime install-ml install-artefacts build-onnx
	@echo
	@echo "secure-edge-agent (onnx) built."
	@echo "  model + onnxruntime: $(SHIELDNET_MODELS_DIR)/model/"
	@echo "  centroids/disambiguator: $(SHIELDNET_MODELS_DIR)/"
	@echo "Set dlp_ml_boost > 0 in config.yaml to enable ML augmentation."
