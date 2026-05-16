package ml

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Artefacts groups the three on-disk files the ML layer expects to
// find under a single base directory. Layout:
//
//	<base>/centroids.json
//	<base>/disambiguator.json
//	<base>/model/         (ONNX model + tokenizer, used only by the
//	                       onnx build)
//
// The pipeline can run with any subset of these: missing centroids
// only disable the pre-filter; missing disambiguator weights only
// disable the disambiguator; a missing model directory disables the
// whole ML layer (the embedder fails to load, both classifiers
// degrade to no-op).
type Artefacts struct {
	Base string

	Centroids *Centroids
	Linear    *LinearHead
	ModelDir  string // ONNX model + tokenizer directory; empty if missing
}

// LoadArtefacts reads centroids and disambiguator weights from the
// given base directory. Missing files are *not* errors — the
// returned Artefacts contains nil pointers for whatever could not
// be loaded, and callers should branch on those nils rather than
// errors.Is checks. A non-nil error is returned only when a file
// exists but cannot be parsed (malformed JSON, dimension mismatch,
// etc.) — that is a corruption or version-skew issue worth
// surfacing to the operator.
//
// Privacy invariant: this function only reads from base; it does
// not write, does not phone home, and does not log file contents.
func LoadArtefacts(base string) (*Artefacts, error) {
	if base == "" {
		return &Artefacts{}, nil
	}
	out := &Artefacts{Base: base}

	if c, err := loadCentroids(filepath.Join(base, "centroids.json")); err == nil {
		out.Centroids = c
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, fmt.Errorf("ml: load centroids: %w", err)
	}

	if h, err := loadLinearHead(filepath.Join(base, "disambiguator.json")); err == nil {
		out.Linear = h
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, fmt.Errorf("ml: load disambiguator: %w", err)
	}

	modelDir := filepath.Join(base, "model")
	if st, err := os.Stat(modelDir); err == nil && st.IsDir() {
		out.ModelDir = modelDir
	}

	return out, nil
}

// loadCentroids parses the centroids.json sidecar. Returns
// (*Centroids, nil) on success, (nil, os.ErrNotExist) when the file
// is missing, and (nil, err) otherwise.
func loadCentroids(path string) (*Centroids, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var on struct {
		TP []float32 `json:"tp"`
		TN []float32 `json:"tn"`
	}
	if err := json.Unmarshal(raw, &on); err != nil {
		return nil, err
	}
	if len(on.TP) == 0 || len(on.TN) == 0 {
		return nil, fmt.Errorf("ml: centroids.json has empty tp or tn vector")
	}
	if len(on.TP) != len(on.TN) {
		return nil, fmt.Errorf("ml: centroids.json tp/tn dimension mismatch: tp=%d tn=%d", len(on.TP), len(on.TN))
	}
	return &Centroids{TP: on.TP, TN: on.TN}, nil
}

// loadLinearHead parses the disambiguator.json sidecar. Returns
// (*LinearHead, nil) on success, (nil, os.ErrNotExist) when the
// file is missing, and (nil, err) otherwise.
func loadLinearHead(path string) (*LinearHead, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var h LinearHead
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, err
	}
	if len(h.Weights) == 0 {
		return nil, fmt.Errorf("ml: disambiguator.json has empty weights")
	}
	return &h, nil
}

// DefaultBaseDir is the model directory the agent uses when no
// override is configured. ~/.shieldnet/models keeps user-supplied
// model artefacts out of the repo and out of /etc — the agent's
// privacy posture means we do not want model files installed into
// system paths where they could be confused with policy files.
func DefaultBaseDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".shieldnet", "models")
}
