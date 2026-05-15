// Package profile defines the enterprise configuration profile format
// and the in-memory holder used to expose the current profile to the
// API and tamper / heartbeat subsystems.
//
// A profile is a JSON document that a managed deployment ships to the
// agent (either as a local file or a downloadable URL). It pins the
// per-category actions, DLP thresholds, and the rule-update URL the
// agent should follow. When Managed is true, the agent rejects local
// policy mutations via PUT /api/policies/:category so end users cannot
// drift the device away from the central baseline.
//
// Privacy note: the profile itself contains only configuration — it
// never carries access logs, domain history, or DLP match content.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// CategoryAction values stored in Profile.Categories. Mirrors the
// store.Action constants without forcing a profile→store import.
const (
	ActionAllow        = "allow"
	ActionAllowWithDLP = "allow_with_dlp"
	ActionDeny         = "deny"
)

// DLPThresholds mirrors store.DLPConfig so a profile can ship the full
// DLP scoring envelope. All fields are optional; zero means "leave the
// existing value untouched" when ApplyTo is called.
type DLPThresholds struct {
	ThresholdCritical int `json:"threshold_critical,omitempty"`
	ThresholdHigh     int `json:"threshold_high,omitempty"`
	ThresholdMedium   int `json:"threshold_medium,omitempty"`
	ThresholdLow      int `json:"threshold_low,omitempty"`
	HotwordBoost      int `json:"hotword_boost,omitempty"`
	EntropyBoost      int `json:"entropy_boost,omitempty"`
	EntropyPenalty    int `json:"entropy_penalty,omitempty"`
	ExclusionPenalty  int `json:"exclusion_penalty,omitempty"`
	MultiMatchBoost   int `json:"multi_match_boost,omitempty"`
}

// Profile is the JSON document a managed deployment ships to the
// agent. Name and Version are human-readable identifiers used in
// admin tooling; they have no semantic effect on the agent.
//
// Signature is the hex-encoded Ed25519 signature over the canonical
// JSON serialisation of the body — i.e. the profile with the
// `signature` field omitted (see CanonicalForSigning). It is
// optional: when an operator has not configured a public key
// (`profile_public_key`), the loader falls back to accepting
// unsigned profiles and logs a one-time warning. When a public key
// IS configured, every loaded profile MUST carry a well-formed
// signature that verifies against that key. The trust model mirrors
// the rule-manifest signing posture shipped in A3 (PR #20).
//
// IMPORTANT: when adding new profile fields, also extend
// `profileBody` below so the new field participates in the signed
// canonical form. The two struct shapes (Profile minus Signature)
// MUST stay in lockstep; the dedicated body type makes that
// requirement explicit at the source level rather than relying on
// `omitempty` to silently exclude future fields. A reflection drift
// test (TestProfileBody_MirrorsProfileMinusSignature in profile_test.go)
// enforces this at every CI run.
type Profile struct {
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	Managed       bool              `json:"managed"`
	Categories    map[string]string `json:"categories,omitempty"`
	DLPThresholds *DLPThresholds    `json:"dlp_thresholds,omitempty"`
	RuleUpdateURL string            `json:"rule_update_url,omitempty"`
	HeartbeatURL  string            `json:"heartbeat_url,omitempty"`
	Signature     string            `json:"signature,omitempty"`
}

// profileBody is the structurally-explicit canonical-signing shape
// of Profile with the Signature field physically removed.
//
// Why a separate type (mirrors rules.manifestBody on the rule
// manifest side):
//
//   - The naive approach of relying on `json:"signature,omitempty"`
//     to drop Signature from the canonical bytes works today but is
//     fragile: any future field added to Profile without
//     `omitempty` would silently change the canonical form and
//     invalidate every previously-signed profile.
//   - With a dedicated body type, drift between Profile and
//     profileBody is caught loudly at run time by
//     TestProfileBody_MirrorsProfileMinusSignature (in
//     profile_test.go), which uses reflection to compare the two
//     structs field-by-field. Note: this is a test-time check, not
//     a compile-time check — Profile and profileBody are
//     independent struct types, so the Go compiler does NOT report
//     missing fields here. Skipping the profile signing tests would
//     let the drift land silently. CI must run the full `make test`
//     target (which exercises this test) before any change to
//     Profile is merged.
//   - Every new field added to Profile must be mirrored here (or
//     explicitly chosen not to participate in the signature, in
//     which case the test must be updated to mark it non-canonical).
//   - Field order MUST match Profile's declaration order because
//     `encoding/json` emits fields in source order, and the signed
//     byte sequence is order-sensitive.
type profileBody struct {
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	Managed       bool              `json:"managed"`
	Categories    map[string]string `json:"categories,omitempty"`
	DLPThresholds *DLPThresholds    `json:"dlp_thresholds,omitempty"`
	RuleUpdateURL string            `json:"rule_update_url,omitempty"`
	HeartbeatURL  string            `json:"heartbeat_url,omitempty"`
}

// CanonicalForSigning returns the byte sequence that the
// enterprise-profile signer signs over and that the verifier
// verifies. The signature field itself is omitted from the
// canonical body — otherwise the signer would have to fixed-point
// its own input. The body is marshalled through `profileBody`, a
// sibling struct that physically lacks a Signature field, so this
// code is robust against future additions to Profile that forget
// `omitempty` (see the doc comment on profileBody for the full
// reasoning).
//
// Field order is fixed by Go's encoding/json (declaration order on
// profileBody), which must match Profile's order field-for-field so
// existing signatures remain valid.
func CanonicalForSigning(p Profile) ([]byte, error) {
	// The shallow copy below shares its Categories map and
	// DLPThresholds pointer with p. Safe here because json.Marshal
	// only reads them and CanonicalForSigning is never called on a
	// Profile that is being mutated concurrently (the only writers
	// are deserialisation in Parse + the API import handler + the
	// signer tool, all of which finish before this is called).
	body := profileBody{
		Name:          p.Name,
		Version:       p.Version,
		Managed:       p.Managed,
		Categories:    p.Categories,
		DLPThresholds: p.DLPThresholds,
		RuleUpdateURL: p.RuleUpdateURL,
		HeartbeatURL:  p.HeartbeatURL,
	}
	return json.Marshal(body)
}

// ErrInvalidProfile is returned by Validate when the profile fails
// schema validation.
var ErrInvalidProfile = errors.New("invalid profile")

// Validate enforces the minimal schema invariants: Name is required,
// every category action (if any) is one of the supported values, and
// scoring thresholds (if any) are non-negative.
func (p *Profile) Validate() error {
	if p == nil {
		return fmt.Errorf("%w: profile is nil", ErrInvalidProfile)
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidProfile)
	}
	for cat, act := range p.Categories {
		switch act {
		case ActionAllow, ActionAllowWithDLP, ActionDeny:
		default:
			return fmt.Errorf("%w: category %q has invalid action %q",
				ErrInvalidProfile, cat, act)
		}
	}
	if t := p.DLPThresholds; t != nil {
		if t.ThresholdCritical < 0 || t.ThresholdHigh < 0 ||
			t.ThresholdMedium < 0 || t.ThresholdLow < 0 {
			return fmt.Errorf("%w: dlp thresholds must be non-negative",
				ErrInvalidProfile)
		}
	}
	return nil
}

// Parse unmarshals raw bytes into a Profile and validates it.
func Parse(raw []byte) (*Profile, error) {
	var p Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Holder owns the active profile and exposes thread-safe accessors.
// The API package, the policy locker, and any future heartbeat /
// tamper observer share a single Holder instance constructed in
// cmd/agent/main.go.
type Holder struct {
	mu      sync.RWMutex
	current *Profile
}

// NewHolder returns a Holder that holds the given profile (which may
// be nil for unmanaged deployments).
func NewHolder(p *Profile) *Holder { return &Holder{current: p} }

// Get returns a defensive copy of the active profile, or nil when no
// profile has been applied. Callers must not mutate the returned
// pointer's referenced sub-objects.
func (h *Holder) Get() *Profile {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.current == nil {
		return nil
	}
	cp := *h.current
	if h.current.Categories != nil {
		cp.Categories = make(map[string]string, len(h.current.Categories))
		for k, v := range h.current.Categories {
			cp.Categories[k] = v
		}
	}
	if h.current.DLPThresholds != nil {
		t := *h.current.DLPThresholds
		cp.DLPThresholds = &t
	}
	return &cp
}

// Set replaces the active profile. p must be non-nil.
func (h *Holder) Set(p *Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	h.mu.Lock()
	h.current = p
	h.mu.Unlock()
	return nil
}

// Locked reports whether the active profile is locked. A nil Holder or
// an unset profile is considered unlocked so a fresh install behaves
// like a Phase 1-4 deployment.
func (h *Holder) Locked() bool {
	if h == nil {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current != nil && h.current.Managed
}
