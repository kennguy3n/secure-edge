package profile

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
)

// Verifier enforces the operator's configured trust posture on every
// enterprise profile the agent loads.
//
// The verifier is constructed once at agent startup from the
// hex-encoded `profile_public_key` config knob and passed into every
// site that loads or imports a profile: the startup loader
// (LoadFromFile / LoadFromURL via cfg.ProfilePath / cfg.ProfileURL)
// and the POST /api/profile/import handler (both the URL fetch path
// and the inline `{profile: {...}}` body path).
//
// The trust model mirrors the rule-manifest verifier shipped in A3
// (PR #20) verbatim: configure a public key to flip into strict mode,
// or leave it unset for a backwards-compatible warn-once posture.
//
// Trust matrix:
//
//	+------------------+----------------+---------------------------+
//	| PublicKey set?   | Signature set? | Behaviour                 |
//	+------------------+----------------+---------------------------+
//	| no               | no             | accept, warn once         |
//	| no               | yes            | accept, warn once         |
//	| yes              | no             | REJECT                    |
//	| yes              | yes            | verify; REJECT on mismatch|
//	+------------------+----------------+---------------------------+
//
// The "warn once" branches log a single line per Verifier instance so
// an operator who forgot to wire the public key sees a breadcrumb in
// the agent logs without spam on every profile reload.
//
// A nil *Verifier is the unset state — equivalent to "no public key
// configured". Callers MUST tolerate nil so the pre-D2 code paths
// keep working when the config knob is empty.
type Verifier struct {
	publicKey ed25519.PublicKey

	mu                   sync.Mutex
	unsignedWarned       bool
	signedButNoKeyWarned bool
}

// NewVerifier returns a Verifier configured with the given Ed25519
// public key. Pass a nil or empty slice to construct a verifier that
// operates in the backwards-compatible "no key" posture (warn once,
// accept everything). Returns an error on any key that isn't
// exactly ed25519.PublicKeySize bytes long.
func NewVerifier(pub ed25519.PublicKey) (*Verifier, error) {
	if len(pub) == 0 {
		return &Verifier{}, nil
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("profile: public key: expected %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	// Copy to defend against external mutation. The verifier is
	// passed around the agent process and stored on the API
	// server; a caller who reused the slice and overwrote it
	// later could otherwise silently flip every subsequent
	// verification.
	dup := make(ed25519.PublicKey, len(pub))
	copy(dup, pub)
	return &Verifier{publicKey: dup}, nil
}

// NewVerifierFromHex decodes a hex-encoded Ed25519 public key and
// returns the resulting Verifier. The empty / whitespace-only string
// is treated as "no key configured" and returns a verifier in the
// warn-once posture. The accepted hex shape matches what
// `sign-enterprise-profile` prints to stderr after signing, and what
// the matching A3 `rule_update_public_key` config knob accepts.
func NewVerifierFromHex(s string) (*Verifier, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return &Verifier{}, nil
	}
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("profile: public key: hex decode: %w", err)
	}
	return NewVerifier(ed25519.PublicKey(raw))
}

// HasKey reports whether the verifier has a configured public key
// and is therefore in strict mode. A nil receiver returns false.
func (v *Verifier) HasKey() bool {
	if v == nil {
		return false
	}
	return len(v.publicKey) == ed25519.PublicKeySize
}

// Verify enforces the configured trust posture against p.
//
// A nil *Verifier is the unset state and is treated the same as a
// non-nil verifier with no public key: signature absent → warn once
// and accept; signature present → warn once (key-not-configured) and
// accept. This lets pre-D2 callers (and tests that don't care about
// signing) pass nil without having to construct a no-op verifier.
//
// When a public key IS configured:
//   - missing / blank signature → reject with "signature required"
//   - malformed hex / wrong length → reject with a precise diagnostic
//   - signature that does not verify → reject with "verification failed"
//
// Verify NEVER mutates p; the canonical bytes are computed via
// CanonicalForSigning(*p), which goes through profileBody and so
// produces the same bytes the signer signed regardless of whether p
// already has a populated Signature field.
func (v *Verifier) Verify(p *Profile) error {
	if p == nil {
		return errors.New("profile: nil profile")
	}
	if !v.HasKey() {
		// No key configured — emit one breadcrumb per Verifier
		// instance and accept the profile. Two distinct branches
		// so the log line accurately reflects whether the
		// caller's profile was signed or not.
		if strings.TrimSpace(p.Signature) == "" {
			v.warnOnceUnsigned()
		} else {
			v.warnOnceSignedNoKey()
		}
		return nil
	}
	if strings.TrimSpace(p.Signature) == "" {
		return errors.New("profile: signature required (profile_public_key configured)")
	}
	sig, err := hex.DecodeString(p.Signature)
	if err != nil {
		return fmt.Errorf("profile: invalid signature encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("profile: invalid signature length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
	body, err := CanonicalForSigning(*p)
	if err != nil {
		return fmt.Errorf("profile: canonicalize: %w", err)
	}
	if !ed25519.Verify(v.publicKey, body, sig) {
		return errors.New("profile: signature verification failed")
	}
	return nil
}

// warnOnceUnsigned emits the "no key + unsigned profile" breadcrumb
// at most once per Verifier instance. Split out so Verify reads as a
// trust-matrix dispatch instead of an inline log dance, and so tests
// can drive the warn-once branch without reaching into private state.
func (v *Verifier) warnOnceUnsigned() {
	if v == nil {
		return
	}
	v.mu.Lock()
	warned := v.unsignedWarned
	v.unsignedWarned = true
	v.mu.Unlock()
	if warned {
		return
	}
	log.Printf("profile: profile_public_key not configured " +
		"and profile is unsigned; accepting profile without " +
		"signature verification (configure a public key to enable " +
		"end-to-end profile verification)")
}

// warnOnceSignedNoKey emits the "signed profile but no key
// configured" breadcrumb at most once per Verifier instance. This
// catches the partial-rollout footgun: a deployment signs profiles
// but forgets to wire `profile_public_key` on some agents, leaving
// those agents running the unverified profile path.
func (v *Verifier) warnOnceSignedNoKey() {
	if v == nil {
		return
	}
	v.mu.Lock()
	warned := v.signedButNoKeyWarned
	v.signedButNoKeyWarned = true
	v.mu.Unlock()
	if warned {
		return
	}
	log.Printf("profile: profile carries a signature but " +
		"profile_public_key is not configured on this agent; " +
		"signature verification is being skipped (configure the " +
		"matching public key to enable verification)")
}
