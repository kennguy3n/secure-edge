package profile

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestProfileBody_MirrorsProfileMinusSignature locks in the
// invariant that the dedicated `profileBody` struct used by
// CanonicalForSigning has exactly the same fields as Profile, in
// the same order, with the same JSON tags, minus the Signature
// field. If a future contributor adds a new field to Profile without
// mirroring it on profileBody, this test fails — making the silent
// canonical-form-drift footgun unreachable.
//
// This mirrors the equivalent test on the rule-manifest side
// (rules.TestManifestBody_MirrorsManifestMinusSignature, shipped in
// A3) and serves the same purpose: catch drift at test time rather
// than at the next field push, when previously-signed profiles in
// the wild would silently fail verification or, worse, silently keep
// verifying against a canonical body that no longer matched the
// shipped Profile.
func TestProfileBody_MirrorsProfileMinusSignature(t *testing.T) {
	mt := reflect.TypeOf(Profile{})
	bt := reflect.TypeOf(profileBody{})

	type field struct {
		Name string
		Type reflect.Type
		Tag  string
	}
	var want []field
	for i := 0; i < mt.NumField(); i++ {
		f := mt.Field(i)
		if f.Name == "Signature" {
			continue
		}
		want = append(want, field{
			Name: f.Name,
			Type: f.Type,
			Tag:  f.Tag.Get("json"),
		})
	}

	if bt.NumField() != len(want) {
		t.Fatalf("profileBody has %d fields; expected %d (Profile minus Signature). "+
			"Did you add a field to Profile without mirroring it on profileBody?",
			bt.NumField(), len(want))
	}
	for i, w := range want {
		got := bt.Field(i)
		if got.Name != w.Name || got.Type != w.Type || got.Tag.Get("json") != w.Tag {
			t.Fatalf("profileBody field %d = {%s, %s, json=%q}; want {%s, %s, json=%q}. "+
				"Field order and JSON tags MUST match Profile exactly so existing "+
				"signatures over the canonical form remain valid.",
				i, got.Name, got.Type, got.Tag.Get("json"),
				w.Name, w.Type, w.Tag)
		}
	}
}

// TestCanonicalForSigning_BytesUnchangedByRefactor pins the exact
// canonical byte sequence so we'd notice if a future change
// accidentally altered the bytes a previously-valid signature was
// computed over. Updating this test means breaking every
// previously-signed profile in the wild — do not change the
// expected literal lightly.
func TestCanonicalForSigning_BytesUnchangedByRefactor(t *testing.T) {
	body, err := CanonicalForSigning(Profile{
		Name:    "acme",
		Version: "1.0.0",
		Managed: true,
		Categories: map[string]string{
			"AI Allowed": "allow",
		},
		Signature: "this-must-not-affect-the-bytes",
	})
	if err != nil {
		t.Fatalf("CanonicalForSigning: %v", err)
	}
	want := `{"name":"acme","version":"1.0.0","managed":true,"categories":{"AI Allowed":"allow"}}`
	if string(body) != want {
		t.Fatalf("canonical bytes drifted:\n  got:  %s\n  want: %s", body, want)
	}
}

// TestCanonicalForSigning_SignatureFieldExcluded asserts the most
// important invariant: two profiles that differ only in their
// Signature field MUST produce identical canonical bytes. Without
// this, the signer would have to fixed-point its own input.
func TestCanonicalForSigning_SignatureFieldExcluded(t *testing.T) {
	base := Profile{Name: "acme", Version: "1.0.0"}

	a, err := CanonicalForSigning(base)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	withSig := base
	withSig.Signature = strings.Repeat("ab", ed25519.SignatureSize)
	b, err := CanonicalForSigning(withSig)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("Signature field leaked into canonical bytes:\n  a: %s\n  b: %s", a, b)
	}
}

// signProfile is a test helper that mirrors what the
// sign-enterprise-profile CLI does at runtime: compute the canonical
// bytes, sign them with the supplied Ed25519 private key, and set
// the resulting hex signature on the profile. Callers pass the
// profile by value and receive a signed copy back so individual
// table-rows can build on a shared base without aliasing.
func signProfile(t *testing.T, p Profile, priv ed25519.PrivateKey) Profile {
	t.Helper()
	body, err := CanonicalForSigning(p)
	if err != nil {
		t.Fatalf("CanonicalForSigning: %v", err)
	}
	p.Signature = hex.EncodeToString(ed25519.Sign(priv, body))
	return p
}

// testKey returns a deterministic Ed25519 keypair for use across
// the verifier tests. Using a fixed seed keeps the canonical-byte
// assertions reproducible from one run to the next.
func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// TestVerifier_TrustMatrix walks the full {publicKey-set, signature-set}
// product space:
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
// plus the two failure sub-modes of the "yes/yes" cell (tampered
// body vs. wrong signing key). All four cells are pinned in one
// table so any future change to the trust posture is loud.
func TestVerifier_TrustMatrix(t *testing.T) {
	pub, priv := testKey(t)
	_, otherPriv := testKey(t)

	base := Profile{Name: "acme", Version: "1.0.0", Managed: true}
	signedOK := signProfile(t, base, priv)
	signedByOther := signProfile(t, base, otherPriv)

	cases := []struct {
		name      string
		pubKey    ed25519.PublicKey // nil ⇒ no key configured
		profile   Profile
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "no key + unsigned ⇒ accept",
			pubKey:  nil,
			profile: base,
			wantErr: false,
		},
		{
			name:    "no key + signed ⇒ accept (warn)",
			pubKey:  nil,
			profile: signedOK,
			wantErr: false,
		},
		{
			name:      "key + unsigned ⇒ reject",
			pubKey:    pub,
			profile:   base,
			wantErr:   true,
			errSubstr: "signature required",
		},
		{
			name:    "key + signed-by-same-key ⇒ accept",
			pubKey:  pub,
			profile: signedOK,
			wantErr: false,
		},
		{
			name:      "key + signed-by-different-key ⇒ reject",
			pubKey:    pub,
			profile:   signedByOther,
			wantErr:   true,
			errSubstr: "signature verification failed",
		},
		{
			name:   "key + tampered body ⇒ reject",
			pubKey: pub,
			profile: func() Profile {
				p := signedOK
				p.Name = "different-name-after-signing"
				return p
			}(),
			wantErr:   true,
			errSubstr: "signature verification failed",
		},
		{
			name:   "key + signature wrong length ⇒ reject",
			pubKey: pub,
			profile: func() Profile {
				p := base
				p.Signature = hex.EncodeToString([]byte{0x01, 0x02})
				return p
			}(),
			wantErr:   true,
			errSubstr: "invalid signature length",
		},
		{
			name:   "key + signature not hex ⇒ reject",
			pubKey: pub,
			profile: func() Profile {
				p := base
				p.Signature = "not-a-hex-string!!"
				return p
			}(),
			wantErr:   true,
			errSubstr: "invalid signature encoding",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewVerifier(tc.pubKey)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			err = v.Verify(&tc.profile)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("error %q must contain %q", err, tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestVerifier_NilReceiverAcceptsAllProfiles documents the
// "nil = unset Verifier = legacy posture" contract. Callers that
// don't pass a verifier (e.g. pre-D2 code paths, tests that build
// Profile in memory) must still get successful verification.
func TestVerifier_NilReceiverAcceptsAllProfiles(t *testing.T) {
	var v *Verifier
	if err := v.Verify(&Profile{Name: "acme"}); err != nil {
		t.Fatalf("nil verifier must accept unsigned: %v", err)
	}
	if err := v.Verify(&Profile{Name: "acme", Signature: "deadbeef"}); err != nil {
		t.Fatalf("nil verifier must accept signed-but-unverified: %v", err)
	}
}

// TestNewVerifierFromHex covers the three concrete shapes operators
// might write into `profile_public_key`: empty / whitespace-only
// (treated as unset → warn-once posture), a valid hex public key,
// and a malformed key (must surface a precise error so an operator
// who fat-fingers the value sees it at boot).
func TestNewVerifierFromHex(t *testing.T) {
	pub, _ := testKey(t)

	v, err := NewVerifierFromHex("")
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if v.HasKey() {
		t.Fatalf("empty hex must produce a verifier without a key")
	}

	v, err = NewVerifierFromHex("   \n  ")
	if err != nil {
		t.Fatalf("whitespace: %v", err)
	}
	if v.HasKey() {
		t.Fatalf("whitespace-only hex must produce a verifier without a key")
	}

	v, err = NewVerifierFromHex(hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("valid hex: %v", err)
	}
	if !v.HasKey() {
		t.Fatalf("expected configured verifier")
	}

	// Padded valid hex must still decode after trimming.
	v, err = NewVerifierFromHex("  " + hex.EncodeToString(pub) + "  ")
	if err != nil {
		t.Fatalf("padded valid hex: %v", err)
	}
	if !v.HasKey() {
		t.Fatalf("padded hex must still produce a configured verifier")
	}

	if _, err := NewVerifierFromHex("zzzz"); err == nil {
		t.Fatalf("expected hex decode error")
	}
	if _, err := NewVerifierFromHex("abcd"); err == nil {
		t.Fatalf("expected wrong-length error")
	}
}

// TestVerifier_KeyCopyDefendsAgainstCallerMutation asserts that
// NewVerifier copies its input so a caller that reuses the slice
// later cannot silently flip the verifier into a wrong-key state.
func TestVerifier_KeyCopyDefendsAgainstCallerMutation(t *testing.T) {
	pub, priv := testKey(t)
	owned := append(ed25519.PublicKey(nil), pub...)

	v, err := NewVerifier(owned)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// Stomp the caller's copy after construction.
	for i := range owned {
		owned[i] ^= 0xff
	}

	p := signProfile(t, Profile{Name: "acme", Version: "1.0.0"}, priv)
	if err := v.Verify(&p); err != nil {
		t.Fatalf("verify must still succeed after caller mutation: %v", err)
	}
}

// TestLoadFromFile_WithVerifier exercises the wired verifier on the
// disk-loading path: a signed-with-the-configured-key profile must
// load; a tampered version of the same profile must be rejected.
func TestLoadFromFile_WithVerifier(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()

	signed := signProfile(t, Profile{Name: "acme", Version: "1.0.0", Managed: true}, priv)
	signedRaw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal signed: %v", err)
	}
	signedPath := filepath.Join(dir, "signed.json")
	if err := os.WriteFile(signedPath, signedRaw, 0o600); err != nil {
		t.Fatalf("write signed: %v", err)
	}

	v, err := NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := LoadFromFile(signedPath, v); err != nil {
		t.Fatalf("signed profile must load: %v", err)
	}

	// Same payload, but Name mutated post-signature — must fail
	// verification.
	tampered := signed
	tampered.Name = "different-name"
	tamperedRaw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	tamperedPath := filepath.Join(dir, "tampered.json")
	if err := os.WriteFile(tamperedPath, tamperedRaw, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	if _, err := LoadFromFile(tamperedPath, v); err == nil {
		t.Fatalf("tampered profile must fail verification")
	}
}

// TestLoadFromURL_WithVerifier exercises the wired verifier on the
// HTTPS-fetch path so we know both call sites of Verify behave
// identically. Uses the same hostCheck stub trick the other URL
// tests rely on so we can run against an httptest TLS server bound
// to 127.0.0.1.
func TestLoadFromURL_WithVerifier(t *testing.T) {
	orig := hostCheck
	hostCheck = func(_ context.Context, _ string) error { return nil }
	t.Cleanup(func() { hostCheck = orig })

	pub, priv := testKey(t)
	signed := signProfile(t, Profile{Name: "acme", Version: "1.0.0"}, priv)
	signedRaw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal signed: %v", err)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/signed":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(signedRaw)
		case "/unsigned":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"acme","version":"1.0.0"}`))
		}
	}))
	t.Cleanup(srv.Close)

	v, err := NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	if _, err := LoadFromURL(context.Background(), srv.Client(), srv.URL+"/signed", v); err != nil {
		t.Fatalf("signed URL must load: %v", err)
	}
	if _, err := LoadFromURL(context.Background(), srv.Client(), srv.URL+"/unsigned", v); err == nil {
		t.Fatalf("unsigned URL must be rejected when key is configured")
	}
}
