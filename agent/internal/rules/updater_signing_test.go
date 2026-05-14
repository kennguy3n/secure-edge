package rules

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// signedServer is a mockServer variant that signs the manifest body
// with the supplied private key before serving it. Tests can tamper
// with the served manifest (mutateBeforeSign / mutateAfterSign) to
// exercise the verifier's reject paths.
type signedServer struct {
	mu       sync.Mutex
	manifest Manifest
	files    map[string][]byte
	priv     ed25519.PrivateKey
	// mutateBeforeSign runs against a copy of the manifest before
	// the signature is computed. Use it when the change is meant
	// to remain signed (i.e. the verifier should still accept).
	mutateBeforeSign func(*Manifest)
	// mutateAfterSign runs against a copy of the manifest AFTER
	// the signature is computed. Use it to forge tampering that
	// the verifier must reject.
	mutateAfterSign func(*Manifest)
}

func (s *signedServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.URL.Path {
		case "/manifest.json":
			m := s.manifest
			if s.mutateBeforeSign != nil {
				s.mutateBeforeSign(&m)
			}
			if len(s.priv) != 0 {
				body, err := CanonicalForSigning(m)
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				sig := ed25519.Sign(s.priv, body)
				m.Signature = hex.EncodeToString(sig)
			}
			if s.mutateAfterSign != nil {
				s.mutateAfterSign(&m)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(m)
		default:
			name := strings.TrimPrefix(r.URL.Path, "/")
			b, ok := s.files[name]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(b)
		}
	})
}

func newSignedServer(t *testing.T, files map[string]string, version string, priv ed25519.PrivateKey) (*signedServer, *httptest.Server) {
	t.Helper()
	s := &signedServer{
		manifest: Manifest{Version: version},
		files:    make(map[string][]byte, len(files)),
		priv:     priv,
	}
	for name, content := range files {
		b := []byte(content)
		s.files[name] = b
		s.manifest.Files = append(s.manifest.Files, ManifestFile{
			Name:   name,
			SHA256: sha256Hex(b),
		})
	}
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return s, srv
}

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func TestUpdater_VerifiesSignedManifest(t *testing.T) {
	dir := t.TempDir()
	pub, priv := mustKeypair(t)
	_, srv := newSignedServer(t, map[string]string{
		"ai_allowed.txt": "openai.com\n",
	}, "1.0.0", priv)

	u, err := New(Options{
		ManifestURL:  srv.URL + "/manifest.json",
		PollInterval: time.Hour,
		RulesDir:     dir,
		PublicKey:    pub,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := u.CheckNow(context.Background())
	if err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if !res.Updated || res.Version != "1.0.0" {
		t.Fatalf("first run = %+v", res)
	}
}

func TestUpdater_RejectsMissingSignatureWhenKeyConfigured(t *testing.T) {
	dir := t.TempDir()
	pub, _ := mustKeypair(t)
	// Serve an UNSIGNED manifest (priv == nil) against a verifier
	// that expects a signature.
	_, srv := newSignedServer(t, map[string]string{
		"ai_allowed.txt": "openai.com\n",
	}, "1.0.0", nil)

	u, err := New(Options{
		ManifestURL:  srv.URL + "/manifest.json",
		PollInterval: time.Hour,
		RulesDir:     dir,
		PublicKey:    pub,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := u.CheckNow(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "signature required") {
		t.Fatalf("expected signature-required error, got %v", err)
	}
}

func TestUpdater_RejectsTamperedManifest(t *testing.T) {
	dir := t.TempDir()
	pub, priv := mustKeypair(t)
	s, srv := newSignedServer(t, map[string]string{
		"ai_allowed.txt": "openai.com\n",
	}, "1.0.0", priv)
	// After the signature is computed for the original manifest,
	// mutate the served body to bump the version. The signature
	// is still well-formed but no longer matches the body.
	s.mutateAfterSign = func(m *Manifest) {
		m.Version = "1.0.0-tampered"
	}

	u, err := New(Options{
		ManifestURL:  srv.URL + "/manifest.json",
		PollInterval: time.Hour,
		RulesDir:     dir,
		PublicKey:    pub,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := u.CheckNow(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("expected verification-failed error, got %v", err)
	}
}

func TestUpdater_RejectsWrongKey(t *testing.T) {
	dir := t.TempDir()
	pubAttacker, _ := mustKeypair(t)
	_, priv := mustKeypair(t)
	_, srv := newSignedServer(t, map[string]string{
		"ai_allowed.txt": "openai.com\n",
	}, "1.0.0", priv)

	u, err := New(Options{
		ManifestURL:  srv.URL + "/manifest.json",
		PollInterval: time.Hour,
		RulesDir:     dir,
		PublicKey:    pubAttacker,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := u.CheckNow(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("expected verification-failed error, got %v", err)
	}
}

func TestUpdater_RejectsMalformedSignatureBytes(t *testing.T) {
	dir := t.TempDir()
	pub, priv := mustKeypair(t)
	s, srv := newSignedServer(t, map[string]string{
		"ai_allowed.txt": "openai.com\n",
	}, "1.0.0", priv)
	s.mutateAfterSign = func(m *Manifest) {
		m.Signature = "not-hex"
	}

	u, err := New(Options{
		ManifestURL:  srv.URL + "/manifest.json",
		PollInterval: time.Hour,
		RulesDir:     dir,
		PublicKey:    pub,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := u.CheckNow(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "invalid signature encoding") {
		t.Fatalf("expected invalid-encoding error, got %v", err)
	}
}

func TestUpdater_RejectsShortSignature(t *testing.T) {
	dir := t.TempDir()
	pub, priv := mustKeypair(t)
	s, srv := newSignedServer(t, map[string]string{
		"ai_allowed.txt": "openai.com\n",
	}, "1.0.0", priv)
	s.mutateAfterSign = func(m *Manifest) {
		m.Signature = hex.EncodeToString([]byte{0xde, 0xad, 0xbe, 0xef})
	}

	u, err := New(Options{
		ManifestURL:  srv.URL + "/manifest.json",
		PollInterval: time.Hour,
		RulesDir:     dir,
		PublicKey:    pub,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := u.CheckNow(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "invalid signature length") {
		t.Fatalf("expected invalid-length error, got %v", err)
	}
}

func TestUpdater_AcceptsUnsignedManifestWhenNoKeyConfigured(t *testing.T) {
	// Backwards-compat path: a deployment that hasn't enabled the
	// new signing feature must still apply unsigned manifests so
	// the upgrade is opt-in. The updater logs a warning the first
	// time it observes one (not asserted here; the verifier's
	// log line isn't exposed in the public surface).
	dir := t.TempDir()
	_, srv := newSignedServer(t, map[string]string{
		"ai_allowed.txt": "openai.com\n",
	}, "1.0.0", nil)

	u, err := New(Options{
		ManifestURL:  srv.URL + "/manifest.json",
		PollInterval: time.Hour,
		RulesDir:     dir,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := u.CheckNow(context.Background())
	if err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if !res.Updated || res.Version != "1.0.0" {
		t.Fatalf("first run = %+v", res)
	}
}

func TestUpdater_AcceptsSignedManifestWhenNoKeyConfigured(t *testing.T) {
	// Mixed-deployment path: the upstream IS signing manifests
	// but THIS agent has no rule_update_public_key configured.
	// The updater must still apply the manifest (matching the
	// unsigned-no-key backwards-compat path) so a partial rollout
	// of public keys across a fleet doesn't break rule updates
	// on the agents that haven't received the key yet. The
	// updater logs a one-time WARN noting verification is being
	// skipped despite the signature being present — that signal
	// is the operator's only breadcrumb that some agents are
	// running unverified while others aren't.
	dir := t.TempDir()
	_, priv := mustKeypair(t)
	_, srv := newSignedServer(t, map[string]string{
		"ai_allowed.txt": "openai.com\n",
	}, "1.2.3", priv)

	u, err := New(Options{
		ManifestURL:  srv.URL + "/manifest.json",
		PollInterval: time.Hour,
		RulesDir:     dir,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := u.CheckNow(context.Background())
	if err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if !res.Updated || res.Version != "1.2.3" {
		t.Fatalf("first run = %+v", res)
	}
	// Second call should not return an error either — the warn
	// flag is set, but the verification still passes.
	if _, err := u.CheckNow(context.Background()); err != nil {
		t.Fatalf("CheckNow (second): %v", err)
	}
}

func TestCanonicalForSigning_OmitsSignatureField(t *testing.T) {
	body, err := CanonicalForSigning(Manifest{
		Version:   "1.0.0",
		Files:     []ManifestFile{{Name: "a.txt", SHA256: strings.Repeat("0", 64)}},
		Signature: "ffff",
	})
	if err != nil {
		t.Fatalf("CanonicalForSigning: %v", err)
	}
	if strings.Contains(string(body), "ffff") {
		t.Fatalf("canonical body must not include the signature field: %s", body)
	}
	if !strings.Contains(string(body), `"version":"1.0.0"`) {
		t.Fatalf("canonical body missing version: %s", body)
	}
}

func TestCanonicalForSigning_StableAcrossSigningAndVerifying(t *testing.T) {
	// Round-trip: sign a body, drop the signature, recanonicalise,
	// verify. The verifier MUST reproduce the same bytes the
	// signer signed over even though the wire-shape manifest has
	// `signature` populated when handed to it.
	pub, priv := mustKeypair(t)
	m := Manifest{
		Version: "9.9.9",
		Files: []ManifestFile{
			{Name: "ai_chat.txt", SHA256: strings.Repeat("a", 64)},
			{Name: "phishing.txt", SHA256: strings.Repeat("b", 64)},
		},
	}
	canonical, err := CanonicalForSigning(m)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sig := ed25519.Sign(priv, canonical)
	// Re-canonicalise after attaching the signature: the verifier
	// must produce the same bytes regardless of whether the
	// signature field is present on the input.
	mSigned := m
	mSigned.Signature = hex.EncodeToString(sig)
	again, err := CanonicalForSigning(mSigned)
	if err != nil {
		t.Fatalf("canonical (signed): %v", err)
	}
	if string(again) != string(canonical) {
		t.Fatalf("canonical mismatch:\n  pre:  %s\n  post: %s", canonical, again)
	}
	if !ed25519.Verify(pub, again, sig) {
		t.Fatalf("verify failed on round-tripped canonical body")
	}
}

// TestManifestBody_MirrorsManifestMinusSignature locks in the
// invariant that the dedicated `manifestBody` struct used by
// CanonicalForSigning has exactly the same fields as Manifest,
// in the same order, with the same JSON tags, minus the Signature
// field. If a future contributor adds a new field to Manifest
// without mirroring it on manifestBody, this test fails — making
// the silent-canonical-form-drift footgun unreachable.
func TestManifestBody_MirrorsManifestMinusSignature(t *testing.T) {
	mt := reflect.TypeOf(Manifest{})
	bt := reflect.TypeOf(manifestBody{})

	// Build a slice of (name, type, jsonTag) for every field in
	// Manifest that is NOT the Signature field.
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
		t.Fatalf("manifestBody has %d fields; expected %d (Manifest minus Signature). "+
			"Did you add a field to Manifest without mirroring it on manifestBody?",
			bt.NumField(), len(want))
	}
	for i, w := range want {
		got := bt.Field(i)
		if got.Name != w.Name || got.Type != w.Type || got.Tag.Get("json") != w.Tag {
			t.Fatalf("manifestBody field %d = {%s, %s, json=%q}; want {%s, %s, json=%q}. "+
				"Field order and JSON tags MUST match Manifest exactly so existing "+
				"signatures over the canonical form remain valid.",
				i, got.Name, got.Type, got.Tag.Get("json"),
				w.Name, w.Type, w.Tag)
		}
	}
}

// TestCanonicalForSigning_BytesUnchangedByRefactor pins the exact
// canonical byte sequence so we'd notice if the refactor (or any
// future change) accidentally altered the bytes a previously-valid
// signature was computed over. Updating this test means breaking
// every previously-signed manifest in the wild — do not change the
// expected literal lightly.
func TestCanonicalForSigning_BytesUnchangedByRefactor(t *testing.T) {
	body, err := CanonicalForSigning(Manifest{
		Version: "1.2.3",
		Files: []ManifestFile{
			{Name: "a.txt", SHA256: strings.Repeat("0", 64)},
		},
		Signature: "any-signature-here-must-not-affect-bytes",
	})
	if err != nil {
		t.Fatalf("CanonicalForSigning: %v", err)
	}
	want := `{"version":"1.2.3","files":[{"name":"a.txt","sha256":"` + strings.Repeat("0", 64) + `"}]}`
	if string(body) != want {
		t.Fatalf("canonical bytes drifted:\n  got:  %s\n  want: %s", body, want)
	}
}
