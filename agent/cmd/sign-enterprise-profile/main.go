// sign-enterprise-profile reads an unsigned enterprise profile
// (config/profile.json by convention), signs its canonical body
// with the supplied Ed25519 private key, and writes the result back
// with a populated `signature` field.
//
// It is intentionally minimal: the agent verifies signatures with
// `profile.CanonicalForSigning(p)` followed by `ed25519.Verify`,
// so the signer round-trips through the same package to guarantee
// the two agree on canonical bytes.
//
// Usage:
//
//	sign-enterprise-profile \
//	    -in config/profile.json \
//	    -out config/profile.json \
//	    -key /path/to/ed25519-private.hex
//
// The private-key file holds a 64-byte (128 hex-character) Ed25519
// private key as documented by crypto/ed25519. The matching public
// key is the last 32 bytes of that value; pass its hex encoding to
// the agent as `profile_public_key`.
//
// The signer never touches the network — it operates on a local
// profile file only. Distribute the signed profile exactly as you
// would distribute the unsigned one. This binary mirrors
// sign-rule-manifest (shipped in A3 / PR #20) verbatim so the two
// signing flows can be operated with one mental model.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/kennguy3n/secure-edge/agent/internal/profile"
)

func main() {
	inPath := flag.String("in", "config/profile.json", "Path to the unsigned profile")
	outPath := flag.String("out", "", "Where to write the signed profile. Defaults to -in (overwrite).")
	keyPath := flag.String("key", "", "Path to a file holding the Ed25519 private key as hex (128 hex chars)")
	flag.Parse()

	if *keyPath == "" {
		log.Fatal("sign-enterprise-profile: -key is required")
	}
	if *outPath == "" {
		*outPath = *inPath
	}

	keyBytes, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatalf("sign-enterprise-profile: read key: %v", err)
	}
	priv, err := decodePrivateKey(strings.TrimSpace(string(keyBytes)))
	if err != nil {
		log.Fatalf("sign-enterprise-profile: parse key: %v", err)
	}

	raw, err := os.ReadFile(*inPath)
	if err != nil {
		log.Fatalf("sign-enterprise-profile: read profile: %v", err)
	}
	var p profile.Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		log.Fatalf("sign-enterprise-profile: parse profile: %v", err)
	}
	if strings.TrimSpace(p.Name) == "" {
		log.Fatal("sign-enterprise-profile: profile is missing name")
	}
	// Drop any pre-existing signature so the canonical body is
	// computed from the body alone. profileBody physically lacks a
	// Signature field, so even without this line CanonicalForSigning
	// would emit the same bytes — but clearing the field keeps the
	// serialized output we write back to disk free of stale
	// signature material if the caller pointed the signer at a
	// profile that had already been signed once.
	p.Signature = ""

	body, err := profile.CanonicalForSigning(p)
	if err != nil {
		log.Fatalf("sign-enterprise-profile: canonicalize: %v", err)
	}
	sig := ed25519.Sign(priv, body)
	p.Signature = hex.EncodeToString(sig)

	signed, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		log.Fatalf("sign-enterprise-profile: encode signed profile: %v", err)
	}
	// Match the trailing newline most editors emit so the file
	// round-trips through git without churn.
	signed = append(signed, '\n')
	if err := os.WriteFile(*outPath, signed, 0o644); err != nil {
		log.Fatalf("sign-enterprise-profile: write %s: %v", *outPath, err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Fprintf(os.Stderr,
		"sign-enterprise-profile: signed %s (name=%s version=%s)\n  public key: %s\n  configure the agent with `profile_public_key: \"%s\"`\n",
		*outPath, p.Name, p.Version, hex.EncodeToString(pub), hex.EncodeToString(pub))
}

func decodePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", ed25519.PrivateKeySize, len(b))
	}
	return ed25519.PrivateKey(b), nil
}
