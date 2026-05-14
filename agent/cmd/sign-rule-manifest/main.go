// sign-rule-manifest reads an unsigned rule manifest (rules/manifest.json
// by default), signs its canonical body with the supplied Ed25519
// private key, and writes the result back with a populated `signature`
// field.
//
// It is intentionally minimal: the agent verifies signatures with
// `rules.CanonicalForSigning(m)` followed by `ed25519.Verify`, so the
// signer round-trips through the same package to guarantee the two
// agree on canonical bytes.
//
// Usage:
//
//	sign-rule-manifest \
//	    -in rules/manifest.json \
//	    -out rules/manifest.json \
//	    -key /path/to/ed25519-private.hex
//
// The private-key file holds a 64-byte (128 hex-character) Ed25519
// private key as documented by crypto/ed25519. The matching public
// key is the last 32 bytes of that value; pass its hex encoding to
// the agent as `rule_update_public_key`.
//
// The signer never touches the network — it operates on a local
// manifest file only. Distribute the signed manifest exactly as you
// would distribute the unsigned one.
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

	"github.com/kennguy3n/secure-edge/agent/internal/rules"
)

func main() {
	inPath := flag.String("in", "rules/manifest.json", "Path to the unsigned manifest")
	outPath := flag.String("out", "", "Where to write the signed manifest. Defaults to -in (overwrite).")
	keyPath := flag.String("key", "", "Path to a file holding the Ed25519 private key as hex (128 hex chars)")
	flag.Parse()

	if *keyPath == "" {
		log.Fatal("sign-rule-manifest: -key is required")
	}
	if *outPath == "" {
		*outPath = *inPath
	}

	keyBytes, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatalf("sign-rule-manifest: read key: %v", err)
	}
	priv, err := decodePrivateKey(strings.TrimSpace(string(keyBytes)))
	if err != nil {
		log.Fatalf("sign-rule-manifest: parse key: %v", err)
	}

	raw, err := os.ReadFile(*inPath)
	if err != nil {
		log.Fatalf("sign-rule-manifest: read manifest: %v", err)
	}
	var m rules.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		log.Fatalf("sign-rule-manifest: parse manifest: %v", err)
	}
	if strings.TrimSpace(m.Version) == "" || len(m.Files) == 0 {
		log.Fatal("sign-rule-manifest: manifest is missing version or files")
	}
	// Drop any pre-existing signature so the canonical body is
	// computed from the body alone.
	m.Signature = ""

	body, err := rules.CanonicalForSigning(m)
	if err != nil {
		log.Fatalf("sign-rule-manifest: canonicalize: %v", err)
	}
	sig := ed25519.Sign(priv, body)
	m.Signature = hex.EncodeToString(sig)

	signed, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Fatalf("sign-rule-manifest: encode signed manifest: %v", err)
	}
	// Match the trailing newline most editors emit so the file
	// round-trips through git without churn.
	signed = append(signed, '\n')
	if err := os.WriteFile(*outPath, signed, 0o644); err != nil {
		log.Fatalf("sign-rule-manifest: write %s: %v", *outPath, err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Fprintf(os.Stderr,
		"sign-rule-manifest: signed %s (version=%s)\n  public key: %s\n  configure the agent with `rule_update_public_key: \"%s\"`\n",
		*outPath, m.Version, hex.EncodeToString(pub), hex.EncodeToString(pub))
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
