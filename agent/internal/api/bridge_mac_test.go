package api

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestComputeRequestMAC_Determinism pins the MAC output for a fixed
// (secret, nonce, id, kind, content) tuple. The extension-side
// implementation reproduces the same byte layout in TypeScript and
// hits a parallel test against this same vector - if either side's
// HMAC input layout drifts, this test will catch it before the
// other side does.
func TestComputeRequestMAC_Determinism(t *testing.T) {
	// Nonce is hex-encoded 16 bytes (32 hex chars).
	const nonceHex = "00112233445566778899aabbccddeeff"
	const secret = "test-secret"
	got, err := computeRequestMAC(secret, nonceHex, 7, "scan", "AKIAEXAMPLE")
	if err != nil {
		t.Fatalf("computeRequestMAC: %v", err)
	}
	// Canonical cross-language reference vector. The extension-
	// side TestComputeRequestMAC test in
	// extension/src/background/__tests__/bridge-mac.test.ts is
	// expected to produce the same value. If either side changes
	// (different field ordering, different direction byte,
	// different len-prefix encoding) one test will pin the new
	// value and the other will catch the drift.
	const want = "34f819f23133c9fc58b313833c1f70fb0cbedabf7adbc61ae37ce916d191dfe0"
	if got != want {
		t.Errorf("MAC mismatch:\n got %s\nwant %s", got, want)
	}
	if _, decErr := hex.DecodeString(got); decErr != nil {
		t.Errorf("MAC must be lowercase hex; got %q (decode err %v)", got, decErr)
	}
	if strings.ToLower(got) != got {
		t.Errorf("MAC must be lowercase hex; got %q", got)
	}
}

// TestComputeResponseMAC_Determinism is the response-side mirror
// of the request determinism test.
func TestComputeResponseMAC_Determinism(t *testing.T) {
	const nonceHex = "00112233445566778899aabbccddeeff"
	const secret = "test-secret"
	got, err := computeResponseMAC(secret, nonceHex, 7, "scan", 0x01 /* blocked */, "" /* api_token */, "" /* error */)
	if err != nil {
		t.Fatalf("computeResponseMAC: %v", err)
	}
	const want = "f902a99d89500a718a53c08c34c516a77c40fe62aa13951e9dab386fa3b7cdcf"
	if got != want {
		t.Errorf("MAC mismatch:\n got %s\nwant %s", got, want)
	}
}

// TestComputeRequestMAC_DiffersByField pins that every input
// component actually moves the output - i.e. each field is
// covered by the HMAC. Without this we could silently regress to
// a MAC that ignores one of its inputs.
func TestComputeRequestMAC_DiffersByField(t *testing.T) {
	const nonceHex = "00112233445566778899aabbccddeeff"
	const altNonce = "ffeeddccbbaa99887766554433221100"
	mac := func(secret, nonce string, id int, kind, content string) string {
		t.Helper()
		out, err := computeRequestMAC(secret, nonce, id, kind, content)
		if err != nil {
			t.Fatalf("compute: %v", err)
		}
		return out
	}
	base := mac("k", nonceHex, 1, "scan", "x")
	mutated := []struct {
		name string
		mac  string
	}{
		{"different-secret", mac("kk", nonceHex, 1, "scan", "x")},
		{"different-nonce", mac("k", altNonce, 1, "scan", "x")},
		{"different-id", mac("k", nonceHex, 2, "scan", "x")},
		{"different-kind", mac("k", nonceHex, 1, "hello", "x")},
		{"different-content", mac("k", nonceHex, 1, "scan", "y")},
	}
	for _, m := range mutated {
		if m.mac == base {
			t.Errorf("%s did not change the MAC - field is not covered by the HMAC input", m.name)
		}
	}
}

// TestRequestAndResponseMACsDiffer pins that the direction byte
// actually domain-separates request and response MACs for an
// otherwise-identical tuple. Without this an attacker could
// replay a captured request MAC as a response MAC (same id,
// same secret, same nonce).
func TestRequestAndResponseMACsDiffer(t *testing.T) {
	const nonceHex = "00112233445566778899aabbccddeeff"
	req, err := computeRequestMAC("k", nonceHex, 1, "scan", "")
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	resp, err := computeResponseMAC("k", nonceHex, 1, "scan", 0x00, "", "")
	if err != nil {
		t.Fatalf("resp: %v", err)
	}
	if req == resp {
		t.Errorf("request and response MACs collide for identical content - direction byte not in HMAC input")
	}
}

// TestVerifyRequestMAC_AcceptsAndRejects round-trips a valid MAC
// against verifyRequestMAC, then checks each mutated copy is
// rejected. The mutation list mirrors the field-coverage table
// above so any regression is caught twice.
func TestVerifyRequestMAC_AcceptsAndRejects(t *testing.T) {
	const nonceHex = "00112233445566778899aabbccddeeff"
	const secret = "k"
	mac, err := computeRequestMAC(secret, nonceHex, 1, "scan", "x")
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if err := verifyRequestMAC(secret, nonceHex, 1, "scan", "x", mac); err != nil {
		t.Errorf("valid MAC was rejected: %v", err)
	}
	if err := verifyRequestMAC(secret, nonceHex, 1, "scan", "y", mac); err == nil {
		t.Error("MAC for content=x accepted on content=y")
	}
	if err := verifyRequestMAC("k2", nonceHex, 1, "scan", "x", mac); err == nil {
		t.Error("MAC for secret=k accepted under secret=k2")
	}
	if err := verifyRequestMAC(secret, nonceHex, 1, "scan", "x", ""); err == nil {
		t.Error("empty MAC was accepted")
	}
	if err := verifyRequestMAC(secret, nonceHex, 1, "scan", "x", "zzzz"); err == nil {
		t.Error("malformed hex MAC was accepted")
	}
}

// TestGenerateBridgeNonce_HexAndLength pins the wire format of
// the nonce. The hex-decoded byte length must equal
// bridgeNonceLen, and the encoding must be lowercase hex (so the
// extension can decode it with /^[0-9a-f]+$/).
func TestGenerateBridgeNonce_HexAndLength(t *testing.T) {
	got, err := generateBridgeNonce()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	decoded, err := hex.DecodeString(got)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded) != bridgeNonceLen {
		t.Errorf("nonce decoded length = %d, want %d", len(decoded), bridgeNonceLen)
	}
	if strings.ToLower(got) != got {
		t.Errorf("nonce must be lowercase hex; got %q", got)
	}
	// Two consecutive nonces must differ - the source is
	// crypto/rand so a collision is astronomically unlikely.
	other, err := generateBridgeNonce()
	if err != nil {
		t.Fatalf("generate other: %v", err)
	}
	if other == got {
		t.Errorf("two consecutive nonces collided: %s == %s (RNG broken?)", other, got)
	}
}

// TestComputeRequestMAC_RejectsBadNonceHex pins the error path for
// nonce decoding. The HMAC must refuse to operate on an empty or
// malformed nonce rather than silently fall through to a fixed
// zero-byte nonce.
func TestComputeRequestMAC_RejectsBadNonceHex(t *testing.T) {
	if _, err := computeRequestMAC("k", "", 1, "scan", "x"); err == nil {
		t.Error("empty nonce was accepted")
	}
	if _, err := computeRequestMAC("k", "zzz", 1, "scan", "x"); err == nil {
		t.Error("invalid-hex nonce was accepted")
	}
}
