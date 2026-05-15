// Random string helpers used by both the value generators and the
// context renderers. All functions take a *rand.Rand so the caller can
// seed the generator and get reproducible output.

package main

import (
	"fmt"
	"math/rand"
	"strings"
)

const (
	lower    = "abcdefghijklmnopqrstuvwxyz"
	upper    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits   = "0123456789"
	alpha    = lower + upper
	alnum    = alpha + digits
	hexLower = "0123456789abcdef"
	hexUpper = "0123456789ABCDEF"
	upAlnum  = upper + digits
	// Base64 std alphabet (no padding).
	b64Alpha = upper + lower + digits + "+/"
	// Base64 URL-safe alphabet.
	b64URLAlpha = upper + lower + digits + "_-"
	// Base32 lowercase (used for the Azure DevOps PAT pattern: [a-z2-7]).
	base32Alpha = "abcdefghijklmnopqrstuvwxyz234567"
)

func randFromAlphabet(r *rand.Rand, alphabet string, n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

// randAlnum returns a string of length n drawn from [A-Za-z0-9].
// We bias roughly half the chars to digits so the resulting string has
// healthy Shannon entropy (>= 4.0) for entropy_min checks.
func randAlnum(r *rand.Rand, n int) string {
	return randFromAlphabet(r, alnum, n)
}

func randUpperAlnum(r *rand.Rand, n int) string {
	return randFromAlphabet(r, upAlnum, n)
}

func randLowerAlnum(r *rand.Rand, n int) string {
	return randFromAlphabet(r, lower+digits, n)
}

func randHex(r *rand.Rand, n int) string {
	return randFromAlphabet(r, hexLower, n)
}

func randHexUpper(r *rand.Rand, n int) string {
	return randFromAlphabet(r, hexUpper, n)
}

func randBase64(r *rand.Rand, n int) string {
	return randFromAlphabet(r, b64Alpha, n)
}

func randBase64URL(r *rand.Rand, n int) string {
	return randFromAlphabet(r, b64URLAlpha, n)
}

func randBase32Lower(r *rand.Rand, n int) string {
	return randFromAlphabet(r, base32Alpha, n)
}

// randUUID returns a random hex UUID in the canonical 8-4-4-4-12 form.
func randUUID(r *rand.Rand) string {
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		randHex(r, 8), randHex(r, 4), randHex(r, 4),
		randHex(r, 4), randHex(r, 12))
}

// randSecretAlphabet returns a mixed-case alnum with the extra
// characters used by many secret formats (+ / = _ - .).
func randSecretAlphabet(r *rand.Rand, n int) string {
	return randFromAlphabet(r, alnum+"+/=_-.", n)
}

// pick returns a uniformly-chosen element of xs.
func pick[T any](r *rand.Rand, xs []T) T {
	return xs[r.Intn(len(xs))]
}

// pickMany returns k distinct elements of xs (without replacement).
// If k > len(xs), it returns a shuffled copy of xs.
func pickMany[T any](r *rand.Rand, xs []T, k int) []T {
	if k <= 0 || len(xs) == 0 {
		return nil
	}
	if k > len(xs) {
		k = len(xs)
	}
	idx := r.Perm(len(xs))[:k]
	out := make([]T, 0, k)
	for _, i := range idx {
		out = append(out, xs[i])
	}
	return out
}

// joinLines joins lines with "\n" and trims trailing empties.
func joinLines(lines ...string) string {
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

// colonHexPairs returns n hex byte pairs joined by ':',
// matching the (?:[0-9a-f]{2}:){n-1}[0-9a-f]{2} shape used in
// API key fingerprints (e.g. Oracle Cloud OCI).
func colonHexPairs(r *rand.Rand, n int) string {
	if n <= 0 {
		return ""
	}
	pairs := make([]string, n)
	for i := range pairs {
		pairs[i] = randHex(r, 2)
	}
	return strings.Join(pairs, ":")
}

// bip39LikePhrase returns a 12- or 24-word lowercase phrase that
// matches the loose mnemonic regex used by W1 batch 3 crypto patterns.
// The words are not the real BIP-39 dictionary; they are random
// lowercase letter clusters between 3 and 8 characters long so the
// regex engine sees the expected shape ("word word word ... word").
func bip39LikePhrase(r *rand.Rand, n int) string {
	if n <= 0 {
		n = 12
	}
	out := make([]string, n)
	for i := range out {
		out[i] = randFromAlphabet(r, "abcdefghijklmnopqrstuvwxyz", 3+r.Intn(6))
	}
	return strings.Join(out, " ")
}

// solanaKeypair returns the JSON-array form of a Solana 64-byte
// secret key, e.g. "[12,34,56,...,200]" (64 numbers, each 0-255).
func solanaKeypair(r *rand.Rand) string {
	nums := make([]string, 64)
	for i := range nums {
		nums[i] = fmt.Sprintf("%d", r.Intn(256))
	}
	return "[" + strings.Join(nums, ",") + "]"
}
