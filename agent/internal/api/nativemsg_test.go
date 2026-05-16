package api

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"

	"github.com/kennguy3n/secure-edge/agent/internal/dlp"
	"github.com/kennguy3n/secure-edge/agent/internal/dlp/ml"
	"github.com/kennguy3n/secure-edge/agent/internal/store"
)

// fakeScanner is a DLPScanner that returns a fixed result.
type fakeScanner struct {
	result   dlp.ScanResult
	lastSeen string
}

func (f *fakeScanner) Scan(_ context.Context, content string) dlp.ScanResult {
	f.lastSeen = content
	return f.result
}
func (f *fakeScanner) Threshold() *dlp.ThresholdEngine { return nil }
func (f *fakeScanner) SetWeights(_ dlp.ScoreWeights)   {}
func (f *fakeScanner) Weights() dlp.ScoreWeights       { return dlp.ScoreWeights{} }
func (f *fakeScanner) Patterns() []*dlp.Pattern        { return nil }
func (f *fakeScanner) MLLayer() *ml.Layer              { return nil }

func frame(t *testing.T, msg any) []byte {
	t.Helper()
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(body)))
	copy(out[4:], body)
	return out
}

// readFrames splits a serialised stream produced by ServeNativeMessaging
// into its individual length-prefixed JSON payloads.
func readFrames(t *testing.T, r io.Reader) []NativeMessageResponse {
	t.Helper()
	var out []NativeMessageResponse
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if err == io.EOF {
				return out
			}
			t.Fatalf("readFrames len: %v", err)
		}
		n := binary.LittleEndian.Uint32(lenBuf[:])
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			t.Fatalf("readFrames body: %v", err)
		}
		var resp NativeMessageResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("readFrames decode: %v", err)
		}
		out = append(out, resp)
	}
}

func TestNativeMessaging_ScanRoundTrip(t *testing.T) {
	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: true, PatternName: "aws_access_key_id", Score: 9}}
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 42, Kind: "scan", Content: "AKIAEXAMPLE"}))

	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), scanner, nil, &in, &out); err != nil {
		t.Fatalf("ServeNativeMessaging: %v", err)
	}

	frames := readFrames(t, &out)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	if frames[0].ID != 42 {
		t.Errorf("id = %d, want 42", frames[0].ID)
	}
	if frames[0].Result == nil || !frames[0].Result.Blocked {
		t.Errorf("result = %+v, want Blocked=true", frames[0].Result)
	}
	if frames[0].Result.PatternName != "aws_access_key_id" {
		t.Errorf("pattern = %q", frames[0].Result.PatternName)
	}
	if scanner.lastSeen != "AKIAEXAMPLE" {
		t.Errorf("scanner saw %q", scanner.lastSeen)
	}
}

func TestNativeMessaging_MultipleFrames(t *testing.T) {
	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: false}}
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "scan", Content: "hello"}))
	in.Write(frame(t, NativeMessageRequest{ID: 2, Kind: "scan", Content: "world"}))

	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), scanner, nil, &in, &out); err != nil {
		t.Fatalf("ServeNativeMessaging: %v", err)
	}

	frames := readFrames(t, &out)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	if frames[0].ID != 1 || frames[1].ID != 2 {
		t.Errorf("ids = %d/%d", frames[0].ID, frames[1].ID)
	}
}

func TestNativeMessaging_NilScanner(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 7, Kind: "scan", Content: "x"}))

	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), nil, nil, &in, &out); err != nil {
		t.Fatalf("err: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 1 || frames[0].Error == "" {
		t.Fatalf("expected error response, got %+v", frames)
	}
	if frames[0].Result != nil {
		t.Errorf("result should be nil when error set")
	}
}

func TestNativeMessaging_UnknownKind(t *testing.T) {
	scanner := &fakeScanner{}
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "frobnicate", Content: ""}))

	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), scanner, nil, &in, &out); err != nil {
		t.Fatalf("err: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 1 || frames[0].Error == "" {
		t.Fatalf("expected error response, got %+v", frames)
	}
}

func TestNativeMessaging_MalformedJSON(t *testing.T) {
	var in bytes.Buffer
	body := []byte("not json")
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(body)))
	in.Write(lenBuf[:])
	in.Write(body)

	scanner := &fakeScanner{}
	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), scanner, nil, &in, &out); err != nil {
		t.Fatalf("err: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 1 || frames[0].Error == "" {
		t.Fatalf("expected error response, got %+v", frames)
	}
}

func TestNativeMessaging_OverlargeMessageRejected(t *testing.T) {
	// Forge a length prefix above the cap; readNativeMessage should error.
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], MaxNativeMessageBytes+1)
	var in bytes.Buffer
	in.Write(lenBuf[:])

	scanner := &fakeScanner{}
	var out bytes.Buffer
	err := ServeNativeMessaging(context.Background(), scanner, nil, &in, &out)
	if err == nil {
		t.Fatalf("expected error for oversize frame")
	}
}

func TestNativeMessaging_ContextCanceledBeforeRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done

	scanner := &fakeScanner{}
	var in bytes.Buffer
	var out bytes.Buffer
	if err := ServeNativeMessaging(ctx, scanner, nil, &in, &out); err != nil {
		t.Fatalf("err: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("no writes expected when ctx cancelled before read, got %d bytes", out.Len())
	}
}

func TestNativeMessaging_FramingRoundTripsWithReader(t *testing.T) {
	// Drive ServeNativeMessaging with a pipe so we exercise the
	// length-prefix decoder against a real io.Reader. Send two
	// requests, close the writer, then confirm both responses came
	// back through.
	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: true, PatternName: "github_pat", Score: 7}}
	pr, pw := io.Pipe()
	defer pr.Close()

	var out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- ServeNativeMessaging(context.Background(), scanner, nil, pr, &out)
	}()

	for i, id := range []int{10, 11} {
		_ = i
		if _, err := pw.Write(frame(t, NativeMessageRequest{ID: id, Kind: "scan", Content: "ghp_token"})); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	_ = pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("serve err: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	if frames[0].Result == nil || !frames[0].Result.Blocked {
		t.Fatalf("first response missing block: %+v", frames[0])
	}
}

// TestNativeMessaging_StatsCountersBump verifies the Native Messaging
// transport bumps the same dlp_scans_total / dlp_blocks_total counters
// that the HTTP /api/dlp/scan handler bumps. Without this, the Status
// page silently undercounts whenever Chrome picks NM over the HTTP
// fallback (which is the default once the host manifest is installed).
func TestNativeMessaging_StatsCountersBump(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nm-stats.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()

	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: true, PatternName: "aws_access_key_id", Score: 9}}
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "scan", Content: "AKIA00000000000000000"}))
	in.Write(frame(t, NativeMessageRequest{ID: 2, Kind: "scan", Content: "AKIA11111111111111111"}))

	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), scanner, s, &in, &out); err != nil {
		t.Fatalf("ServeNativeMessaging: %v", err)
	}

	got, err := s.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	// Both frames were blocked by fakeScanner, so dlp_scans_total
	// and dlp_blocks_total should both have advanced by exactly 2.
	if got.DLPScansTotal != 2 {
		t.Errorf("dlp_scans_total = %d, want 2", got.DLPScansTotal)
	}
	if got.DLPBlocksTotal != 2 {
		t.Errorf("dlp_blocks_total = %d, want 2", got.DLPBlocksTotal)
	}
	if got.DNSQueriesTotal != 0 || got.DNSBlocksTotal != 0 {
		t.Errorf("DNS counters touched: %+v", got)
	}
}

// TestNativeMessaging_StatsCountersBumpOnAllow confirms that an
// unblocked scan only increments dlp_scans_total, not dlp_blocks_total.
func TestNativeMessaging_StatsCountersBumpOnAllow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nm-stats-allow.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()

	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: false}}
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "scan", Content: "harmless"}))

	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), scanner, s, &in, &out); err != nil {
		t.Fatalf("ServeNativeMessaging: %v", err)
	}

	got, err := s.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if got.DLPScansTotal != 1 {
		t.Errorf("dlp_scans_total = %d, want 1", got.DLPScansTotal)
	}
	if got.DLPBlocksTotal != 0 {
		t.Errorf("dlp_blocks_total = %d, want 0 (allow path)", got.DLPBlocksTotal)
	}
}

// TestNativeMessaging_HelloReturnsAPIToken confirms the A2
// capability-token bootstrap: a "hello" request returns the
// configured token in api_token so the extension can cache it for
// its HTTP-fallback path.
func TestNativeMessaging_HelloReturnsAPIToken(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 7, Kind: "hello"}))

	var out bytes.Buffer
	err := ServeNativeMessagingWithOptions(
		context.Background(),
		nil, // scanner not needed for hello
		nil, // no stats store needed
		NativeMessagingOptions{APIToken: "tok-12345"},
		&in, &out,
	)
	if err != nil {
		t.Fatalf("ServeNativeMessagingWithOptions: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	got := frames[0]
	if got.ID != 7 {
		t.Errorf("ID = %d, want 7", got.ID)
	}
	if got.APIToken != "tok-12345" {
		t.Errorf("APIToken = %q, want %q", got.APIToken, "tok-12345")
	}
	if got.Error != "" {
		t.Errorf("Error = %q, want empty", got.Error)
	}
}

// TestNativeMessaging_HelloWithoutTokenReturnsEmpty confirms the
// backwards-compat path: a hello request against a host that has
// no token wired in returns an empty api_token (not an error) so
// the extension can fall back to the pre-A2 posture.
func TestNativeMessaging_HelloWithoutTokenReturnsEmpty(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 7, Kind: "hello"}))

	var out bytes.Buffer
	err := ServeNativeMessagingWithOptions(
		context.Background(),
		nil, nil,
		NativeMessagingOptions{}, // no token
		&in, &out,
	)
	if err != nil {
		t.Fatalf("ServeNativeMessagingWithOptions: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	if frames[0].APIToken != "" {
		t.Errorf("APIToken = %q, want empty", frames[0].APIToken)
	}
	if frames[0].Error != "" {
		t.Errorf("Error = %q, want empty", frames[0].Error)
	}
}

// TestNativeMessaging_ShimDelegatesToOptions confirms that the
// backwards-compat shim ServeNativeMessaging delegates correctly:
// scans still work, and hello returns empty token because the shim
// passes a zero-value options struct.
func TestNativeMessaging_ShimDelegatesToOptions(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 9, Kind: "hello"}))

	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), nil, nil, &in, &out); err != nil {
		t.Fatalf("shim: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	if frames[0].APIToken != "" {
		t.Errorf("shim hello: APIToken = %q, want empty", frames[0].APIToken)
	}
}

// TestNativeMessaging_HelloReturnsBridgeNonceWhenTokenConfigured
// pins the C1 bootstrap contract: when an API token is configured,
// the hello reply must surface a bridge_nonce so the extension can
// seed its MAC computation. The reply itself is NOT MAC'd (TOFU).
func TestNativeMessaging_HelloReturnsBridgeNonceWhenTokenConfigured(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "hello"}))

	var out bytes.Buffer
	err := ServeNativeMessagingWithOptions(
		context.Background(),
		nil, nil,
		NativeMessagingOptions{APIToken: "secret-token"},
		&in, &out,
	)
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	if frames[0].BridgeNonce == "" {
		t.Errorf("bridge_nonce empty on hello reply with token configured")
	}
	if frames[0].MAC != "" {
		t.Errorf("hello reply must NOT carry mac (TOFU); got %q", frames[0].MAC)
	}
	if frames[0].APIToken != "secret-token" {
		t.Errorf("api_token = %q, want secret-token", frames[0].APIToken)
	}
}

// TestNativeMessaging_HelloOmitsBridgeNonceWhenNoToken pins the
// backwards-compat path: with no API token wired in, the agent
// omits bridge_nonce so a pre-A2 deployment's extension probe
// reads "no MAC infrastructure available" rather than "nonce
// configured but no key to verify against".
func TestNativeMessaging_HelloOmitsBridgeNonceWhenNoToken(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "hello"}))

	var out bytes.Buffer
	if err := ServeNativeMessagingWithOptions(
		context.Background(),
		nil, nil,
		NativeMessagingOptions{}, // no token
		&in, &out,
	); err != nil {
		t.Fatalf("serve: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	if frames[0].BridgeNonce != "" {
		t.Errorf("bridge_nonce should be empty when no token, got %q", frames[0].BridgeNonce)
	}
}

// TestNativeMessaging_HelloOnlyOncePerConnection pins the
// "hello-issued" guard. A second hello on the same connection MUST
// fail so an attacker cannot re-bootstrap the shared nonce
// mid-stream.
func TestNativeMessaging_HelloOnlyOncePerConnection(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "hello"}))
	in.Write(frame(t, NativeMessageRequest{ID: 2, Kind: "hello"}))

	var out bytes.Buffer
	if err := ServeNativeMessagingWithOptions(
		context.Background(),
		nil, nil,
		NativeMessagingOptions{APIToken: "tok"},
		&in, &out,
	); err != nil {
		t.Fatalf("serve: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want 2", len(frames))
	}
	if frames[0].Error != "" {
		t.Errorf("first hello error = %q, want empty", frames[0].Error)
	}
	if frames[1].Error != "hello already issued" {
		t.Errorf("second hello error = %q, want 'hello already issued'", frames[1].Error)
	}
}

// TestNativeMessaging_ValidRequestMACRoundTrip pins the happy path:
// extension computes a valid MAC over the scan request, agent
// verifies + serves, agent's scan reply also carries a MAC that
// the extension can verify.
//
// Implementation note: we use synchronous io.Pipe()s for both
// stdin and stdout so the test can read the hello reply (and
// extract the nonce) before having to write the scan request.
// A pre-buffered bytes.Buffer wouldn't let us do that — the
// nonce is minted at the start of each ServeNativeMessaging
// invocation, so we can't compute the MAC ahead of time.
func TestNativeMessaging_ValidRequestMACRoundTrip(t *testing.T) {
	const token = "test-bridge-secret"
	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: true, PatternName: "aws_access_key_id", Score: 9}}

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	defer stdinR.Close()
	defer stdoutW.Close()

	done := make(chan error, 1)
	go func() {
		done <- ServeNativeMessagingWithOptions(context.Background(), scanner, nil,
			NativeMessagingOptions{APIToken: token, BridgeMACRequired: true},
			stdinR, stdoutW)
		// Close stdoutW so the test side's reads unblock once
		// the agent has finished.
		_ = stdoutW.Close()
	}()

	// Send hello, then synchronously read the hello reply to
	// extract the freshly-minted nonce.
	if _, err := stdinW.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "hello"})); err != nil {
		t.Fatalf("hello write: %v", err)
	}
	helloReply := readOneFrame(t, stdoutR)
	if helloReply.BridgeNonce == "" {
		t.Fatalf("hello reply missing bridge_nonce: %+v", helloReply)
	}

	// Compute a request MAC against the agent's nonce.
	const id = 7
	const kind = "scan"
	const content = "AKIAEXAMPLE"
	mac, err := computeRequestMAC(token, helloReply.BridgeNonce, id, kind, content)
	if err != nil {
		t.Fatalf("computeRequestMAC: %v", err)
	}

	// Send the scan with a valid MAC, then close the agent's
	// stdin so it returns from the read loop.
	if _, err := stdinW.Write(frame(t, NativeMessageRequest{ID: id, Kind: kind, Content: content, MAC: mac})); err != nil {
		t.Fatalf("scan write: %v", err)
	}
	_ = stdinW.Close()

	scanResp := readOneFrame(t, stdoutR)
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}
	if scanResp.Error != "" {
		t.Fatalf("scan error = %q, want empty (strict-mode happy path)", scanResp.Error)
	}
	if scanResp.Result == nil || !scanResp.Result.Blocked {
		t.Errorf("scan result = %+v, want Blocked=true", scanResp.Result)
	}
	if scanResp.MAC == "" {
		t.Errorf("scan reply must carry mac")
	}
	wantMAC, err := computeResponseMAC(token, helloReply.BridgeNonce, id, kind, 0x01 /* Blocked */, "", "")
	if err != nil {
		t.Fatalf("computeResponseMAC: %v", err)
	}
	if scanResp.MAC != wantMAC {
		t.Errorf("response MAC = %q, want %q", scanResp.MAC, wantMAC)
	}
	if scanner.lastSeen != content {
		t.Errorf("scanner saw %q, want %q", scanner.lastSeen, content)
	}
}

// readOneFrame reads a single length-prefixed JSON frame from r.
// Helper for tests that need to read replies synchronously from
// an io.Pipe (i.e. before sending the next request).
func readOneFrame(t *testing.T, r io.Reader) NativeMessageResponse {
	t.Helper()
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		t.Fatalf("readOneFrame len: %v", err)
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatalf("readOneFrame body: %v", err)
	}
	var resp NativeMessageResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("readOneFrame decode: %v", err)
	}
	return resp
}

// TestNativeMessaging_BadMACStrictRejects pins the strict-mode
// posture: a scan with no MAC (or a bad MAC) gets rejected with
// the documented error string and the scanner is NOT invoked.
func TestNativeMessaging_BadMACStrictRejects(t *testing.T) {
	// Pre-rendered 32-byte hex strings to avoid Python-style
	// `"x" * n` syntax that Go doesn't have.
	cases := []struct {
		name    string
		mac     string
		wantErr string
	}{
		{"missing", "", "bridge MAC required"},
		{"wrong-hex", "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee", "bridge MAC mismatch"},
		{"truncated", "deadbeef", "bridge MAC mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanner := &fakeScanner{result: dlp.ScanResult{Blocked: true}}
			var in bytes.Buffer
			in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "hello"}))
			in.Write(frame(t, NativeMessageRequest{ID: 2, Kind: "scan", Content: "x", MAC: tc.mac}))

			var out bytes.Buffer
			if err := ServeNativeMessagingWithOptions(context.Background(), scanner, nil,
				NativeMessagingOptions{APIToken: "tok", BridgeMACRequired: true}, &in, &out); err != nil {
				t.Fatalf("serve: %v", err)
			}
			frames := readFrames(t, &out)
			if len(frames) != 2 {
				t.Fatalf("frames = %d, want 2", len(frames))
			}
			if frames[1].Error != tc.wantErr {
				t.Errorf("scan reply error = %q, want %q", frames[1].Error, tc.wantErr)
			}
			if frames[1].Result != nil {
				t.Errorf("scanner must not run on MAC failure; got result %+v", frames[1].Result)
			}
			if scanner.lastSeen != "" {
				t.Errorf("scanner saw %q on rejected frame; should be empty", scanner.lastSeen)
			}
		})
	}
}

// TestNativeMessaging_BadMACLenientWarnsAndServes pins the
// staged-rollout posture (default): a scan with no MAC still
// gets served but a one-time-per-connection warning lands on
// stderr. Subsequent bad-MAC scans on the same connection do
// NOT re-emit the warning (we don't want to flood stderr).
func TestNativeMessaging_BadMACLenientWarnsAndServes(t *testing.T) {
	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: false}}
	var stderr bytes.Buffer
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "hello"}))
	in.Write(frame(t, NativeMessageRequest{ID: 2, Kind: "scan", Content: "a"})) // no MAC
	in.Write(frame(t, NativeMessageRequest{ID: 3, Kind: "scan", Content: "b"})) // also no MAC

	var out bytes.Buffer
	if err := ServeNativeMessagingWithOptions(context.Background(), scanner, nil,
		NativeMessagingOptions{APIToken: "tok", LogStderr: &stderr},
		&in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 3 {
		t.Fatalf("frames = %d, want 3", len(frames))
	}
	if frames[1].Result == nil {
		t.Errorf("scan 1 should have been served in lenient mode; result was nil")
	}
	if frames[2].Result == nil {
		t.Errorf("scan 2 should have been served in lenient mode; result was nil")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("bridge MAC missing")) {
		t.Errorf("expected 'bridge MAC missing' on stderr, got %q", stderr.String())
	}
	// Warning text should appear exactly once even though we
	// dispatched two unsigned scans on the same connection.
	if got := bytes.Count(stderr.Bytes(), []byte("agent: bridge MAC")); got != 1 {
		t.Errorf("warning count = %d, want 1 (warn once per connection)", got)
	}
}

// TestNativeMessaging_IDRollbackRejected pins the replay defence:
// a scan whose id is not strictly greater than the largest id
// seen on this connection is dropped with "bridge id rollback".
// The id check runs BEFORE MAC verification so it survives in
// both strict and lenient modes.
func TestNativeMessaging_IDRollbackRejected(t *testing.T) {
	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: false}}
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "hello"}))
	in.Write(frame(t, NativeMessageRequest{ID: 5, Kind: "scan", Content: "first"}))
	in.Write(frame(t, NativeMessageRequest{ID: 3, Kind: "scan", Content: "rollback"})) // 3 ≤ 5

	var out bytes.Buffer
	if err := ServeNativeMessagingWithOptions(context.Background(), scanner, nil,
		NativeMessagingOptions{APIToken: "tok"}, // lenient (default)
		&in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 3 {
		t.Fatalf("frames = %d, want 3", len(frames))
	}
	if frames[1].Error != "" {
		t.Errorf("first scan unexpectedly errored: %q", frames[1].Error)
	}
	if frames[2].Error != "bridge id rollback" {
		t.Errorf("rollback reply error = %q, want 'bridge id rollback'", frames[2].Error)
	}
	if frames[2].Result != nil {
		t.Errorf("rolled-back scan must not invoke scanner; got result %+v", frames[2].Result)
	}
}

// TestNativeMessaging_NoTokenSkipsMACEnforcement pins the
// pre-A2 backwards-compat path: when the agent has no API
// token wired in, MAC verification is short-circuited even in
// strict mode (there is no shared secret to verify against).
// Without this, a deployment that upgrades the agent but not
// the api_token_path config would brick every scan.
func TestNativeMessaging_NoTokenSkipsMACEnforcement(t *testing.T) {
	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: false}}
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "scan", Content: "x"}))

	var out bytes.Buffer
	if err := ServeNativeMessagingWithOptions(context.Background(), scanner, nil,
		NativeMessagingOptions{APIToken: "", BridgeMACRequired: true},
		&in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	if frames[0].Error != "" {
		t.Errorf("scan with no-token + strict should fall through, got error %q", frames[0].Error)
	}
	if frames[0].MAC != "" {
		t.Errorf("response must not be MAC'd when no token configured; got %q", frames[0].MAC)
	}
}
