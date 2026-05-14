// Shared types and constants for the Secure Edge companion extension.

/** Default agent endpoint. Must remain loopback. */
export const AGENT_BASE = "http://127.0.0.1:8080";

/** Wire shape returned by POST /api/dlp/scan. Must match
 * agent/internal/dlp.ScanResult and the OpenAPI-ish JSON contract. */
export interface ScanResult {
    blocked: boolean;
    pattern_name: string;
    score: number;
}

/** Wire shape returned by GET /api/status. */
export interface StatusResponse {
    status: string;
    version: string;
    uptime_seconds: number;
    /** Phase 7 work item C2 — the agent echoes the active fail
     *  policy on /api/status so the Electron tray can surface the
     *  posture without a second round trip. The extension prefers
     *  the dedicated /api/config/enforcement-mode endpoint because
     *  the service worker doesn't want the runtime/stats payload. */
    enforcement_mode?: EnforcementMode;
}

/** Phase 7 / C2 — fail-policy posture the agent advertises. Empty
 *  string is intentionally not part of the union; both the agent's
 *  config validator and the extension cache normalise empty to
 *  "personal" before this type is reached. */
export type EnforcementMode = "personal" | "team" | "managed";

/** Wire shape of GET /api/config/enforcement-mode. The agent
 *  reserves this endpoint for the extension's cold-start fetch; the
 *  body is a single small object so the service worker doesn't have
 *  to parse the full status payload. */
export interface EnforcementModeResponse {
    mode: EnforcementMode;
}

/** Wire shape of messages sent from the popup to the service worker. */
export type PopupRequest = { kind: "ping" };

/** Wire shape of replies from the service worker to the popup. */
export type PopupReply =
    | { kind: "ok"; version: string; uptime_seconds: number }
    | { kind: "error"; message: string };

/** Wire shape of scan-proxy requests sent from a content script to the
 *  background service worker. The worker tries Native Messaging first
 *  and falls back to HTTP fetch — both paths produce the same reply. */
export type ScanRequest = { kind: "scan"; content: string };

/** Wire shape of the reply to a ScanRequest. result === null means
 *  "fall open" (agent unreachable / scan failed). */
export type ScanReply = { kind: "scan-result"; result: ScanResult | null };

/** Request from a content script asking the service worker for the
 *  agent's currently advertised enforcement mode (Phase 7 / C2). The
 *  worker holds the canonical cached value and refreshes it from
 *  /api/config/enforcement-mode on cold start so each content script
 *  doesn't have to repeat that round trip. */
export type EnforcementModeRequest = { kind: "enforcement-mode" };

/** Wire shape of the reply to an EnforcementModeRequest. mode is
 *  always one of the three accepted values; the service worker
 *  defaults to "personal" when the agent is unreachable so the
 *  extension preserves its pre-C2 fall-open behaviour. */
export type EnforcementModeReply = { kind: "enforcement-mode-result"; mode: EnforcementMode };

/** chrome.storage.session key the service worker writes the cached
 *  enforcement mode to. Content scripts may read it directly as a
 *  fast path on subsequent navigations within the same browser
 *  session; the runtime.sendMessage round trip is the source of
 *  truth. */
export const ENFORCEMENT_MODE_STORAGE_KEY = "secureEdge:enforcementMode";

/** Tier-2 AI tool host suffixes — kept in sync with the
 *  content_scripts.matches list in extension/manifest.json. Used by
 *  the network interceptor to decide which requests to inspect. */
export const TIER2_HOSTNAMES: ReadonlyArray<string> = [
    "chat.openai.com",
    "chatgpt.com",
    "claude.ai",
    "gemini.google.com",
    "copilot.microsoft.com",
    "www.bing.com",
    "you.com",
    "www.perplexity.ai",
    "huggingface.co",
    "poe.com",
    // Tier-2 expansion (P1-2). Kept in sync with manifest.json
    // content_scripts.matches and agent CORS aiPageOrigins.
    "grok.com",
    "x.ai",
    "chat.mistral.ai",
    "mistral.ai",
    "openrouter.ai",
    "chat.lmsys.org",
    "aistudio.google.com",
    "notebooklm.google.com",
];

/** Native Messaging host application identifier. Must match the
 *  "name" field in extension/native-messaging/com.secureedge.agent.json
 *  installed by the user's OS. */
export const NATIVE_HOST = "com.secureedge.agent";
