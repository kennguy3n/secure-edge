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
