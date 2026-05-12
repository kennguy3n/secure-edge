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
