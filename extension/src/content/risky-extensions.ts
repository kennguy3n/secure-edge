// Risky-file-extension matcher and cache for the file-upload
// interceptor (Phase 7 / B2).
//
// SCOPE
// -----
// This module owns the canonical baked-in list of file extensions
// the extension hard-blocks at the upload gesture, and the per-
// content-script cache of any operator override the agent
// advertises via GET /api/config/risky-extensions. It does NOT
// implement the synchronous suppression itself (that lives in
// file-upload-interceptor.ts) — it only answers the question
// "is this filename's extension on the active blocklist?" so the
// interceptor's sync-first contract is preserved.
//
// THREE WIRE STATES (mirroring the agent endpoint)
// ------------------------------------------------
// The service worker may return any of:
//
//   mode: "default"     — the agent did not supply an override
//                         list; the extension uses BAKED_IN_RISKY_EXTENSIONS.
//   mode: "configured"  — the operator supplied an explicit
//                         override. extensions may be:
//                           []      — opt-out, nothing is blocked.
//                           [...]   — use this list verbatim.
//
// The interceptor's match call is the only path that consults the
// cache, so the active list is always either BAKED_IN or whatever
// the operator opted into — never both.
//
// PRIVACY INVARIANT
// -----------------
// The filename is read from the File object in-page and matched
// against a local list. NO filename, NO file content, NO match
// signal ever leaves the device for the risky-extension check.
// (Files that pass the extension check go on to scanContent, which
// is itself loopback-only.) The agent never sees filenames; it
// only owns the override list.

import { RISKY_EXTENSIONS_STORAGE_KEY } from "../shared.js";
import type {
    RiskyExtensionsReply,
    RiskyExtensionsRequest,
} from "../shared.js";

/** Baked-in default blocklist (34 extensions). The list covers
 *  Windows / macOS / Linux executables, installers, scripts (sans
 *  .js — too noisy for developer workflows), disk images, and
 *  cross-platform Java archives. All entries are lowercase and
 *  dot-less, matching the agent's wire format produced by
 *  config.normaliseExtensions.
 *
 *  This list is intentionally NOT exported as a mutable structure:
 *  the cache below holds a ReadonlyArray copy so a test that
 *  mutates the returned slice cannot poison the next case. */
const BAKED_IN_RISKY_EXTENSIONS_RAW: ReadonlyArray<string> = [
    // Windows native executables and installers
    "exe",
    "scr",
    "com",
    "pif",
    "msi",
    "msp",
    "mst",
    "appx",
    "appxbundle",
    "msix",
    // Windows / cross-platform scripts. Intentionally no .js.
    "bat",
    "cmd",
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "ps1",
    "psm1",
    "psd1",
    // POSIX scripts
    "sh",
    // System libraries / drivers that should never be uploaded
    // through a chat surface — high-value targets for tampering
    // payloads.
    "dll",
    "sys",
    "reg",
    // macOS / Linux installers and bundles
    "app",
    "pkg",
    "dmg",
    "deb",
    "rpm",
    // Cross-platform Java archives
    "jar",
    "class",
    // Disk images that often carry installers
    "iso",
    "img",
    "vhd",
    "vhdx",
];

/** Frozen view used by the production hot path. Freezing tolerates a
 *  caller that accidentally tries to push() onto the slice. */
export const BAKED_IN_RISKY_EXTENSIONS: ReadonlyArray<string> = Object.freeze([
    ...BAKED_IN_RISKY_EXTENSIONS_RAW,
]);

/** Lowercase dot-less file extension extracted from `filename`.
 *  Returns "" when the filename has no dot, ends with a dot, or
 *  consists of nothing but dots (".", ".."). The empty string is
 *  treated as "no extension" by isRiskyExtension below, so a
 *  dotless name like "README" or a hidden POSIX file like
 *  ".bashrc" can never be matched against any entry.
 *
 *  Only the LAST extension is considered. A file named
 *  "report.txt.exe" yields "exe" — the operator wants to block on
 *  the apparent file type, not on the inner segment, because that
 *  is what the user's OS would dispatch to (and what an attacker
 *  would dress up to look benign in the file picker). */
export function extensionOf(filename: string): string {
    if (typeof filename !== "string") return "";
    // Strip any directory prefix the page might leak through
    // (legacy "C:\path\file.exe" naming on Windows or "/tmp/x.exe"
    // on Linux). The native file picker on every modern browser
    // returns just the basename, but pages occasionally synthesise
    // File objects with custom names.
    const base = filename.replace(/^.*[\\/]/, "");
    if (base.length === 0) return "";
    // Treat a name whose only dot is the leading one (e.g.
    // ".bashrc") as having no extension. The lastIndexOf check
    // covers this: a hidden file with `lastIndexOf(".") === 0`
    // returns "" rather than "bashrc", because we want
    // POSIX-style hidden files to be treated as opaque-no-extension
    // rather than as a `.bashrc`-extension match.
    const dot = base.lastIndexOf(".");
    if (dot <= 0) return "";
    if (dot === base.length - 1) return "";
    return base.slice(dot + 1).toLowerCase();
}

/** Decide whether `filename` should be blocked given the active
 *  override `list`. Empty `list` always returns false (opt-out
 *  wire shape); non-empty lists do a case-insensitive lookup
 *  against the dot-less extension extracted from the filename.
 *
 *  Pure — no DOM, no chrome.* APIs. Safe to call from the
 *  synchronous prelude of an event listener before any await. */
export function isRiskyExtension(
    filename: string,
    list: ReadonlyArray<string> = BAKED_IN_RISKY_EXTENSIONS,
): boolean {
    if (list.length === 0) return false;
    const ext = extensionOf(filename);
    if (ext === "") return false;
    // Linear search is fine — the list is at most a few dozen
    // entries and the call is on the user-gesture path, not a
    // tight inner loop. Promoting to a Set would add lifecycle
    // complexity (cache invalidation on refresh) for no
    // user-visible win.
    for (let i = 0; i < list.length; i++) {
        if (list[i] === ext) return true;
    }
    return false;
}

/** Module-local cache of the active blocklist. Default is the
 *  baked-in list so a file-upload gesture that races the cold-start
 *  bootstrap still falls safe (blocks risky uploads). The cache is
 *  mutated only via refreshRiskyExtensions / __test__ helpers. */
let cachedRiskyExtensions: ReadonlyArray<string> = BAKED_IN_RISKY_EXTENSIONS;

/** True once the cache has been populated from the service worker
 *  (or the cold-start fallback path) at least once in this content
 *  script's lifetime. Mirrors the enforcement-mode bootstrap flag
 *  in scan-client.ts. */
let riskyExtensionsBootstrapped = false;

/** Synchronous accessor for the hot path. Always returns a
 *  non-null list (default is the baked-in set). */
export function getCachedRiskyExtensions(): ReadonlyArray<string> {
    return cachedRiskyExtensions;
}

/** Refresh the cached list from the background service worker
 *  (which holds the canonical fetched value). Falls back to
 *  chrome.storage.session on worker-eviction, then leaves the
 *  previous value intact so a transient service-worker eviction
 *  doesn't flip every page back to the default mid-session.
 *  Returns the value now in the cache. */
export async function refreshRiskyExtensions(): Promise<ReadonlyArray<string>> {
    riskyExtensionsBootstrapped = true;
    const viaWorker = await readRiskyExtensionsFromWorker();
    if (viaWorker !== null) {
        cachedRiskyExtensions = viaWorker;
        return cachedRiskyExtensions;
    }
    const viaStorage = await readRiskyExtensionsFromStorage();
    if (viaStorage !== null) {
        cachedRiskyExtensions = viaStorage;
    }
    return cachedRiskyExtensions;
}

/** Boot the risky-extension cache exactly once per content-script
 *  lifetime. Safe to call from a module top-level — failures stay
 *  silent and the baked-in default remains active. */
export function ensureRiskyExtensionsBootstrapped(): void {
    if (riskyExtensionsBootstrapped) return;
    riskyExtensionsBootstrapped = true;
    void refreshRiskyExtensions();
}

/** Ask the background service worker for the cached blocklist.
 *  Returns null on any failure so the caller falls through to the
 *  storage path. Mirrors readEnforcementModeFromWorker. */
async function readRiskyExtensionsFromWorker(): Promise<ReadonlyArray<string> | null> {
    const runtime = typeof chrome !== "undefined" ? chrome.runtime : undefined;
    if (!runtime || typeof runtime.sendMessage !== "function") return null;
    try {
        const req: RiskyExtensionsRequest = { kind: "risky-extensions" };
        const reply = (await runtime.sendMessage(req)) as
            | RiskyExtensionsReply
            | undefined;
        if (reply && reply.kind === "risky-extensions-result") {
            return materialiseReply(reply);
        }
    } catch {
        // service worker asleep, no receiving end, etc.
    }
    return null;
}

/** Storage-fallback path. The service worker mirrors every refresh
 *  into chrome.storage.session; on a worker eviction the storage
 *  read still surfaces the list the operator last configured. */
async function readRiskyExtensionsFromStorage(): Promise<ReadonlyArray<string> | null> {
    try {
        const c = typeof chrome !== "undefined" ? chrome : undefined;
        const session = c?.storage?.session;
        if (!session) return null;
        const got = await session.get(RISKY_EXTENSIONS_STORAGE_KEY);
        const raw = got[RISKY_EXTENSIONS_STORAGE_KEY];
        if (raw == null) return null;
        // Storage carries either a string sentinel "default" (use
        // baked-in) or a serialised JSON array (configured).
        if (raw === "default") return BAKED_IN_RISKY_EXTENSIONS;
        if (Array.isArray(raw)) {
            return normaliseEntries(raw);
        }
    } catch {
        /* storage unavailable. */
    }
    return null;
}

/** Convert a `RiskyExtensionsReply` into the cache's list view. A
 *  "default" reply produces the baked-in list verbatim; a
 *  "configured" reply produces the operator's list (already
 *  normalised by the agent, but we re-normalise defensively in
 *  case a storage-cache entry carries an older format). */
function materialiseReply(reply: RiskyExtensionsReply): ReadonlyArray<string> {
    if (reply.mode === "default") return BAKED_IN_RISKY_EXTENSIONS;
    return normaliseEntries(reply.extensions);
}

/** Normalise an arbitrary list of strings into the dot-less
 *  lowercase shape isRiskyExtension expects. Empty / non-string
 *  entries are dropped. Mirrors `config.normaliseExtensions` on the
 *  agent side so the two views stay in lock-step.
 *
 *  Exported for tests; not part of the production hot path. */
export function normaliseEntries(in_: ReadonlyArray<unknown>): ReadonlyArray<string> {
    const out: string[] = [];
    for (let i = 0; i < in_.length; i++) {
        const e = in_[i];
        if (typeof e !== "string") continue;
        let s = e.trim();
        if (s.length > 0 && s.charCodeAt(0) === 0x2e /* '.' */) s = s.slice(1);
        s = s.toLowerCase();
        if (s.length === 0) continue;
        out.push(s);
    }
    return out;
}

/** Exported test handle so unit tests can reset the cache between
 *  cases and inject specific blocklist values. Not part of the
 *  production surface. */
export const __test__ = {
    /** Force the cached list to a known value. Callers must
     *  invoke reset() in afterEach to avoid bleeding state across
     *  cases. */
    setCachedRiskyExtensions(list: ReadonlyArray<string>): void {
        cachedRiskyExtensions = list;
        riskyExtensionsBootstrapped = true;
    },
    /** Restore the cache to its post-import state (baked-in
     *  default + no bootstrap yet attempted). */
    reset(): void {
        cachedRiskyExtensions = BAKED_IN_RISKY_EXTENSIONS;
        riskyExtensionsBootstrapped = false;
    },
    readRiskyExtensionsFromWorker,
    readRiskyExtensionsFromStorage,
    materialiseReply,
};
