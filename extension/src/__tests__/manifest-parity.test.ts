// Pins the three platform manifests (Chrome, Firefox, Safari) to the
// same set of content_scripts.matches + web_accessible_resources
// matches. P1-2 expanded the Chrome manifest with eight new Tier-2 AI
// host patterns but the Firefox/Safari manifests were initially left
// behind, creating a real cross-browser coverage gap (Devin Review
// finding on PR #16). The Firefox/Safari build scripts copy these
// files verbatim — there's no derivation pass — so the only way to
// keep coverage parity is to mirror the patterns in all three files
// and pin that with a test.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoExt = path.resolve(here, "..", "..");

type Manifest = {
    content_scripts?: Array<{ matches?: string[] }>;
    web_accessible_resources?: Array<{ matches?: string[] }>;
};

function loadManifest(filename: string): Manifest {
    return JSON.parse(fs.readFileSync(path.join(repoExt, filename), "utf8")) as Manifest;
}

function allHostPatterns(m: Manifest): Set<string> {
    const out = new Set<string>();
    for (const cs of m.content_scripts ?? []) {
        for (const p of cs.matches ?? []) out.add(p);
    }
    for (const w of m.web_accessible_resources ?? []) {
        for (const p of w.matches ?? []) out.add(p);
    }
    return out;
}

function setEqual<T>(a: Set<T>, b: Set<T>): boolean {
    if (a.size !== b.size) return false;
    for (const v of a) if (!b.has(v)) return false;
    return true;
}

test("Firefox + Safari manifests have the same host coverage as the Chrome manifest", () => {
    const chrome = allHostPatterns(loadManifest("manifest.json"));
    const firefox = allHostPatterns(loadManifest("manifest.firefox.json"));
    const safari = allHostPatterns(loadManifest("manifest.safari.json"));

    // The Chrome manifest is the source of truth — when we extend the
    // Tier-2 host list (P1-2 style), Firefox + Safari must follow.
    assert.ok(chrome.size > 0, "Chrome manifest must declare at least one match pattern");

    const missingFromFirefox = [...chrome].filter((p) => !firefox.has(p));
    assert.deepEqual(missingFromFirefox, [], `Firefox manifest is missing: ${missingFromFirefox.join(", ")}`);

    const missingFromSafari = [...chrome].filter((p) => !safari.has(p));
    assert.deepEqual(missingFromSafari, [], `Safari manifest is missing: ${missingFromSafari.join(", ")}`);

    assert.ok(setEqual(chrome, firefox), "Chrome <-> Firefox manifest host sets must be identical");
    assert.ok(setEqual(chrome, safari), "Chrome <-> Safari manifest host sets must be identical");
});

test("each content_scripts entry within a manifest covers the same host set", () => {
    // Within a single manifest, the two content_scripts entries
    // (paste/form interceptors vs. network interceptor) must cover
    // the same hosts — otherwise one bypass surface stays open on
    // some sites. This is the invariant the Chrome manifest already
    // satisfies; pin it for Firefox + Safari too.
    for (const file of ["manifest.json", "manifest.firefox.json", "manifest.safari.json"]) {
        const m = loadManifest(file);
        const groups = (m.content_scripts ?? []).map((cs) => new Set(cs.matches ?? []));
        if (groups.length < 2) continue;
        const ref = groups[0];
        for (let i = 1; i < groups.length; i++) {
            assert.ok(
                setEqual(ref, groups[i]),
                `${file}: content_scripts[0] and content_scripts[${i}] cover different host sets`,
            );
        }
    }
});
