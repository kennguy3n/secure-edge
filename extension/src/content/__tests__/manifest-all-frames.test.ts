// Manifest parity test: every content_scripts entry across the
// three packaging targets (Chrome / Edge, Firefox, Safari) must
// declare `all_frames: true`.
//
// Why. Modern Tier-2 AI surfaces (ChatGPT's project canvas,
// Claude's artefact view, several embedded Copilot chat widgets)
// render the input area inside a same-origin iframe; the agent's
// content scripts only see that input when Chrome injects them
// into every frame. The historical default was `all_frames: false`
// because the early Tier-2 surfaces all ran in the top frame, and
// the team was wary of paying the injection cost on every ad
// iframe. The DLP coverage gap that the false setting opens is
// real (a `paste` into an iframe-hosted editor would slip the
// scanner), and the cost is bounded by the existing
// `matches` allowlist — only Tier-2 sites match in the first
// place, so the extra injections happen on a small set of pages
// the user has opted into.
//
// This test pins the contract so a refactor that re-introduces
// `all_frames: false` (or, equivalently, omits the key — `false`
// is the manifest default) fails CI with a precise per-target
// diagnostic instead of silently dropping iframe DLP coverage on
// one packaging path.
//
// The test parses the manifests with the platform JSON parser
// instead of taking the value through a build step so any future
// build-time mutation that strips or overrides the field also
// gets caught here.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
// extension/src/content/__tests__/ → extension/ is three levels up.
const extensionRoot = resolve(__dirname, "..", "..", "..");

interface ContentScriptEntry {
    matches?: string[];
    js?: string[];
    run_at?: string;
    all_frames?: boolean;
    world?: string;
}

interface Manifest {
    content_scripts?: ContentScriptEntry[];
}

function readManifest(name: string): Manifest {
    const raw = readFileSync(resolve(extensionRoot, name), "utf8");
    return JSON.parse(raw) as Manifest;
}

// The three packaging targets all live next to package.json. If a
// future packaging target lands (e.g. an MV3 Safari split or an
// MV2 fallback), it must be added to this list — the test will not
// auto-discover unfamiliar manifest files.
const TARGETS = [
    "manifest.json",
    "manifest.firefox.json",
    "manifest.safari.json",
] as const;

for (const target of TARGETS) {
    test(`${target} declares all_frames: true on every content_scripts entry`, () => {
        const manifest = readManifest(target);
        const entries = manifest.content_scripts;
        assert.ok(
            Array.isArray(entries) && entries.length > 0,
            `${target} is missing or has an empty content_scripts array`,
        );
        entries!.forEach((entry, index) => {
            // The default value of `all_frames` in Chrome / Edge
            // manifests is `false`; a missing key therefore counts
            // as a regression for the purposes of this test.
            assert.strictEqual(
                entry.all_frames,
                true,
                `${target} content_scripts[${index}] (matches=${JSON.stringify(
                    entry.matches,
                )}) has all_frames=${entry.all_frames}; expected true so iframe-hosted Tier-2 surfaces stay covered by the scanner`,
            );
        });
    });
}
