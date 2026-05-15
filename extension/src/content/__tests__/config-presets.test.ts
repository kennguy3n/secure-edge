// Wire-shape tests for the three reference config presets at the
// repo root (config.personal.example.yaml, config.team.example.yaml,
// config.managed.example.yaml).
//
// Background. The agent's risky-extension blocklist (B2) has a
// three-state wire protocol (see docs/admin-guide.md §2.2):
//
//   - Key absent       → extension uses the baked-in 34-entry default
//   - Empty list `[]`  → opts out of B2 entirely
//   - Populated list   → REPLACES the baked-in default verbatim
//
// The wire shape for "use baked-in default" is therefore an empty
// `risky_file_extensions` BLOCK (or no key at all). A populated
// explicit list silently shrinks the on-wire blocklist — that
// regression is exactly what Devin Review caught on the first
// version of these presets (the managed preset was shipped with an
// 8-entry list, which replaced the 34-entry default and left the
// "fail-closed end-state" with strictly LESS coverage than the
// personal preset).
//
// These tests pin the contract so a future PR cannot silently
// reintroduce the same shrinkage on the personal or managed preset.
// The team preset is allowed to populate the key (its surrounding
// comment documents the conservative-subset trade-off), so we
// assert the inverse there: it MUST set the key, and the entries
// MUST be a strict subset of the baked-in default (we cannot let
// the team preset add an entry that the default does not already
// cover — anything genuinely new belongs on the managed preset's
// extension-hook example).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { BAKED_IN_RISKY_EXTENSIONS } from "../risky-extensions.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
// extension/src/content/__tests__/ → repo root is four levels up.
const repoRoot = resolve(__dirname, "..", "..", "..", "..");

function readPreset(name: string): string {
    return readFileSync(resolve(repoRoot, name), "utf8");
}

/** Return the list of `risky_file_extensions` entries set by the
 *  preset, OR null if the key is omitted / fully commented out.
 *
 *  This is a deliberately tiny parser (no js-yaml dependency in
 *  the extension test suite). It looks for the FIRST uncommented
 *  line whose first non-space character is "r" and that begins
 *  with `risky_file_extensions:`. Everything that follows up to
 *  the next non-list, non-comment, non-blank line is treated as
 *  the list body. Entries are extracted from `  - foo` style
 *  list items. */
function readRiskyExtensionEntries(yaml: string): string[] | null {
    const lines = yaml.split("\n");
    let inBlock = false;
    const entries: string[] = [];
    for (const raw of lines) {
        const line = raw.replace(/\r$/, "");
        const trimmed = line.trimStart();
        if (!inBlock) {
            if (trimmed.startsWith("#")) continue;
            if (trimmed === "") continue;
            if (trimmed.startsWith("risky_file_extensions:")) {
                inBlock = true;
                // Inline `risky_file_extensions: []` opens AND
                // closes in one line — opt-out of B2.
                const rest = trimmed.slice("risky_file_extensions:".length).trim();
                if (rest === "[]") return [];
                if (rest !== "") {
                    // Not the YAML shape we author here; bail loudly.
                    throw new Error(`unexpected inline value: ${trimmed}`);
                }
            }
            continue;
        }
        // We are inside the block. A blank line, a top-level key
        // (zero leading space), or a non-list line terminates it.
        if (trimmed === "") return entries;
        if (trimmed.startsWith("#")) continue;
        if (!line.startsWith(" ")) return entries;
        const m = /^\s+-\s+["']?([A-Za-z0-9._-]+)["']?\s*$/.exec(line);
        if (m) {
            entries.push(m[1]!.toLowerCase());
            continue;
        }
        // A sibling key (no list marker) ends the block.
        return entries;
    }
    return inBlock ? entries : null;
}

test("config.personal.example.yaml: risky_file_extensions key is omitted (falls through to baked-in 34-entry default)", () => {
    const yaml = readPreset("config.personal.example.yaml");
    const entries = readRiskyExtensionEntries(yaml);
    assert.equal(
        entries,
        null,
        "personal preset MUST leave risky_file_extensions unset — an explicit populated list replaces the baked-in default and silently shrinks B2 coverage. See config.managed.example.yaml for the documented override hook.",
    );
});

test("config.managed.example.yaml: risky_file_extensions key is omitted (falls through to baked-in 34-entry default)", () => {
    const yaml = readPreset("config.managed.example.yaml");
    const entries = readRiskyExtensionEntries(yaml);
    assert.equal(
        entries,
        null,
        "managed preset MUST leave risky_file_extensions unset. The wire protocol replaces (not augments) the baked-in default, so an explicit list here silently shrinks B2 coverage on the fail-closed end-state. If you need to EXTEND the default, follow the in-file override-hook example (copy the baked-in list and append your additions).",
    );
});

test("config.team.example.yaml: risky_file_extensions is populated and a strict subset of the baked-in default", () => {
    const yaml = readPreset("config.team.example.yaml");
    const entries = readRiskyExtensionEntries(yaml);
    assert.notEqual(
        entries,
        null,
        "team preset is expected to set risky_file_extensions to a conservative subset (see surrounding comment). The wire-shape test on the managed preset already covers the no-key-set posture.",
    );
    assert.notEqual(entries!.length, 0, "team preset must not opt out of B2");
    const bakedIn = new Set(BAKED_IN_RISKY_EXTENSIONS);
    const novel = entries!.filter((e) => !bakedIn.has(e));
    assert.deepEqual(
        novel,
        [],
        "every team-preset entry MUST exist in the baked-in default. A genuinely new extension belongs on the managed preset's documented override hook (copy the baked-in list + append), not on the team preset (which is a conservative subset, not an extension surface).",
    );
});
