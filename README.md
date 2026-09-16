# CWI Change Ledger

A governed pipeline for agent behavior changes. Prompt edits, skill updates, and config changes ship with a review trail: **propose → risk-scan → review → decide**, recorded as append-only, hash-chained entries.

**Live:** https://cumulativewebinc.github.io/cwi-change-ledger/

## The problem

Harness (2026-09-10): 42% of teams run prompt edits through code pipelines, 58% report rising incidents per 100 changes, ~7 in 8 had a tangible agent issue this year. Behavior changes ship with no repeatable standard and no review trail. This ledger is that trail.

## How it works

1. **Propose** — paste before/after text. The engine computes a line diff and runs heuristic risk flags over the *added* lines (prompt-injection, data-exfiltration, destructive, privilege, approval-bypass) plus one semantic rule: a safety gate present before but gone after.
2. **Review** — the ledger lists every change with its diff, flags, and status filter.
3. **Decide** — approve / reject / needs-changes with a rationale. Decisions are separate ledger entries referencing the change, so the trail is complete and append-only.
4. **Export** — download a `cwi.change-record/1.0` decision record (proposal + trail + chain verification) to send to the maintainer.
5. **Publish** — the maintainer merges new entries via repo PR and Ed25519-seals the canonical `ledger/ledger.json` (`seal.js`; key never leaves `~/.config/gear-ledger/`).

`?change=<id>` deep-links to any change's detail page.

## Honest limits

**Advisory review trail, not a sandbox.** Risk flags are regex heuristics — they catch known-bad patterns, not novel ones, and can false-positive on innocent words (e.g. "delete" in documentation). The browser working copy is yours alone until sealed into the canonical log. Verify any published ledger with `node verify.js <ledger.json URL>` — never on trust.

## Machine-readable

- `ledger/ledger.json` — canonical hash-chained entries
- `ledger/index.json` — tip hash, count, per-change status
- `ledger/seal.json` — Ed25519 publish seal
- `schema/ledger.schema.json` — `cwi.change-record/1.0`
- `keys/ed25519.pub` — CWI publish key (byte-identical to the gear-ledger copy)

## Files

| File | Purpose |
|---|---|
| `index.html` | Propose / Ledger / Review / Export UI (mobile-first, i18n-ready) |
| `ledger.js` | UMD zero-dependency engine: sha256, canon, ULID, diff, risk scan, chain |
| `verify.js` | Zero-trust checker (signature + chain, exit 0/1) |
| `seal.js` | Publish-time Ed25519 sealer (maintainer only) |
| `seed.cjs` | Dogfood seed: 4 real 2026-09-16 changes as proposal+decision entries |
| `LEDGER-PROTOCOL.md` | Protocol spec, change/1.0 |

## Tests

`node --test tests/ledger.test.js` — 24 tests: sha256 vs platform, canonicalization, ULID, diff, one risk test per category, safety-gate removal, proposal/decision validation, chain integrity, tamper detection, status lifecycle, export, schema conformance.
