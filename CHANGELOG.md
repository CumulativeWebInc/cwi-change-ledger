# Changelog
## 2026-09-23 — v2026.09.23 — trust infra (A7/A8)
- **A7 PR preview bot:** `.github/workflows/pr-preview.yml` builds each PR branch, deploys a live preview to `pr-previews/<PR#>/`, and posts the preview link + contract validation checklist as a PR comment (Vercel pattern).
- **A8/A9 contract CI gate:** the build now fails if `.well-known/agent-card.json` is missing or invalid (name/url required), if the `SCHEMA-VERSIONS.json` contract breaks (where the registry exists), if `content.json` is invalid, or if `CHANGELOG.md` is missing.

## v1.0.0 — 2026-09-16
- Initial release: propose → risk-scan → review → decide workflow.
- UMD zero-dependency engine (ledger.js): pure-JS SHA-256, canonical JSON, ULID, LCS diff, 14 heuristic risk rules in 5 categories, hash-chained append-only entries.
- Schema `cwi.change-record/1.0`; protocol `change/1.0`.
- Ed25519 publish seal (`seal.js`) + zero-trust `verify.js` (chain + seal, exit 0/1).
- `?change=<id>` deep links; machine-readable ledger/index/seal JSON.
- i18n-ready: `data-i18n` keys + cwi-i18n loader hook (`data-app="change-ledger"`), 6 languages.
- Dogfood seed: 4 real 2026-09-16 CWI changes (clearance-chip fix, i18n retrofit, invalidation-policy deviation, badge→proof wiring), each proposal + approved decision, 8 entries chained from GENESIS.
- 24/24 tests green (`node --test`).
