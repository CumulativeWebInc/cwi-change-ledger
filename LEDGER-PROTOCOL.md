# LEDGER-PROTOCOL.md — change/1.0

## Purpose
A repeatable, auditable standard for agent behavior changes: every prompt edit, skill update, config change, or policy change is proposed with a diff, scanned for risk heuristics, reviewed, and decided — on an append-only, hash-chained, Ed25519-sealed ledger.

## Entry model (`cwi.change-record/1.0`)
- `proposal`: proposer, proposed_at, change_type ∈ {prompt_edit, skill_update, config_change, policy_change}, target, rationale, before, after, diff_summary {added_lines, removed_lines}, risk_flags[], risk_level ∈ {none, low, medium, high, critical} (worst flag severity).
- `decision`: references change_id; decider, decided_at, decision ∈ {approved, rejected, needs_changes}, rationale, supersedes (optional prior decision_id).
- Change status = latest decision entry, else `proposed`.

## Hashing
- `entry_hash` = sha256hex(canonical JSON of the entry with `prev_hash` set and `entry_hash` excluded). Canonical = recursive key sort, no whitespace.
- `prev_hash` links to the previous entry's `entry_hash`; first entry uses `GENESIS`.
- IDs: `chg_<ULID>` for changes, `dec_<ULID>` for decisions (Crockford base32, time-ordered).

## Risk heuristics (advisory)
- 14 rules in 5 categories: prompt-injection, data-exfiltration, destructive, privilege, approval-bypass. Rules run against **added lines only** — a change is judged by what it introduces.
- One semantic rule (CHG-AB-002): a safety gate present in `before` but absent in `after` is flagged high.
- Rule catalog lives in `ledger.js` (`RISK_RULES`) and is the single source of truth.

## Publish seal
The canonical `ledger/ledger.json` is sealed at publish time: Ed25519 over canonical `{tip_hash, count, sealed_at, issuer}` → `ledger/seal.json`. Public key at `keys/ed25519.pub`. Verify with `node verify.js`.

## Evolution
- Protocol version is in every entry (`protocol: change/1.0`). Old entries stay valid forever.
- Rule additions are additive; rule IDs are never reused with changed semantics.
- Quarterly review alongside the CWI teach cycle. Changelog in CHANGELOG.md.

## Non-goals
- Not a sandbox, not a policy enforcer, not an eval harness. It records the review; it does not replace human judgment or automated evals.
- v1 never auto-approves or auto-rejects. Decisions are human (or human-delegated) and signed by name.
