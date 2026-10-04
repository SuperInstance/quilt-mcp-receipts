# quilt-mcp-receipts — Engineering Notes
> Architecture, invariants, failure modes, cost envelope, operations, design
> decisions — for engineers operating or reviewing the organ.

## Architecture

A single-process, stdio-only MCP server over a single append-only JSONL file.
No database, no network, no dependencies (stdlib `node:crypto` + `node:fs`).

```
 MCP host (Claude Code / Cursor / CI / any agent)
     │  stdin: newline-delimited JSON-RPC 2.0        stdout: one JSON reply per line
     ▼
┌─────────────────────────── server.mjs ───────────────────────────┐
│ MCP loop: initialize→version negotiation→tools/list→tools/call    │
│   tools: read_receipts | verify_chain | append_receipt            │
│          + (QMR2) dialects, upgrade_chain                         │
│          + (V3)   verify_attribution                              │
│                        │ re-parse store.jsonl on EVERY call        │
│                        ▼                                           │
│   verifyChain(): genesis → row-by-row → structure, seq, prev,      │
│   id recompute (per-dialect hash), sig verify (HMAC | Ed25519      │
│   under caller keyring) — first failure wins, named code at_seq    │
│                        │ append-only                              │
│                        ▼                                           │
│   store.jsonl   {"seq","prev","body","id","sig"(,"dialect",       │
│                 "sigAlg","sigKeyFp")} × N   + upgrades/ outputs    │
└────────────────────────────────────────────────────────────────────┘
```

Data flow: the client either reads (store re-parsed from disk, cursor semantics
via `since_seq`), audits (`verify_chain` re-derives every id from genesis under
the row's own dialect and, for Ed25519 rows, the caller's keyring), or commits
(`append_receipt` — the CLIENT signs; the server re-derives and only then does
one `fs.appendFileSync`). Side outputs: `upgrades/upgrade-<a>-<b>-<sha8>.jsonl`
+ timestamp-free manifests from `upgrade_chain`, and the dogfood receipt set in
`receipts/dogfood-67b.jsonl` (itself a valid chain this server verifies).

## Invariants
1. **Append-only store** — the only write is a validated append; no update or
   delete verb exists; `verify_chain` re-derives from genesis so any
   behind-the-back edit is caught and localized at `at_seq`. Enforced in
   `appendLine` (sole `fs.appendFileSync`) and `verifyChain`.
2. **Nothing invalid is ever written** — `validateAppend` runs the full law
   BEFORE the append, against a fresh re-read of the store (a stale in-memory
   tip can never authorize a write). A corrupt store refuses appends outright
   (`E_STORE_CORRUPT`).
3. **Never-rewrite, including shape** — qmr1 five-field rows are stored
   byte-for-byte as submitted; `dialect`/`sigAlg`/`sigKeyFp` are stored only
   when the client supplied them (server never injects). Enforced in
   `toolAppend`.
4. **The server is a verifier, not a co-signer** — no signing tool exists;
   key material never flows through the wire. Enforced by the tool surface
   itself (DESIGN.md §3).
5. **The custody law has exactly one enforcement point with a name** —
   `verify_chain({dialect_mode:"custody"})` → `E_DIALECT_FORBIDDEN` at_seq on
   any canary row. Append is dialect-neutral on purpose: a canary row is legal;
   *calling the chain custody* is what fails (docs/qmr2-design.md §3).
6. **Fail-closed attribution** — an Ed25519 row without its signer in the
   keyring is `E_UNKNOWN_SIGNER`; a keyring that lies about itself is
   `E_BAD_KEYRING` refused BEFORE any row is read (a broken trust root is not a
   signature failure).
7. **Versioned tool surfaces** — the default `tools/list` is exactly three
   tools, pinned by the untouched v1 suite; gated layers are additive only.
8. **Honest substrate** — unparseable store lines surface as
   `corrupted_lines:[…]` on reads and `E_STORE_CORRUPT` on verify/append; they
   are never silently skipped.

## Failure modes & blast radius
- **Tamper via direct file edit** (the threat model's core): body value flip →
  `E_HASH_MISMATCH` at_seq; sig flip → `E_BAD_SIGNATURE`; row deletion →
  `E_SEQ_MISMATCH` (the chain breaks at the missing link); replay →
  `E_SEQ_MISMATCH`. Blast radius: zero silent damage — wrongness has a name and
  a row number. Not covered (v1 honest residual): local-storage TRUNCATION
  without an external tip anchor — see DESIGN.md §5 "cannot yet", cured by
  anchoring the tip (quilt-organ-workers is the ready host).
- **Corrupt line in the store**: reads still return parseable rows plus
  `corrupted_lines`; verify/append refuse `E_STORE_CORRUPT`. Blast radius: the
  organ refuses to launder a broken substrate; recovery is restoring honest
  bytes (the server never edits).
- **Secret leakage/rotation**: HMAC rows signed under an old secret fail
  `E_BAD_SIGNATURE` after rotation — the chain is honest about the era change
  but cannot distinguish "wrong secret" from "forged id". Mitigation: per-era
  keyrings (v3) or re-signing via `upgrade_chain` mechanics are the designed
  paths; nothing automatic exists (stated residual).
- **DoS by connection volume**: accepted spike residual (single process, no
  rate limiting, stdio so the host bounds it). v2 HTTP transport would put a
  queue/WAF in front.
- **Host passes a bad `--store` path**: the server treats a missing file as an
  empty store (genesis append legal); a WRONG path silently starts a fresh
  chain — mitigation is operational: pin absolute paths in client configs
  (USER-GUIDE troubleshooting table).
- **Non-JSON on stdin**: `-32700` parse error reply, connection stays up;
  notifications (id-less) never receive replies by protocol.

## Performance & cost envelope
- **Compute**: pure Node, stdlib. The full suite (40 tests, each spawning real
  server processes) runs in ~10 s on this container; the single-store verify is
  O(n) hash recomputations. Measured, labeled: the receipted dogfood run
  verifies 3 receipts and the client demo 12 checks in well under a second.
  No benchmark receipts exist for very large stores; estimate, labeled:
  per-call cost is dominated by full-file re-parse + n SHA-256s — linear, fine
  for fleet-scale ledgers (thousands of rows), worth revisiting only if a store
  reaches millions.
- **Cost**: $0. No external services, no network calls, no keys required to
  operate (the HMAC secret is generated by the operator, not bought).
- **Storage**: one line per receipt; the receipted dogfood set is 3 lines ≈ 1 KB.
  KV/DB costs: none.

## Operations
- **Run modes**: `node server.mjs [--store PATH] [--demo] [--qmr2] [--v3]
  [--quiet-notice]`; env `MCP_RECEIPT_SECRET` (HMAC key; unset = built-in dev
  secret with a loud stderr warning), `QMR2=1`, `V3=1` (tool-layer gates).
- **Client config**: absolute `--store` path in every MCP host config; the
  default resolves against the server process's cwd, which hosts vary.
- **Credentials model (honest)**: the only secret material is the operator's own
  HMAC secret / Ed25519 private keys. None exist in this repo, none are needed
  to run the tests or the demo (test keys are minted at runtime and never
  committed). No external credentials are involved anywhere in this organ.
- **CI**: none; the fleet's proof standard is receipts. `npm test` is the
  on-demand gate (40/40 green as of this wave).
- **Receipts of operation**: `receipts/dogfood-67b.jsonl` (sha256 of the file
  receipted in `receipts/DOGFOOD-67B.md`; tip `afbc460a…`; verifies under BOTH
  `any` and `custody` modes) and `receipts/69b-death-audit.md` (the audit that
  classified a dead lane's uncommitted work before completing it).

## Design decisions & why
1. **Stdio JSON-RPC + no SDK** (wave 65) — the MCP stdio shape is ~120 lines of
   owned code; depending on an SDK for that surface would trade auditability
   for convenience on the fleet's most audit-sensitive organ. Tradeoff: the
   team owns protocol edges (version negotiation, error codes) forever.
2. **Client signs, server verifies** (DESIGN.md §3) — no `sign_receipt` tool,
   deliberately: signing power must not concentrate in the server process, and
   key material must never transit the wire. Tradeoff: every writer needs a
   ~15-line signer (shipped as `examples/client-demo.mjs`).
3. **HMAC first, Ed25519 as the additive v3 slot** (DESIGN.md §4 → §8) — the
   spike shipped with the 3-line shared-secret scheme and an HONEST residual
   ("attribution is fleet-trust, not identity"), designed so the keypair swap
   would be additive. v3 delivered exactly that: `sigAlg`+`sigKeyFp` fields,
   keyring verification, zero change to qmr1 rows.
4. **One receipt primitive, pluggable hash, one law** (qmr2) — the wave-66
   census found the chain re-implemented 12+ times in two contradicting hash
   dialects with the tamper battery re-proven ~8×. The distill keeps five
   fields, adds the `dialect` field, and pins the custody law where it can have
   a name and a row number. Tradeoff: mixed-dialect chains are legal in
   `"any"` mode; the law is an assertion at verify time, not a gate at append.
5. **The untouched-test-suite constraint as a design input** (qmr2 §7) — the v1
   suite pins `tools/list` to three tools, so new capabilities ship behind
   gates (`--qmr2`, `--v3`) instead of mutating the default surface. Tradeoff:
   two extra flags to document; benefit: the original contract is provably
   stable.
6. **The vendored conformance harness** (qmr2 §6) — instead of every fleet repo
   re-proving the tamper battery by hand, `test/conformance.mjs` is copied
   verbatim and adapted in ~40 lines; the harness mints runtime keys and never
   signs itself. First customer was this repo itself (16/16 receipted), then
   the first external producer (fleet-seeds `wal-conformance`), then the
   fleet-seeds qmr1-bridge (18/18, tip `719123ffc6d8d575…` verifying live under
   this server's `verify_chain`).
