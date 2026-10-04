# quilt-mcp-receipts — CTO Brief
> Executive summary for investment decisions. Read time: ~5 minutes.

## One-paragraph value statement
quilt-mcp-receipts turns the fleet's receipt culture into a networked
instrument: a signed, hash-chained, append-only ledger that any agent can read,
verify, and append over the standard Model Context Protocol with zero
infrastructure (one Node file, stdlib only, one JSONL file of storage, $0
running cost). It converts "trust me, we ran it" into a fail-closed audit with
named errors and row numbers, and it already has its first external producers
sealing real ledgers under the same law.

## What it does & for whom
For every agent in (or outside) the account: **recall** (`read_receipts` with a
cursor), **self-audit** (`verify_chain` re-derives the whole chain from genesis,
or localizes tampering with a named error at the exact row), and **commit**
(`append_receipt` — the client signs, the server validates fail-closed and
appends). Optional layers: `qmr2` (pluggable hash with one custody law plus a
re-hash upgrade path) and `v3` (Ed25519 per-signer attribution under fail-closed
keyrings). Consumers are agent lanes that need shared memory with integrity
guarantees, external verifiers applying the Stone standard, and any fleet repo
with a ledger that wants to adopt the seal discipline instead of re-proving it.

## Maturity assessment: **working, hardening** (prototype → working transition
complete)
- **Evidence**: six commits of receipted evolution (spike v1 → qmr2 → v3
  attribution → first external producer); `npm test` 40/40 green on Node
  v24.21.0 (verified this wave); the end-to-end client demo passes 12/12; the
  vendored tamper-conformance battery self-applies 16/16 against the real
  server (`receipts/DOGFOOD-67B.md`).
- **Real producers live**: `fleet-seeds` ships `tools/qmr1-bridge.mjs` sealing
  its actual lode ledgers (registry/lessons/mines) under this dialect, re-
  verifying the full chain from genesis before every write; its store verifies
  live under this server's `verify_chain`.
- **Dead-lane resilience demonstrated**: wave-69 lane 69-b died before
  committing; the 69-b-r2 finisher audit (`receipts/69b-death-audit.md`)
  classified every dirty file COMPLETE with full suites green before landing
  the work — the repo's own discipline absorbed an operational failure.
- **Not hardened**: stdio only (no HTTP), no ACL, no rate limiting, no external
  tip anchoring yet. All are declared non-goals with designed cures, not
  oversights.

## Risks
| risk | severity | mitigation status |
|---|---|---|
| HMAC shared secret = any holder can sign (attribution is fleet-trust) | medium | resolved architecturally by the v3 Ed25519 slot; adoption (real keyrings in daily use) is the open remainder |
| Local-storage attacker truncates the file | medium | outside v1's threat model BY DESIGN; cure designed — periodic tip anchoring on quilt-organ-workers' KV (the host already exists) |
| No ACL: reads are public | low (by design) | stated in DESIGN.md §5/§7; discipline is "put hashes in the chain, payloads elsewhere" |
| Single process, no rate limiting (DoS by connection volume) | low | stdio hosts bound it; v2 HTTP transport would add a queue/WAF |
| Ecosystem fragmentation (each repo re-implementing the chain) | medium | actively cured: the vendored conformance harness + the qmr2 dialect registry are the distill; adoption is in progress (first producers receipted) |
| Store path misconfiguration (silent fresh chain) | low | documented; operational discipline: absolute paths in client configs |

## Cost profile
$0. Stdlib Node, no external services, storage is one JSONL file (KBs at
current scale), no keys to buy, no services to host. Development cost to date
is a handful of lane-days across waves 65/67/68/69 — the cheapest organ in the
fleet per unit of trust delivered. Future HTTP transport would ride the already-
provisioned free-tier Cloudflare Workers stack.

## Strategic options
- **Invest (recommended, modest)** — land the v2 path: HTTP transport + tip
  anchoring on the existing quilt-organ-workers stack, and hosting inside
  superinstance-api's existing MCP surface so the context brain and the receipt
  chain share one address. Both are designed, scoped, and unblocked.
- **Maintain** — the organ is stable, tested, and adopted by its first
  producers; keeping it stdio-only with receipts is defensible at current
  fleet scale.
- **Harvest-learnings** — the strongest export is the METHOD: zero-shot spec
  before code, spec-derived test signers (not imported ones), fail-closed named
  errors, and the vendored tamper-conformance harness. These patterns are
  already spreading (fleet-seeds bridge, quilt-chrono seals, quilt-jev-toolkit
  fingerprint law).
- **Retire** — not indicated: it is the fleet's memory instrument and its first
  producers depend on the dialect.

## Integration surface
- **fleet-seeds** — first honest producer: `tools/qmr1-bridge.mjs` seals the
  lode ledgers under qmr1; `wal-conformance` receipted through the harness.
- **quilt-organ-workers** — the designed v2 host (HTTP transport + KV tip
  anchoring; loader routes map 1:1 onto read/verify/append).
- **quilt-jev-toolkit** — shares the SPKI fingerprint law (one identity, two
  organs, zero shared secrets); §11 key-revocation enforcement completed there.
- **quilt-chrono** — sibling seal law (Ed25519 seals, HMAC byte-compatible);
  cross-repo Ed25519 identity proof receipted in quilt-chrono.
- **superinstance-api** — the fleet's existing MCP surface (commit 5ded07cd);
  hosting the receipt tools there is queued.
- **RARS-oss/tabularium** — the external MCP-ization template that inspired the
  wire shape.
- **superinstance-lab worklog** — journal of record (tasks 65-a, 66-d, 68-a;
  in-repo receipts carry 67-b, 68-b, 69-b).
