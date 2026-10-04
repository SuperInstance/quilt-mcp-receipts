# quilt-mcp-receipts — Knowledge Map
> The index of indexes: everything deeper than the README, mapped.

## In this repo
- `server.mjs` — the entire organ (809 lines, stdlib only): sig-scheme registry
  (v3), dialect registry (qmr2), `verifyChain`, `validateAppend`, demo seeding,
  `upgradeChain`, tool definitions with their version gates, and the
  stdio JSON-RPC/MCP loop.
- `DESIGN.md` — the qmr1 spec, written zero-shot BEFORE code: what the organ
  is (§1), the receipt dialect (§2), the tool surface (§3), signing schemes
  spike vs v2 (§4), the threat model can/cannot/cannot-yet (§5), the
  memory-organ framing (§6), and explicit v1 non-goals (§7).
- `docs/qmr2-design.md` — the qmr2 + v3 spec: what changes (§1), the portable
  preimage (§2), the dialect registry with the pinned café FNV vector (§3),
  versioned tool surface (§4), re-hash upgrading (§5), the shared conformance
  harness (§6), and v3 attribution (§8).
- `test/mcp.test.mjs` (15) — wire-level v1 suite; its signer is re-derived from
  DESIGN.md §2, not imported from the server.
- `test/qmr2.test.mjs` (part of the 15 qmr2) — dialect-layer + v3 row law.
- `test/v3-attribution.test.mjs` (7) — keyring, `verify_attribution`, gating.
- `test/conformance.mjs` — THE vendored tamper-conformance battery
  (dependency-free; designed to be copied verbatim into other repos).
- `test/adapter-self.mjs` + `test/mcp-client.mjs` — the self-application
  adapter (drives the real server over stdio) and the minimal MCP client.
- `examples/client-demo.mjs` — the reference CLIENT-side signer + 12-check
  end-to-end drive (handshake → list → read → verify → append → forgery
  rejected → verify-still-ok → cursor read).
- `scripts/dogfood.mjs` — re-runs and re-receipts the dogfood set.
- `receipts/dogfood-67b.jsonl` — 3-receipt chain (genesis + harness run +
  wal-conformance run); file sha256 `a982b308…`; tip `afbc460a…`; verifies
  under both `any` and `custody` modes.
- `receipts/DOGFOOD-67B.md` — the prose receipt for the above.
- `receipts/69b-death-audit.md` — the wave-69 dead-lane audit (69-b's
  uncommitted work in three repos classified COMPLETE by 69-b-r2; this repo:
  8 modified files, suite 40/40, self-application 16/16).
- `package.json` — v0.3.0, private, `engines.node >=18.17`, scripts
  `test` (bare `node --test`) and `demo`; zero runtime dependencies.
- `docs/` (wave-69 package) — this file's five siblings + the README section.

## Pre-existing docs (before wave-69)
- `README.md` — the living overview: what/why, tool surface table, named error
  codes, the qmr2 layer, the vendored-harness recipe with the full adapter
  contract, run commands, honest limits (v1), the v2 path, the "door has been
  knocked on" section documenting the fleet-seeds qmr1-bridge producer.
- `DESIGN.md` — qmr1 law (see above; load-bearing — the test suite re-derives
  §2 independently).
- `docs/qmr2-design.md` — qmr2/v3 law (see above; §3 carries the pinned
  FNV-1a vector `fnv1a64("café Δ 日本語") = 24a555471370b18d` and the census
  erratum about the 17-hex-digit transcription).
- `receipts/DOGFOOD-67B.md`, `receipts/69b-death-audit.md` — operational
  receipts (pre-existing; this wave added none).

## In the fleet
- **fleet-seeds** — downstream producer (uses): its `tools/qmr1-bridge.mjs`
  seals the real lode ledgers (`registry`/`lessons`/`mines`) under this
  dialect; its store `ledger/qmr1-store.jsonl` (tip `719123ffc6d8d575…`,
  count 4 at genesis) verifies live under this server's `verify_chain`;
  `wal-conformance` was the first external producer receipted through the
  shared harness.
- **quilt-organ-workers** — designed host (used-by, v2): its KV organ store,
  boot-loader, and watcher are the ready substrate for HTTP transport + tip
  anchoring; read/verify/append map 1:1 onto loader routes.
- **quilt-jev-toolkit** — sibling (shares the identity law): the v3
  fingerprint (`sha256` of the normalized SPKI PEM) is byte-identical to
  toolkit organ v3 checkpoints — one identity, two organs, zero shared secrets.
- **quilt-chrono** — sibling seal law: Ed25519 seals with HMAC byte-compat;
  the cross-repo proof (one toolkit-minted identity sealing a chrono ledger,
  accepted by both laws) is receipted in quilt-chrono.
- **superinstance-api** — potential host: the fleet's existing MCP surface
  (commit 5ded07cd added its first MCP tool).
- **RARS-oss/tabularium** — external template that inspired MCP-izing a ledger.
- **slackwater-quilt / jev-quilt / quilt-qcells** — context: the wave-66 census
  sources for the two hash dialects (canary vs custody) that qmr2 reconciles;
  slackwater-quilt explicitly refutes canary hashes for custody chains.

## In the journal
Grep `SuperInstance/superinstance-lab → worklog.md` for `quilt-mcp-receipts`:
- **65-a** (wave 65) — repo created via GitHub API; DESIGN.md written before
  code; 15/15 wire tests + 12/12 client demo; push discipline with ls-remote
  verify; the HMAC attribution residual flagged for v2.
- **66-d** (wave 66) — organ-family decomposition: read DESIGN.md + server.mjs +
  mcp.test.mjs; smoke 15/15; the `node --test test/` MODULE_NOT_FOUND finding
  on Node v24 receipted; 4 decomposition JSONs written.
- **66 (keeper)** — the organ-family gate-density reading (mcp-receipts 16/16
  gates: tamper-evidence discipline).
- **68-a** (wave 68) — push-wave integration (fast-forward-pull, audit, push).
- In-repo receipts carry the tasks the journal does not yet list: **67-b**
  (dogfood receipt set), **68-b / 68-b-r2** (qmr2 §8 v3 attribution, commit
  d3ab7bf), **69-b / 69-b-r2** (conformance §9 v3 sig cases, commit c8ad04e,
  dead-lane audit), **round-71** (qmr1-bridge producer section, commit 4866bcd).

## Receipts of record
- `receipts/dogfood-67b.jsonl` + `receipts/DOGFOOD-67B.md` — proof the shared
  harness works against the real server (16/16 named cases) and that an
  external producer's verdict flowed through it (`wal.conformance.run`).
  Re-derive: `node scripts/dogfood.mjs` or point the server at the jsonl and
  call `verify_chain`.
- `receipts/69b-death-audit.md` — proof that uncommitted work from a dead lane
  was evaluated honestly (not rewritten) before being landed: per-repo dirty
  sets, full-suite verdicts (this repo 40/40), broken inventory "none".
- `receipts/dogfood-67b.jsonl` itself doubles as a live specimen of the dialect
  (genesis prev 64 zeros, canonical bodies, HMAC sigs).
- Commit history as receipt chain-of-custody: 47f5699 → 889960a → 2df417d →
  d3ab7bf → c8ad04e → 4866bcd, each message carrying the claim and residual.

## How to search further
```bash
# every named fail-closed error and where it fires
grep -n "E_[A-Z_]*" server.mjs | sort -u
# the sig-slot and hash-slot laws side by side
grep -n "sigAlg\|sigKeyFp\|E_UNKNOWN_SIGNER\|E_BAD_KEYRING" server.mjs
# the portable preimage and dialect id derivation
grep -n "preimage\|dialectId\|qmr1:" server.mjs docs/qmr2-design.md
# conformance case roster (what the vendored battery proves)
grep -n "name: '" test/conformance.mjs
# journal history for this repo
grep -n "quilt-mcp-receipts" /home/z/my-project/worklog.md
# verify the receipted dogfood chain yourself
node server.mjs --store receipts/dogfood-67b.jsonl   # then tools/call verify_chain
```
