# DOGFOOD-67B — the qmr2 harness receipts itself + its first external producer

Run: `node scripts/dogfood.mjs` (re-runnable; each run rewrites this receipt set).

## What ran

1. **Conformance self-application** — `test/conformance.mjs` (`runConformance`)
   against the live qmr2 server over stdio MCP via `test/adapter-self.mjs`:
   **10/10 cases pass** (clean-chain, body-flip, sig-flip, row-deletion, replay, wrong-secret, unknown-dialect, empty-body, custody-law, determinism); skipped: none.
2. **First external producer** — `fleet-seeds/tools/wal-conformance.mjs` (real
   tool, read-only, offline) ran green (`ok: true`, chains: qthe, pong, toyStone)
   and its verdict was appended THROUGH the harness adapter API as a
   `wal.conformance.run` receipt. The fleet's wal-* wiring is no longer queued:
   one real wal receipt has flowed through the shared battery.

## The receipt set

- File: `receipts/dogfood-67b.jsonl` — 3 receipts, sha256 dce7bc1a022a1590a2c3fb8e4669091956ceef5c38fc04d7831b1d4ded7eb2f3
- Tip: `edad077f542cb265a39132b5a51fb0e0ee6d237dfdac5d4aeab59428bfac6d4b`
- verify (any mode): ok · verify (dialect_mode "custody"): ok — the set is a lawful custody chain.
- Re-derive independently: `node server.mjs --store receipts/dogfood-67b.jsonl`
  then call `verify_chain` over stdio MCP.

## Receipt index

- seq 2 `conformance.harness.run` — id `afe542ca20122173…`
- seq 3 `wal.conformance.run` — id `edad077f542cb265…`
