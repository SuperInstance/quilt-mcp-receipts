# DOGFOOD-67B — the qmr2 harness receipts itself + its first external producer

Run: `node scripts/dogfood.mjs` (re-runnable; each run rewrites this receipt set).

## What ran

1. **Conformance self-application** — `test/conformance.mjs` (`runConformance`)
   against the live qmr2 server over stdio MCP via `test/adapter-self.mjs`:
   **16/16 cases pass** (clean-chain, body-flip, sig-flip, row-deletion, replay, wrong-secret, unknown-dialect, empty-body, custody-law, determinism, v3-clean, v3-wrong-key, v3-unknown-signer, v3-forged-sig, v3-qmr1-shape, v3-tool-gating); skipped: none.
2. **First external producer** — `fleet-seeds/tools/wal-conformance.mjs` (real
   tool, read-only, offline) ran green (`ok: true`, chains: qthe, pong, toyStone)
   and its verdict was appended THROUGH the harness adapter API as a
   `wal.conformance.run` receipt. The fleet's wal-* wiring is no longer queued:
   one real wal receipt has flowed through the shared battery.

## The receipt set

- File: `receipts/dogfood-67b.jsonl` — 3 receipts, sha256 a982b30801280253ed8d044a1a77038738ca5f78e39e36a929bf7212522710ec
- Tip: `afbc460a4664123e3798b7fcc73f57ab21eb4b84677ecd06291da6a85b11b651`
- verify (any mode): ok · verify (dialect_mode "custody"): ok — the set is a lawful custody chain.
- Re-derive independently: `node server.mjs --store receipts/dogfood-67b.jsonl`
  then call `verify_chain` over stdio MCP.

## Receipt index

- seq 2 `conformance.harness.run` — id `47c4a0b94a2fa952…`
- seq 3 `wal.conformance.run` — id `afbc460a4664123e…`
