# quilt-mcp-receipts — Agent Onboarding
> Zero-shot entry point. Clone → competent in ~10 minutes.

## Identity (2 sentences)
This repo exposes the fleet's receipt chain as a **signed append-only MCP organ**: any agent, inside or outside the account, can read, verify, and append fleet receipts over the Model Context Protocol (stdio JSON-RPC 2.0) without cloning a repo and without being trusted by anything. It is stdlib-only Node (no SDK), one file (`server.mjs`), speaking the `qmr1` receipt dialect with the `qmr2` pluggable-hash layer and the v3 Ed25519 attribution layer stacked additively on top.

## Why it exists (the fleet problem it solves)
The fleet already ran a receipt culture — append-only ledgers like `fleet-seeds/lode/registry.jsonl` and `lessons.jsonl` — but, honestly stated, those were not hash-chained: a rewritten line was detectable only by humans comparing receipts (DESIGN.md §1). Wave-65 (task 65-a) built this organ to add the missing instrument: prev-hash linkage plus a signature on every line, re-derivable by anyone, addressable over a wire. Wave-67/68 added the `qmr2` layer after the seed-dna census found the receipt chain re-implemented 12+ times across the fleet in two contradicting hash dialects — one receipt primitive, pluggable hash, one law, one shared tamper-conformance harness. Wave-68-b/69-b (the latter finished by 69-b-r2 after the lane died — see `receipts/69b-death-audit.md`) added v3 attribution: Ed25519 per-signer identity replacing HMAC's anonymous shared secret. DESIGN.md was written zero-shot BEFORE any code, and the test suite re-derives the spec independently from it — the spec is the law, not the implementation.

## Verify it works (exact commands)
All of these are offline and credential-free; all verified green on Node v24.21.0 during this documentation wave.

```bash
npm test                        # 40/40 — 37 test cases (15 v1 wire + 15 qmr2/dialect/conformance + 7 v3)
                                #   + 3 helper-module pass-throughs counted by the node runner
node examples/client-demo.mjs   # end-to-end client drive: handshake → list → read → verify → append → forgery rejected → ALL CHECKS PASSED
node server.mjs --demo          # seeds 5 sample receipts into ./store.jsonl (ONLY into an empty/missing store), then serves
node scripts/dogfood.mjs        # re-runs the dogfood: harness self-application 16/16 + the fleet-seeds wal-conformance producer receipt
```

To drive the server as an MCP client by hand: start `node server.mjs --demo` and
speak newline-delimited JSON-RPC 2.0 on stdin (`initialize`,
`notifications/initialized`, `tools/list`, `tools/call`). No external service,
no credentials. `MCP_RECEIPT_SECRET` is optional; if unset, a built-in dev
secret is used with a loud stderr warning (fine for demos only).

## Reading order (paths, not vibes)
1. `DESIGN.md` — the qmr1 law: dialect formulas, tool surface, threat model (§5 can/cannot/cannot-yet), v1 non-goals. Written before the code; the tests re-derive it.
2. `docs/qmr2-design.md` — the pluggable-hash layer: portable preimage (§2), dialect registry (§3), custody law, upgrade_chain (§5), v3 attribution (§8).
3. `server.mjs` — one 809-line file: sig schemes, dialect registry, `verifyChain`, `validateAppend`, tool handlers, JSON-RPC/MCP loop.
4. `test/mcp.test.mjs` — the wire-level suite; its signer is re-derived from DESIGN.md §2, not imported from the server (spec-verified, not self-tautological).
5. `test/conformance.mjs` + `test/adapter-self.mjs` — the vendored tamper-conformance battery and its self-application against the real server.
6. `receipts/DOGFOOD-67B.md` + `receipts/dogfood-67b.jsonl` — the harness receipts itself (16/16) and the first external producer.
7. `examples/client-demo.mjs` — the reference client-side signer (the server deliberately offers no signing helper).

## The things that will bite you (gotchas)
- **Run tests as `npm test` (bare `node --test`), not `node --test test/`.** The trailing-directory form fails MODULE_NOT_FOUND on Node v24.21.0 (receipted in the journal, task 66-d).
- **The store path defaults to `process.cwd()/store.jsonl`.** MCP client configs must pass an absolute `--store` path, or the server will look relative to wherever the host process started.
- **The server never signs.** There is deliberately no `sign_receipt` tool: key material must not flow through the wire, and the server must stay a verifier, not a co-signer (DESIGN.md §3). Your client signs; `examples/client-demo.mjs` is the reference.
- **HMAC's honest residual**: the shared secret means any holder can sign — attribution is fleet-trust, not identity, until a row uses v3 Ed25519 (`sigAlg` + `sigKeyFp`) and you verify under a keyring.
- **A canary row in custody mode is the law's only hard gate**: `verify_chain({dialect_mode:"custody"})` fails `E_DIALECT_FORBIDDEN` on any `fnv1a-canary` row; in default `"any"` mode mixed chains are legal. Append is dialect-neutral by design — the assertion happens at verify time, where it can have a name and a row number.
- **Ed25519 rows fail closed without a keyring**: `append_receipt` and `verify_chain` refuse `E_UNKNOWN_SIGNER` when the named `sigKeyFp` is not in the provided keyring; a mislabeled keyring (fingerprint does not match the key it holds) is refused `E_BAD_KEYRING` before any row is read.
- **qmr1 rows are never rewritten**: rows without `dialect`/`sigAlg` stay five-field byte-for-byte; the server writes exactly what the client submitted (never injects tags) — never-delete-data applies to shape too.
- **Versioned tool surfaces**: base trio always listed; `dialects` + `upgrade_chain` only under `--qmr2`/`QMR2=1`; `verify_attribution` only under `--v3`/`V3=1`. The untouched v1 suite pins the three-tool contract, so do not add tools to the default listing.
- **`--demo` never deletes**: it seeds only into an empty/missing store; an existing store is left untouched with a note on stderr.

## Where deeper knowledge lives
- Knowledge map: [docs/KNOWLEDGE-MAP.md](./KNOWLEDGE-MAP.md)
- Fleet journal: SuperInstance/superinstance-lab → worklog.md (grep `quilt-mcp-receipts`; task 65-a created it, 66-d decomposed it, 68-a pushed it)
- `receipts/` — the dogfood receipt set (jsonl + md) and the 69-b death audit; re-derivable via `node scripts/dogfood.mjs`
- `DESIGN.md` + `docs/qmr2-design.md` — the two zero-shot spec documents (qmr1 §1-7, qmr2 §1-9 incl. §8 v3)
- Related repos: `fleet-seeds` (first honest producer — its `tools/qmr1-bridge.mjs` seals the real lode ledgers under this dialect), `quilt-organ-workers` (the ready HTTP/tip-anchor host for v2), `quilt-jev-toolkit` (same SPKI fingerprint law in its organ v3), `quilt-chrono` (sibling seal law with Ed25519, cross-repo proof receipted there)

## Current frontier (what is open right now)
- **HTTP transport + tip anchoring on a Cloudflare Worker** (v2 path #2): the read/verify/append verbs map 1:1 onto quilt-organ-workers loader routes, and a periodic tip-anchor makes truncation detectable — designed, not built.
- **Host inside the fleet's existing MCP surface** (v2 path #3): superinstance-api already serves MCP tools (commit 5ded07cd); the receipt tools joining that server is queued, not done.
- **Fleet roll-out breadth**: the first external producer is receipted (fleet-seeds `wal-conformance`, plus the qmr1-bridge sealing registry/lessons/mines); `registry.jsonl`/`lessons.jsonl` rows gaining qmr1 mirrors and other fleet repos vendoring `test/conformance.mjs` instead of re-proving the tamper battery by hand remain the open adoption queue.
- **Key revocation statement layer**: quilt-jev-toolkit §11 implemented the enforcement half and parked the signed-statement half until an adoption story exists (see `receipts/69b-death-audit.md` §quilt-jev-toolkit) — the demand signal applies here too once v3 keys see real use.
- **ACL / authz**: reads are public-by-design; nothing has been built or scheduled to change that (put hashes in the chain, payloads elsewhere).
