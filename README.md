# quilt-mcp-receipts

The fleet's receipt chain, exposed as a **signed append-only MCP organ**: any
agent — inside or outside the account — can **read**, **verify**, and **append**
fleet receipts through the Model Context Protocol, without cloning a repo and
without being trusted by anything.

Spike v1, dialect `qmr1`; v0.2.0 adds the **qmr2 pluggable-hash layer** (below).
Stdio JSON-RPC 2.0, **stdlib only, no SDK**.

## What

A receipt chain is an append-only JSONL file of hash-chained, signed receipts:

```
{"seq":1,"prev":"000…0","body":{…},"id":"9c1b…","sig":"5d0e…"}
{"seq":2,"prev":"9c1b…","body":{…},"id":"3cc4…","sig":"d2f7…"}
```

- `id  = SHA-256("qmr1:" + seq + ":" + prev + ":" + canonicalJSON(body))`
- `sig = HMAC-SHA256(secret, "qmr1:sig:" + id)`

This is the fleet's existing seal discipline (append-only ledgers like
`fleet-seeds/lode/registry.jsonl` and `lessons.jsonl`) with the missing
instrument added: every line is linked and signed, and anyone can re-derive the
whole chain from genesis. Full spec + threat model: [DESIGN.md](DESIGN.md).

### Tool surface (exactly three tools)

| tool | verb | semantics |
|---|---|---|
| `read_receipts` | recall | receipts with `seq > since_seq`, up to `limit`; flags unparseable store lines, never skips them silently |
| `verify_chain` | self-audit | re-derives the full hash chain from genesis → `{ok, count, tip}` or fail-closed `{ok:false, error, at_seq}` |
| `append_receipt` | commit | client signs the full receipt; server validates fail-closed (structure → seq → prev → id → sig) and appends |

Named error codes: `E_STORE_CORRUPT`, `E_MISSING_FIELD`, `E_UNKNOWN_FIELD`,
`E_BODY_INVALID`, `E_SEQ_MISMATCH` (covers replay), `E_PREV_MISMATCH` (broken
hash link), `E_HASH_MISMATCH`, `E_BAD_SIGNATURE` — qmr2 adds `E_DIALECT_FORBIDDEN`
and `E_UNKNOWN_DIALECT`.

## qmr2 — the pluggable-hash dialect layer (v0.2.0)

The wave-66 seed-dna census found the receipt chain re-implemented 12+ times
across the fleet in TWO contradicting hash dialects — fnv1a-64 "canary" (fast)
vs sha256 "custody" — with the tamper battery re-proven ~8×. qmr2 is the
distill: **one receipt primitive, pluggable hash, one law.** Spec:
[docs/qmr2-design.md](docs/qmr2-design.md).

- **Same five fields.** A row MAY carry a sixth field `dialect`; qmr1 rows read
  as `sha256-custody` and are never rewritten on disk (never-delete-data holds
  for shape too).
- **Portable preimage** — `"qmr1:" + seq + ":" + prev + ":" + canonicalJSON(body)`
  is identical across dialects, so a chain can be **re-hash-upgraded** row-by-row.
- **Registry:**

  | dialect | hash | id form | custody |
  |---|---|---|---|
  | `sha256-custody` | SHA-256 | 64 hex | **yes** — qmr1-compatible |
  | `fnv1a-canary` | FNV-1a 64 | `0x` + 16 hex | **no** — fast chains that will never hold custody |

- **The one law:** custody chains MUST use `sha256-custody`. Enforced where it
  can have a name and a row number: `verify_chain({dialect_mode:"custody"})`
  fails `E_DIALECT_FORBIDDEN` on any canary row. Default mode `"any"` verifies
  each row under its own dialect (mixed chains legal). Unknown dialect name →
  `E_UNKNOWN_DIALECT`.
- **`upgrade_chain({from_seq, to_seq})`** re-hashes a verified chain segment
  into a NEW standalone custody receipt set under `upgrades/` (bodies
  byte-identical, seqs renumbered from genesis, timestamp-free manifest →
  re-runs are byte-identical, source store never mutated).
- **Versioned tool surface:** the v1 contract (exactly the three tools above,
  pinned by the untouched test suite) holds by default; run with `--qmr2` (or
  env `QMR2=1`) to also list the `dialects` + `upgrade_chain` tools. The
  `tools/list` RESULT always carries an additive `dialects` field (registry +
  law), and the row-level dialect layer is always active.

## Vendor the tamper-conformance harness (retires the ~8 re-implementations)

`test/conformance.mjs` is the shared battery: tamper trio (body flip →
`E_HASH_MISMATCH` at_seq · sig flip → `E_BAD_SIGNATURE` · row deletion →
`E_SEQ_MISMATCH`), replay, wrong-secret, unknown-dialect, empty-body,
custody-law, determinism, plus a clean-chain positive control — and, since the
§9 wave, the **v3 sig cases** (Ed25519 attribution, docs/qmr2-design.md §8):
`v3-clean` (Ed25519 row appends + verifies under its keyring — the control),
`v3-wrong-key` (sig minted by an impostor's key while the row names the honest
fingerprint → `E_BAD_SIGNATURE` at the door), `v3-unknown-signer` (keyring
missing that fingerprint, or absent → `E_UNKNOWN_SIGNER`), `v3-forged-sig`
(sig flipped behind the API → `E_BAD_SIGNATURE` at_seq), `v3-qmr1-shape` (the
five-field qmr1 row is byte-unchanged; keyring does not disturb hmac rows),
and `v3-tool-gating` (the base trio is listed always, `verify_attribution` iff
the v3 gate is open). Copy it into your repo verbatim (it is dependency-free),
write a ~40-line adapter, run:

```js
import { runConformance } from './conformance.mjs';

const verdict = await runConformance({
  name: 'my-repo-receipt-chain',
  features: { dialects: true, v3: true }, // false → that layer's cases are marked
                                          // skipped, not failed (visible, honest);
                                          // UNDECLARED = the full battery is attempted
  async reset() { /* fresh empty chain */ },
  makeReceipt(seq, prev, body, { secret, dialect, sigAlg, signer, signWith } = {}) {
    /* sign per your dialect → full receipt; sigAlg:'ed25519' signs under
       signer.privateKeyPem and names signer.fp (signWith = mint with a
       DIFFERENT private key than the claimed fingerprint — the impostor path) */
  },
  async appendRaw(receipt, { keyring } = {}) { /* submit → {ok} | {ok:false, error, at_seq?, detail?} */ },
  async verify(opts = {}) { /* full audit; opts.dialect_mode? / opts.keyring? → {ok} | {ok:false, error, at_seq?} */ },
  async readTip() { /* tip id | null */ },
  async rows() { /* raw rows (persistence-level read) */ },
  async rewrite(rows) { /* persistence-level rewrite — tampering happens behind the API's back */ },
  async listTools() { /* optional: your host's tool names — enables v3-tool-gating */ },
  // errorMap: { yourLegacyName: 'E_HASH_MISMATCH' }  // optional bridge for legacy error names
});
assert.equal(verdict.ok, true);            // your chain now speaks the fleet's named fail-closed law
```

The harness mints Ed25519 identities AT RUNTIME (`node:crypto`; test-time keys
only, never committed) and never signs itself — signing is the adapter's law
under test. The v3 named-law count grew 10 → 16; the self-application below
proves all 16 against the real server.

First customer: this harness's own host — `test/adapter-self.mjs` drives the
real server over stdio MCP, and the run is receipted in
`receipts/dogfood-67b.jsonl` (see `receipts/DOGFOOD-67B.md`, re-derivable via
`node scripts/dogfood.mjs`).

## Why

Memory is the scarcest shared organ in a 5,000-repo agent fleet. The receipt
culture already exists — it just wasn't addressable over a wire. MCP-izing it
(template: [RARS-oss/tabularium](https://github.com/RARS-oss/tabularium)) means:

- a lane finishing a run **appends one receipt** instead of editing a ledger by hand;
- any agent **catches up** with one cursor call (`since_seq = my last seq`);
- `verify_chain` is a standing instrument against well-formed-but-wrong artifacts —
  wrongness here has a name and a row number.

## Run

```sh
node server.mjs --demo          # seed 5 sample receipts into ./store.jsonl, then serve
node examples/client-demo.mjs   # end-to-end client drive: handshake → list → read → verify → append
npm test                        # 37/37 test cases green — 15 v1 + 15 qmr2 (dialect layer,
                                #   upgrade determinism, conformance self-application) + 7 v3
                                #   (sig slot, keyring, verify_attribution); the node runner
                                #   additionally counts the 3 helper modules as pass-throughs
node scripts/dogfood.mjs        # re-run the dogfood: harness self-receipt + wal-* external producer
```

Environment: `MCP_RECEIPT_SECRET` — HMAC key for the spike scheme. If unset, a
built-in dev secret is used **with a loud stderr warning** (fine for demos;
set your own for anything real).

Point an MCP client (Claude Code, Cursor, any stdio MCP host) at it:

```json
{
  "mcpServers": {
    "quilt-receipts": {
      "command": "node",
      "args": ["/path/to/quilt-mcp-receipts/server.mjs", "--store", "/path/to/store.jsonl"],
      "env": { "MCP_RECEIPT_SECRET": "<shared secret>" }
    }
  }
}
```

The store file is append-only by convention; the server never mutates or deletes
existing lines, and `verify_chain` detects any behind-the-back edit with a named
error at the exact row.

## Honest limits (v1)

- HMAC = shared secret: any holder can sign, so attribution is fleet-trust, not identity.
- No ACL: reads are public-by-design (put hashes in the chain, payloads elsewhere).
- No tip anchoring: a local-storage attacker who can truncate the file is outside
  v1's threat model.
- Single process, no HTTP: stdio only.

## Next (v2 path)

1. **Ed25519 per-agent keypairs** replace the shared HMAC secret — offline
   verification, per-agent attribution, non-repudiation (`qmr2` dialect, additive).
2. **HTTP transport + tip anchoring on a Cloudflare Worker** — reference
   [quilt-organ-workers](https://github.com/SuperInstance/quilt-organ-workers):
   the KV-backed organ store, boot-loader, and watcher already exist; the
   read/verify/append verbs here map 1:1 onto loader routes, and a periodic
   tip-anchor makes truncation detectable.
3. **Host inside the fleet's existing MCP surface** — superinstance-api already
   serves MCP tools (commit `5ded07cd`); the receipt tools join that server so
   the context brain and the receipt chain share one address.
4. Fleet roll-out: **done for the first producer** — `fleet-seeds`' real
   `wal-conformance` tool receipted through the shared harness
   (`receipts/dogfood-67b.jsonl`); next: `registry.jsonl` / `lessons.jsonl`
   rows gain `qmr1` mirrors, and fleet repos vendor `test/conformance.mjs`
   instead of re-proving the tamper battery by hand.

## The door has been knocked on — the first honest producer (fleet-seeds qmr1-bridge)

Insight #3 of the erised-fleet-table playtest said it exactly: *a receipt chain
with no producer is a door nobody knocks on.* The chain no longer waits.
[fleet-seeds](https://github.com/SuperInstance/fleet-seeds) now ships
`tools/qmr1-bridge.mjs` — a stdlib-only writer that seals its real lode ledgers
(`registry` / `lessons` / `mines`) under this dialect:

- every invocation **re-verifies the whole chain from genesis, ids and HMAC sigs,
  and refuses to write on any failure** (fail-closed, named error, `at_seq`);
- one `lode.row` receipt per lode append going forward, appended only — the
  bridge has no rewrite, delete, or reorder verb;
- backfilled honestly at round 71: genesis + one `lode.snapshot` receipt per
  lode ({rows, sha256 of the full lode file}) — the pre-71 rows are covered by
  snapshot digests, NOT retroactive per-row sealing; per-row receipts start now;
- its store, `fleet-seeds/ledger/qmr1-store.jsonl` (tip `719123ffc6d8d575…`,
  count 4 at genesis), verifies **live** under this server's `verify_chain`
  when handed the bridge's secret — same formulas, same dialect, one fleet law.

Conformance is proven the right way: the bridge's tests re-derive the signer
from DESIGN.md §2 independently and run the tamper trio against a real store
(18/18). Secret material stays in fleet-seeds' gitignored `.qmr1-secret` — the
HMAC residual (sigs verify for secret holders) is receipted in both repos.
