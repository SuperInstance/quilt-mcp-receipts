# quilt-mcp-receipts — User Guide
> For end users: any agent or human who wants to read, verify, or append the
> fleet receipt chain over MCP.

## What you get
A signed, hash-chained, append-only receipt ledger exposed as an MCP server.
One JSONL file (`store.jsonl`) is the whole database; one line is one receipt;
every line is linked to the previous line by hash and signed. You get three
always-on tools, plus two optional layers that unlock under flags:

| tool | verb | semantics |
|---|---|---|
| `read_receipts` | recall | receipts with `seq > since_seq`, up to `limit` (1–1000, default 100); flags unparseable store lines as `corrupted_lines`, never skips them silently |
| `verify_chain` | self-audit | re-derives the full hash chain from genesis → `{ok:true, count, tip}` or fail-closed `{ok:false, error, at_seq, detail}` on the FIRST broken row |
| `append_receipt` | commit | you build and sign the full receipt; the server validates fail-closed (structure → seq → prev → id → sig) and appends; nothing invalid is ever written |
| `dialects` (qmr2 flag) | introspect | the hash-dialect registry + the custody law |
| `upgrade_chain` (qmr2 flag) | migrate | re-hash rows [from_seq..to_seq] into a NEW standalone sha256-custody receipt set under `upgrades/`; source store never mutated |
| `verify_attribution` (v3 flag) | attribute | who signed each row, under a keyring `{fingerprint → publicKeyPem}` |

Everything is stdlib Node — no SDK, no database, no network. The transport is
stdio, newline-delimited JSON-RPC 2.0 (the MCP stdio shape), protocol version
`2024-11-05` with client version negotiation.

## Install
```bash
git clone https://github.com/SuperInstance/quilt-mcp-receipts
cd quilt-mcp-receipts
node --version          # >= 18.17
npm test                # 40/40 green = healthy checkout (verified on Node v24.21.0)
```
There are no dependencies to install. `package.json` declares no runtime deps.

## First success in 5 minutes
```bash
node server.mjs --demo          # seeds 5 sample receipts into ./store.jsonl (empty/missing store only)
```
Then point any MCP client at it — e.g. a Claude Code / Cursor config:
```json
{
  "mcpServers": {
    "quilt-receipts": {
      "command": "node",
      "args": ["/absolute/path/to/quilt-mcp-receipts/server.mjs",
               "--store", "/absolute/path/to/store.jsonl"],
      "env": { "MCP_RECEIPT_SECRET": "choose-a-real-secret" }
    }
  }
}
```
Or drive it by hand with the end-to-end demo, which starts its own server and
runs handshake → list → read → verify → client-signed append → broken-prev
forgery rejected → verify-still-ok → cursor read:
```bash
node examples/client-demo.mjs
# → ... ALL CHECKS PASSED
```
Expected shape of a receipt (the five-field law):
```json
{"seq":1,"prev":"000…0 (64 zeros)","body":{"kind":"…","ts":"…"},"id":"<64 hex>","sig":"<64 hex>"}
```
- `id = SHA-256("qmr1:" + seq + ":" + prev + ":" + canonicalJSON(body))`
- `sig = HMAC-SHA256(secret, "qmr1:sig:" + id)`
- canonicalJSON = recursive key-sorted, no whitespace

## Everyday usage

### 1. Catch up on fleet state since your last read (cursor read)
```jsonc
// tools/call → read_receipts {"since_seq": 42, "limit": 100}
// → {"ok":true,"count":7,"tip":"afbc…","receipts":[… seq 43..49 …]}
```
One call with a cursor replaces diffing file trees; the store is re-parsed from
disk on every call, so answers describe the file as it IS.

### 2. Self-audit the chain before you trust it
```jsonc
// tools/call → verify_chain {}
// → {"ok":true,"dialect":"qmr1","count":6,"tip":"3cc4…"}
// tampered store → {"ok":false,"error":"E_HASH_MISMATCH","at_seq":3,"detail":"…","count_checked":2,"tip":null}
```
With the qmr2 layer: `{"dialect_mode":"custody"}` asserts the chain is a custody
chain (any `fnv1a-canary` row fails `E_DIALECT_FORBIDDEN` at its seq).

### 3. Append one receipt after finishing a run (the seal discipline as a wire call)
Sign client-side first (see `examples/client-demo.mjs` for the ~15-line
reference signer), then:
```jsonc
// tools/call → append_receipt {"receipt": {"seq":7,"prev":"<tip>","body":{"kind":"engine.run.sealed","ts":"…","claim":"…","refs":[…]},"id":"<recomputed>","sig":"<hmac>"}}
// → {"ok":true,"seq":7,"id":"…","tip":"…","dialect":"sha256-custody","sigAlg":"hmac-sha256"}
```
Replays and gaps fail `E_SEQ_MISMATCH`; broken links fail `E_PREV_MISMATCH`;
body/seq/prev edits fail `E_HASH_MISMATCH`; a wrong secret fails
`E_BAD_SIGNATURE`. The order matters and first failure wins.

### 4. Attribute rows to signers (v3)
```jsonc
// tools/call → verify_attribution {"keyring": {"<64hex fingerprint>": "<public key PEM>"}}
// → {"ok":true,"attribution":[{"seq":1,"sigAlg":"ed25519","sigKeyFp":"…","signedBy":{"fingerprint":"…","verified":true,"source":"keyring"}}, …]}
```
The fingerprint law: `sha256(normalized SPKI PEM of the public key)` → 64 hex —
the same law as quilt-jev-toolkit's organ v3, so one identity works across both
organs. HMAC rows report the honest residual ("one anonymous writer").

### 5. Upgrade a canary chain to custody (qmr2)
```jsonc
// tools/call → upgrade_chain {"from_seq":1,"to_seq":12}
// → {"ok":true,"rows_upgraded":12,"out":"…/upgrades/upgrade-1-12-<sha8>.jsonl","manifest":"…/upgrade-….manifest.json",…}
```
Bodies are byte-identical, seqs renumbered from genesis, the manifest is
timestamp-free (re-runs are byte-identical), and the source store is never
mutated. The full source chain must verify before anything is written — an
upgrade launders nothing.

### 6. Run the tamper-conformance battery against your own receipt chain
Copy `test/conformance.mjs` (dependency-free) into your repo, write the ~40-line
adapter (`reset/makeReceipt/appendRaw/verify/readTip/rows/rewrite`), and run
`runConformance`. The README shows the full adapter contract; the vendored
`test/adapter-self.mjs` is the worked example (16/16 against the real server).

## Troubleshooting

| symptom | cause | fix |
|---|---|---|
| stderr warning about a dev secret | `MCP_RECEIPT_SECRET` unset — the built-in dev secret is in use | set a real secret in the MCP client's `env` block for anything you care about |
| `node --test test/` fails with MODULE_NOT_FOUND | trailing-dir form of the test runner on Node v24 | use `npm test` (bare `node --test`) — receipted journal finding |
| every append fails `E_BAD_SIGNATURE` | your client signs under a different secret than the server verifies with | align `MCP_RECEIPT_SECRET` between signer and server |
| append fails `E_SEQ_MISMATCH` with "expected seq N" | replay of an old receipt, or a gap | re-read the tip (`read_receipts` with a high `since_seq`, or `verify_chain`) and build on the real tip |
| append fails `E_PREV_MISMATCH` | your `prev` is not the current tip id | re-fetch the tip; prev must equal the previous row's id verbatim (which may be `0x…` on a canary chain) |
| append fails `E_HASH_MISMATCH` | body was edited after signing, or non-canonical serialization was hashed | hash exactly `sha256("qmr1:"+seq+":"+prev+":"+canonicalJSON(body))`; whitespace/key-order do not matter, values do |
| append fails `E_UNKNOWN_FIELD` | a sixth+ field beyond `dialect`/`sigAlg`/`sigKeyFp` | strictness is on purpose; move extra data inside `body` |
| ed25519 append/verify fails `E_UNKNOWN_SIGNER` | the row's `sigKeyFp` is not in the provided keyring | pass `arguments.keyring {fingerprint → publicKeyPem}`; an unverifiable signer is an unknown signer, by law |
| `E_BAD_KEYRING` before any row is read | a keyring fingerprint is not 64-hex or does not match the key it holds | re-derive fingerprints as `sha256(spkiPem)`; the trust root must be honest |
| `E_STORE_CORRUPT` naming line numbers | a line in the store is not valid JSON (edited behind the server's back) | the server never rewrites; restore the honest bytes from your own backup — verify will localize the tamper |
| `verify_chain` fails `E_DIALECT_FORBIDDEN` | a canary row sits in a chain you asserted as custody | either verify in `"any"` mode, or `upgrade_chain` the segment to sha256-custody |
| server seems to answer nothing | it speaks line-delimited JSON-RPC on stdio; notifications (`id`-less messages) get no reply | send `initialize` first, then `notifications/initialized`, then requests WITH ids |

## FAQ

**Do I need the repo cloned to use the organ?** You need the file `server.mjs` running somewhere you can spawn a process. The point of MCP-izing the chain is that any host (Claude Code, Cursor, a CI job, your agent) can address it over the protocol — you do not clone fleet repos to read their ledgers; you point a server at a store path. An outside account can run the same server over its own store and interoperate at the receipt level, because the dialect is one file plus two formulas.

**Who can sign a receipt?** Anyone holding the HMAC secret (or holding an Ed25519 private key whose fingerprint your keyring trusts). That is the model's honest shape: HMAC = one anonymous writer (fleet-trust); v3 Ed25519 = per-signer identity with fail-closed keyrings. The server itself never signs and never holds private keys.

**Can the server rewrite or delete history?** No. There is no update or delete verb; the only write is an append of a fully validated line. Edits made behind the server's back (direct file writes) are caught by `verify_chain` from genesis and localized with a named error at the exact row. `--demo` seeds only an empty/missing store; upgrade_chain writes new files under `upgrades/` and never touches the source.

**What stops garbage appends?** Fixed-order fail-closed validation (structure → body shape → seq → prev → id → sig) with named codes; nothing invalid is ever written, and the store is re-read from disk before every append so the server cannot be fooled by a stale in-memory tip. A corrupt store refuses appends outright (`E_STORE_CORRUPT`).

**Is my data private on this chain?** No — reads are public-by-design (the spike has no ACL; DESIGN.md §5). If a receipt must be secret, keep the payload elsewhere and put a hash of it in the body. This is stated as a v1 non-goal, not an oversight.

**What is the difference between qmr1, qmr2, and v3?** qmr1 is the receipt dialect (five fields, two formulas, eight named errors). qmr2 adds the pluggable-hash slot: a row MAY carry `dialect`, custody chains must use sha256-custody (the one law), and canary chains can be re-hash-upgraded mechanically thanks to the portable preimage. v3 adds the pluggable-signature slot: `sigAlg:"ed25519"` + `sigKeyFp`, verified under a caller-provided keyring, fail-closed. Both layers are additive; qmr1 rows are byte-unchanged and never rewritten.
