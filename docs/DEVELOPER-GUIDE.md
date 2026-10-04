# quilt-mcp-receipts — Developer Guide
> For developers extending the server, porting the dialect, or vendoring the
> conformance harness.

## Code layout

```
server.mjs                    # the whole organ: 809 lines, stdlib only
  ├─ sig schemes (§8 registry)  ed25519KeyFingerprint / ed25519VerifySig / keyringError
  ├─ dialect registry (§3)      fnv1a64, DIALECTS {sha256-custody, fnv1a-canary}, dialectId (portable preimage)
  ├─ CLI/env                    --store | --demo | --qmr2 | --v3 | --quiet-notice ; MCP_RECEIPT_SECRET, QMR2, V3
  ├─ store IO                   loadStore (re-parse from disk every call, corrupted_lines), appendLine (fs.appendFileSync)
  ├─ verification               verifyChain({dialect_mode, keyring}) — full re-derivation from genesis, first failure wins
  ├─ append                     validateAppend(receipt, keyring) — fixed order structure→seq→prev→id→sig
  ├─ demo seeding               seedDemo — 5 fleet-flavored receipts, ONLY into an empty/missing store
  ├─ upgrade                    upgradeChain(fromSeq,toSeq) — verified segment → new custody set under upgrades/
  ├─ tool defs                  TOOLS (base trio) + QMR2_TOOLS (dialects, upgrade_chain) + V3_TOOLS (verify_attribution)
  └─ JSON-RPC/MCP loop          initialize / ping / tools/list / tools/call; -32601/-32602/-32700; notifications silent
DESIGN.md                     # qmr1 spec, written zero-shot BEFORE code (§1 organ, §2 dialect, §3 tools,
                              #   §4 signing, §5 threat model, §6 memory-organ framing, §7 non-goals)
docs/qmr2-design.md           # qmr2 + v3 spec (§2 portable preimage, §3 registry, §4 versioned tools,
                              #   §5 upgrade, §6 conformance harness, §8 v3 attribution, §9 wave-67/68 findings)
test/mcp.test.mjs             # 15 v1 wire tests; signer re-derived from DESIGN.md §2, NOT imported from server
test/qmr2.test.mjs            # dialect layer tests incl. v3 row law (sigKeyFp = sha256 of SPKI PEM)
test/v3-attribution.test.mjs  # keyring / verify_attribution / gating tests (7)
test/conformance.mjs          # THE vendored tamper-conformance battery (dependency-free; copy into your repo)
test/adapter-self.mjs         # self-application: drives the REAL server over stdio MCP with that battery
test/mcp-client.mjs           # minimal stdio MCP client used by the suites
examples/client-demo.mjs      # reference CLIENT-side signer + end-to-end drive (12 checks)
scripts/dogfood.mjs           # re-runs the dogfood: harness self-receipt + wal-* external producer
receipts/dogfood-67b.jsonl    # 3 receipt chain (genesis + harness run + wal run); tip afbc460a…
receipts/DOGFOOD-67B.md       # prose receipt for the above (16/16 conformance, custody-verified)
receipts/69b-death-audit.md   # the dead-lane audit: 69-b's uncommitted work classified COMPLETE by 69-b-r2
```

## Core concepts (named as the code names them)

- **qmr1 dialect** — the five-field row `{seq, prev, body, id, sig}`;
  `id = sha256("qmr1:"+seq+":"+prev+":"+canonicalJSON(body))`;
  `sig = HMAC-SHA256(secret, "qmr1:sig:"+id)`; genesis `prev = "0"×64`;
  `body` must be an object with non-empty `kind` and `ts`. OPTIONAL_FIELDS are
  exactly `dialect`, `sigAlg`, `sigKeyFp` — anything else is `E_UNKNOWN_FIELD`.
- **canonicalJSON** — recursive key-sorted, no-whitespace serialization. The hash
  binds canonical form, so re-serialization/key-reordering/whitespace edits do
  not break verification; only value edits do.
- **Portable preimage** — `qmr1:<seq>:<prev>:<canonicalJSON(body)>` is identical
  across dialects (the domain tag names the preimage CONTRACT, not the hash),
  which is what makes re-hash upgrading a pure function.
- **Dialect registry** — `sha256-custody` (SHA-256, 64-hex ids, custody: yes) and
  `fnv1a-canary` (FNV-1a 64-bit, `"0x"+16hex` ids, custody: never). THE law:
  custody chains MUST be sha256-custody — enforced as
  `verify_chain({dialect_mode:"custody"})` failing `E_DIALECT_FORBIDDEN` at_seq.
- **v3 sig slot** — `sigAlg:"ed25519"` rows carry `sigKeyFp` =
  `sha256(createPublicKey(pem).export({type:'spki',format:'pem'}))` (normalized
  SPKI PEM, trailing newline included — the same fingerprint law as
  quilt-jev-toolkit organ v3). Verification requires a caller-provided
  `keyring {fingerprint → publicKeyPem}`; absent/unknown signer →
  `E_UNKNOWN_SIGNER`; mislabeled trust root → `E_BAD_KEYRING` before any row is
  read.
- **Versioned capability gates** — `QMR2 = --qmr2 || env QMR2=1`;
  `V3 = --v3 || env V3=1`. The row-level layers are ALWAYS active; only the
  tool LISTING is versioned, because the untouched v1 suite pins `tools/list` to
  exactly three tools. `tools/list`'s result always carries the additive
  `dialects` field (registry + law) in both modes.
- **Fail-closed named errors** — `E_STORE_CORRUPT`, `E_MISSING_FIELD`,
  `E_UNKNOWN_FIELD`, `E_BODY_INVALID`, `E_SEQ_MISMATCH` (covers replay),
  `E_PREV_MISMATCH`, `E_HASH_MISMATCH`, `E_BAD_SIGNATURE`, `E_DIALECT_FORBIDDEN`,
  `E_UNKNOWN_DIALECT`, `E_UNKNOWN_SIGNER`, `E_BAD_KEYRING`, `E_UNKNOWN_SIGALG`,
  `E_SIGNER_MALFORMED`, `E_BAD_ARGS`. Every refusal is grep-able and localized
  (`at_seq`, `detail`).

## How to extend

### Register a new hash dialect (qmr2)
One row in `DIALECTS` + one hash function — never touch the law:
```js
const DIALECTS = {
  // …existing…
  'blake3-experimental': {
    hash: 'blake3', custody: false,                     // custody requires sha256 by law
    note: 'example; registered ≠ endorsed',
    computeId: (preimage) => myBlake3Hex(preimage),
  },
};
```
Then: add row-shape handling if the id form is new (`isPrevForm` must recognize
it or chains cannot link onto it), add a pinned test vector to
`test/qmr2.test.mjs`, and document it in `docs/qmr2-design.md` §3. Verify in
default `"any"` mode still passes and custody mode still refuses it
(`E_DIALECT_FORBIDDEN`).

### Register a new signature scheme (v3 path)
Extend the sig-scheme checks in BOTH `verifyChain` and `validateAppend` (they
mirror each other deliberately — keep them in sync), extend `REGISTRY_INFO.sig_schemes`,
and add conformance cases in the `features.v3` block of `test/conformance.mjs`.
The invariant to preserve: rows without the new fields must remain byte-unchanged
qmr1 HMAC rows, and an unverifiable signer fails closed with a name.

### Add an MCP tool without breaking the pinned contract
The v1 suite pins the default `tools/list` to exactly three names. Follow the
qmr2 pattern: define the tool in a gated array, advertise it only under a new
flag/env, and keep the base listing untouched. If the tool changes the wire
contract, it needs its own spec section in `docs/` and its own gating, not an
edit to the default surface.

### Vendor the conformance harness into your repo
1. Copy `test/conformance.mjs` verbatim (dependency-free).
2. Write an adapter (~40 lines) exposing: `reset`, `makeReceipt(seq, prev, body,
   {secret, dialect, sigAlg, signer, signWith})`, `appendRaw(receipt,
   {keyring})`, `verify(opts)`, `readTip`, `rows`, `rewrite(rows)`, optional
   `listTools` and `errorMap`.
3. Declare `features: { dialects: true|false, v3: true|false }` — undeclared
   features attempt the full battery; declared-false features mark those cases
   SKIPPED, visibly, not failed.
4. Assert `verdict.ok === true`.
The harness never signs and never commits key material: it mints Ed25519
identities at runtime via `node:crypto`, and `signWith` exists precisely to
mint the impostor path (sig by a DIFFERENT private key than the claimed
fingerprint). `test/adapter-self.mjs` is the reference adapter.

### Change the qmr1 law (don't, but if you must)
Any change to the five fields, the preimage, or genesis breaks every existing
chain and every vendored harness. The upgrade path is a new dialect (hash slot)
or a new sig scheme (sig slot) with the portable preimage preserved — that is
the whole reason the preimage is dialect-independent.

## Testing
```bash
npm test        # 40/40: 15 v1 wire + 15 qmr2 (dialect layer, upgrade determinism,
                #   conformance self-application) + 7 v3 (sig slot, keyring,
                #   verify_attribution); the node runner counts 3 helper modules
                #   as pass-throughs, hence 40 lines in the summary
node examples/client-demo.mjs   # 12/12 checks, exit 0
node scripts/dogfood.mjs        # re-runs + re-receipts the dogfood set
```
Green means: every tamper case fails closed with the NAMED code at the NAMED
row (body flip → `E_HASH_MISMATCH` at_seq, sig flip → `E_BAD_SIGNATURE`,
deletion → `E_SEQ_MISMATCH`, replay, wrong-secret, unknown-dialect, custody-law,
determinism of `upgrade_chain`, v3 impostor/unknown-signer/forged cases), the
clean-chain positive control passes, and the v1 three-tool contract holds.
Verified 40/40 green on Node v24.21.0 during this documentation wave. The
wire-level suite spawns real server processes and speaks JSON-RPC over stdio;
its signer is re-derived from DESIGN.md §2 rather than imported — spec-verified,
not self-tautological.

## Conventions
- **Spec-first**: DESIGN.md (qmr1) and docs/qmr2-design.md (qmr2/v3) were
  written zero-shot before the code; new behavior gets a spec section first,
  with honest residuals stated in the doc, not discovered in review.
- **Never-delete-data, including shape**: the server appends only, writes what
  the client submitted (no field injection), rewrites nothing, and
  `--demo`/`upgrade_chain` never mutate an existing store.
- **Stdlib only**: the protocol surface (~120 lines) is deliberately owned, not
  delegated to an SDK. New dependencies need a receipt-grade justification.
- **Named errors everywhere**: new failure paths get `E_*` codes, localized
  detail, and a test; `E_BAD_ARGS` for malformed tool arguments.
- **Receipts for runs**: dogfood/dead-lane events land in `receipts/` as md +
  machine-checkable jsonl chains (re-derivable via this server itself).
- **Commit style**: single-purpose commits whose message carries the claim and
  the honest residual (see `git log` — each commit is a small receipt).

## Gotchas for editors
- **Do not un-pin the v1 tool contract.** `test/mcp.test.mjs` test #3 asserts
  `tools/list` returns EXACTLY the three tools. Gated layers are the only
  additive path.
- **Keep `verifyChain` and `validateAppend` law-identical.** They mirror each
  other on purpose (verify = full audit; append = same refusals at the door).
  A divergence between them is an acceptance hole.
- **Store IO is synchronous and re-read per call** — this is the freshness
  guarantee (answers describe the file as it is). Do not add a cache without
  revisiting DESIGN.md §3's "no cache" sentence and the tamper-detection story.
- **`resolveDialect(undefined) → sha256-custody` is the qmr1 compat rule**; a
  non-string `dialect` must fall to `E_UNKNOWN_DIALECT`. Preserve both edges.
- **`prev` linkage is string equality on the VERBATIM id** — after a canary row,
  `prev` literally contains `0x…`. Any "normalization" of ids breaks mixed chains.
- **The fingerprint law normalizes the SPKI PEM via createPublicKey round-trip**
  — hashing the raw incoming PEM instead would break equality with
  quilt-jev-toolkit identities.
- **Genesis prev is `"0"×64 across all dialects`** (qmr2-design §1) so the
  preimage shape never forks; do not specialize it per dialect.
- **`node --test test/` is broken on Node v24** (MODULE_NOT_FOUND); the package
  script's bare `node --test` is the working invocation — keep `npm test` as-is.
