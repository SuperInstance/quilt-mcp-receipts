# qmr2 — the pluggable-hash receipt dialect + the shared tamper-conformance harness

Zero-shot design: written before any qmr2 code, self-contained, no open questions.
Additive to `qmr1` (DESIGN.md, spike v1) — nothing in qmr1 changes meaning; the
old test suite (`test/mcp.test.mjs`, 15 tests) must stay green **untouched**, and
that constraint is itself a design input (see §7).

Provenance: the wave-66 seed-dna census (quilt-atlas `6df5d1d`, §3.1/3.2) found
the receipt chain re-implemented 12+ times across the fleet in **two
contradicting hash dialects** — an fnv1a-64 "canary" class (fast, e.g. jev-quilt's
café canary `0x24a555471370b18d`) and a sha256 "custody" class (this organ's
qmr1, organ chains) — with the tamper/verify battery re-proven ~8×. Slackwater-quilt
explicitly refutes canary-class hashes for custody chains. The distill is this
document: **ONE receipt primitive with a pluggable hash + ONE shared
tamper-conformance harness.**

## 1. What changes and what does not

Unchanged from qmr1 (five fields, still the whole row):

```
{ "seq": n, "prev": "<link>", "body": {…}, "id": "<link hash>", "sig": "<hmac>" }
```

- Genesis: `seq = 1`, `prev = "0" × 64` — **across all dialects** (genesis prev is
  dialect-independent so the preimage shape never forks).
- Canonical JSON: recursive key-sorted, no-whitespace (identical to qmr1).
- Signature: `sig = HMAC-SHA256(secret, "qmr1:sig:" + id)` — the sig scheme is
  **not** pluggable in qmr2 (Ed25519 remains the v3 path, DESIGN.md §4). The id
  string that gets HMAC'd differs per dialect, so sigs differ naturally.
- `seq` chaining, `prev = prev-row.id`, fail-closed named errors, append-only
  store, never-delete-data: all unchanged.

New in qmr2:

1. **The dialect parameter.** A receipt row MAY carry a sixth field `dialect`
   (string). A row without `dialect` is a qmr1 row and reads as
   `sha256-custody`. On disk nothing is ever rewritten or injected: qmr1 rows
   stay five-field rows byte-for-byte; dialect-tagged rows keep the tag the
   client wrote (never-delete-data applies to *shape* too).
2. **The dialect registry** — pluggable hash, one law.
3. **Custody-mode enforcement** in `verify_chain` — the one rule, with a name.
4. **Re-hash upgrading** — a portable preimage makes canary → custody conversion
   a mechanical, receipted row-by-row re-hash.
5. **The shared tamper-conformance harness** (`test/conformance.mjs`) — the
   battery that retires the ~8 re-implementations.

## 2. The portable preimage (the whole trick)

Every dialect hashes the **same preimage string shape**:

```
preimage = "qmr1:" + seq + ":" + prev + ":" + canonicalJSON(body)
```

The domain tag stays `qmr1:` (it names the *preimage contract*, not the hash —
qmr1 compatibility demands byte-identical custody ids). `seq` is decimal,
`prev` is the previous row's id **verbatim as stored** (so after a canary row,
`prev` literally contains `0x…`), `body` is canonical JSON. Because the preimage
is dialect-independent, a row's identity under ANY registered hash is derivable
from the same three ingredients — which is exactly what makes re-hash upgrading
(§5) a pure function instead of a migration project.

## 3. The dialect registry

| name | hash | id encoding | custody | note |
|---|---|---|---|---|
| `sha256-custody` | SHA-256 | 64 lowercase hex | **yes** | qmr1-compatible; byte-identical ids to qmr1 |
| `fnv1a-canary` | FNV-1a 64-bit | `"0x"` + 16 lowercase hex | **no** | fast, collision-prone by design; for in-memory chains that will NEVER hold custody |

- FNV-1a 64: offset basis `0xcbf29ce484222325`, prime `0x100000001b3`, per-byte
  XOR-then-multiply over the preimage's UTF-8 bytes, mod 2^64 (BigInt).
  Pinned vector (the fleet's canary, verified by this spec):
  `fnv1a64("café Δ 日本語") = 24a555471370b18d` → id `"0x24a555471370b18d"`.
  (The wave-66 census recorded it as `0x024a555471370b18d` — 17 hex digits, a
  transcription artifact; the true 64-bit value is the 16-digit form. receipted
  here so the census erratum is on record.)
- **The law (the registry's single rule):** a chain asserted as a *custody
  chain* MUST be `sha256-custody`. Enforcement point: `verify_chain` called
  with `dialect_mode: "custody"`. A `fnv1a-canary` row encountered in custody
  mode fails with `E_DIALECT_FORBIDDEN`, localized `at_seq`.
- `verify_chain({})` (no mode) defaults to `"any"`: every row is verified under
  its own dialect, mixed-dialect chains verify if internally consistent. This
  preserves qmr1 behavior byte-for-byte (qmr1 stores have no `dialect` fields
  and read as all-custody anyway).
- Unknown dialect name (in a row's `dialect` field, on append or verify):
  `E_UNKNOWN_DIALECT`. A non-string `dialect` field is also
  `E_UNKNOWN_DIALECT` (it is not the name of a known dialect).
- Why is append dialect-neutral (no custody gate at append time)? Because the
  server cannot know which chains will later be *claimed* as custody; the named
  mode assertion at verify is the instrument. A canary row is legal in a store;
  calling that store a custody chain is what has a name and fails closed.

Row-level shape rules per dialect (verify + append, identical logic):

| check | sha256-custody | fnv1a-canary |
|---|---|---|
| `id` shape | 64 hex | `^0x[0-9a-f]{16}$` |
| `prev` shape | genesis (`"0"×64`) or the previous row's id **verbatim** — either dialect's form (mixed chains are legal in `"any"` mode: a canary tail may link onto a custody row and vice versa; linkage is string equality) | same |
| `sig` shape | 64 hex (HMAC over `qmr1:sig:`+id) | 64 hex (HMAC over `qmr1:sig:`+id — sig scheme is shared) |
| id recomputation | `sha256(preimage)` hex | `"0x" + fnv1a64(preimage)` |

## 4. Tool surface — versioned, additive

Constraint honored as a feature: the untouched v1 suite pins `tools/list` to
exactly `append_receipt`, `read_receipts`, `verify_chain` (test #3: "exactly the
three receipt-organ tools"). Therefore:

- **Always on (row-level layer, invisible to v1 clients):** `dialect` field
  accepted on append; dialect-aware verify; `verify_chain` gains optional
  `dialect_mode` (`"any"` default | `"custody"`); `tools/list`'s **result**
  gains an additive `dialects` field carrying the registry + the law (v1
  clients read `tools`; qmr2 clients read `dialects` — wire-discoverable in
  both modes without breaking the pinned name set).
- **`--qmr2` flag (or env `QMR2=1`) — the v2 tool layer**, adds two tools to
  `tools/list`:
  - `dialects` — returns the registry + the law (MCP-callable form of the
    `tools/list` field; for hosts that prefer a tool call).
  - `upgrade_chain({from_seq, to_seq})` — see §5.

Server version: `0.1.0 → 0.2.0`. Error vocabulary gains exactly two names:
`E_DIALECT_FORBIDDEN`, `E_UNKNOWN_DIALECT`. No existing error changes meaning.

## 5. `upgrade_chain(from_seq, to_seq)` — re-hash upgrading, receipted

Canary chains are fast and forgettable; custody chains are forever. When an
in-memory canary chain turns out to matter, it is **re-hashed-upgraded** —
never re-run, never re-typed:

1. Refuse fail-closed if the source store does not fully verify (any mode) —
   an upgrade launders nothing; tamper keeps its name and `at_seq`.
2. Read rows `[from_seq, to_seq]`; copy each `body` **byte-identically**
   (canonical JSON identical — the body is the evidence, it is not touched).
3. Re-issue as a NEW standalone custody chain: seqs renumbered `1..n`,
   genesis-rooted, ids recomputed under `sha256-custody`, sigs re-HMAC'd,
   `dialect: "sha256-custody"` written explicitly (these are qmr2-minted rows).
   Renumbering is inherent: the preimage binds `seq` and the new chain is a new
   total order rooted at genesis — the upgrade proves the *bodies* survived,
   under a hash that can hold custody.
4. Write `upgrades/upgrade-<from>-<to>-<sourceSha8>.jsonl` (the receipt set) +
   `<name>.manifest.json` (source sha256, source tip, upgraded tip, counts,
   dialect mapping). The filename embeds the source file's sha256 prefix, and
   the manifest carries **no timestamps** — so the same source always produces
   the same bytes at the same path: **upgrade twice → byte-identical** is a
   test, not a hope.
5. The original store is never mutated (append-only is also never-rewrite).

Determinism note: outputs depend only on (store bytes, secret, from, to). Two
independently-seeded identical stores upgrade to byte-identical receipt sets.

## 6. The shared tamper-conformance harness

`test/conformance.mjs` exports `runConformance(adapter)` — zero dependencies,
importable (or vendored verbatim) by ANY fleet repo. It proves the named
fail-closed law against a ~40-line adapter, so every repo stops re-proving it
by hand (the ~8× census item retires here).

Adapter contract (all functions, no magic):

```js
{
  name,                                   // display name for the report
  reset(),                                // fresh empty chain
  makeReceipt(seq, prev, body, opts={}),  // → full receipt; opts: {secret?, dialect?}
                                          //   (secret omitted = host default key)
  appendRaw(receipt),                     // submit a fully-formed receipt → {ok}|{ok:false,error,at_seq?,detail?}
  verify(opts={}),                        // full audit; opts: {dialect_mode?} → {ok}|{ok:false,error,at_seq?,detail?}
  readTip(),                              // → tip id | null
  rows(),                                 // → array of raw rows (persistence-level read)
  rewrite(rows),                          // persistence-level rewrite (tamper happens behind the API's back)
  errorMap?: { legacyName: canonicalName } // optional: adapters over legacy front-ends
}
```

Battery (each case asserts a **named** error and, where meaningful, `at_seq`):

| case | op | expected law |
|---|---|---|
| clean-chain | honest appends, verify | positive control: ok with a non-null tip |
| body-flip | flip a body value behind the API, verify | `E_HASH_MISMATCH` localized `at_seq` |
| sig-flip | flip one sig char, verify | `E_BAD_SIGNATURE` |
| row-deletion | delete one row, verify | `E_SEQ_MISMATCH` at the hole |
| replay | append a valid old receipt again | `E_SEQ_MISMATCH` |
| wrong-secret | receipt signed under a different secret | `E_BAD_SIGNATURE` |
| unknown-dialect | valid receipt tagged `dialect: "no-such-dialect"` | `E_UNKNOWN_DIALECT` |
| empty-body | body without `kind` / empty `kind` | `E_BODY_INVALID` |
| custody-law | canary chain, `verify({dialect_mode:"custody"})` | `E_DIALECT_FORBIDDEN` |
| determinism | same op sequence on two fresh chains | identical tips |

`runConformance(adapter)` → `{ok, adapter, cases: [{name, ok, got?, want?, detail?}]}`.
Deterministic: no clock, no randomness. First customer: this server itself
(`test/adapter-self.mjs` drives the real MCP server over stdio — the harness
verifies the organ, the organ receipts the harness).

## 7. Explicit non-goals (no overreach)

No Ed25519 (v3), no per-dialect sig schemes (one sig scheme in qmr2 — the
pluggable surface is the HASH, and only the hash), no third dialect (registry
grows by adding one table row + one hash function, not by touching the law), no
mixed-chain prohibition in default mode (custody assertions are opt-in and
named), no migration of qmr1 stores (qmr1 rows ARE custody rows by default),
no HTTP transport, no anchoring. Each stays a later-lane item.
