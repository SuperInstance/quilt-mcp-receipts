# DESIGN — quilt-mcp-receipts (spike v1, dialect `qmr1`)

Zero-shot design: written before any code, self-contained, no open questions.
Spike scope = minimal but honest. Every simplification is stated, not hidden.

## 1. What the organ is

A **receipt chain** is an append-only JSONL file of hash-chained, signed receipts —
the fleet's seal discipline expressed as a single file that any process can hold.

The fleet already runs this culture by hand:

- `fleet-seeds/lode/registry.jsonl` — 16 rows, one per sealed prediction set
  (JEPA-R4 … JEPA-R10, …), each row carrying `set_id / repo / commit / verdict /
  registration_ref / ts`.
- `fleet-seeds/lode/lessons.jsonl` — 16 rows, one per minted law (L1…L16), each
  carrying `id / claim / evidence / status`.

These are **live examples of the append-only ledger shape** — and, honestly stated,
they are *not yet hash-chained*: a rewritten line in `registry.jsonl` is detectable
only by humans comparing receipts. The delta this organ adds is exactly that
missing instrument: **prev-hash linkage + signature on every line, re-derivable by
anyone, readable and appendable over the Model Context Protocol.**

So the organ is: *the fleet's receipt memory, exposed as a signed append-only MCP
server.* Read = memory recall. Append = memory commit. Verify = self-audit.
Any agent in the 5,108-repo namespace (or outside it) can now read the chain,
verify its integrity end-to-end, and append a new receipt under the same seal
discipline — without cloning anything or being trusted by anything.

## 2. The receipt dialect `qmr1`

Store = one JSONL file (`store.jsonl`), one receipt per line, append-only
(creation allowed, mutation and deletion are not operations the server performs —
and `verify_chain()` detects them when done behind its back).

A receipt line is exactly five fields (no extras, no fewer):

```json
{
  "seq":  6,
  "prev": "3f2a…64-hex",
  "body": { "kind": "engine.run.sealed", "ts": "2026-10-02T03:00:00Z", "…": "…" },
  "id":   "9c1b…64-hex",
  "sig":  "5d0e…64-hex"
}
```

Definitions (the complete spec — the test suite re-derives these independently
from this section, not from the server's code):

- `GENESIS_PREV` = `"0" × 64`. First receipt has `seq = 1`, `prev = GENESIS_PREV`.
- **Canonical JSON**: recursive key-sorted, no-whitespace `JSON` serialization
  (arrays keep order; object keys sorted lexicographically at every depth).
- **Receipt id** (the chain link):
  `id = SHA-256( "qmr1:" + seq + ":" + prev + ":" + canonicalJSON(body) )`
- **Signature** (spike scheme):
  `sig = HMAC-SHA256( secret, "qmr1:sig:" + id )`
  where `secret` = env `MCP_RECEIPT_SECRET` (dev fallback documented in README;
  the server warns loudly on stderr when the fallback is in use).
- `seq` must equal `prev-row.seq + 1`; `prev` must equal `prev-row.id`.

Everything hash-relevant lives inside the id: the body is bound by canonical
form (not by byte layout), so re-serialization, key reordering, and whitespace
edits do **not** break verification — only value edits do. The chain is
`row₁ ← row₂ ← … ← tip`; `verify_chain()` re-derives every id from genesis.

## 3. MCP tool surface (exactly three tools, spike scope)

Transport: stdio, newline-delimited JSON-RPC 2.0 (the MCP stdio shape).
Handshake: `initialize` → capabilities `{tools:{}}` + `serverInfo{name:"quilt-mcp-receipts",version:"0.1.0"}`; then `notifications/initialized`. Also answered: `ping`, `tools/list`, `tools/call`. Unknown method → `-32601`; unparseable line → `-32700`; malformed params → `-32602`.

### `read_receipts({since_seq=0, limit=100})` → recall
Returns `{ok:true, count, tip, receipts:[…]}` where receipts have `seq > since_seq`,
capped at `limit` (1–1000). Reads re-parse the store from disk each call (no cache):
the answer always describes the file as it is, not as it was at boot.
If the store contains unparseable lines they are *never silently skipped*:
the response carries `corrupted_lines:[n…]` — recall stays honest about its own substrate.

### `verify_chain()` → self-audit
Re-derives the full chain from genesis on disk, row by row, checking in order:
structure (five fields, no extras) → `seq` → `prev` linkage → `id` recomputation
→ `sig` recomputation.
Returns `{ok:true, count, tip, dialect:"qmr1"}` — or fail-closed on the **first**
broken row: `{ok:false, error:<CODE>, at_seq:n, detail:…, count_checked:n}`.

Named error codes (stable, grep-able, the whole point of fail-closed):

| code | meaning |
|---|---|
| `E_STORE_CORRUPT` | a line in the store is not valid JSON (named line numbers) |
| `E_MISSING_FIELD` | receipt is missing one of the five required fields (named) |
| `E_UNKNOWN_FIELD` | receipt carries a field outside the five (strictness on purpose) |
| `E_BODY_INVALID` | `body` not an object, or `body.kind`/`body.ts` missing/empty |
| `E_SEQ_MISMATCH` | `seq` ≠ expected next sequence (covers replay of an old receipt) |
| `E_PREV_MISMATCH` | `prev` ≠ current tip id — the broken-hash-link case |
| `E_HASH_MISMATCH` | recomputed `id` ≠ stored `id` (body/seq/prev were altered) |
| `E_BAD_SIGNATURE` | HMAC over `id` does not verify (altered id, or wrong secret) |

### `append_receipt({receipt})` → commit (fail-closed)
The client **constructs and signs** the full five-field receipt and submits it.
The server validates, in order: structure → `body` shape → `seq` (must be
tip+1) → `prev` (must equal tip id) → `id` (recomputed) → `sig` (HMAC over id).
First failure wins, returned as a tool error result (`isError:true`) carrying the
named code. No failure → the line is appended to disk (`fs.appendFileSync`) and
the server returns `{ok:true, seq, id, tip}` — tip is the new tip.

There is deliberately no "draft" tool, no `sign_receipt` helper tool: the signing
key material must not flow through the wire, and the server must stay a
verifier, not a co-signer. (Client-side reference signer: `examples/client-demo.mjs`.)

## 4. Signing scheme — spike vs v2

**Spike (v1): HMAC-SHA256 with a server-side-configured shared secret.**
- Pros: stdlib-only, 3 lines of code, trivially fast, symmetric so any writer
  with the secret can produce verifiable receipts.
- Cons (stated): the secret is shared by *all* writers, so attribution is
  fleet-trust, not identity; any client that can append already holds signing
  power; the server config is the secret's single point of custody.

**v2 path: Ed25519 per-agent keypairs.** Each agent signs with its private key;
the chain (or a header row) pins a set of trusted public keys; verification
becomes offline and attribution becomes per-agent non-repudiation. `qmr1` was
designed so this is an additive change: swap `sig` for a key-id + signature
envelope (`qmr2` dialect) without touching the id formula.

## 5. Threat model (what a malicious client can / cannot do)

Can:

- **Read everything.** The spike has no ACL; receipts are public-by-design, like
  the lode files. If a receipt must be secret, it must not be in the chain
  (put a hash of it in the body and keep the payload elsewhere).
- **Attempt arbitrary appends** — garbage, malformed, replayed, forged. All are
  rejected with a named code; nothing invalid is ever written.
- **Deny service by connection volume** — accepted residual risk of the spike
  (single process, no rate limiting). v2 HTTP transport puts a queue/WAF in front.

Cannot (through the organ):

- **Rewrite or erase history.** There is no update/delete verb; the server only
  appends; and `verify_chain()` re-derives from genesis, so any behind-the-back
  file edit (one flipped value, one removed row, one reordered pair) is caught
  and localized at `at_seq` with a named code.
- **Forge a receipt** without the secret: body edits break `E_HASH_MISMATCH`
  (the id binds `seq:prev:body`), id edits break `E_BAD_SIGNATURE` (HMAC over id),
  prev edits break `E_PREV_MISMATCH`, replay breaks `E_SEQ_MISMATCH`.
- **Fork the chain silently** — any fork must reuse a `seq`, which is rejected;
  a fork built off-chain is a different file whose tip differs, detectable by
  comparing tips.
- **Smuggle structure** — unknown fields are rejected (`E_UNKNOWN_FIELD`), so no
  client can add semantics the verifier does not check.

Cannot (yet) — honest residuals:

- **Stop a local-storage attacker who truncates the file** (append-only is a
  convention until v2 anchors the tip externally — e.g. periodic tip commit into
  a git ref or the organ-workers KV store; then truncation is a detectable
  count/tip regression against the anchor).
- **Attribute a receipt to an agent** under HMAC (see §4).

## 6. How this becomes the memory organ for cross-agent fleets

- **Recall**: any agent asks `read_receipts(since_seq=my_last_seq)` to catch up
  on fleet state since it last looked — the chain is a total order of what
  happened, so "catch up" is one call with a cursor, not a diff of file trees.
- **Commit**: an agent finishing a run appends one receipt (`kind:"engine.run.sealed"`,
  refs to its registration + verdict commits); the fleet-wide seal discipline
  becomes a wire call instead of a repo edit.
- **Self-audit**: `verify_chain()` is the fleet's standing instrument against the
  BOARD's seven-lane finding — *a well-formed, checkable, wrong artifact* — because
  wrongness here has a named name and a row number.
- **Hosting**: v1 is stdio (local agents, CI). v2 = HTTP transport on a Cloudflare
  Worker (reference `quilt-organ-workers`: the KV-backed organ store + watcher
  already exist there; this organ's store/verify/append verbs map 1:1 onto
  loader `PUT/GET/verify` routes) and/or hosted inside the existing
  superinstance-api MCP surface (commit `5ded07cd` added the intents MCP tool —
  the receipt tools join that same server).
- **Cross-fleet**: the dialect is one file + two formulas; an outside account can
  run the same server over its own store and interoperate at the receipt level
  (same `qmr1` ids), which is the point of MCP-izing it rather than shelving it
  in a repo.

## 7. Explicit v1 non-goals (no overreach)

No HTTP transport, no ACL/authz, no Ed25519, no tip anchoring, no compaction or
snapshotting, no multi-store, no subscriptions (`tools/list_changed` is declared
false), no SDK dependency (stdlib only — the protocol surface is ~120 lines and
worth owning), no remote stores. Each is a v2 item, not an oversight.
