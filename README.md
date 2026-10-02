# quilt-mcp-receipts

The fleet's receipt chain, exposed as a **signed append-only MCP organ**: any
agent — inside or outside the account — can **read**, **verify**, and **append**
fleet receipts through the Model Context Protocol, without cloning a repo and
without being trusted by anything.

Spike v1, dialect `qmr1`. Stdio JSON-RPC 2.0, **stdlib only, no SDK**.

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
hash link), `E_HASH_MISMATCH`, `E_BAD_SIGNATURE`.

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
npm test                        # 15/15 wire-level conformance tests
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
4. Fleet roll-out: `fleet-seeds` `wal-*` tools become the first real producer;
   `registry.jsonl` / `lessons.jsonl` rows gain `qmr1` mirrors.
