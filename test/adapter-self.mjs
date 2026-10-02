// test/adapter-self.mjs — runConformance adapter that drives the REAL
// quilt-mcp-receipts server over stdio MCP. This is the harness's first
// customer: the harness verifies its own host, and the host can then receipt
// the harness run (see scripts/dogfood.mjs).
//
// Honesty note: the signer here is an INDEPENDENT re-derivation of the qmr1 +
// qmr2 dialect spec (DESIGN.md §2, docs/qmr2-design.md §2–3) — deliberately
// NOT imported from server.mjs — so conformance verifies the spec, not the
// implementation against itself.

import { createHash, createHmac } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { McpClient } from './mcp-client.mjs';

function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}
// FNV-1a 64 (docs/qmr2-design.md §3): basis 0xcbf29ce484222325, prime 0x100000001b3.
function fnv1a64(str) {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const mask = (1n << 64n) - 1n;
  for (const b of Buffer.from(str, 'utf8')) {
    h ^= BigInt(b);
    h = (h * prime) & mask;
  }
  return h.toString(16).padStart(16, '0');
}

export const SELF_SECRET = 'conformance-self-secret-67b';

export function makeServerAdapter({ qmr2 = true } = {}) {
  const client = new McpClient({ demo: false, qmr2, env: { MCP_RECEIPT_SECRET: SELF_SECRET } });
  let handshaken = false;

  async function ensureHandshake() {
    if (!handshaken) {
      await client.handshake();
      handshaken = true;
    }
  }

  function dialectId(dialectName, seq, prev, body) {
    // Portable preimage (§2) — identical string shape across dialects.
    const preimage = `qmr1:${seq}:${prev}:${canonicalJSON(body)}`;
    return dialectName === 'fnv1a-canary' ? '0x' + fnv1a64(preimage)
      : createHash('sha256').update(preimage).digest('hex');
  }

  const adapter = {
    name: `quilt-mcp-receipts server (stdio MCP, qmr2=${qmr2 ? 'on' : 'off'})`,
    features: { dialects: true },
    store: () => client.store, // where this adapter's chain lives (dogfood copies it out)

    async reset() {
      await ensureHandshake();
      if (fs.existsSync(client.store)) fs.rmSync(client.store);
      const up = path.join(path.dirname(client.store), 'upgrades');
      if (fs.existsSync(up)) fs.rmSync(up, { recursive: true, force: true });
    },

    makeReceipt(seq, prev, body, opts = {}) {
      const secret = opts.secret ?? SELF_SECRET;
      const dialectName = opts.dialect ?? 'sha256-custody';
      const id = dialectId(dialectName, seq, prev, body);
      const sig = createHmac('sha256', secret).update(`qmr1:sig:${id}`).digest('hex');
      const receipt = { seq, prev, body, id, sig };
      if (opts.dialect !== undefined) receipt.dialect = opts.dialect;
      return receipt;
    },

    async appendRaw(receipt) {
      await ensureHandshake();
      const res = await client.callTool('append_receipt', { receipt });
      return res.payload; // {ok:true,…} | {ok:false,error,…}
    },

    async verify(opts = {}) {
      await ensureHandshake();
      const args = opts.dialect_mode ? { dialect_mode: opts.dialect_mode } : {};
      const res = await client.callTool('verify_chain', args);
      return res.payload;
    },

    async readTip() {
      await ensureHandshake();
      // read_receipts reports the full store tip regardless of the window size
      const res = await client.callTool('read_receipts', { limit: 1 });
      if (!res.payload.ok) return null;
      return res.payload.tip ?? null;
    },

    async rows() {
      return client.lines().map((l) => JSON.parse(l));
    },

    async rewrite(rows) {
      client.writeLines(rows.map((r) => JSON.stringify(r)));
    },

    async stop() {
      await client.stop();
    },
  };
  return adapter;
}
