// test/adapter-self.mjs — runConformance adapter that drives the REAL
// quilt-mcp-receipts server over stdio MCP. This is the harness's first
// customer: the harness verifies its own host, and the host can then receipt
// the harness run (see scripts/dogfood.mjs).
//
// Honesty note: the signer here is an INDEPENDENT re-derivation of the qmr1 +
// qmr2 dialect spec (DESIGN.md §2, docs/qmr2-design.md §2–3) — deliberately
// NOT imported from server.mjs — so conformance verifies the spec, not the
// implementation against itself.

import { createHash, createHmac, sign as cryptoSign } from 'node:crypto';
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

export function makeServerAdapter({ qmr2 = true, v3 = false } = {}) {
  const client = new McpClient({ demo: false, qmr2, v3, env: { MCP_RECEIPT_SECRET: SELF_SECRET } });
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
    name: `quilt-mcp-receipts server (stdio MCP, qmr2=${qmr2 ? 'on' : 'off'}, v3=${v3 ? 'on' : 'off'})`,
    features: { dialects: true, v3 },
    store: () => client.store, // where this adapter's chain lives (dogfood copies it out)

    async reset() {
      await ensureHandshake();
      if (fs.existsSync(client.store)) fs.rmSync(client.store);
      const up = path.join(path.dirname(client.store), 'upgrades');
      if (fs.existsSync(up)) fs.rmSync(up, { recursive: true, force: true });
    },

    makeReceipt(seq, prev, body, opts = {}) {
      const dialectName = opts.dialect ?? 'sha256-custody';
      const id = dialectId(dialectName, seq, prev, body);
      // v3 sig slot (docs/qmr2-design.md §8): sigAlg "ed25519" — sig =
      // Ed25519("qmr1:sig:"+id) under the signer's private key, the row NAMES
      // the signer by fingerprint. opts.signWith mints the sig with a DIFFERENT
      // private key than the claimed fingerprint — the impostor path the
      // harness's v3-wrong-key case must be able to express THROUGH this
      // signing law (a well-formed row that fails VERIFICATION, not construction).
      if (opts.sigAlg === 'ed25519') {
        const signer = opts.signer;
        if (!signer || !signer.privateKeyPem || !signer.fp) {
          throw new Error('adapter makeReceipt: sigAlg ed25519 needs opts.signer {privateKeyPem, fp}');
        }
        const signingKey = opts.signWith ?? signer.privateKeyPem;
        const sig = cryptoSign(null, Buffer.from(`qmr1:sig:${id}`, 'utf8'), signingKey).toString('hex');
        const receipt = { seq, prev, body, id, sig, sigAlg: 'ed25519', sigKeyFp: signer.fp };
        if (opts.dialect !== undefined) receipt.dialect = opts.dialect;
        return receipt;
      }
      const sig = createHmac('sha256', opts.secret ?? SELF_SECRET).update(`qmr1:sig:${id}`).digest('hex');
      const receipt = { seq, prev, body, id, sig };
      if (opts.dialect !== undefined) receipt.dialect = opts.dialect;
      return receipt;
    },

    async appendRaw(receipt, opts = {}) {
      await ensureHandshake();
      const args = { receipt };
      if (opts.keyring !== undefined) args.keyring = opts.keyring; // v3: prove the signer at the door
      const res = await client.callTool('append_receipt', args);
      return res.payload; // {ok:true,…} | {ok:false,error,…}
    },

    async verify(opts = {}) {
      await ensureHandshake();
      const args = {};
      if (opts.dialect_mode) args.dialect_mode = opts.dialect_mode;
      if (opts.keyring !== undefined) args.keyring = opts.keyring; // v3: the per-verify trust root
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

    // The versioned tool surface, as the host itself reports it (the harness's
    // v3-tool-gating case asserts verify_attribution is listed iff features.v3).
    async listTools() {
      await ensureHandshake();
      const res = await client.request('tools/list', {});
      return res.tools.map((t) => t.name);
    },

    async stop() {
      await client.stop();
    },
  };
  return adapter;
}
