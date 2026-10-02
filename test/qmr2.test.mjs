// test/qmr2.test.mjs — the pluggable-hash dialect layer, the shared tamper-
// conformance harness applied to its own host, and upgrade-chain determinism.
// Spec: docs/qmr2-design.md. The v1 suite (test/mcp.test.mjs) stays untouched.
//
// Honesty note: the canary/custody signer below is an INDEPENDENT re-derivation
// from the design doc, not an import from server.mjs.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { runConformance } from './conformance.mjs';
import { makeServerAdapter, SELF_SECRET } from './adapter-self.mjs';
import { McpClient } from './mcp-client.mjs';

const GENESIS_PREV = '0'.repeat(64);
const CANARY_VECTOR = '24a555471370b18d'; // fnv1a64("café Δ 日本語") — the fleet's canary

function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}
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
function dialectId(dialectName, seq, prev, body) {
  const preimage = `qmr1:${seq}:${prev}:${canonicalJSON(body)}`;
  return dialectName === 'fnv1a-canary' ? '0x' + fnv1a64(preimage)
    : createHash('sha256').update(preimage).digest('hex');
}
function makeReceipt(seq, prev, body, { dialect, secret = SELF_SECRET } = {}) {
  const id = dialectId(dialect ?? 'sha256-custody', seq, prev, body);
  const receipt = { seq, prev, body, id, sig: createHmac('sha256', secret).update(`qmr1:sig:${id}`).digest('hex') };
  if (dialect !== undefined) receipt.dialect = dialect;
  return receipt;
}

const newClient = (opts) => new McpClient({ ...opts, env: { MCP_RECEIPT_SECRET: SELF_SECRET } });

const body = (note) => ({ kind: 'qmr2.test', ts: '2026-10-02T05:00:00Z', note });

// ---- A. canary vector (the census constant, pinned) -------------------------
test('fnv1a-64 vector: the fleet café canary re-derives to the 64-bit census value', () => {
  assert.equal(fnv1a64('café Δ 日本語'), CANARY_VECTOR);
});

// ---- B. versioned tool surface ----------------------------------------------
test('tools/list (v1 mode): exactly the three qmr1 tools, PLUS the additive dialects registry field', async () => {
  const c = newClient({});
  try {
    await c.handshake();
    const res = await c.request('tools/list', {});
    assert.deepEqual(res.tools.map((t) => t.name).sort(), ['append_receipt', 'read_receipts', 'verify_chain']);
    assert.equal(typeof res.dialects, 'object', 'tools/list result must carry the dialects registry');
    assert.deepEqual(res.dialects.dialects.map((d) => d.name).sort(), ['fnv1a-canary', 'sha256-custody']);
    assert.match(res.dialects.law, /E_DIALECT_FORBIDDEN/);
    assert.match(res.dialects.preimage, /qmr1:/);
  } finally {
    await c.stop();
  }
});

test('tools/list (--qmr2): gains dialects + upgrade_chain tools; dialects tool returns registry + law', async () => {
  const c = newClient({ qmr2: true });
  try {
    await c.handshake();
    const res = await c.request('tools/list', {});
    assert.deepEqual(res.tools.map((t) => t.name).sort(),
      ['append_receipt', 'dialects', 'read_receipts', 'upgrade_chain', 'verify_chain']);
    const d = await c.callTool('dialects', {});
    assert.equal(d.isError, false);
    assert.equal(d.payload.ok, true);
    assert.equal(d.payload.law.match(/E_DIALECT_FORBIDDEN/) !== null, true);
    const custody = d.payload.dialects.find((x) => x.name === 'sha256-custody');
    const canary = d.payload.dialects.find((x) => x.name === 'fnv1a-canary');
    assert.equal(custody.custody, true);
    assert.equal(canary.custody, false);
  } finally {
    await c.stop();
  }
});

test('tools/call (v1 mode): qmr2-only tools are unknown tools there (-32602)', async () => {
  const c = newClient({});
  try {
    await c.handshake();
    await assert.rejects(() => c.request('tools/call', { name: 'upgrade_chain', arguments: { from_seq: 1, to_seq: 1 } }),
      (e) => e.rpcError.code === -32602);
  } finally {
    await c.stop();
  }
});

// ---- C. canary chain + the custody law ---------------------------------------
test('fnv1a-canary chain: appends, verifies in any mode, and the canary vector lands server-side', async () => {
  const c = newClient({});
  try {
    await c.handshake();
    const b1 = body('canary genesis');
    const r1 = makeReceipt(1, GENESIS_PREV, b1, { dialect: 'fnv1a-canary' });
    assert.equal(r1.id, `0x${fnv1a64(`qmr1:1:${GENESIS_PREV}:${canonicalJSON(b1)}`)}`);
    const res1 = await c.callTool('append_receipt', { receipt: r1 });
    assert.equal(res1.isError, false, JSON.stringify(res1.payload));
    assert.equal(res1.payload.dialect, 'fnv1a-canary');
    // row 2 links to the canary id verbatim (prev carries the 0x… form)
    const b2 = body('canary second');
    const r2 = makeReceipt(2, r1.id, b2, { dialect: 'fnv1a-canary' });
    const res2 = await c.callTool('append_receipt', { receipt: r2 });
    assert.equal(res2.isError, false, JSON.stringify(res2.payload));
    const v = await c.callTool('verify_chain', {});
    assert.equal(v.payload.ok, true);
    assert.equal(v.payload.count, 2);
    // disk keeps the tag verbatim (never rewritten, never injected)
    const lines = c.lines();
    assert.match(lines[0], /"dialect":"fnv1a-canary"/);
  } finally {
    await c.stop();
  }
});

test('custody law: canary chain verify_chain({dialect_mode:"custody"}) → E_DIALECT_FORBIDDEN at first canary row', async () => {
  const c = newClient({});
  try {
    await c.handshake();
    await c.callTool('append_receipt', { receipt: makeReceipt(1, GENESIS_PREV, body('canary row'), { dialect: 'fnv1a-canary' }) });
    const v = await c.callTool('verify_chain', { dialect_mode: 'custody' });
    assert.equal(v.isError, true);
    assert.equal(v.payload.error, 'E_DIALECT_FORBIDDEN');
    assert.equal(v.payload.at_seq, 1);
    // ...while any-mode still verifies it honestly
    const vAny = await c.callTool('verify_chain', {});
    assert.equal(vAny.payload.ok, true);
  } finally {
    await c.stop();
  }
});

test('mixed chain: demo qmr1 store + one canary tail verifies in any mode; custody mode names the canary row', async () => {
  const c = newClient({ demo: true });
  try {
    await c.handshake();
    const before = await c.callTool('read_receipts', {});
    const r6 = makeReceipt(6, before.payload.tip, body('canary tail on a custody chain'), { dialect: 'fnv1a-canary' });
    const res = await c.callTool('append_receipt', { receipt: r6 });
    assert.equal(res.isError, false, JSON.stringify(res.payload));
    const vAny = await c.callTool('verify_chain', {});
    assert.equal(vAny.payload.ok, true);
    assert.equal(vAny.payload.count, 6);
    const vC = await c.callTool('verify_chain', { dialect_mode: 'custody' });
    assert.equal(vC.payload.error, 'E_DIALECT_FORBIDDEN');
    assert.equal(vC.payload.at_seq, 6);
  } finally {
    await c.stop();
  }
});

test('qmr1 rows default to sha256-custody on read: custody-mode verify of the demo store is ok, disk stays five-field', async () => {
  const c = newClient({ demo: true });
  try {
    await c.handshake();
    const v = await c.callTool('verify_chain', { dialect_mode: 'custody' });
    assert.equal(v.payload.ok, true);
    assert.equal(v.payload.count, 5);
    assert.equal(v.payload.dialect_mode, 'custody');
    // never-delete-data applies to shape: the server never injects a dialect tag
    for (const line of c.lines()) {
      const row = JSON.parse(line);
      assert.deepEqual(Object.keys(row).sort(), ['body', 'id', 'prev', 'seq', 'sig']);
    }
  } finally {
    await c.stop();
  }
});

// ---- D. unknown dialect ------------------------------------------------------
test('unknown dialect: append rejected E_UNKNOWN_DIALECT; behind-the-back rewrite caught E_UNKNOWN_DIALECT at_seq', async () => {
  const c = newClient({ demo: true });
  try {
    await c.handshake();
    const before = await c.callTool('read_receipts', {});
    const r = makeReceipt(6, before.payload.tip, body('valid receipt, bogus tag'));
    r.dialect = 'sha512-someday'; // id/sig still valid — the tag is not bound by the preimage
    const res = await c.callTool('append_receipt', { receipt: r });
    assert.equal(res.isError, true);
    assert.equal(res.payload.error, 'E_UNKNOWN_DIALECT');
    // tamper path: rewrite an existing row's tag behind the API
    const lines = c.lines();
    const row = JSON.parse(lines[2]);
    row.dialect = 'no-such-dialect';
    lines[2] = JSON.stringify(row);
    c.writeLines(lines);
    const v = await c.callTool('verify_chain', {});
    assert.equal(v.payload.ok, false);
    assert.equal(v.payload.error, 'E_UNKNOWN_DIALECT');
    assert.equal(v.payload.at_seq, 3);
  } finally {
    await c.stop();
  }
});

// ---- E. upgrade_chain ---------------------------------------------------------
function seedCanaryStore(c, n) {
  // sync-seed via the wire helper is async; this returns a promise chain instead
}
test('upgrade_chain: canary store → NEW custody receipt set; source untouched; upgraded set verifies in custody mode', async () => {
  const c = newClient({ qmr2: true });
  try {
    await c.handshake();
    for (const note of ['canary one', 'canary two', 'canary three']) {
      const all = await c.callTool('read_receipts', {});
      const seq = all.payload.count + 1;
      const prev = seq === 1 ? GENESIS_PREV : all.payload.tip;
      const res = await c.callTool('append_receipt', { receipt: makeReceipt(seq, prev, body(note), { dialect: 'fnv1a-canary' }) });
      assert.equal(res.isError, false, JSON.stringify(res.payload));
    }
    const storeBytesBefore = fs.readFileSync(c.store);
    const up = await c.callTool('upgrade_chain', { from_seq: 1, to_seq: 3 });
    assert.equal(up.isError, false, JSON.stringify(up.payload));
    assert.equal(up.payload.ok, true);
    assert.equal(up.payload.rows_upgraded, 3);
    assert.equal(up.payload.dialect_from === undefined, true); // not part of the tool result; lives in the manifest
    // source store byte-identical (never mutated)
    assert.deepEqual(fs.readFileSync(c.store), storeBytesBefore);
    // output exists, deterministic name, manifest carries the dialect mapping and no timestamps
    assert.equal(fs.existsSync(up.payload.out), true);
    const manifest = JSON.parse(fs.readFileSync(up.payload.manifest, 'utf8'));
    assert.deepEqual(manifest.dialect_from, ['fnv1a-canary']);
    assert.equal(manifest.dialect_to, 'sha256-custody');
    assert.equal(/T\d\d:/.test(JSON.stringify(manifest)), false, 'manifest must be timestamp-free (determinism)');
    // the upgraded set is a valid STANDALONE custody chain: verify it with a fresh server
    const c2 = newClient({ qmr2: true, store: up.payload.out });
    try {
      await c2.handshake();
      const v = await c2.callTool('verify_chain', { dialect_mode: 'custody' });
      assert.equal(v.payload.ok, true, JSON.stringify(v.payload));
      assert.equal(v.payload.count, 3);
      // bodies survived byte-identically (same canonical JSON, new hashes)
      const srcRows = c.lines().map((l) => JSON.parse(l));
      const upRows = fs.readFileSync(up.payload.out, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
      assert.deepEqual(upRows.map((r) => r.body), srcRows.map((r) => r.body));
      assert.deepEqual(upRows.map((r) => r.seq), [1, 2, 3]);
      for (const r of upRows) assert.equal(r.dialect, 'sha256-custody');
    } finally {
      await c2.stop();
    }
  } finally {
    await c.stop();
  }
});

test('upgrade_chain determinism: same store upgraded twice → byte-identical .jsonl AND manifest; two identical stores → byte-identical .jsonl', async () => {
  const mk = async () => {
    const c = newClient({ qmr2: true });
    await c.handshake();
    for (const note of ['det one', 'det two']) {
      const all = await c.callTool('read_receipts', {});
      const seq = all.payload.count + 1;
      const prev = seq === 1 ? GENESIS_PREV : all.payload.tip;
      await c.callTool('append_receipt', { receipt: makeReceipt(seq, prev, body(note), { dialect: 'fnv1a-canary' }) });
    }
    return c;
  };
  const c1 = await mk();
  const c2 = await mk();
  try {
    const u1 = await c1.callTool('upgrade_chain', { from_seq: 1, to_seq: 2 });
    const firstJsonl = fs.readFileSync(u1.payload.out);
    const firstManifest = fs.readFileSync(u1.payload.manifest);
    const u1b = await c1.callTool('upgrade_chain', { from_seq: 1, to_seq: 2 }); // re-run, same store
    assert.deepEqual(fs.readFileSync(u1b.payload.out), firstJsonl, 're-run must be byte-identical');
    assert.deepEqual(fs.readFileSync(u1b.payload.manifest), firstManifest);
    const u2 = await c2.callTool('upgrade_chain', { from_seq: 1, to_seq: 2 }); // independent identical store
    assert.deepEqual(fs.readFileSync(u2.payload.out), firstJsonl, 'independent identical stores must upgrade byte-identically');
  } finally {
    await c1.stop();
    await c2.stop();
  }
});

test('upgrade_chain refuses fail-closed: tampered source keeps its name (E_HASH_MISMATCH, at_seq) and writes nothing', async () => {
  const c = newClient({ demo: true, qmr2: true });
  try {
    await c.handshake();
    const lines = c.lines();
    const row = JSON.parse(lines[1]);
    row.body.claim = 'tampered upgrade attempt';
    lines[1] = JSON.stringify(row);
    c.writeLines(lines);
    const upDir = path.join(path.dirname(c.store), 'upgrades');
    const up = await c.callTool('upgrade_chain', { from_seq: 1, to_seq: 5 });
    assert.equal(up.isError, true);
    assert.equal(up.payload.ok, false);
    assert.equal(up.payload.error, 'E_HASH_MISMATCH');
    assert.equal(up.payload.at_seq, 2);
    assert.equal(fs.existsSync(upDir), false, 'no output may be written for a tampered source');
  } finally {
    await c.stop();
  }
});

test('upgrade_chain bad args: to_seq beyond chain length → E_BAD_ARGS', async () => {
  const c = newClient({ demo: true, qmr2: true });
  try {
    await c.handshake();
    const up = await c.callTool('upgrade_chain', { from_seq: 1, to_seq: 6 });
    assert.equal(up.isError, true);
    assert.equal(up.payload.error, 'E_BAD_ARGS');
  } finally {
    await c.stop();
  }
});

// ---- F. the harness's first customer: itself ---------------------------------
test('conformance self-application: runConformance(server adapter) — the harness verifies its own host, all cases green', async () => {
  const adapter = makeServerAdapter({ qmr2: true });
  try {
    const verdict = await runConformance(adapter);
    assert.equal(verdict.ok, true, JSON.stringify(verdict, null, 2));
    assert.deepEqual(verdict.skipped, []);
    const names = verdict.cases.map((x) => x.name).sort();
    assert.deepEqual(names, ['body-flip', 'clean-chain', 'custody-law', 'determinism', 'empty-body', 'replay', 'row-deletion', 'sig-flip', 'unknown-dialect', 'wrong-secret']);
  } finally {
    await adapter.stop();
  }
});

test('conformance adapter honors the dialect feature flag: dialects=false skips dialect cases, marks them visibly', async () => {
  const adapter = makeServerAdapter({ qmr2: false });
  adapter.features = { dialects: false };
  try {
    const verdict = await runConformance(adapter);
    assert.equal(verdict.ok, true, JSON.stringify(verdict, null, 2));
    assert.deepEqual(verdict.skipped, ['unknown-dialect', 'custody-law']);
    assert.equal(verdict.cases.length, 8);
  } finally {
    await adapter.stop();
  }
});
