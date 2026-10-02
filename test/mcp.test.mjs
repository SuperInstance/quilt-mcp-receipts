// test/mcp.test.mjs — wire-level conformance for quilt-mcp-receipts (spike v1).
// Every test spawns a real server process and speaks newline-delimited JSON-RPC
// 2.0 over stdio, exactly as an MCP client would.
//
// Honesty note: the signer/hash helpers below are an INDEPENDENT re-derivation
// of the qmr1 dialect from DESIGN.md §2 — deliberately NOT imported from
// server.mjs — so the tests verify the spec, not the implementation against itself.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SERVER = fileURLToPath(new URL('../server.mjs', import.meta.url));
const SECRET = 'test-only-secret-65a-independent-of-server';
const GENESIS_PREV = '0'.repeat(64);

// ---- independent qmr1 signer (per DESIGN.md §2) ----------------------------
function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}
function qmrId(seq, prev, body) {
  return createHash('sha256').update(`qmr1:${seq}:${prev}:${canonicalJSON(body)}`).digest('hex');
}
function qmrSig(id) {
  return createHmac('sha256', SECRET).update(`qmr1:sig:${id}`).digest('hex');
}
function makeReceipt(seq, prev, body) {
  const id = qmrId(seq, prev, body);
  return { seq, prev, body, id, sig: qmrSig(id) };
}

// ---- minimal MCP stdio client ---------------------------------------------
class McpClient {
  constructor({ demo = true } = {}) {
    this.dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qmr-test-'));
    this.store = path.join(this.dir, 'store.jsonl');
    this.argv = [SERVER, '--store', this.store, '--quiet-notice'];
    if (demo) this.argv.push('--demo');
    this.nextId = 1;
    this.pending = new Map();
    this.buffer = '';
    this.stderr = [];
    this.child = spawn(process.execPath, this.argv, {
      env: { ...process.env, MCP_RECEIPT_SECRET: SECRET },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.child.stdout.setEncoding('utf8');
    this.child.stdout.on('data', (c) => this.#onData(c));
    this.child.stderr.setEncoding('utf8');
    this.child.stderr.on('data', (c) => this.stderr.push(c));
  }
  #onData(chunk) {
    this.buffer += chunk;
    let idx;
    while ((idx = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, idx).trim();
      this.buffer = this.buffer.slice(idx + 1);
      if (!line) continue;
      const msg = JSON.parse(line);
      const p = this.pending.get(msg.id);
      if (p) {
        this.pending.delete(msg.id);
        if (msg.error) p.reject(Object.assign(new Error(`${msg.error.message} (code ${msg.error.code})`), { rpcError: msg.error }));
        else p.resolve(msg.result);
      }
    }
  }
  request(method, params, timeoutMs = 8000) {
    const id = this.nextId++;
    const payload = { jsonrpc: '2.0', id, method, params };
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timeout waiting for ${method} (stderr: ${this.stderr.join('')})`));
      }, timeoutMs);
      this.pending.set(id, { resolve: (v) => { clearTimeout(timer); resolve(v); }, reject: (e) => { clearTimeout(timer); reject(e); } });
      this.child.stdin.write(JSON.stringify(payload) + '\n');
    });
  }
  notify(method, params) {
    this.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  }
  async callTool(name, args) {
    const res = await this.request('tools/call', { name, arguments: args ?? {} });
    assert.equal(Array.isArray(res.content), true, 'tool result must have content array');
    assert.equal(res.content[0].type, 'text');
    return { isError: res.isError === true, payload: JSON.parse(res.content[0].text) };
  }
  lines() {
    const text = fs.readFileSync(this.store, 'utf8');
    return text.split('\n').filter((l) => l.trim().length > 0);
  }
  stop() {
    return new Promise((resolve) => {
      this.child.stdin.end();
      this.child.kill('SIGTERM');
      this.child.on('exit', () => resolve());
      setTimeout(() => { try { this.child.kill('SIGKILL'); } catch {} resolve(); }, 1500);
    });
  }
}

async function handshake(client) {
  const init = await client.request('initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'mcp-test-harness', version: '0.0.0' },
  });
  client.notify('notifications/initialized', {});
  return init;
}

// ---- 1. handshake ----------------------------------------------------------
test('handshake: initialize echoes protocol version, advertises tools, accepts notifications/initialized', async () => {
  const c = new McpClient();
  try {
    const init = await handshake(c);
    assert.equal(init.protocolVersion, '2024-11-05');
    assert.equal(init.serverInfo.name, 'quilt-mcp-receipts');
    assert.equal(typeof init.serverInfo.version, 'string');
    assert.deepEqual(init.capabilities.tools, { listChanged: false });
    // the server must keep serving after the initialized notification
    const tools = await c.request('tools/list', {});
    assert.equal(Array.isArray(tools.tools), true);
  } finally {
    await c.stop();
  }
});

test('handshake: unknown requested protocol version falls back to 2024-11-05', async () => {
  const c = new McpClient();
  try {
    const init = await c.request('initialize', { protocolVersion: '1999-01-01', capabilities: {} });
    assert.equal(init.protocolVersion, '2024-11-05');
  } finally {
    await c.stop();
  }
});

// ---- 2. tools/list ---------------------------------------------------------
test('tools/list: exactly the three receipt-organ tools with input schemas', async () => {
  const c = new McpClient();
  try {
    await handshake(c);
    const { tools } = await c.request('tools/list', {});
    assert.deepEqual(tools.map((t) => t.name).sort(), ['append_receipt', 'read_receipts', 'verify_chain']);
    for (const t of tools) {
      assert.equal(typeof t.description, 'string');
      assert.equal(t.inputSchema.type, 'object');
    }
  } finally {
    await c.stop();
  }
});

// ---- 3. read_receipts ------------------------------------------------------
test('read_receipts: demo store returns 5 seeded receipts; since_seq and limit honor the cursor', async () => {
  const c = new McpClient();
  try {
    await handshake(c);
    const all = await c.callTool('read_receipts', {});
    assert.equal(all.isError, false);
    assert.equal(all.payload.ok, true);
    assert.equal(all.payload.count, 5);
    assert.equal(all.payload.receipts[0].seq, 1);
    assert.equal(all.payload.receipts[4].seq, 5);
    assert.equal(all.payload.receipts[0].prev, GENESIS_PREV);
    // cursor: exclusive since_seq
    const tail = await c.callTool('read_receipts', { since_seq: 3 });
    assert.equal(tail.payload.count, 2);
    assert.deepEqual(tail.payload.receipts.map((r) => r.seq), [4, 5]);
    // limit caps the window
    const head = await c.callTool('read_receipts', { since_seq: 0, limit: 2 });
    assert.equal(head.payload.count, 2);
    assert.deepEqual(head.payload.receipts.map((r) => r.seq), [1, 2]);
  } finally {
    await c.stop();
  }
});

// ---- 4. verify_chain ok ----------------------------------------------------
test('verify_chain: seeded demo chain re-derives clean from genesis (ok, count, tip)', async () => {
  const c = new McpClient();
  try {
    await handshake(c);
    const all = await c.callTool('read_receipts', {});
    const v = await c.callTool('verify_chain', {});
    assert.equal(v.isError, false);
    assert.equal(v.payload.ok, true);
    assert.equal(v.payload.dialect, 'qmr1');
    assert.equal(v.payload.count, 5);
    assert.equal(v.payload.tip, all.payload.tip);
    assert.equal(v.payload.tip, all.payload.receipts[4].id);
  } finally {
    await c.stop();
  }
});

// ---- 5. verify after tamper (fail-closed, named) ---------------------------
test('verify_chain after body tamper: fail-closed E_HASH_MISMATCH localized at at_seq', async () => {
  const c = new McpClient();
  try {
    await handshake(c);
    const v0 = await c.callTool('verify_chain', {});
    assert.equal(v0.payload.ok, true);
    // flip one body VALUE on row 3 (keep it valid JSON — hash is over canonical form)
    const lines = c.lines();
    const row = JSON.parse(lines[2]);
    row.body.claim = 'tampered by the test, not by fate';
    lines[2] = JSON.stringify(row);
    fs.writeFileSync(c.store, lines.join('\n') + '\n');
    const v = await c.callTool('verify_chain', {});
    assert.equal(v.isError, true);
    assert.equal(v.payload.ok, false);
    assert.equal(v.payload.error, 'E_HASH_MISMATCH');
    assert.equal(v.payload.at_seq, 3);
  } finally {
    await c.stop();
  }
});

test('verify_chain after signature tamper: fail-closed E_BAD_SIGNATURE', async () => {
  const c = new McpClient();
  try {
    await handshake(c);
    const lines = c.lines();
    const row = JSON.parse(lines[1]);
    row.sig = (row.sig[0] === 'f' ? 'a' : 'f') + row.sig.slice(1);
    lines[1] = JSON.stringify(row);
    fs.writeFileSync(c.store, lines.join('\n') + '\n');
    const v = await c.callTool('verify_chain', {});
    assert.equal(v.payload.ok, false);
    assert.equal(v.payload.error, 'E_BAD_SIGNATURE');
    assert.equal(v.payload.at_seq, 2);
  } finally {
    await c.stop();
  }
});

test('verify_chain after row deletion: fail-closed (removed row cannot be silently skipped)', async () => {
  const c = new McpClient();
  try {
    await handshake(c);
    const lines = c.lines();
    lines.splice(2, 1); // delete row 3 entirely
    fs.writeFileSync(c.store, lines.join('\n') + '\n');
    const v = await c.callTool('verify_chain', {});
    assert.equal(v.payload.ok, false);
    // row 4 now sits where seq 3 is expected → sequence mismatch names the hole
    assert.equal(v.payload.error, 'E_SEQ_MISMATCH');
    assert.equal(v.payload.at_seq, 3);
  } finally {
    await c.stop();
  }
});

// ---- 6. append valid -------------------------------------------------------
test('append_receipt valid: accepted, tip advances, verify stays ok, read sees 6', async () => {
  const c = new McpClient();
  try {
    await handshake(c);
    const before = await c.callTool('read_receipts', {});
    const tip = before.payload.tip;
    const body = { kind: 'engine.run.sealed', ts: '2026-10-02T04:00:00Z', actor: 'test-suite', claim: 'append via independent signer', refs: ['test/mcp.test.mjs'] };
    const receipt = makeReceipt(6, tip, body);
    const res = await c.callTool('append_receipt', { receipt });
    assert.equal(res.isError, false);
    assert.equal(res.payload.ok, true);
    assert.equal(res.payload.seq, 6);
    assert.equal(res.payload.tip, receipt.id);
    // the chain re-verifies with the new row included
    const v = await c.callTool('verify_chain', {});
    assert.equal(v.payload.ok, true);
    assert.equal(v.payload.count, 6);
    assert.equal(v.payload.tip, receipt.id);
    const after = await c.callTool('read_receipts', { since_seq: 5 });
    assert.equal(after.payload.count, 1);
    assert.deepEqual(after.payload.receipts[0].body, body);
  } finally {
    await c.stop();
  }
});

test('append_receipt valid on empty store: genesis row (seq 1, prev zeros) is accepted', async () => {
  const c = new McpClient({ demo: false });
  try {
    await handshake(c);
    const body = { kind: 'receipt.chain.genesis', ts: '2026-10-02T04:00:00Z', note: 'fresh store' };
    const receipt = makeReceipt(1, GENESIS_PREV, body);
    const res = await c.callTool('append_receipt', { receipt });
    assert.equal(res.payload.ok, true);
    const v = await c.callTool('verify_chain', {});
    assert.equal(v.payload.ok, true);
    assert.equal(v.payload.count, 1);
    assert.equal(v.payload.tip, receipt.id);
  } finally {
    await c.stop();
  }
});

// ---- 7. append with broken prev-hash --------------------------------------
test('append_receipt with broken prev-hash: rejected E_PREV_MISMATCH, store untouched', async () => {
  const c = new McpClient();
  try {
    await handshake(c);
    const before = await c.callTool('read_receipts', {});
    const tip = before.payload.tip;
    const body = { kind: 'attack.simulation', ts: '2026-10-02T04:00:00Z', note: 'wrong prev link' };
    const forgedPrev = 'f'.repeat(64);
    const receipt = makeReceipt(6, forgedPrev, body); // valid id+sig over the WRONG prev
    // make id/sig internally consistent with forgedPrev so the failure is purely linkage
    const res = await c.callTool('append_receipt', { receipt });
    assert.equal(res.isError, true);
    assert.equal(res.payload.ok, false);
    assert.equal(res.payload.error, 'E_PREV_MISMATCH');
    assert.match(res.payload.detail, /expected prev/);
    // fail-closed means nothing was written
    const after = await c.callTool('read_receipts', {});
    assert.equal(after.payload.count, 5);
    assert.equal(after.payload.tip, tip);
    const v = await c.callTool('verify_chain', {});
    assert.equal(v.payload.ok, true);
  } finally {
    await c.stop();
  }
});

// ---- 8. replay / seq mismatch ---------------------------------------------
test('append_receipt replaying an old receipt: rejected E_SEQ_MISMATCH', async () => {
  const c = new McpClient();
  try {
    await handshake(c);
    const before = await c.callTool('read_receipts', {});
    const old = before.payload.receipts[2]; // a VALID past receipt
    const res = await c.callTool('append_receipt', { receipt: old });
    assert.equal(res.isError, true);
    assert.equal(res.payload.error, 'E_SEQ_MISMATCH');
    assert.match(res.payload.detail, /replay or gap/);
  } finally {
    await c.stop();
  }
});

// ---- 9. forged signature ---------------------------------------------------
test('append_receipt with wrong-secret signature: rejected E_BAD_SIGNATURE', async () => {
  const c = new McpClient();
  try {
    await handshake(c);
    const before = await c.callTool('read_receipts', {});
    const body = { kind: 'attack.simulation', ts: '2026-10-02T04:00:00Z', note: 'signed by an impostor' };
    const receipt = makeReceipt(6, before.payload.tip, body);
    receipt.sig = qmrSig(receipt.id).slice(0, 62) + (receipt.sig.endsWith('aa') ? 'bb' : 'aa');
    const res = await c.callTool('append_receipt', { receipt });
    assert.equal(res.isError, true);
    assert.equal(res.payload.error, 'E_BAD_SIGNATURE');
  } finally {
    await c.stop();
  }
});

// ---- 10. body contract -----------------------------------------------------
test('append_receipt body contract: missing kind / non-object body rejected fail-closed', async () => {
  const c = new McpClient();
  try {
    await handshake(c);
    const before = await c.callTool('read_receipts', {});
    const tip = before.payload.tip;
    for (const badBody of [{ ts: '2026-10-02T04:00:00Z' }, { kind: '', ts: '2026-10-02T04:00:00Z' }, 'not-an-object']) {
      const receipt = makeReceipt(6, tip, badBody);
      const res = await c.callTool('append_receipt', { receipt });
      assert.equal(res.isError, true, `expected rejection for body ${JSON.stringify(badBody)}`);
      assert.equal(res.payload.error, 'E_BODY_INVALID');
    }
  } finally {
    await c.stop();
  }
});

// ---- 11. protocol robustness ----------------------------------------------
test('protocol: unknown method → -32601, unknown tool → -32602, parse error → -32700', async () => {
  const c = new McpClient();
  try {
    await handshake(c);
    await assert.rejects(
      () => c.request('resources/list', {}),
      (e) => e.rpcError.code === -32601,
    );
    await assert.rejects(
      () => c.request('tools/call', { name: 'delete_history', arguments: {} }),
      (e) => e.rpcError.code === -32602,
    );
    // raw garbage line → JSON-RPC parse error reply with id null
    await assert.rejects(
      () => new Promise((resolve, reject) => {
        c.pending.set(null, { resolve, reject });
        c.child.stdin.write('this is not json\n');
        setTimeout(() => { c.pending.delete(null); reject(new Error('no parse-error reply')); }, 5000);
      }),
      (e) => e.rpcError && e.rpcError.code === -32700 && e.rpcError.message === 'Parse error',
    );
  } finally {
    await c.stop();
  }
});
