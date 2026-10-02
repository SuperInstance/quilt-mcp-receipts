#!/usr/bin/env node
// examples/client-demo.mjs — drive quilt-mcp-receipts end-to-end exactly as an
// MCP client would: spawn the server, handshake, list tools, read the chain,
// verify it, sign + append a new receipt, verify again.
//
// Run: node examples/client-demo.mjs          (uses a throwaway temp store)
//      MCP_RECEIPT_SECRET=<s> node examples/client-demo.mjs
//      node examples/client-demo.mjs --store ./store.jsonl   (your own store)

import { spawn } from 'node:child_process';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SERVER = fileURLToPath(new URL('../server.mjs', import.meta.url));
const SECRET = process.env.MCP_RECEIPT_SECRET || 'quilt-mcp-receipts-dev-secret-do-not-use-in-prod';
const GENESIS_PREV = '0'.repeat(64);

const argv = process.argv.slice(2);
const storeIdx = argv.indexOf('--store');
const store = storeIdx >= 0 ? path.resolve(argv[storeIdx + 1]) : path.join(os.tmpdir(), `qmr-demo-${randomBytes(4).toString('hex')}.jsonl`);

// ---- qmr1 signer (per DESIGN.md §2; same formulas the test suite re-derives)
const canonicalJSON = (v) =>
  v === null || typeof v !== 'object' ? JSON.stringify(v) ?? 'null'
  : Array.isArray(v) ? '[' + v.map(canonicalJSON).join(',') + ']'
  : '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalJSON(v[k])).join(',') + '}';
const qmrId = (seq, prev, body) => createHash('sha256').update(`qmr1:${seq}:${prev}:${canonicalJSON(body)}`).digest('hex');
const qmrSig = (id) => createHmac('sha256', SECRET).update(`qmr1:sig:${id}`).digest('hex');

// ---- tiny stdio MCP client ------------------------------------------------
const child = spawn(process.execPath, [SERVER, '--store', store, '--demo'], {
  env: { ...process.env, MCP_RECEIPT_SECRET: SECRET },
  stdio: ['pipe', 'pipe', 'inherit'],
});
let buffer = '';
let nextId = 1;
const pending = new Map();
child.stdout.setEncoding('utf8');
child.stdout.on('data', (c) => {
  buffer += c;
  let i;
  while ((i = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, i).trim();
    buffer = buffer.slice(i + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    const p = pending.get(msg.id);
    if (!p) continue;
    pending.delete(msg.id);
    msg.error ? p.reject(new Error(`${msg.error.message} (${msg.error.code})`)) : p.resolve(msg.result);
  }
});
function request(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    setTimeout(() => { if (pending.has(id)) { pending.delete(id); reject(new Error(`timeout: ${method}`)); } }, 8000);
  });
}
const callTool = async (name, args) => {
  const res = await request('tools/call', { name, arguments: args ?? {} });
  return { isError: res.isError === true, payload: JSON.parse(res.content[0].text) };
};
const step = (n, msg) => process.stdout.write(`\n[${n}] ${msg}\n`);

// ---- the demo --------------------------------------------------------------
let failures = 0;
const check = (label, cond, extra = '') => {
  process.stdout.write(`  ${cond ? 'PASS' : 'FAIL'}  ${label}${extra ? ' — ' + extra : ''}\n`);
  if (!cond) failures++;
};

try {
  step(1, 'handshake (initialize → notifications/initialized)');
  const init = await request('initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'client-demo', version: '0.1.0' },
  });
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  check('serverInfo', init.serverInfo.name === 'quilt-mcp-receipts', JSON.stringify(init.serverInfo));
  check('protocolVersion', init.protocolVersion === '2024-11-05');

  step(2, 'tools/list');
  const { tools } = await request('tools/list', {});
  check('three tools', JSON.stringify(tools.map((t) => t.name).sort()) === JSON.stringify(['append_receipt', 'read_receipts', 'verify_chain']), tools.map((t) => t.name).join(', '));

  step(3, 'read_receipts (demo store seeded 5 receipts)');
  const all = await callTool('read_receipts', {});
  check('count 5', all.payload.count === 5);
  check('genesis prev is 64 zeros', all.payload.receipts[0].prev === GENESIS_PREV);

  step(4, 'verify_chain (re-derives from genesis)');
  const v1 = await callTool('verify_chain', {});
  check('ok', v1.payload.ok === true, `count=${v1.payload.count} tip=${(v1.payload.tip || '').slice(0, 12)}…`);

  step(5, 'append_receipt (client signs per qmr1, server validates fail-closed)');
  const body = {
    kind: 'receipt.chain.checkpoint',
    ts: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    actor: 'client-demo',
    claim: 'end-to-end demo append over MCP stdio',
    refs: ['examples/client-demo.mjs'],
  };
  const receipt = { seq: 6, prev: all.payload.tip, body, id: '', sig: '' };
  receipt.id = qmrId(receipt.seq, receipt.prev, receipt.body);
  receipt.sig = qmrSig(receipt.id);
  const ap = await callTool('append_receipt', { receipt });
  check('accepted', ap.payload.ok === true && ap.payload.seq === 6, `id=${(ap.payload.id || '').slice(0, 12)}…`);

  step(6, 'fail-closed control: append with a broken prev-hash must be rejected');
  const forged = { seq: 7, prev: 'f'.repeat(64), body: { kind: 'attack.simulation', ts: body.ts, note: 'wrong link' }, id: '', sig: '' };
  forged.id = qmrId(forged.seq, forged.prev, forged.body);
  forged.sig = qmrSig(forged.id);
  const bad = await callTool('append_receipt', { receipt: forged });
  check(`rejected E_PREV_MISMATCH`, bad.isError && bad.payload.error === 'E_PREV_MISMATCH', bad.payload.detail || '');

  step(7, 'verify_chain after the attempted forgery (chain still intact)');
  const v2 = await callTool('verify_chain', {});
  check('ok, count 6, tip unchanged by forgery', v2.payload.ok === true && v2.payload.count === 6 && v2.payload.tip === receipt.id);

  step(8, 'read_receipts cursor (catch-up read: since_seq=5)');
  const tail = await callTool('read_receipts', { since_seq: 5 });
  check('one new receipt, seq 6', tail.payload.count === 1 && tail.payload.receipts[0].seq === 6);

  process.stdout.write(`\nstore: ${store}\n`);
} catch (e) {
  failures++;
  console.error(`DEMO ERROR: ${e.message}`);
} finally {
  child.stdin.end();
  child.kill('SIGTERM');
}

process.stdout.write(`\n${failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED'}\n`);
process.exit(failures === 0 ? 0 : 1);
