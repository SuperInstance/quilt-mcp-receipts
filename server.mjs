#!/usr/bin/env node
// quilt-mcp-receipts — the fleet receipt chain as a signed append-only MCP organ.
// Spike v1, dialect `qmr1`. Spec: DESIGN.md. Transport: stdio, newline-delimited
// JSON-RPC 2.0 (MCP handshake + tools/list + tools/call). Stdlib only, no SDK.

import { createHash, createHmac, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const SERVER_NAME = 'quilt-mcp-receipts';
const SERVER_VERSION = '0.1.0';
const PROTOCOL_VERSION = '2024-11-05';
const GENESIS_PREV = '0'.repeat(64);
const DIALECT = 'qmr1';
const DEFAULT_SECRET = 'quilt-mcp-receipts-dev-secret-do-not-use-in-prod';
const REQUIRED_FIELDS = ['seq', 'prev', 'body', 'id', 'sig'];

// ---------------------------------------------------------------- cli / env
const argv = process.argv.slice(2);
const argValue = (flag) => {
  const i = argv.indexOf(flag);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null;
};
const STORE = path.resolve(argValue('--store') || path.join(process.cwd(), 'store.jsonl'));
const SECRET = process.env.MCP_RECEIPT_SECRET || DEFAULT_SECRET;
const QUIET = argv.includes('--quiet-notice');

function note(msg) {
  process.stderr.write(`[${SERVER_NAME}] ${msg}\n`);
}
if (SECRET === DEFAULT_SECRET && !QUIET) {
  note(`WARNING: using the built-in dev HMAC secret. Set MCP_RECEIPT_SECRET for anything real.`);
}
note(`store=${STORE}`);

// ------------------------------------------------- qmr1 dialect (see DESIGN.md)
function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}

function receiptId(seq, prev, body) {
  return createHash('sha256').update(`qmr1:${seq}:${prev}:${canonicalJSON(body)}`).digest('hex');
}

function receiptSig(id) {
  return createHmac('sha256', SECRET).update(`qmr1:sig:${id}`).digest('hex');
}

function isHex64(s) {
  return typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
}

// ------------------------------------------------------------------ store IO
// Read path always re-parses from disk: every answer describes the file as it
// is now. Unparseable lines are never silently skipped.
function loadStore() {
  if (!fs.existsSync(STORE)) return { receipts: [], corrupted_lines: [] };
  const text = fs.readFileSync(STORE, 'utf8');
  const receipts = [];
  const corrupted_lines = [];
  text.split('\n').forEach((line, i) => {
    if (!line.trim()) return;
    try {
      receipts.push(JSON.parse(line));
    } catch {
      corrupted_lines.push(i + 1);
    }
  });
  return { receipts, corrupted_lines };
}

function appendLine(obj) {
  fs.appendFileSync(STORE, JSON.stringify(obj) + '\n');
}

// ------------------------------------------------------------- verification
// Re-derives the full chain from genesis; fails closed on the first bad row.
function verifyChain() {
  const { receipts, corrupted_lines } = loadStore();
  if (corrupted_lines.length > 0) {
    return {
      ok: false,
      error: 'E_STORE_CORRUPT',
      detail: `store contains non-JSON lines: ${corrupted_lines.join(',')}`,
      corrupted_lines,
      count_checked: receipts.length,
      tip: null,
    };
  }
  let prev = GENESIS_PREV;
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    const at_seq = i + 1;
    const fail = (error, detail) => ({ ok: false, error, at_seq, detail, count_checked: i, tip: null });

    if (r === null || typeof r !== 'object' || Array.isArray(r)) return fail('E_BODY_INVALID', 'row is not an object');
    for (const f of REQUIRED_FIELDS) if (!(f in r)) return fail('E_MISSING_FIELD', `missing field "${f}"`);
    for (const k of Object.keys(r)) if (!REQUIRED_FIELDS.includes(k)) return fail('E_UNKNOWN_FIELD', `unknown field "${k}"`);
    if (!Number.isInteger(r.seq) || r.seq < 1) return fail('E_SEQ_MISMATCH', `seq ${JSON.stringify(r.seq)} is not a positive integer`);
    if (!isHex64(r.prev)) return fail('E_PREV_MISMATCH', `prev is not 64-hex`);
    if (!isHex64(r.id)) return fail('E_HASH_MISMATCH', `id is not 64-hex`);
    if (!isHex64(r.sig)) return fail('E_BAD_SIGNATURE', `sig is not 64-hex`);
    if (!r.body || typeof r.body !== 'object' || Array.isArray(r.body)) return fail('E_BODY_INVALID', 'body must be a JSON object');
    if (typeof r.body.kind !== 'string' || r.body.kind.length === 0) return fail('E_BODY_INVALID', 'body.kind must be a non-empty string');
    if (typeof r.body.ts !== 'string' || r.body.ts.length === 0) return fail('E_BODY_INVALID', 'body.ts must be a non-empty string');
    if (r.seq !== at_seq) return fail('E_SEQ_MISMATCH', `row ${i + 1} claims seq ${r.seq}`);
    if (r.prev !== prev) return fail('E_PREV_MISMATCH', `row ${r.seq} links to ${r.prev.slice(0, 12)}…, expected ${prev.slice(0, 12)}…`);
    const recomputedId = receiptId(r.seq, r.prev, r.body);
    if (r.id !== recomputedId) return fail('E_HASH_MISMATCH', `recomputed id ${recomputedId.slice(0, 12)}… ≠ stored ${r.id.slice(0, 12)}…`);
    const recomputedSig = receiptSig(r.id);
    if (r.sig !== recomputedSig) return fail('E_BAD_SIGNATURE', `HMAC mismatch over id ${r.id.slice(0, 12)}… (wrong secret or altered id)`);
    prev = r.id;
  }
  return { ok: true, dialect: DIALECT, count: receipts.length, tip: receipts.length ? prev : null };
}

// ------------------------------------------------------------------- appends
// Fail-closed, named errors, first failure wins. Never writes anything invalid.
function validateAppend(receipt) {
  const { receipts, corrupted_lines } = loadStore();
  if (corrupted_lines.length > 0) {
    return { error: 'E_STORE_CORRUPT', detail: `refusing to append onto a corrupt store (lines ${corrupted_lines.join(',')})` };
  }
  const tip = receipts.length ? receipts[receipts.length - 1] : null;
  const expectedSeq = receipts.length + 1;
  const expectedPrev = tip ? tip.id : GENESIS_PREV;
  const fail = (error, detail) => ({ error, detail });

  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) return fail('E_BODY_INVALID', 'receipt must be a JSON object');
  for (const f of REQUIRED_FIELDS) if (!(f in receipt)) return fail('E_MISSING_FIELD', `missing field "${f}"`);
  for (const k of Object.keys(receipt)) if (!REQUIRED_FIELDS.includes(k)) return fail('E_UNKNOWN_FIELD', `unknown field "${k}"`);
  if (!Number.isInteger(receipt.seq)) return fail('E_SEQ_MISMATCH', `seq must be an integer, got ${JSON.stringify(receipt.seq)}`);
  if (!receipt.body || typeof receipt.body !== 'object' || Array.isArray(receipt.body)) return fail('E_BODY_INVALID', 'body must be a JSON object');
  if (typeof receipt.body.kind !== 'string' || receipt.body.kind.length === 0) return fail('E_BODY_INVALID', 'body.kind must be a non-empty string');
  if (typeof receipt.body.ts !== 'string' || receipt.body.ts.length === 0) return fail('E_BODY_INVALID', 'body.ts must be a non-empty string');
  if (receipt.seq !== expectedSeq) return fail('E_SEQ_MISMATCH', `expected seq ${expectedSeq}, got ${receipt.seq} (replay or gap)`);
  if (!isHex64(receipt.prev) || receipt.prev !== expectedPrev) {
    return fail('E_PREV_MISMATCH', `expected prev ${expectedPrev.slice(0, 12)}…, got ${String(receipt.prev).slice(0, 12)}…`);
  }
  const recomputedId = receiptId(receipt.seq, receipt.prev, receipt.body);
  if (!isHex64(receipt.id) || receipt.id !== recomputedId) {
    return fail('E_HASH_MISMATCH', `recomputed id ${recomputedId.slice(0, 12)}… ≠ submitted ${String(receipt.id).slice(0, 12)}…`);
  }
  const recomputedSig = receiptSig(receipt.id);
  if (!isHex64(receipt.sig) || receipt.sig !== recomputedSig) {
    return fail('E_BAD_SIGNATURE', `HMAC mismatch over id (wrong secret or altered id)`);
  }
  return { ok: true, tip };
}

// -------------------------------------------------------------- demo seeding
// NEVER deletes data: seeds only into an empty/missing store.
function seedDemo() {
  const { receipts, corrupted_lines } = loadStore();
  if (corrupted_lines.length > 0) {
    note(`refusing to seed a corrupt store (lines ${corrupted_lines.join(',')})`);
    return;
  }
  if (receipts.length > 0) {
    note(`store already holds ${receipts.length} receipts; demo seeding skipped (append-only, never delete)`);
    return;
  }
  const t = '2026-10-02T03:00:00Z';
  const bodies = [
    { kind: 'receipt.chain.genesis', ts: t, note: 'quilt-mcp-receipts spike store opened', dialect: DIALECT },
    { kind: 'engine.run.sealed', ts: t, actor: 'quilt-jepa', round: 10, claim: 'round-10 sealed 22/28 from receipt of record, zero re-execution', refs: ['SuperInstance/quilt-jepa@a47762a1'] },
    { kind: 'lesson.minted', ts: t, id: 'L16', claim: 'receipt-of-record-first: score from sealed receipts, not re-runs', refs: ['fleet-seeds/lode/lessons.jsonl'] },
    { kind: 'organ.boot.verified', ts: t, actor: 'quilt-organ-workers', claim: 'organ store 5/5 bootable, watcher healthy', refs: ['SuperInstance/quilt-organ-workers@45f4768f'] },
    { kind: 'scout.report.landed', ts: t, actor: 'wave-63-scout', claim: 'TOP-5 snowball queued; item #1 = MCP-ize the receipt chain (this organ)', refs: ['fleet-seeds/scouts/wave63-scout-report.md'] },
  ];
  let prev = GENESIS_PREV;
  const lines = [];
  for (let i = 0; i < bodies.length; i++) {
    const seq = i + 1;
    const id = receiptId(seq, prev, bodies[i]);
    const sig = receiptSig(id);
    lines.push(JSON.stringify({ seq, prev, body: bodies[i], id, sig }));
    prev = id;
  }
  fs.writeFileSync(STORE, lines.join('\n') + '\n');
  note(`demo store seeded: 5 receipts, tip ${prev.slice(0, 12)}…`);
}

if (argv.includes('--demo')) seedDemo();

// ------------------------------------------------------------- MCP tool defs
const TOOLS = [
  {
    name: 'read_receipts',
    description:
      'Recall from the fleet receipt chain: return hash-chained receipts with seq > since_seq, up to limit. ' +
      'Reads the store from disk on every call and flags unparseable lines as corrupted_lines (never silently skipped).',
    inputSchema: {
      type: 'object',
      properties: {
        since_seq: { type: 'integer', minimum: 0, default: 0, description: 'exclusive lower bound on seq (cursor for catch-up reads)' },
        limit: { type: 'integer', minimum: 1, maximum: 1000, default: 100 },
      },
    },
  },
  {
    name: 'verify_chain',
    description:
      'Self-audit: re-derive the full hash chain from genesis (structure, seq, prev linkage, id recomputation, HMAC signature). ' +
      'Returns {ok:true, count, tip} or fails closed with a named error code (E_PREV_MISMATCH, E_HASH_MISMATCH, E_BAD_SIGNATURE, …) at the first broken row.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'append_receipt',
    description:
      'Commit one receipt to the chain. The client builds and signs the full receipt {seq, prev, body, id, sig} per the qmr1 dialect (DESIGN.md): ' +
      'id = sha256("qmr1:"+seq+":"+prev+":"+canonicalJSON(body)); sig = HMAC-SHA256(secret, "qmr1:sig:"+id). ' +
      'Validation is fail-closed with named errors; nothing invalid is ever written.',
    inputSchema: { type: 'object', properties: { receipt: { type: 'object', description: 'complete qmr1 receipt incl. seq/prev/id/sig' } }, required: ['receipt'] },
  },
];

// ---------------------------------------------------------------- tool calls
function toolRead(args) {
  const since = args && args.since_seq !== undefined ? args.since_seq : 0;
  const limit = args && args.limit !== undefined ? args.limit : 100;
  if (!Number.isInteger(since) || since < 0) return { isError: true, payload: { ok: false, error: 'E_BAD_ARGS', detail: 'since_seq must be a non-negative integer' } };
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) return { isError: true, payload: { ok: false, error: 'E_BAD_ARGS', detail: 'limit must be an integer in [1,1000]' } };
  const { receipts, corrupted_lines } = loadStore();
  const selected = receipts.filter((r) => r && typeof r === 'object' && r.seq > since).slice(0, limit);
  const tip = receipts.length ? receipts[receipts.length - 1].id ?? null : null;
  const payload = { ok: true, count: selected.length, tip, receipts: selected };
  if (corrupted_lines.length > 0) payload.corrupted_lines = corrupted_lines;
  return { isError: false, payload };
}

function toolVerify() {
  const result = verifyChain();
  return { isError: result.ok !== true, payload: result };
}

function toolAppend(args) {
  if (!args || typeof args !== 'object' || !('receipt' in args)) {
    return { isError: true, payload: { ok: false, error: 'E_MISSING_FIELD', detail: 'arguments.receipt is required' } };
  }
  const verdict = validateAppend(args.receipt);
  if (verdict.error) return { isError: true, payload: { ok: false, ...verdict } };
  const r = args.receipt;
  appendLine({ seq: r.seq, prev: r.prev, body: r.body, id: r.id, sig: r.sig });
  return { isError: false, payload: { ok: true, seq: r.seq, id: r.id, tip: r.id, dialect: DIALECT } };
}

function callTool(name, args) {
  switch (name) {
    case 'read_receipts': return toolRead(args);
    case 'verify_chain': return toolVerify();
    case 'append_receipt': return toolAppend(args);
    default: return null; // unknown tool
  }
}

// ------------------------------------------------------- JSON-RPC 2.0 / MCP
function send(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

function result(id, payload) {
  send({ jsonrpc: '2.0', id, result: payload });
}

function errorReply(id, code, message) {
  send({ jsonrpc: '2.0', id, error: { code, message } });
}

const ERR_PARSE = -32700;
const ERR_INVALID_REQUEST = -32600;
const ERR_METHOD_NOT_FOUND = -32601;
const ERR_INVALID_PARAMS = -32602;

function handleRequest(msg) {
  const { id, method, params } = msg;
  switch (method) {
    case 'initialize': {
      const requested = params && typeof params.protocolVersion === 'string' ? params.protocolVersion : null;
      const version = requested && /^20\d\d-/.test(requested) ? requested : PROTOCOL_VERSION;
      return result(id, {
        protocolVersion: version,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      });
    }
    case 'ping':
      return result(id, {});
    case 'tools/list':
      return result(id, { tools: TOOLS });
    case 'tools/call': {
      const name = params && params.name;
      if (typeof name !== 'string') return errorReply(id, ERR_INVALID_PARAMS, 'params.name must be a string');
      if (!TOOLS.some((t) => t.name === name)) return errorReply(id, ERR_INVALID_PARAMS, `unknown tool: ${name}`);
      const args = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};
      const out = callTool(name, args);
      if (out === null) return errorReply(id, ERR_METHOD_NOT_FOUND, `unknown tool: ${name}`);
      return result(id, {
        content: [{ type: 'text', text: JSON.stringify(out.payload) }],
        isError: out.isError,
      });
    }
    default:
      return errorReply(id, ERR_METHOD_NOT_FOUND, `method not found: ${method}`);
  }
}

function handleLine(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return errorReply(null, ERR_PARSE, 'Parse error');
  }
  if (msg === null || typeof msg !== 'object' || Array.isArray(msg) || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    return errorReply(msg && msg.id !== undefined ? msg.id : null, ERR_INVALID_REQUEST, 'Invalid Request');
  }
  if (msg.id === undefined || msg.id === null) {
    // notification: no reply ever. Known notifications are accepted silently.
    return;
  }
  try {
    handleRequest(msg);
  } catch (e) {
    note(`handler error: ${e && e.stack ? e.stack.split('\n')[0] : e}`);
    errorReply(msg.id, ERR_INVALID_REQUEST, 'Internal error');
  }
}

let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buf += chunk;
  let idx;
  while ((idx = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (line) handleLine(line);
  }
});
process.stdin.on('end', () => process.exit(0));
process.stdin.resume();

// keep the event loop honest: randomUUID imported for future request-id helpers
void randomUUID;
