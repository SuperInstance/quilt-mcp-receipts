#!/usr/bin/env node
// quilt-mcp-receipts — the fleet receipt chain as a signed append-only MCP organ.
// v0.3.0, dialect family `qmr1` + pluggable-hash layer `qmr2` + attribution layer
// `v3` (docs/qmr2-design.md §8).
// Transport: stdio, newline-delimited JSON-RPC 2.0 (MCP handshake + tools/list +
// tools/call). Stdlib only, no SDK.
//
// qmr2 (additive, never rewrites qmr1 semantics):
//   - row MAY carry `dialect` field; qmr1 rows read as sha256-custody, are never
//     rewritten on disk
//   - registry: sha256-custody (custody law) + fnv1a-canary (fast, never custody)
//   - law: custody chains MUST use sha256-custody → verify_chain({dialect_mode:"custody"})
//     fails E_DIALECT_FORBIDDEN on any fnv1a-canary row
//   - portable preimage ("qmr1:seq:prev:canonicalJSON(body)", dialect-independent)
//     → upgrade_chain re-hashes canary chains into NEW custody receipt sets
//   - two new tools (`dialects`, `upgrade_chain`) advertise only under --qmr2 / env
//     QMR2=1, so the v1 tool-name contract pinned by the untouched test suite holds
//
// v3 attribution (additive; the sig SLOT opens the way the hash slot did):
//   - row MAY carry `sigAlg` + `sigKeyFp`; rows without them are qmr1 HMAC rows,
//     byte-unchanged and never rewritten
//   - sigAlg "ed25519": sig = Ed25519 over "qmr1:sig:"+id (128-hex); sigKeyFp =
//     sha256 of the signer's SPKI PEM (the SAME fingerprint law as
//     quilt-jev-toolkit's organ v3 — one identity, two organs, zero shared secrets)
//   - verify_chain gains an optional keyring {fingerprint → publicKeyPem}; a row
//     signed under a fingerprint not in the keyring → E_UNKNOWN_SIGNER (fail-closed)
//   - new tool `verify_attribution` (advertises under --v3 / env V3=1 — same
//     versioned-capability pattern as qmr2) reports WHO signed each row
//   - HMAC's honest residual stays receipted: a shared secret has no per-signer
//     identity — attribution is fleet-trust until v3

import { createHash, createHmac, createPublicKey, randomUUID, verify as cryptoVerify } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const SERVER_NAME = 'quilt-mcp-receipts';
const SERVER_VERSION = '0.3.0';
const PROTOCOL_VERSION = '2024-11-05';
const GENESIS_PREV = '0'.repeat(64);
const DIALECT = 'qmr1'; // the preimage/domain contract name (qmr1-compatible by design)
const DEFAULT_DIALECT = 'sha256-custody';
const DEFAULT_SECRET = 'quilt-mcp-receipts-dev-secret-do-not-use-in-prod';
const REQUIRED_FIELDS = ['seq', 'prev', 'body', 'id', 'sig'];
const OPTIONAL_FIELDS = ['dialect', 'sigAlg', 'sigKeyFp'];

// -------------------------------------------------- v3 sig-scheme registry (§8)
// The sig SLOT opens the way the hash slot opened: registry + named law +
// fail-closed verification, and the default (absent field) stays qmr1.
const DEFAULT_SIGALG = 'hmac-sha256';
const FINGERPRINT_HEX = /^[0-9a-f]{64}$/;
const ED25519_SIG_HEX = /^[0-9a-f]{128}$/; // Ed25519 sigs are 64 bytes

// THE FINGERPRINT LAW (shared byte-for-byte with quilt-jev-toolkit's organ v3):
// sha256 over the normalized SPKI PEM (`createPublicKey(pem).export({type:'spki',
// format:'pem'})`, trailing newline included) → 64 lowercase hex.
function ed25519KeyFingerprint(pem) {
  return createHash('sha256').update(createPublicKey(pem).export({ type: 'spki', format: 'pem' })).digest('hex');
}

function ed25519VerifySig(publicKeyPem, id, sigHex) {
  if (typeof sigHex !== 'string' || !ED25519_SIG_HEX.test(sigHex)) return false;
  try {
    return cryptoVerify(null, Buffer.from(`qmr1:sig:${id}`, 'utf8'), publicKeyPem, Buffer.from(sigHex, 'hex'));
  } catch {
    return false;
  }
}

/** Validate a keyring {fingerprint → publicKeyPem} up front — fail-closed
 *  BEFORE any row is consulted: a mislabeled or unparseable key is a broken
 *  trust root, not a signature failure. Returns null or an error object. */
function keyringError(keyring) {
  if (keyring === null || keyring === undefined) return null;
  if (typeof keyring !== 'object' || Array.isArray(keyring)) {
    return { error: 'E_BAD_KEYRING', detail: 'keyring must be an object {fingerprint → publicKeyPem}' };
  }
  for (const [fp, pem] of Object.entries(keyring)) {
    if (!FINGERPRINT_HEX.test(fp)) {
      return { error: 'E_BAD_KEYRING', detail: `keyring fingerprint ${JSON.stringify(fp.slice(0, 24))} is not 64-hex (sha256 of the key's SPKI PEM)` };
    }
    let realFp;
    try {
      realFp = ed25519KeyFingerprint(pem);
    } catch {
      return { error: 'E_BAD_KEYRING', detail: `keyring[${fp.slice(0, 12)}…] does not hold a parseable public key PEM` };
    }
    if (realFp !== fp) {
      return { error: 'E_BAD_KEYRING', detail: `keyring[${fp.slice(0, 12)}…] is mislabeled — the key it holds bears fingerprint ${realFp.slice(0, 12)}…` };
    }
  }
  return null;
}

// ------------------------------------------------ qmr2 dialect registry (§3)
// ONE receipt primitive, pluggable hash, ONE law. Adding a dialect = adding a
// row here + a hash function — never touching the law.
const FNV_OFFSET = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const FNV_MASK = (1n << 64n) - 1n;
function fnv1a64(str) {
  let h = FNV_OFFSET;
  for (const b of Buffer.from(str, 'utf8')) {
    h ^= BigInt(b);
    h = (h * FNV_PRIME) & FNV_MASK;
  }
  return h.toString(16).padStart(16, '0');
}

const DIALECTS = {
  'sha256-custody': {
    hash: 'sha256',
    custody: true,
    note: 'qmr1-compatible custody class; ids byte-identical to qmr1',
    computeId: (preimage) => createHash('sha256').update(preimage).digest('hex'),
  },
  'fnv1a-canary': {
    hash: 'fnv1a-64',
    custody: false,
    note: 'fast in-memory chains that will NEVER hold custody (slackwater-quilt refutes canary for custody chains)',
    computeId: (preimage) => '0x' + fnv1a64(preimage),
  },
};

function resolveDialect(name) {
  // undefined → qmr1 default on read (sha256-custody); anything else must be a
  // registered name (non-string included → E_UNKNOWN_DIALECT by the caller).
  if (name === undefined) return DEFAULT_DIALECT;
  return DIALECTS[name] ? name : null;
}

function dialectId(dialectName, seq, prev, body) {
  // Portable preimage (§2): identical string shape across ALL dialects — this is
  // what makes re-hash upgrading a pure function.
  const preimage = `qmr1:${seq}:${prev}:${canonicalJSON(body)}`;
  return DIALECTS[dialectName].computeId(preimage);
}

function isCustodyId(s) {
  return typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
}
function isCanaryId(s) {
  return typeof s === 'string' && /^0x[0-9a-f]{16}$/.test(s);
}
// prev form: genesis, or the previous row's id VERBATIM — which may carry EITHER
// dialect's form, because mixed chains are legal in "any" mode (docs/qmr2-design.md §3):
// a canary tail may link onto a custody row and vice versa; linkage is string equality.
function isPrevForm(s) {
  if (s === GENESIS_PREV) return true;
  return isCustodyId(s) || isCanaryId(s);
}

const REGISTRY_INFO = {
  version: 'qmr2',
  preimage: 'qmr1:<seq>:<prev>:<canonicalJSON(body)> — identical string shape across dialects (portable preimage, docs/qmr2-design.md §2)',
  sig: 'HMAC-SHA256(secret, "qmr1:sig:"+id) — the qmr1 default across dialects; v3 adds the pluggable SIG slot (sigAlg "ed25519" + sigKeyFp, docs/qmr2-design.md §8)',
  genesis_prev: GENESIS_PREV,
  law: 'custody chains MUST use sha256-custody: verify_chain({dialect_mode:"custody"}) fails E_DIALECT_FORBIDDEN on any fnv1a-canary row (localized at_seq)',
  dialects: Object.entries(DIALECTS).map(([name, d]) => ({
    name, hash: d.hash, custody: d.custody, note: d.note,
  })),
  sig_schemes: [
    { name: 'hmac-sha256', default: true, keyring: false, note: 'qmr1 shared secret — one anonymous writer, no per-signer identity (the honest residual)' },
    { name: 'ed25519', default: false, keyring: true, note: 'v3 attribution: sig = Ed25519("qmr1:sig:"+id), 128-hex; sigKeyFp = sha256 of the signer\'s SPKI PEM; verify_chain({keyring:{fingerprint→publicKeyPem}}) refuses E_UNKNOWN_SIGNER (fail-closed)' },
  ],
  fingerprint: 'sha256(normalized SPKI PEM of the public key) → 64-hex — the SAME law as quilt-jev-toolkit\'s organ v3 checkpoints (one identity, two organs, zero shared secrets)',
  upgrade: 'upgrade_chain({from_seq,to_seq}) re-hashes a verified chain into a NEW standalone custody receipt set under upgrades/ (deterministic, source store never mutated)',
  spec: 'docs/qmr2-design.md',
};

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
  return dialectId(DEFAULT_DIALECT, seq, prev, body);
}

function receiptSig(id) {
  return createHmac('sha256', SECRET).update(`qmr1:sig:${id}`).digest('hex');
}

const isHex64 = isCustodyId; // qmr1 spelling kept for the seed/read paths below

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
// verifyChain(opts): opts may be the legacy mode string ("any"|"custody") or
// { dialect_mode?: "any"|"custody", keyring?: {fingerprint → publicKeyPem} }.
// dialectMode "any" (default): each row verified under its own dialect, mixed
// chains allowed. "custody": the law — every row must be sha256-custody
// (fnv1a-canary → E_DIALECT_FORBIDDEN, localized at_seq).
// keyring (v3, docs/qmr2-design.md §8): required by ed25519-signed rows; a row
// whose sigKeyFp is not in the keyring → E_UNKNOWN_SIGNER (fail-closed — an
// unverifiable signer is an unknown signer). HMAC rows ignore the keyring.
function verifyChain(opts = 'any') {
  let dialectMode = 'any';
  let keyring = null;
  if (typeof opts === 'string') {
    dialectMode = opts;
  } else if (opts && typeof opts === 'object') {
    dialectMode = opts.dialect_mode === undefined ? 'any' : opts.dialect_mode;
    keyring = opts.keyring === undefined ? null : opts.keyring;
  }
  if (dialectMode !== 'any' && dialectMode !== 'custody') {
    return { ok: false, error: 'E_BAD_ARGS', detail: `dialect_mode must be "any" or "custody", got ${JSON.stringify(dialectMode)}`, count_checked: 0, tip: null };
  }
  const badKeyring = keyringError(keyring);
  if (badKeyring) {
    return { ok: false, ...badKeyring, detail: `${badKeyring.detail} — the trust root itself is broken, refusing before any row is read`, count_checked: 0, tip: null };
  }
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
    for (const k of Object.keys(r)) if (!REQUIRED_FIELDS.includes(k) && !OPTIONAL_FIELDS.includes(k)) return fail('E_UNKNOWN_FIELD', `unknown field "${k}"`);
    // qmr2: dialect name must be registered (undefined = qmr1 row → custody default on read)
    const dialectName = resolveDialect(r.dialect);
    if (dialectName === null) return fail('E_UNKNOWN_DIALECT', `dialect ${JSON.stringify(r.dialect)} is not in the registry (registered: ${Object.keys(DIALECTS).join(', ')})`);
    if (dialectMode === 'custody' && dialectName === 'fnv1a-canary') {
      return fail('E_DIALECT_FORBIDDEN', `fnv1a-canary row in a chain asserted as custody (law: custody chains MUST use sha256-custody, docs/qmr2-design.md §3)`);
    }
    if (!Number.isInteger(r.seq) || r.seq < 1) return fail('E_SEQ_MISMATCH', `seq ${JSON.stringify(r.seq)} is not a positive integer`);
    if (!isPrevForm(r.prev)) return fail('E_PREV_MISMATCH', `prev is not a valid link id (genesis or a registered dialect id form)`);
    if (dialectName === 'fnv1a-canary' ? !isCanaryId(r.id) : !isHex64(r.id)) return fail('E_HASH_MISMATCH', `id is not a valid ${dialectName} id`);
    // -- v3 sig law (docs/qmr2-design.md §8) ---------------------------------
    // A row without sigAlg is a qmr1 row: HMAC under the shared secret. The
    // sig SLOT is pluggable the way the hash slot is: registry + named
    // refusals, default preserved, nothing ever rewritten.
    const sigAlg = r.sigAlg === undefined ? DEFAULT_SIGALG : r.sigAlg;
    if (typeof sigAlg !== 'string' || (sigAlg !== 'hmac-sha256' && sigAlg !== 'ed25519')) {
      return fail('E_UNKNOWN_SIGALG', `sigAlg ${JSON.stringify(r.sigAlg)} is not registered (registered: hmac-sha256, ed25519)`);
    }
    if (r.sigKeyFp !== undefined && sigAlg !== 'ed25519') {
      return fail('E_SIGNER_MALFORMED', 'sigKeyFp is only meaningful on ed25519-signed rows — a shared-secret HMAC has no signer identity');
    }
    if (r.sigKeyFp !== undefined && (typeof r.sigKeyFp !== 'string' || !FINGERPRINT_HEX.test(r.sigKeyFp))) {
      return fail('E_SIGNER_MALFORMED', 'sigKeyFp must be 64-hex (sha256 of the signer\'s SPKI PEM)');
    }
    if (sigAlg === 'ed25519' && r.sigKeyFp === undefined) {
      return fail('E_MISSING_FIELD', 'ed25519-signed row missing "sigKeyFp" — an unnamed signer cannot be verified');
    }
    if (sigAlg === 'ed25519' ? !ED25519_SIG_HEX.test(r.sig) : !isHex64(r.sig)) {
      return fail('E_BAD_SIGNATURE', `sig is not ${sigAlg === 'ed25519' ? '128-hex (Ed25519)' : '64-hex'}`);
    }
    if (!r.body || typeof r.body !== 'object' || Array.isArray(r.body)) return fail('E_BODY_INVALID', 'body must be a JSON object');
    if (typeof r.body.kind !== 'string' || r.body.kind.length === 0) return fail('E_BODY_INVALID', 'body.kind must be a non-empty string');
    if (typeof r.body.ts !== 'string' || r.body.ts.length === 0) return fail('E_BODY_INVALID', 'body.ts must be a non-empty string');
    if (r.seq !== at_seq) return fail('E_SEQ_MISMATCH', `row ${i + 1} claims seq ${r.seq}`);
    if (r.prev !== prev) return fail('E_PREV_MISMATCH', `row ${r.seq} links to ${String(r.prev).slice(0, 12)}…, expected ${prev.slice(0, 12)}…`);
    const recomputedId = dialectId(dialectName, r.seq, r.prev, r.body);
    if (r.id !== recomputedId) return fail('E_HASH_MISMATCH', `recomputed id ${recomputedId.slice(0, 12)}… ≠ stored ${String(r.id).slice(0, 12)}…`);
    if (sigAlg === 'hmac-sha256') {
      const recomputedSig = receiptSig(r.id);
      if (r.sig !== recomputedSig) return fail('E_BAD_SIGNATURE', `HMAC mismatch over id ${r.id.slice(0, 12)}… (wrong secret or altered id)`);
    } else {
      // v3: the row NAMES its signer; the keyring must hold that exact key.
      if (!keyring) {
        return fail('E_UNKNOWN_SIGNER', `row signed by ${r.sigKeyFp.slice(0, 12)}… but no keyring was provided — attribution is fail-closed (docs/qmr2-design.md §8)`);
      }
      if (!(r.sigKeyFp in keyring)) {
        return fail('E_UNKNOWN_SIGNER', `no key in the keyring bears fingerprint ${r.sigKeyFp.slice(0, 12)}… — an unverifiable signer is an unknown signer`);
      }
      if (!ed25519VerifySig(keyring[r.sigKeyFp], r.id, r.sig)) {
        return fail('E_BAD_SIGNATURE', `Ed25519 signature does not verify under keyring[${r.sigKeyFp.slice(0, 12)}…] over id ${r.id.slice(0, 12)}… (forged sig, altered id, or the wrong key under that fingerprint)`);
      }
    }
    prev = r.id;
  }
  const out = { ok: true, dialect: DIALECT, count: receipts.length, tip: receipts.length ? prev : null };
  if (dialectMode !== 'any') out.dialect_mode = dialectMode;
  return out;
}

// ------------------------------------------------------------------- appends
// Fail-closed, named errors, first failure wins. Never writes anything invalid.
// Dialect-neutral by design (docs/qmr2-design.md §3): append cannot know which
// chains will later be CLAIMED as custody — the named mode assertion at verify
// is the enforcement instrument.
function validateAppend(receipt, keyring = null) {
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
  for (const k of Object.keys(receipt)) if (!REQUIRED_FIELDS.includes(k) && !OPTIONAL_FIELDS.includes(k)) return fail('E_UNKNOWN_FIELD', `unknown field "${k}"`);
  const dialectName = resolveDialect(receipt.dialect);
  if (dialectName === null) return fail('E_UNKNOWN_DIALECT', `dialect ${JSON.stringify(receipt.dialect)} is not in the registry (registered: ${Object.keys(DIALECTS).join(', ')})`);
  if (!Number.isInteger(receipt.seq)) return fail('E_SEQ_MISMATCH', `seq must be an integer, got ${JSON.stringify(receipt.seq)}`);
  if (!receipt.body || typeof receipt.body !== 'object' || Array.isArray(receipt.body)) return fail('E_BODY_INVALID', 'body must be a JSON object');
  if (typeof receipt.body.kind !== 'string' || receipt.body.kind.length === 0) return fail('E_BODY_INVALID', 'body.kind must be a non-empty string');
  if (typeof receipt.body.ts !== 'string' || receipt.body.ts.length === 0) return fail('E_BODY_INVALID', 'body.ts must be a non-empty string');
  if (receipt.seq !== expectedSeq) return fail('E_SEQ_MISMATCH', `expected seq ${expectedSeq}, got ${receipt.seq} (replay or gap)`);
  if (!isPrevForm(receipt.prev) || receipt.prev !== expectedPrev) {
    return fail('E_PREV_MISMATCH', `expected prev ${String(expectedPrev).slice(0, 12)}…, got ${String(receipt.prev).slice(0, 12)}…`);
  }
  const recomputedId = dialectId(dialectName, receipt.seq, receipt.prev, receipt.body);
  if (receipt.id !== recomputedId) {
    return fail('E_HASH_MISMATCH', `recomputed id ${recomputedId.slice(0, 12)}… ≠ submitted ${String(receipt.id).slice(0, 12)}…`);
  }
  // v3 sig law at the door (mirrors verifyChain): an ed25519 row must name a
  // signer the submitted keyring can prove — append never accepts a row it
  // cannot attribute (fail-closed).
  const sigAlg = receipt.sigAlg === undefined ? DEFAULT_SIGALG : receipt.sigAlg;
  if (typeof sigAlg !== 'string' || (sigAlg !== 'hmac-sha256' && sigAlg !== 'ed25519')) {
    return fail('E_UNKNOWN_SIGALG', `sigAlg ${JSON.stringify(receipt.sigAlg)} is not registered (registered: hmac-sha256, ed25519)`);
  }
  if (receipt.sigKeyFp !== undefined && sigAlg !== 'ed25519') {
    return fail('E_SIGNER_MALFORMED', 'sigKeyFp is only meaningful on ed25519-signed rows — a shared-secret HMAC has no signer identity');
  }
  if (receipt.sigKeyFp !== undefined && (typeof receipt.sigKeyFp !== 'string' || !FINGERPRINT_HEX.test(receipt.sigKeyFp))) {
    return fail('E_SIGNER_MALFORMED', 'sigKeyFp must be 64-hex (sha256 of the signer\'s SPKI PEM)');
  }
  if (sigAlg === 'ed25519' && receipt.sigKeyFp === undefined) {
    return fail('E_MISSING_FIELD', 'ed25519-signed row missing "sigKeyFp" — an unnamed signer cannot be verified');
  }
  if (sigAlg === 'hmac-sha256') {
    const recomputedSig = receiptSig(receipt.id);
    if (!isHex64(receipt.sig) || receipt.sig !== recomputedSig) {
      return fail('E_BAD_SIGNATURE', `HMAC mismatch over id (wrong secret or altered id)`);
    }
  } else {
    if (!ED25519_SIG_HEX.test(receipt.sig ?? '')) {
      return fail('E_BAD_SIGNATURE', 'sig is not 128-hex (Ed25519)');
    }
    const badKeyring = keyringError(keyring);
    if (badKeyring) return badKeyring;
    if (!keyring) {
      return fail('E_UNKNOWN_SIGNER', `append cannot verify an Ed25519 row signed by ${receipt.sigKeyFp.slice(0, 12)}… without a keyring — pass arguments.keyring {fingerprint → publicKeyPem} (fail-closed, docs/qmr2-design.md §8)`);
    }
    if (!(receipt.sigKeyFp in keyring)) {
      return fail('E_UNKNOWN_SIGNER', `no key in the keyring bears fingerprint ${receipt.sigKeyFp.slice(0, 12)}… — an unverifiable signer is an unknown signer`);
    }
    if (!ed25519VerifySig(keyring[receipt.sigKeyFp], receipt.id, receipt.sig)) {
      return fail('E_BAD_SIGNATURE', `Ed25519 signature does not verify under keyring[${receipt.sigKeyFp.slice(0, 12)}…] over id (forged sig, altered id, or the wrong key under that fingerprint)`);
    }
  }
  return { ok: true, tip, dialect: dialectName, sigAlg };
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

// ------------------------------------------------------------- qmr2 tool layer
// Versioned capability: the untouched v1 suite pins tools/list to exactly the
// three qmr1 tools (test #3, "exactly the three receipt-organ tools") — so the
// two qmr2 tools advertise only under --qmr2 / env QMR2=1. The row-level dialect
// layer above is ALWAYS active; only the tool listing is versioned.
const QMR2 = argv.includes('--qmr2') || (process.env.QMR2 !== undefined && process.env.QMR2 !== '' && process.env.QMR2 !== '0');

// upgrade_chain (docs/qmr2-design.md §5): re-hash a VERIFIED chain segment into
// a NEW standalone custody receipt set. Deterministic: content-derived output
// name, timestamp-free manifest, so re-running on the same source is
// byte-identical. The original store is never mutated.
function upgradeChain(fromSeq, toSeq) {
  const { receipts, corrupted_lines } = loadStore();
  if (corrupted_lines.length > 0) {
    return { ok: false, error: 'E_STORE_CORRUPT', detail: `refusing to upgrade a corrupt store (lines ${corrupted_lines.join(',')})` };
  }
  const bad = (error, detail) => ({ ok: false, error, detail });
  if (!Number.isInteger(fromSeq) || !Number.isInteger(toSeq)) return bad('E_BAD_ARGS', 'from_seq and to_seq must be integers');
  if (fromSeq < 1 || toSeq < fromSeq) return bad('E_BAD_ARGS', `need 1 <= from_seq <= to_seq, got ${fromSeq}..${toSeq}`);
  if (toSeq > receipts.length) return bad('E_BAD_ARGS', `to_seq ${toSeq} exceeds chain length ${receipts.length}`);
  // An upgrade launders nothing: the FULL source chain must verify (any mode —
  // canary rows are exactly the point of upgrading) before any output is written.
  const audit = verifyChain('any');
  if (!audit.ok) return audit;

  const sourceBytes = fs.existsSync(STORE) ? fs.readFileSync(STORE) : Buffer.alloc(0);
  const sourceSha = createHash('sha256').update(sourceBytes).digest('hex');
  const sourceTip = audit.tip;
  const dialectsFrom = [...new Set(receipts.slice(fromSeq - 1, toSeq).map((r) => resolveDialect(r.dialect)))];

  let prev = GENESIS_PREV;
  const upgraded = [];
  for (let s = fromSeq; s <= toSeq; s++) {
    const src = receipts[s - 1];
    const seq = s - fromSeq + 1; // renumbered: new total order rooted at genesis
    const body = JSON.parse(JSON.stringify(src.body)); // byte-identical canonical body
    const id = dialectId(DEFAULT_DIALECT, seq, prev, body);
    const sig = receiptSig(id);
    upgraded.push({ seq, prev, body, id, sig, dialect: DEFAULT_DIALECT });
    prev = id;
  }

  const name = `upgrade-${fromSeq}-${toSeq}-${sourceSha.slice(0, 8)}.jsonl`;
  const outDir = path.join(path.dirname(STORE), 'upgrades');
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, name);
  const manifestPath = path.join(outDir, name.replace(/\.jsonl$/, '.manifest.json'));
  const manifest = {
    source_store: STORE,
    source_sha256: sourceSha,
    from_seq: fromSeq,
    to_seq: toSeq,
    rows: upgraded.length,
    source_tip: sourceTip,
    upgraded_tip: prev,
    dialect_from: dialectsFrom,
    dialect_to: DEFAULT_DIALECT,
    generator: 'quilt-mcp-receipts upgrade_chain v0.3.0',
    spec: 'docs/qmr2-design.md §5',
  };
  fs.writeFileSync(outPath, upgraded.map((r) => JSON.stringify(r)).join('\n') + '\n');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  return {
    ok: true,
    rows_upgraded: upgraded.length,
    from_seq: fromSeq,
    to_seq: toSeq,
    source_tip: sourceTip,
    upgraded_tip: prev,
    source_sha256: sourceSha,
    out: outPath,
    manifest: manifestPath,
  };
}

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
      'Self-audit: re-derive the full hash chain from genesis (structure, seq, prev linkage, id recomputation, signature). ' +
      'Returns {ok:true, count, tip} or fails closed with a named error code (E_PREV_MISMATCH, E_HASH_MISMATCH, E_BAD_SIGNATURE, …) at the first broken row. ' +
      'Optional dialect_mode (qmr2): "any" (default) verifies each row under its own dialect; "custody" enforces the law — any fnv1a-canary row fails E_DIALECT_FORBIDDEN. ' +
      'Optional keyring (v3): {fingerprint → publicKeyPem} — ed25519-signed rows verify under the keyring and refuse E_UNKNOWN_SIGNER if their signer is absent.',
    inputSchema: {
      type: 'object',
      properties: {
        dialect_mode: { type: 'string', enum: ['any', 'custody'], default: 'any', description: 'custody asserts the chain is a custody chain (E_DIALECT_FORBIDDEN on canary rows)' },
        keyring: { type: 'object', description: 'v3 attribution: {fingerprint → publicKeyPem}; ed25519 rows require their signer here (E_UNKNOWN_SIGNER otherwise)', additionalProperties: { type: 'string' } },
      },
    },
  },
  {
    name: 'append_receipt',
    description:
      'Commit one receipt to the chain. The client builds and signs the full receipt {seq, prev, body, id, sig} per the qmr1 dialect (DESIGN.md): ' +
      'id = sha256("qmr1:"+seq+":"+prev+":"+canonicalJSON(body)); sig = HMAC-SHA256(secret, "qmr1:sig:"+id). ' +
      'qmr2: the row MAY carry dialect ("sha256-custody" default on read | "fnv1a-canary"); unknown names are rejected E_UNKNOWN_DIALECT. ' +
      'v3: the row MAY instead carry sigAlg:"ed25519" + sigKeyFp (Ed25519 over "qmr1:sig:"+id, 128-hex); the arguments MUST then include a keyring proving that signer, else E_UNKNOWN_SIGNER. ' +
      'Validation is fail-closed with named errors; nothing invalid is ever written.',
    inputSchema: {
      type: 'object',
      properties: {
        receipt: { type: 'object', description: 'complete receipt incl. seq/prev/id/sig; optional qmr2 dialect tag; optional v3 sigAlg+sigKeyFp' },
        keyring: { type: 'object', description: 'v3: {fingerprint → publicKeyPem} — required to append ed25519-signed rows', additionalProperties: { type: 'string' } },
      },
      required: ['receipt'],
    },
  },
];

const QMR2_TOOLS = [
  {
    name: 'dialects',
    description:
      'The qmr2 dialect registry: the two registered hash dialects, the portable preimage, and THE law (custody chains MUST use sha256-custody, enforced E_DIALECT_FORBIDDEN). Spec: docs/qmr2-design.md.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'upgrade_chain',
    description:
      'Re-hash-upgrade rows [from_seq..to_seq] into a NEW standalone sha256-custody receipt set under upgrades/ (bodies byte-identical, seqs renumbered from genesis, deterministic output, source store never mutated). Refuses fail-closed if the source chain does not verify.',
    inputSchema: {
      type: 'object',
      properties: {
        from_seq: { type: 'integer', minimum: 1 },
        to_seq: { type: 'integer', minimum: 1 },
      },
      required: ['from_seq', 'to_seq'],
    },
  },
];

// v3 attribution tool (docs/qmr2-design.md §8) — same versioned-capability
// pattern as qmr2: advertise only under --v3 / env V3=1, so the v1 (3 tools)
// and qmr2 (5 tools) tool-name contracts pinned by the untouched suites hold.
const V3 = argv.includes('--v3') || (process.env.V3 !== undefined && process.env.V3 !== '' && process.env.V3 !== '0');

const V3_TOOLS = [
  {
    name: 'verify_attribution',
    description:
      'v3 attribution: verify the chain under a keyring {fingerprint → publicKeyPem} (fail-closed, E_UNKNOWN_SIGNER) and report WHO signed each row — ' +
      'ed25519 rows name their signer by fingerprint, hmac rows report the honest residual (one anonymous writer). Spec: docs/qmr2-design.md §8.',
    inputSchema: {
      type: 'object',
      properties: {
        keyring: { type: 'object', description: '{fingerprint → publicKeyPem} — ed25519 rows require their signer here', additionalProperties: { type: 'string' } },
      },
    },
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

function toolVerify(args) {
  const mode = args && args.dialect_mode !== undefined ? args.dialect_mode : 'any';
  if (mode !== 'any' && mode !== 'custody') {
    return { isError: true, payload: { ok: false, error: 'E_BAD_ARGS', detail: `dialect_mode must be "any" or "custody", got ${JSON.stringify(mode)}` } };
  }
  const keyring = args && args.keyring !== undefined ? args.keyring : null;
  const result = verifyChain({ dialect_mode: mode, keyring });
  return { isError: result.ok !== true, payload: result };
}

function toolAppend(args) {
  if (!args || typeof args !== 'object' || !('receipt' in args)) {
    return { isError: true, payload: { ok: false, error: 'E_MISSING_FIELD', detail: 'arguments.receipt is required' } };
  }
  const keyring = args.keyring !== undefined ? args.keyring : null;
  const verdict = validateAppend(args.receipt, keyring);
  if (verdict.error) return { isError: true, payload: { ok: false, ...verdict } };
  const r = args.receipt;
  // Write what the client submitted: qmr1 rows stay five-field (never inject a
  // dialect tag), dialect-tagged rows keep their tag verbatim, and v3 rows keep
  // sigAlg/sigKeyFp verbatim — never rewrite, never inject (never-delete-data
  // applies to SHAPE too).
  const row = { seq: r.seq, prev: r.prev, body: r.body, id: r.id, sig: r.sig };
  if (r.dialect !== undefined) row.dialect = r.dialect;
  if (r.sigAlg !== undefined) row.sigAlg = r.sigAlg;
  if (r.sigKeyFp !== undefined) row.sigKeyFp = r.sigKeyFp;
  appendLine(row);
  return { isError: false, payload: { ok: true, seq: r.seq, id: r.id, tip: r.id, dialect: verdict.dialect, sigAlg: verdict.sigAlg } };
}

function toolDialects() {
  return { isError: false, payload: { ok: true, ...REGISTRY_INFO } };
}

// v3 attribution (docs/qmr2-design.md §8): WHO signed each row, per the
// keyring. The chain must FULLY verify under that keyring first (the same
// fail-closed law as verify_chain — E_UNKNOWN_SIGNER included); only then is
// the per-row attribution report produced. HMAC rows report the honest
// residual: a shared secret has one anonymous writer.
function toolAttribution(args) {
  const keyring = args && args.keyring !== undefined ? args.keyring : null;
  const badKeyring = keyringError(keyring);
  if (badKeyring) return { isError: true, payload: { ok: false, ...badKeyring } };
  const verdict = verifyChain({ dialect_mode: 'any', keyring });
  if (!verdict.ok) return { isError: true, payload: verdict };
  const { receipts } = loadStore();
  const attribution = receipts.map((r) => {
    if (r.sigAlg === 'ed25519') {
      const known = keyring !== null && r.sigKeyFp in keyring;
      return {
        seq: r.seq,
        sigAlg: 'ed25519',
        sigKeyFp: r.sigKeyFp,
        signedBy: known
          ? { fingerprint: r.sigKeyFp, verified: true, source: 'keyring' }
          : { fingerprint: r.sigKeyFp, verified: false, reason: 'E_UNKNOWN_SIGNER' },
      };
    }
    return {
      seq: r.seq,
      sigAlg: 'hmac-sha256',
      sigKeyFp: null,
      signedBy: { fingerprint: null, verified: true, note: 'shared-secret HMAC — one anonymous writer; the honest residual (v3 adds per-signer identity)' },
    };
  });
  const payload = {
    ok: true,
    count: verdict.count,
    tip: verdict.tip,
    keyring_size: keyring ? Object.keys(keyring).length : 0,
    attribution,
    law: 'the chain verifies under the keyring first (E_UNKNOWN_SIGNER is fail-closed); sigKeyFp = sha256 of the signer\'s SPKI PEM — the same fingerprint law as quilt-jev-toolkit organ v3',
    spec: 'docs/qmr2-design.md §8',
  };
  return { isError: false, payload };
}

function toolUpgrade(args) {
  const from = args && args.from_seq;
  const to = args && args.to_seq;
  const result = upgradeChain(from, to);
  return { isError: result.ok !== true, payload: result };
}

function callTool(name, args) {
  switch (name) {
    case 'read_receipts': return toolRead(args);
    case 'verify_chain': return toolVerify(args);
    case 'append_receipt': return toolAppend(args);
    case 'dialects': return QMR2 ? toolDialects() : null;
    case 'upgrade_chain': return QMR2 ? toolUpgrade(args) : null;
    case 'verify_attribution': return V3 ? toolAttribution(args) : null;
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
      // Additive qmr2 field: the dialect registry + the law ride along on every
      // tools/list result (v1 clients read `tools`, qmr2 clients read `dialects`).
      // The two qmr2 TOOLS are listed only in qmr2 mode (--qmr2 / env QMR2=1);
      // the v3 attribution tool only under --v3 / env V3=1 (same pattern).
      return result(id, { tools: [...TOOLS, ...(QMR2 ? QMR2_TOOLS : []), ...(V3 ? V3_TOOLS : [])], dialects: REGISTRY_INFO });
    case 'tools/call': {
      const name = params && params.name;
      if (typeof name !== 'string') return errorReply(id, ERR_INVALID_PARAMS, 'params.name must be a string');
      const activeTools = [...TOOLS, ...(QMR2 ? QMR2_TOOLS : []), ...(V3 ? V3_TOOLS : [])];
      if (!activeTools.some((t) => t.name === name)) return errorReply(id, ERR_INVALID_PARAMS, `unknown tool: ${name}`);
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
