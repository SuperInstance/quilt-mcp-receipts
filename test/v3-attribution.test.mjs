// test/v3-attribution.test.mjs — the v3 sig slot: sigAlg:"ed25519" + sigKeyFp,
// the keyring, E_UNKNOWN_SIGNER fail-closed, and verify_attribution.
// Spec: docs/qmr2-design.md §8. The qmr1 suite (test/mcp.test.mjs) and the
// qmr2 suite (test/qmr2.test.mjs) stay untouched — their contracts are pinned.
//
// Honesty notes: the signer below is an INDEPENDENT re-derivation of §8, not an
// import from server.mjs. KEY HYGIENE: the keypair is generated AT TEST TIME
// (generateKeyPairSync) and never written to disk — committed static key files
// are forbidden; fingerprints in assertions are computed, never hardcoded.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, createPublicKey, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { McpClient } from './mcp-client.mjs';

const GENESIS_PREV = '0'.repeat(64);

function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}

// THE FINGERPRINT LAW (docs/qmr2-design.md §8.2 — sha256 of the normalized
// SPKI PEM; the same law as quilt-jev-toolkit organ v3)
const norm = (pem) => createPublicKey(pem).export({ type: 'spki', format: 'pem' }).toString();
const fingerprint = (pem) => createHash('sha256').update(norm(pem), 'utf8').digest('hex');

const keygen = () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = norm(publicKey.export({ type: 'spki', format: 'pem' }));
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  return { publicKeyPem, privateKeyPem, fp: fingerprint(publicKeyPem) };
};

const body = (note) => ({ kind: 'v3.test', ts: '2026-10-02T18:00:00Z', note });

function makeEd25519Receipt(seq, prev, signer, note) {
  const b = body(note);
  const id = createHash('sha256').update(`qmr1:${seq}:${prev}:${canonicalJSON(b)}`).digest('hex');
  const sig = cryptoSign(null, Buffer.from(`qmr1:sig:${id}`, 'utf8'), signer.privateKeyPem).toString('hex');
  return { seq, prev, body: b, id, sig, sigAlg: 'ed25519', sigKeyFp: signer.fp };
}

const newClient = (opts) => new McpClient({ ...opts, env: { MCP_RECEIPT_SECRET: SELF_SECRET_V3 } });
// reuse the qmr2 suite's convention: an INDEPENDENT dev secret handed via env
import { createHash as _ch } from 'node:crypto'; void _ch;
const SELF_SECRET_V3 = 'v3-attribution-test-secret-not-a-real-key';

// ---- 0. tool surface is versioned: verify_attribution advertises only under --v3
test('v3 tool surface: verify_attribution in tools/list only under --v3; the v1/qmr2 tool lists are unchanged', async () => {
  const bare = newClient({});
  await bare.handshake();
  const bareList = await bare.request('tools/list', {});
  const bareNames = bareList.tools.map((t) => t.name);
  assert.ok(!bareNames.includes('verify_attribution'), 'v3 gate closed by default');
  await bare.stop();

  const c = newClient({ v3: true });
  await c.handshake();
  const list = await c.request('tools/list', {});
  const names = list.tools.map((t) => t.name);
  assert.ok(names.includes('verify_attribution'), 'v3 gate opens under --v3');
  // the pre-existing contracts ride along unchanged
  assert.ok(names.includes('append_receipt') && names.includes('verify_chain') && names.includes('read_receipts'));
  await c.stop();
});

// ---- 1. the additive row verifies; the fingerprint law holds ----------------
test('v3 ed25519 row: append + verify_chain under the keyring; sigKeyFp is sha256 of the SPKI PEM', async () => {
  const signer = keygen();
  const c = newClient({ v3: true });
  await c.handshake();
  const a = await c.callTool('append_receipt', {
    receipt: makeEd25519Receipt(1, GENESIS_PREV, signer, 'the scar carries a name'),
    keyring: { [signer.fp]: signer.publicKeyPem },
  });
  assert.equal(a.isError, false);
  assert.equal(a.payload.sigAlg, 'ed25519');
  const v = await c.callTool('verify_chain', { keyring: { [signer.fp]: signer.publicKeyPem } });
  assert.equal(v.payload.ok, true);
  assert.equal(v.payload.count, 1);
  await c.stop();
});

// ---- 2. verify_attribution: WHO signed each row ------------------------------
test('v3 verify_attribution: the chain verifies under the keyring first, then names every signer', async () => {
  const signer = keygen();
  const c = newClient({ v3: true });
  await c.handshake();
  await c.callTool('append_receipt', {
    receipt: makeEd25519Receipt(1, GENESIS_PREV, signer, 'named row'),
    keyring: { [signer.fp]: signer.publicKeyPem },
  });
  const res = await c.callTool('verify_attribution', { keyring: { [signer.fp]: signer.publicKeyPem } });
  assert.equal(res.isError, false);
  assert.equal(res.payload.ok, true);
  assert.equal(res.payload.count, 1);
  assert.equal(res.payload.attribution[0].sigAlg, 'ed25519');
  assert.equal(res.payload.attribution[0].sigKeyFp, signer.fp);
  assert.equal(res.payload.attribution[0].signedBy.fingerprint, signer.fp);
  assert.equal(res.payload.attribution[0].signedBy.verified, true);
  // a broken keyring is refused before any row is read
  const bad = await c.callTool('verify_attribution', { keyring: { ['b'.repeat(64)]: signer.publicKeyPem } });
  assert.equal(bad.payload.error, 'E_BAD_KEYRING');
  await c.stop();
});

// ---- 3. E_UNKNOWN_SIGNER is fail-closed --------------------------------------
test('v3 E_UNKNOWN_SIGNER: no keyring → refuse; unknown fingerprint → refuse; mislabeled keyring → E_BAD_KEYRING', async () => {
  const signer = keygen();
  const other = keygen();
  const c = newClient({ v3: true });
  await c.handshake();
  // append itself refuses without a keyring (never accepts a row it cannot attribute)
  const noRing = await c.callTool('append_receipt', { receipt: makeEd25519Receipt(1, GENESIS_PREV, signer, 'x') });
  assert.equal(noRing.payload.error, 'E_UNKNOWN_SIGNER');
  // with the keyring the row lands
  const ok = await c.callTool('append_receipt', {
    receipt: makeEd25519Receipt(1, GENESIS_PREV, signer, 'y'),
    keyring: { [signer.fp]: signer.publicKeyPem },
  });
  assert.equal(ok.isError, false);
  // verify without a keyring → E_UNKNOWN_SIGNER
  const v0 = await c.callTool('verify_chain', {});
  assert.equal(v0.payload.error, 'E_UNKNOWN_SIGNER');
  // a keyring holding a DIFFERENT key → E_UNKNOWN_SIGNER
  const v1 = await c.callTool('verify_chain', { keyring: { [other.fp]: other.publicKeyPem } });
  assert.equal(v1.payload.error, 'E_UNKNOWN_SIGNER');
  // a MISLABELED keyring (right key, wrong fingerprint label) → E_BAD_KEYRING
  const v2 = await c.callTool('verify_chain', { keyring: { ['b'.repeat(64)]: signer.publicKeyPem } });
  assert.equal(v2.payload.error, 'E_BAD_KEYRING');
  await c.stop();
});

// ---- 4. forged sig → E_BAD_SIGNATURE under the right key ---------------------
test('v3 E_BAD_SIGNATURE: a flipped sig refuses append and verify even when the signer is known', async () => {
  const signer = keygen();
  const c = newClient({ v3: true });
  await c.handshake();
  const r = makeEd25519Receipt(1, GENESIS_PREV, signer, 'honest');
  const forged = { ...r, sig: r.sig.slice(0, -1) + (r.sig.endsWith('0') ? '1' : '0') };
  const f = await c.callTool('append_receipt', { receipt: forged, keyring: { [signer.fp]: signer.publicKeyPem } });
  assert.equal(f.payload.error, 'E_BAD_SIGNATURE');
  const v = await c.callTool('verify_chain', { keyring: { [signer.fp]: signer.publicKeyPem } });
  assert.equal(v.payload.ok, true, 'the store still holds only honest rows; the forged row never landed');
  await c.stop();
});

// ---- 5. qmr1 shape is untouched ----------------------------------------------
test('v3 qmr1 rows byte-unchanged: no sigAlg/sigKeyFp injected; keyring does not disturb hmac rows; sigKeyFp on hmac row refused', async () => {
  const signer = keygen();
  const c = newClient({ v3: true });
  await c.handshake();
  const b = body('qmr1 row');
  const id = createHash('sha256').update(`qmr1:1:${GENESIS_PREV}:${canonicalJSON(b)}`).digest('hex');
  const hmac = { seq: 1, prev: GENESIS_PREV, body: b, id, sig: createHmac('sha256', SELF_SECRET_V3).update(`qmr1:sig:${id}`).digest('hex') };
  await c.callTool('append_receipt', { receipt: hmac, keyring: { [signer.fp]: signer.publicKeyPem } });
  const read = await c.callTool('read_receipts', {});
  const row = read.payload.receipts[0];
  assert.equal(row.sigAlg, undefined, 'no sigAlg injected');
  assert.equal(row.sigKeyFp, undefined, 'no sigKeyFp injected');
  assert.deepEqual(Object.keys(row).sort(), ['body', 'id', 'prev', 'seq', 'sig'], 'qmr1 five-field shape preserved');
  const v = await c.callTool('verify_chain', { keyring: { [signer.fp]: signer.publicKeyPem } });
  assert.equal(v.payload.ok, true, 'hmac rows ignore the keyring');
  // sigKeyFp on an hmac row is a shape violation, not a signature failure
  const badShape = makeEd25519Receipt(2, id, signer, 'mixed');
  delete badShape.sigAlg;
  const refused = await c.callTool('append_receipt', { receipt: badShape, keyring: { [signer.fp]: signer.publicKeyPem } });
  assert.equal(refused.payload.error, 'E_SIGNER_MALFORMED');
  await c.stop();
});

// ---- 6. unknown sigAlg refuses (the registry is the law) ----------------------
test('v3 E_UNKNOWN_SIGALG: an unregistered sigAlg is refused, never coerced', async () => {
  const signer = keygen();
  const c = newClient({ v3: true });
  await c.handshake();
  const r = makeEd25519Receipt(1, GENESIS_PREV, signer, 'rsa-larp');
  r.sigAlg = 'RSA-SHA256';
  const res = await c.callTool('append_receipt', { receipt: r, keyring: { [signer.fp]: signer.publicKeyPem } });
  assert.equal(res.payload.error, 'E_UNKNOWN_SIGALG');
  await c.stop();
});
