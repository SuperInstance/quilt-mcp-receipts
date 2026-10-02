// test/conformance.mjs — THE shared tamper-conformance harness for fleet
// receipt chains (qmr2 distill, docs/qmr2-design.md §6).
//
// The wave-66 seed-dna census found the tamper/verify battery re-proven ~8×
// across the fleet. This file retires those re-implementations: ONE battery,
// vendored verbatim (copy this file into your repo, or import it), driven by a
// ~40-line adapter YOUR repo writes once.
//
// THE NAMED FAIL-CLOSED LAW it proves, per adapter:
//   tamper trio     body flip   → E_HASH_MISMATCH, localized at_seq
//                   sig flip    → E_BAD_SIGNATURE
//                   row delete  → E_SEQ_MISMATCH at the hole
//   replay          old receipt re-submitted → E_SEQ_MISMATCH
//   wrong-secret    receipt signed under a foreign key → E_BAD_SIGNATURE
//   unknown-dialect row tagged with an unregistered dialect → E_UNKNOWN_DIALECT
//   empty-body      body without kind / empty kind → E_BODY_INVALID
//   custody-law     canary chain verify'd in custody mode → E_DIALECT_FORBIDDEN
//   determinism     same ops → same tips
//   clean-chain     positive control: honest appends verify ok
//
// v3 SIG CASES (§9 — Ed25519 attribution, docs/qmr2-design.md §8; opt-in via
// `features.v3`, exactly the dialects gate):
//   v3-clean         Ed25519 row appends and verifies under its keyring (control —
//                    without it the fail-closed trio could pass vacuously against
//                    an adapter that refuses EVERY ed25519 row)
//   v3-wrong-key     sig minted by an impostor's private key while the row names
//                    the honest signer's fingerprint → E_BAD_SIGNATURE at the door
//   v3-unknown-signer honest Ed25519 row, keyring missing that fingerprint (or
//                    absent entirely) → E_UNKNOWN_SIGNER, fail-closed
//   v3-forged-sig    landed Ed25519 row, sig flipped behind the API →
//                    E_BAD_SIGNATURE localized at_seq
//   v3-qmr1-shape    the qmr1 five-field shape is UNCHANGED by the v3 layer —
//                    no sigAlg/sigKeyFp injected, keyring does not disturb hmac rows
//   v3-tool-gating   the versioned tool surface lists the base trio always and
//                    verify_attribution iff features.v3 (runs whenever the
//                    adapter exposes listTools(), regardless of the sig gate)
//
// Adapter contract for the v3 cases: makeReceipt opts gain
//   { sigAlg:'ed25519', signer:{privateKeyPem, publicKeyPem, fp}, signWith?, keyring? }
// (signWith = mint the sig with a DIFFERENT private key than the claimed
// fingerprint — the impostor path; keyring rides into appendRaw + verify).
// The harness mints identities AT RUNTIME (node:crypto, test-time keys only —
// never committed) and NEVER signs itself: signing is the adapter's law under
// test. Keygen is random, but every verdict is structural (ok / named error /
// at_seq), so conformance outcomes remain deterministic.
//
// Dialect cases (unknown-dialect, custody-law) run only when the adapter
// declares `features.dialects: true`; a qmr1-class vendor sets it false and the
// report marks those cases `skipped` (visible, honest — never silently dropped).
// Same law for `features.v3` and the five sig cases: undeclared = the FULL
// battery is attempted, so a vendor below the fleet's current law fails loudly
// and must declare its level.
//
// Zero dependencies. No clock: verdicts are deterministic.
//
// Vendoring pattern (README carries the full walkthrough):
//   import { runConformance } from './conformance.mjs';
//   const verdict = await runConformance(myAdapter);
//   assert.equal(verdict.ok, true);

import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';

const CANON = {
  HASH: 'E_HASH_MISMATCH',
  SIG: 'E_BAD_SIGNATURE',
  SEQ: 'E_SEQ_MISMATCH',
  UNKNOWN_DIALECT: 'E_UNKNOWN_DIALECT',
  BODY: 'E_BODY_INVALID',
  FORBIDDEN: 'E_DIALECT_FORBIDDEN',
  UNKNOWN_SIGNER: 'E_UNKNOWN_SIGNER',
};

// The v3 case names, in the order they skip (the report's skip list is a
// contract — visible, ordered, honest).
const V3_CASES = ['v3-clean', 'v3-wrong-key', 'v3-unknown-signer', 'v3-forged-sig', 'v3-qmr1-shape'];

// --- runtime identity minting (test-time keys only; the harness NEVER signs) --
// THE FINGERPRINT LAW (qmr2 §8.2 = organ v3, shared byte-for-byte across the
// fleet): sha256 over the normalized SPKI PEM. Independently re-derived here —
// importing it from the host would verify the implementation against itself.
function spkiNorm(pem) {
  return createPublicKey(pem).export({ type: 'spki', format: 'pem' }).toString();
}
function fingerprintOf(pem) {
  return createHash('sha256').update(spkiNorm(pem), 'utf8').digest('hex');
}
function mintIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = spkiNorm(publicKey.export({ type: 'spki', format: 'pem' }));
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  return { privateKeyPem, publicKeyPem, fp: fingerprintOf(publicKeyPem) };
}

// Fixed bodies: no clock, no randomness — determinism must hold byte-for-byte.
const OP_BODIES = [
  { kind: 'conformance.op.append', ts: '2026-10-02T00:00:00Z', note: 'op-1' },
  { kind: 'conformance.op.append', ts: '2026-10-02T00:00:01Z', note: 'op-2' },
  { kind: 'conformance.op.append', ts: '2026-10-02T00:00:02Z', note: 'op-3' },
];

// Genesis prev is dialect-independent qmr law (docs/qmr2-design.md §1).
const GENESIS_PREV = '0'.repeat(64);

function flipHexChar(s) {
  const i = Math.floor(s.length / 2);
  const c = s[i];
  const flipped = c >= '0' && c < '9' ? String.fromCharCode(c.charCodeAt(0) + 1) : '0';
  return s.slice(0, i) + flipped + s.slice(i + 1);
}

export async function runConformance(adapter) {
  if (!adapter || typeof adapter !== 'object') throw new Error('runConformance: adapter object required');
  const required = ['reset', 'makeReceipt', 'appendRaw', 'verify', 'readTip', 'rows', 'rewrite'];
  for (const m of required) {
    if (typeof adapter[m] !== 'function') throw new Error(`runConformance: adapter.${m} must be a function`);
  }
  const errMap = adapter.errorMap ?? {};
  const canon = (code) => errMap[code] ?? code; // adapter-side legacy name → canonical name
  const dialectsOn = !adapter.features || adapter.features.dialects !== false;
  const cases = [];
  const skipped = [];

  const record = (name, ok, extra = {}) => cases.push({ name, ok, ...extra });

  // Convenience: sign + submit one receipt at the current chain head. v3 opts
  // (sigAlg/signer/signWith) flow into makeReceipt; keyring flows into appendRaw.
  async function appendNext(body, opts = {}) {
    const tip = (await adapter.readTip()) ?? GENESIS_PREV;
    const seq = (await adapter.rows()).length + 1;
    const receipt = adapter.makeReceipt(seq, tip, body, opts);
    return adapter.appendRaw(receipt, opts);
  }

  // Seed `n` honest receipts; returns their receipts.
  async function seed(n) {
    const out = [];
    for (let i = 0; i < n; i++) {
      const tip = (await adapter.readTip()) ?? GENESIS_PREV;
      const seq = (await adapter.rows()).length + 1;
      const receipt = adapter.makeReceipt(seq, tip, OP_BODIES[i % OP_BODIES.length], {});
      const res = await adapter.appendRaw(receipt);
      if (!res || res.ok !== true) throw new Error(`seed append failed: ${JSON.stringify(res)}`);
      out.push(receipt);
    }
    return out;
  }

  // ---- 0. positive control --------------------------------------------------
  {
    await adapter.reset();
    await seed(3);
    const v = await adapter.verify({});
    const tipAfter = await adapter.readTip();
    record('clean-chain', v && v.ok === true && typeof tipAfter === 'string',
      { got: v && v.ok ? `ok, tip ${String(tipAfter).slice(0, 12)}…` : JSON.stringify(v), want: 'verify ok with a non-null tip' });
  }

  // ---- 1. tamper trio -------------------------------------------------------
  {
    // body flip → E_HASH_MISMATCH localized at_seq
    await adapter.reset();
    await seed(3);
    const rows = await adapter.rows();
    rows[1].body.note = 'tampered by the conformance harness, not by fate';
    await adapter.rewrite(rows);
    const v = await adapter.verify({});
    record('body-flip', v && v.ok === false && canon(v.error) === CANON.HASH && v.at_seq === 2,
      { got: JSON.stringify(v && { error: v.error, at_seq: v.at_seq }), want: `${CANON.HASH} at_seq 2` });
  }
  {
    // sig flip → E_BAD_SIGNATURE
    await adapter.reset();
    await seed(2);
    const rows = await adapter.rows();
    rows[0].sig = flipHexChar(rows[0].sig);
    await adapter.rewrite(rows);
    const v = await adapter.verify({});
    record('sig-flip', v && v.ok === false && canon(v.error) === CANON.SIG && v.at_seq === 1,
      { got: JSON.stringify(v && { error: v.error, at_seq: v.at_seq }), want: `${CANON.SIG} at_seq 1` });
  }
  {
    // row deletion → E_SEQ_MISMATCH at the hole
    await adapter.reset();
    await seed(3);
    const rows = await adapter.rows();
    rows.splice(1, 1); // delete row 2 entirely
    await adapter.rewrite(rows);
    const v = await adapter.verify({});
    record('row-deletion', v && v.ok === false && canon(v.error) === CANON.SEQ && v.at_seq === 2,
      { got: JSON.stringify(v && { error: v.error, at_seq: v.at_seq }), want: `${CANON.SEQ} at_seq 2` });
  }

  // ---- 2. replay ------------------------------------------------------------
  {
    await adapter.reset();
    await seed(2);
    const rows = await adapter.rows();
    const v = await adapter.appendRaw(rows[0]); // a VALID past receipt, resubmitted verbatim
    record('replay', v && v.ok === false && canon(v.error) === CANON.SEQ,
      { got: JSON.stringify(v && { error: v.error }), want: CANON.SEQ });
  }

  // ---- 3. wrong-secret ------------------------------------------------------
  {
    await adapter.reset();
    await seed(1);
    const v = await appendNext(OP_BODIES[1], { secret: 'attacker-key-not-the-host-secret' });
    record('wrong-secret', v && v.ok === false && canon(v.error) === CANON.SIG,
      { got: JSON.stringify(v && { error: v.error }), want: CANON.SIG });
  }

  // ---- 4. unknown dialect (qmr2 layer) --------------------------------------
  if (!dialectsOn) {
    skipped.push('unknown-dialect');
  } else {
    await adapter.reset();
    await seed(1);
    const receipt = adapter.makeReceipt(2, (await adapter.readTip()) ?? GENESIS_PREV, OP_BODIES[1], {});
    receipt.dialect = 'no-such-dialect'; // unregistered name; id/sig do not bind the tag
    const v = await adapter.appendRaw(receipt);
    record('unknown-dialect', v && v.ok === false && canon(v.error) === CANON.UNKNOWN_DIALECT,
      { got: JSON.stringify(v && { error: v.error }), want: CANON.UNKNOWN_DIALECT });
  }

  // ---- 5. empty-body --------------------------------------------------------
  {
    await adapter.reset();
    await seed(1);
    const badBodies = [{ ts: '2026-10-02T00:00:00Z' }, { kind: '', ts: '2026-10-02T00:00:00Z' }];
    let allRejected = true;
    const got = [];
    for (const b of badBodies) {
      const v = await appendNext(b, {});
      got.push(v && v.error);
      if (!v || v.ok !== false || canon(v.error) !== CANON.BODY) allRejected = false;
    }
    record('empty-body', allRejected, { got: JSON.stringify(got), want: `${CANON.BODY} ×${badBodies.length}` });
  }

  // ---- 6. custody law (qmr2 layer) ------------------------------------------
  if (!dialectsOn) {
    skipped.push('custody-law');
  } else {
    // a canary chain is legal in "any" mode and FORBIDDEN in custody mode, by name
    await adapter.reset();
    for (let i = 0; i < 2; i++) {
      const tip = (await adapter.readTip()) ?? GENESIS_PREV;
      const seq = (await adapter.rows()).length + 1;
      const receipt = adapter.makeReceipt(seq, tip, OP_BODIES[i], { dialect: 'fnv1a-canary' });
      const res = await adapter.appendRaw(receipt);
      if (!res || res.ok !== true) throw new Error(`canary append failed: ${JSON.stringify(res)}`);
    }
    const vAny = await adapter.verify({});
    const vCustody = await adapter.verify({ dialect_mode: 'custody' });
    record('custody-law',
      vAny && vAny.ok === true &&
      vCustody && vCustody.ok === false && canon(vCustody.error) === CANON.FORBIDDEN && vCustody.at_seq === 1,
      { got: `any=${JSON.stringify(vAny && { ok: vAny.ok })} custody=${JSON.stringify(vCustody && { error: vCustody.error, at_seq: vCustody.at_seq })}`,
        want: 'any ok; custody E_DIALECT_FORBIDDEN at_seq 1' });
  }

  // ---- 7. determinism -------------------------------------------------------
  {
    await adapter.reset();
    await seed(3);
    const tip1 = await adapter.readTip();
    const rows1 = (await adapter.rows()).map((r) => JSON.stringify(r));
    await adapter.reset();
    await seed(3);
    const tip2 = await adapter.readTip();
    const rows2 = (await adapter.rows()).map((r) => JSON.stringify(r));
    record('determinism', tip1 === tip2 && rows1.join('\n') === rows2.join('\n'),
      { got: `tip1=${String(tip1).slice(0, 12)}… tip2=${String(tip2).slice(0, 12)}… rows_equal=${rows1.join('\n') === rows2.join('\n')}`,
        want: 'identical tips and identical rows for identical op sequences' });
  }

  // ---- 8. v3 attribution — the Ed25519 sig slot (features.v3 gate) -----------
  const v3On = !adapter.features || adapter.features.v3 !== false;
  if (!v3On) {
    skipped.push(...V3_CASES);
  } else {
    const signer = mintIdentity();   // the honest signer the rows will name
    const impostor = mintIdentity(); // a DIFFERENT key the rows must not verify under
    const ring = { [signer.fp]: signer.publicKeyPem };

    // 8a. positive control: an Ed25519 row lands and verifies under its keyring
    //     (without this control, the fail-closed trio below could pass vacuously
    //     against an adapter that refuses every ed25519 row)
    {
      await adapter.reset();
      await seed(1);
      const a = await appendNext(OP_BODIES[1], { sigAlg: 'ed25519', signer, keyring: ring });
      const v = await adapter.verify({ keyring: ring });
      record('v3-clean', a && a.ok === true && v && v.ok === true,
        { got: JSON.stringify({ append: a && { ok: a.ok, error: a.error }, verify: v && { ok: v.ok, error: v.error } }),
          want: 'append ok; verify ok under the signer keyring' });
    }

    // 8b. wrong-key: the sig is minted by the impostor's private key while the
    //     row CLAIMS the honest signer's fingerprint — refused at the door
    //     (append never accepts a row it cannot attribute)
    {
      await adapter.reset();
      await seed(1);
      const v = await appendNext(OP_BODIES[1], {
        sigAlg: 'ed25519', signer, signWith: impostor.privateKeyPem, keyring: ring,
      });
      record('v3-wrong-key', v && v.ok === false && canon(v.error) === CANON.SIG,
        { got: JSON.stringify(v && { error: v.error }), want: CANON.SIG });
    }

    // 8c. keyring missing the signer's fingerprint → E_UNKNOWN_SIGNER,
    //     fail-closed, both species: no keyring at all, and a keyring holding
    //     only a foreign key. (An unverifiable signer is an unknown signer.)
    {
      await adapter.reset();
      await seed(1);
      const a = await appendNext(OP_BODIES[1], { sigAlg: 'ed25519', signer, keyring: ring });
      if (!a || a.ok !== true) throw new Error(`v3-unknown-signer setup failed: ${JSON.stringify(a)}`);
      const foreignRing = { [impostor.fp]: impostor.publicKeyPem };
      const v0 = await adapter.verify({});
      const v1 = await adapter.verify({ keyring: foreignRing });
      record('v3-unknown-signer',
        v0 && v0.ok === false && canon(v0.error) === CANON.UNKNOWN_SIGNER &&
        v1 && v1.ok === false && canon(v1.error) === CANON.UNKNOWN_SIGNER,
        { got: JSON.stringify({ noKeyring: v0 && { error: v0.error }, foreignOnly: v1 && { error: v1.error } }),
          want: `${CANON.UNKNOWN_SIGNER} with no keyring and with a foreign-only keyring` });
    }

    // 8d. forged sig: a landed Ed25519 row's sig flipped behind the API →
    //     E_BAD_SIGNATURE localized at_seq (the tamper-trio sig-flip, v3 edition)
    {
      await adapter.reset();
      await seed(1);
      const a = await appendNext(OP_BODIES[1], { sigAlg: 'ed25519', signer, keyring: ring });
      if (!a || a.ok !== true) throw new Error(`v3-forged-sig setup failed: ${JSON.stringify(a)}`);
      const rows = await adapter.rows();
      rows[1].sig = flipHexChar(rows[1].sig);
      await adapter.rewrite(rows);
      const v = await adapter.verify({ keyring: ring });
      record('v3-forged-sig', v && v.ok === false && canon(v.error) === CANON.SIG && v.at_seq === 2,
        { got: JSON.stringify(v && { error: v.error, at_seq: v.at_seq }), want: `${CANON.SIG} at_seq 2` });
    }

    // 8e. the qmr1 five-field shape is UNCHANGED by the v3 layer: makeReceipt
    //     without v3 opts produces exactly {seq,prev,body,id,sig}, and a keyring
    //     must not disturb hmac rows (they ignore it)
    {
      await adapter.reset();
      const tip = (await adapter.readTip()) ?? GENESIS_PREV;
      const receipt = adapter.makeReceipt(1, tip, OP_BODIES[0], {});
      const fiveField = !!receipt && Object.keys(receipt).sort().join(',') === 'body,id,prev,seq,sig';
      await adapter.reset();
      await seed(1);
      const v = await adapter.verify({ keyring: ring });
      record('v3-qmr1-shape',
        fiveField && v && v.ok === true,
        { got: JSON.stringify({ keys: receipt ? Object.keys(receipt).sort() : null, verifyWithKeyring: v && { ok: v.ok, error: v.error } }),
          want: 'exactly [body,id,prev,seq,sig]; verify ok with a keyring present' });
    }
  }

  // ---- 9. v3 tool gating — the versioned tool surface ------------------------
  // The base trio is listed ALWAYS; verify_attribution is listed IFF the host's
  // v3 gate is open (features.v3). Runs whenever the adapter exposes listTools(),
  // regardless of the sig gate — a host that lists verify_attribution while
  // declaring v3:false (or the reverse) is lying about its own surface.
  if (typeof adapter.listTools !== 'function') {
    skipped.push('v3-tool-gating');
  } else {
    const names = await adapter.listTools();
    const base = ['append_receipt', 'read_receipts', 'verify_chain'].every((t) => names.includes(t));
    const v3Listed = names.includes('verify_attribution');
    record('v3-tool-gating', base && v3Listed === v3On,
      { got: JSON.stringify({ names, v3Listed, featuresV3: v3On }),
        want: `base trio always listed; verify_attribution listed iff features.v3 (${v3On})` });
  }

  const ok = cases.every((c) => c.ok);
  return { ok, adapter: adapter.name ?? 'unnamed', harness: 'test/conformance.mjs (qmr2 battery)', cases, skipped };
}
