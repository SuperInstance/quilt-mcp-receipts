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
// Dialect cases (unknown-dialect, custody-law) run only when the adapter
// declares `features.dialects: true`; a qmr1-class vendor sets it false and the
// report marks those cases `skipped` (visible, honest — never silently dropped).
//
// Zero dependencies. No clock, no randomness: verdicts are deterministic.
//
// Vendoring pattern (README carries the full walkthrough):
//   import { runConformance } from './conformance.mjs';
//   const verdict = await runConformance(myAdapter);
//   assert.equal(verdict.ok, true);

const CANON = {
  HASH: 'E_HASH_MISMATCH',
  SIG: 'E_BAD_SIGNATURE',
  SEQ: 'E_SEQ_MISMATCH',
  UNKNOWN_DIALECT: 'E_UNKNOWN_DIALECT',
  BODY: 'E_BODY_INVALID',
  FORBIDDEN: 'E_DIALECT_FORBIDDEN',
};

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

  // Convenience: sign + submit one receipt at the current chain head.
  async function appendNext(body, opts = {}) {
    const tip = (await adapter.readTip()) ?? GENESIS_PREV;
    const seq = (await adapter.rows()).length + 1;
    const receipt = adapter.makeReceipt(seq, tip, body, opts);
    return adapter.appendRaw(receipt);
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

  const ok = cases.every((c) => c.ok);
  return { ok, adapter: adapter.name ?? 'unnamed', harness: 'test/conformance.mjs (qmr2 battery)', cases, skipped };
}
