#!/usr/bin/env node
// scripts/dogfood.mjs — the qmr2 dogfood run (wave 67-b).
//
// 1. Runs the shared tamper-conformance harness (test/conformance.mjs) against
//    this server through the stdio-MCP adapter (test/adapter-self.mjs) — the
//    harness's first customer is its own host.
// 2. Runs the FIRST EXTERNAL PRODUCER: fleet-seeds' real wal-conformance tool
//    (read-only, offline) and appends its verdict as a receipt THROUGH the
//    harness adapter API.
// 3. Custody-verifies the resulting receipt set, then records it:
//    receipts/dogfood-67b.jsonl (the receipt set itself) — the narrative lives
//    in receipts/DOGFOOD-67B.md.
//
// Re-run: node scripts/dogfood.mjs   (rewrites the receipt set; runtime stores
// are never committed — only the deliberate receipt set under receipts/ is).

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runConformance } from '../test/conformance.mjs';
import { makeServerAdapter } from '../test/adapter-self.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.dirname(HERE);
const FLEET_SEEDS = path.resolve(REPO, '../fleet-seeds');
const GENESIS_PREV = '0'.repeat(64);
const ts = () => new Date().toISOString();

const main = async () => {
  // v3: true — the receipted self-application carries the FULL named law
  // (16 cases incl. the §9 Ed25519 sig cases), not the v3-skipped subset.
  const adapter = makeServerAdapter({ qmr2: true, v3: true });
  const out = { steps: [] };
  try {
    // -- 1. conformance self-application -------------------------------------
    const verdict = await runConformance(adapter);
    out.steps.push({
      step: 'conformance.self-application',
      ok: verdict.ok,
      cases: verdict.cases.length,
      failed: verdict.cases.filter((c) => !c.ok).length,
      skipped: verdict.skipped,
      names: verdict.cases.map((c) => `${c.name}:${c.ok ? 'pass' : 'FAIL'}`),
    });
    if (!verdict.ok) throw new Error('conformance verdict not ok');

    // -- 2. fresh receipt set for the dogfood records -------------------------
    await adapter.reset();
    let prev = GENESIS_PREV;
    let seq = 1;
    const append = async (body, opts = {}) => {
      const receipt = adapter.makeReceipt(seq, prev, body, opts);
      const res = await adapter.appendRaw(receipt);
      if (!res.ok) throw new Error(`append failed: ${JSON.stringify(res)}`);
      prev = receipt.id;
      seq += 1;
      return receipt;
    };

    await append({
      kind: 'receipt.chain.genesis',
      ts: ts(),
      note: 'qmr2 dogfood receipt set: the harness receipts its own run + its first external producer',
      dialects: ['sha256-custody', 'fnv1a-canary'],
      spec: 'docs/qmr2-design.md',
    });

    const harnessBody = {
      kind: 'conformance.harness.run',
      ts: ts(),
      harness: 'test/conformance.mjs (runConformance)',
      adapter: 'test/adapter-self.mjs (stdio MCP → quilt-mcp-receipts server, qmr2+v3 on)',
      ok: verdict.ok,
      cases: verdict.cases.length,
      failed: 0,
      case_names: verdict.cases.map((c) => c.name),
      skipped: verdict.skipped,
      spec: 'docs/qmr2-design.md §6',
    };
    const harnessReceipt = await append(harnessBody);

    // -- 3. first external producer: fleet-seeds wal-* tool ------------------
    const walOut = execFileSync(process.execPath, ['tools/wal-conformance.mjs', '--json'], {
      cwd: FLEET_SEEDS,
      encoding: 'utf8',
      timeout: 120_000,
    });
    const wal = JSON.parse(walOut);
    if (wal.ok !== true) throw new Error(`wal-conformance not ok: ${wal.why}`);
    const walBody = {
      kind: 'wal.conformance.run',
      ts: ts(),
      producer: 'fleet-seeds/tools/wal-conformance.mjs (external tool, read-only, offline)',
      wired_through: 'test/conformance.mjs runConformance adapter — first external producer receipt (wave 67-b)',
      ok: wal.ok,
      chains: Object.keys(wal.chains),
      scenario_checks: wal.scenarioChecks.map((s) => s.id),
      claims_assessed: wal.claimsAssessment.map((c) => c.id),
      tips: Object.fromEntries(Object.entries(wal.deployedControl).map(([k, v]) => [k, v.tip?.slice(0, 16) + '…'])),
      law: wal.law,
    };
    const walReceipt = await append(walBody);

    // -- 4. custody-verify the dogfood receipt set, then record it ------------
    const vAny = await adapter.verify({});
    const vCustody = await adapter.verify({ dialect_mode: 'custody' });
    if (!vAny.ok || !vCustody.ok) throw new Error(`dogfood set failed verify: ${JSON.stringify({ vAny, vCustody })}`);
    const receiptSetBytes = fs.readFileSync(adapter.store());
    const storeSha = createHash('sha256').update(receiptSetBytes).digest('hex');
    fs.writeFileSync(path.join(REPO, 'receipts', 'dogfood-67b.jsonl'), receiptSetBytes);

    out.steps.push({ step: 'wal.external-producer', ok: true, chains: walBody.chains });
    out.receipts = [harnessReceipt, walReceipt].map((r) => ({ seq: r.seq, id: r.id, kind: r.body.kind }));
    out.count = seq - 1;
    out.tip = prev;
    out.custody_verify_ok = { any: vAny.ok, custody: vCustody.ok };
    out.store_sha256 = storeSha;

    // -- 5. the narrative receipt of record (re-derivable by re-running this) --
    const md = `# DOGFOOD-67B — the qmr2 harness receipts itself + its first external producer

Run: \`node scripts/dogfood.mjs\` (re-runnable; each run rewrites this receipt set).

## What ran

1. **Conformance self-application** — \`test/conformance.mjs\` (\`runConformance\`)
   against the live qmr2 server over stdio MCP via \`test/adapter-self.mjs\`:
   **${verdict.cases.length}/${verdict.cases.length} cases pass** (${verdict.cases.map((c) => c.name).join(', ')}); skipped: ${verdict.skipped.length ? verdict.skipped.join(', ') : 'none'}.
2. **First external producer** — \`fleet-seeds/tools/wal-conformance.mjs\` (real
   tool, read-only, offline) ran green (\`ok: true\`, chains: ${walBody.chains.join(', ')})
   and its verdict was appended THROUGH the harness adapter API as a
   \`wal.conformance.run\` receipt. The fleet's wal-* wiring is no longer queued:
   one real wal receipt has flowed through the shared battery.

## The receipt set

- File: \`receipts/dogfood-67b.jsonl\` — ${seq - 1} receipts, sha256 ${storeSha}
- Tip: \`${prev}\`
- verify (any mode): ok · verify (dialect_mode "custody"): ok — the set is a lawful custody chain.
- Re-derive independently: \`node server.mjs --store receipts/dogfood-67b.jsonl\`
  then call \`verify_chain\` over stdio MCP.

## Receipt index

${[harnessReceipt, walReceipt].map((r) => `- seq ${r.seq} \`${r.body.kind}\` — id \`${r.id.slice(0, 16)}…\``).join('\n')}
`;
    fs.writeFileSync(path.join(REPO, 'receipts', 'DOGFOOD-67B.md'), md);
  } finally {
    await adapter.stop();
  }

  console.log(JSON.stringify(out, null, 2));
};

main().catch((e) => {
  console.error('DOGFOOD FAILED:', e.message);
  process.exit(1);
});
