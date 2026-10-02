// test/mcp-client.mjs — minimal stdio MCP client shared by the qmr2 tests, the
// self-application adapter, and the dogfood script. Speaks newline-delimited
// JSON-RPC 2.0 exactly as an MCP host would. (The v1 suite carries its own
// copy, deliberately untouched — this helper exists so the qmr2 layer doesn't
// grow a third one.)

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SERVER = fileURLToPath(new URL('../server.mjs', import.meta.url));

export class McpClient {
  constructor({ demo = false, qmr2 = false, v3 = false, store = null, env = {} } = {}) {
    this.dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qmr2-'));
    this.store = store ?? path.join(this.dir, 'store.jsonl');
    this.argv = [SERVER, '--store', this.store, '--quiet-notice'];
    if (demo) this.argv.push('--demo');
    if (qmr2) this.argv.push('--qmr2');
    if (v3) this.argv.push('--v3');
    this.nextId = 1;
    this.pending = new Map();
    this.buffer = '';
    this.stderr = [];
    this.child = spawn(process.execPath, this.argv, {
      env: {
        ...process.env,
        ...env,
        QMR2: qmr2 ? '1' : (env.QMR2 ?? '0'),
        V3: v3 ? '1' : (env.V3 ?? '0'),
      },
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
  async handshake() {
    const init = await this.request('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'qmr2-harness-client', version: '0.2.0' },
    });
    this.notify('notifications/initialized', {});
    return init;
  }
  async callTool(name, args) {
    const res = await this.request('tools/call', { name, arguments: args ?? {} });
    if (!Array.isArray(res.content) || res.content[0].type !== 'text') {
      throw new Error(`tool ${name}: malformed result ${JSON.stringify(res).slice(0, 200)}`);
    }
    return { isError: res.isError === true, payload: JSON.parse(res.content[0].text) };
  }
  lines() {
    if (!fs.existsSync(this.store)) return [];
    return fs.readFileSync(this.store, 'utf8').split('\n').filter((l) => l.trim().length > 0);
  }
  writeLines(lines) {
    fs.writeFileSync(this.store, lines.join('\n') + '\n');
  }
  stop() {
    return new Promise((resolve) => {
      try { this.child.stdin.end(); } catch {}
      this.child.kill('SIGTERM');
      this.child.on('exit', () => resolve());
      setTimeout(() => { try { this.child.kill('SIGKILL'); } catch {} resolve(); }, 1500);
    });
  }
}
