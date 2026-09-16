#!/usr/bin/env node
/* CWI Change Ledger — verify.js
 * Zero-trust checker: verifies the hash chain of ledger.json and the
 * Ed25519 publish seal, using only public data. Usage:
 *   node verify.js [ledger.json URL or path] [--seal <seal.json>] [--pubkey <ed25519.pub>]
 * Prints per-check results and exits 0 on RESULT: PASS, 1 on FAIL.
 */
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';

const GENESIS = 'GENESIS';
const args = process.argv.slice(2);
const results = [];
const check = (name, ok, detail) => { results.push({ name, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name} — ${detail}`); };

function canon(v) {
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
const sha256hex = s => createHash('sha256').update(s, 'utf8').digest('hex');

async function loadInput(src) {
  if (/^https?:\/\//.test(src)) { const r = await fetch(src); if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); }
  return readFileSync(src, 'utf8');
}
function defaultBase(u) { const m = /^(.+)\/ledger\/ledger\.json$/.exec(u); return m ? m[1] : null; }

async function main() {
  const src = args.find(a => !a.startsWith('--')) || './ledger/ledger.json';
  let doc;
  try { doc = JSON.parse(await loadInput(src)); }
  catch (e) { check('load', false, e.message); return console.log('RESULT: FAIL'), process.exit(1); }
  check('load', true, `${doc.entries?.length ?? 0} entries from ${src}`);

  // 1. schema/protocol
  check('schema', doc.schema === 'cwi.change-record/1.0' && doc.protocol === 'change/1.0',
    `schema=${doc.schema} protocol=${doc.protocol}`);

  // 2. hash chain
  let prev = GENESIS, ok = true, firstBad = -1;
  (doc.entries || []).forEach((e, i) => {
    const { entry_hash, ...rest } = e;
    const recomputed = sha256hex(canon({ ...rest, prev_hash: e.prev_hash }));
    if (recomputed !== entry_hash || e.prev_hash !== prev) { ok = false; if (firstBad < 0) firstBad = i; }
    prev = entry_hash;
  });
  check('chain', ok, ok ? `${doc.entries.length} entries link unbroken to GENESIS; tip ${String(prev).slice(0, 12)}…` : `broken at entry ${firstBad}`);
  if (doc.tip_hash) check('tip', doc.tip_hash === prev, `tip_hash ${String(doc.tip_hash).slice(0, 12)}… ${doc.tip_hash === prev ? 'matches' : 'MISMATCH'}`);

  // 3. publish seal (Ed25519 over canonical {tip_hash,count,sealed_at,issuer})
  const flag = name => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
  const sealSrc = flag('--seal') || (defaultBase(src) ? defaultBase(src) + '/ledger/seal.json' : './ledger/seal.json');
  const pubSrc = flag('--pubkey') || (defaultBase(src) ? defaultBase(src) + '/keys/ed25519.pub' : './keys/ed25519.pub');
  try {
    const seal = JSON.parse(await loadInput(sealSrc));
    const pubPem = (await loadInput(pubSrc)).trim();
    const msg = Buffer.from(canon({ tip_hash: seal.tip_hash, count: seal.count, sealed_at: seal.sealed_at, issuer: seal.issuer }), 'utf8');
    const sigOk = seal.signature?.alg === 'Ed25519' &&
      verify(null, msg, createPublicKey(pubPem), Buffer.from(seal.signature.sig, 'base64'));
    check('seal', sigOk, sigOk ? `Ed25519 seal over tip ${String(seal.tip_hash).slice(0, 12)}… (${seal.count} entries)` : 'signature invalid or malformed');
  } catch (e) { check('seal', false, 'could not verify: ' + e.message); }

  const allPass = results.every(r => r.ok);
  console.log(`RESULT: ${allPass ? 'PASS' : 'FAIL'}`);
  process.exit(allPass ? 0 : 1);
}
main().catch(e => { console.error('FATAL:', e.message); process.exit(1); });
