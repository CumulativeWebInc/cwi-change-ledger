/* CWI Change Ledger — ledger.js v1.0.0
 * UMD, zero dependencies. Works in browsers and Node.
 * Governance pipeline for agent behavior changes: propose -> risk-scan ->
 * review -> decide, append-only hash-chained entries, Ed25519-sealed on publish.
 * Advisory review trail, NOT a sandbox: risk flags are heuristics, not proofs.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.CWIChangeLedger = factory();
}(typeof self !== 'undefined' ? self : this, function () {
'use strict';

var PROTOCOL = 'change/1.0';
var SCHEMA = 'cwi.change-record/1.0';
var GENESIS = 'GENESIS';
var ISSUER = 'Cumulative Web Inc';

// ---------- SHA-256 (pure JS, sync, UTF-8 safe) ----------
var K256 = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];
function rrot(x, n) { return (x >>> n) | (x << (32 - n)); }
function sha256Bytes(msg) {
  var ml = msg.length, bitLenHi = Math.floor((ml / 0x20000000)), bitLenLo = (ml << 3) >>> 0;
  var paddedLen = (((ml + 8) >> 6) + 1) * 64;
  var m = new Uint8Array(paddedLen);
  m.set(msg); m[ml] = 0x80;
  var dv = new DataView(m.buffer);
  dv.setUint32(paddedLen - 8, bitLenHi); dv.setUint32(paddedLen - 4, bitLenLo);
  var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
      h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  var w = new Array(64);
  for (var off = 0; off < paddedLen; off += 64) {
    for (var i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (i = 16; i < 64; i++) {
      var s0 = rrot(w[i-15],7) ^ rrot(w[i-15],18) ^ (w[i-15] >>> 3);
      var s1 = rrot(w[i-2],17) ^ rrot(w[i-2],19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (i = 0; i < 64; i++) {
      var S1 = rrot(e,6) ^ rrot(e,11) ^ rrot(e,25);
      var ch = (e & f) ^ (~e & g);
      var t1 = (h + S1 + ch + K256[i] + w[i]) | 0;
      var S0 = rrot(a,2) ^ rrot(a,13) ^ rrot(a,22);
      var mj = (a & b) ^ (a & c) ^ (b & c);
      var t2 = (S0 + mj) | 0;
      h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
    }
    h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0;
    h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+h)|0;
  }
  var out = new Uint8Array(32), od = new DataView(out.buffer);
  od.setUint32(0,h0); od.setUint32(4,h1); od.setUint32(8,h2); od.setUint32(12,h3);
  od.setUint32(16,h4); od.setUint32(20,h5); od.setUint32(24,h6); od.setUint32(28,h7);
  return out;
}
function utf8(str) {
  // TextEncoder when available; manual fallback otherwise (UMD-safe).
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
  var s = unescape(encodeURIComponent(str)), out = new Uint8Array(s.length);
  for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
function sha256hex(str) {
  var b = sha256Bytes(utf8(str)), hex = '';
  for (var i = 0; i < b.length; i++) hex += (b[i] < 16 ? '0' : '') + b[i].toString(16);
  return hex;
}

// ---------- canonical JSON: recursive key sort, no whitespace ----------
function canon(v) {
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ':' + canon(v[k]); }).join(',') + '}';
  }
  return JSON.stringify(v);
}

// ---------- ULID (Crockford base32, time-ordered) ----------
var CROCK = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
function ulid() {
  var t = Date.now(), s = '';
  for (var i = 0; i < 10; i++) { s = CROCK[t % 32] + s; t = Math.floor(t / 32); }
  var r = '', rand = sha256Bytes(utf8(String(Math.random()) + t + s));
  for (var j = 0; j < 16; j++) r += CROCK[rand[j] % 32];
  return s + r;
}

// ---------- line diff (LCS) ----------
function diffLines(before, after) {
  var a = String(before || '').split('\n'), b = String(after || '').split('\n');
  if (a.length === 1 && a[0] === '') a = [];
  if (b.length === 1 && b[0] === '') b = [];
  var n = a.length, m = b.length;
  var dp = new Array(n + 1);
  for (var i = 0; i <= n; i++) dp[i] = new Array(m + 1).fill(0);
  for (i = n - 1; i >= 0; i--) for (var j = m - 1; j >= 0; j--) {
    dp[i][j] = a[i] === b[j] ? dp[i+1][j+1] + 1 : Math.max(dp[i+1][j], dp[i][j+1]);
  }
  var ops = [], x = 0, y = 0, added = 0, removed = 0, addedLines = [], removedLines = [];
  while (x < n && y < m) {
    if (a[x] === b[y]) { ops.push({ t: ' ', s: a[x] }); x++; y++; }
    else if (dp[x+1][y] >= dp[x][y+1]) { ops.push({ t: '-', s: a[x] }); removed++; removedLines.push(a[x]); x++; }
    else { ops.push({ t: '+', s: b[y] }); added++; addedLines.push(b[y]); y++; }
  }
  while (x < n) { ops.push({ t: '-', s: a[x] }); removed++; removedLines.push(a[x]); x++; }
  while (y < m) { ops.push({ t: '+', s: b[y] }); added++; addedLines.push(b[y]); y++; }
  return { ops: ops, added: added, removed: removed, addedLines: addedLines, removedLines: removedLines };
}

// ---------- risk-flag heuristics (advisory: regex signals, NOT a sandbox) ----------
// Rules run against ADDED lines only: a change is judged by what it introduces.
// One semantic rule (CHG-AB-002) compares before/after for removed safety gates.
var RISK_RULES = [
  { id: 'CHG-PI-001', category: 'prompt-injection', severity: 'critical',
    title: 'Instruction-override language added',
    patterns: [/ignore\s+(all\s+)?(previous|prior)\s+instructions/i, /disregard\s+(all\s+)?(previous|prior)\s+instructions/i, /override\s+the\s+system\s+prompt/i] },
  { id: 'CHG-PI-002', category: 'prompt-injection', severity: 'high',
    title: 'Persona/role hijack phrasing added',
    patterns: [/you\s+are\s+now\b/i, /\bnew\s+persona\b/i, /\bjailbreak\b/i, /DAN\s+mode/i] },
  { id: 'CHG-EX-001', category: 'data-exfiltration', severity: 'high',
    title: 'New outbound data transmission',
    patterns: [/axios\.post\s*\(/, /requests\.post\s*\(/, /fetch\s*\([^)]*,\s*\{[^}]*method\s*:\s*['"]POST/i, /\.post\s*\(\s*['"]https?:\/\//i] },
  { id: 'CHG-EX-002', category: 'data-exfiltration', severity: 'high',
    title: 'New webhook / chat-ops sink',
    patterns: [/discord\.com\/api\/webhooks/i, /hooks\.slack\.com/i, /\bwebhook\b.*https?:\/\//i] },
  { id: 'CHG-EX-003', category: 'data-exfiltration', severity: 'medium',
    title: 'Environment data encoded for transport',
    patterns: [/btoa\s*\([^)]*env/i, /base64[^;]{0,40}process\.env/i, /Buffer\.from\s*\([^)]*env[^)]*\)\.toString\s*\(\s*['"]base64/i] },
  { id: 'CHG-DE-001', category: 'destructive', severity: 'critical',
    title: 'Recursive delete added',
    patterns: [/\brm\s+-rf?\b/, /shutil\.rmtree\s*\(/, /fs\.rm\s*\([^)]*recursive\s*:\s*true/i, /rimraf/i] },
  { id: 'CHG-DE-002', category: 'destructive', severity: 'critical',
    title: 'Bulk data destruction added',
    patterns: [/\bDROP\s+TABLE\b/i, /\bDELETE\s+FROM\b/i, /\bTRUNCATE\b/i, /deleteMany\s*\(/, /dropDatabase\s*\(/] },
  { id: 'CHG-DE-003', category: 'destructive', severity: 'high',
    title: 'Irreversible on-chain/funds action added',
    patterns: [/signTransaction\s*\(/, /sendTransaction\s*\(/, /wallet\.\s*sign/i, /\bprivate\s*key\b.{0,30}\b(sign|export)\b/i] },
  { id: 'CHG-PR-001', category: 'privilege', severity: 'high',
    title: 'New network access added',
    patterns: [/\bfetch\s*\(/, /XMLHttpRequest/, /axios\.(get|post|put|delete)\s*\(/, /https?:\/\/[^\s'")\]]+/] },
  { id: 'CHG-PR-002', category: 'privilege', severity: 'high',
    title: 'New subprocess/shell execution added',
    patterns: [/\bexec(Sync)?\s*\(/, /\bspawn\s*\(/, /subprocess\.(run|Popen|call)/, /os\.system\s*\(/, /\bpopen\s*\(/] },
  { id: 'CHG-PR-003', category: 'privilege', severity: 'medium',
    title: 'New credential/environment access added',
    patterns: [/process\.env\.[A-Z_]+/, /os\.environ/, /\bgetenv\s*\(/, /\b(API_KEY|SECRET_KEY|PASSWORD|PRIVATE_KEY)\b/] },
  { id: 'CHG-PR-004', category: 'privilege', severity: 'medium',
    title: 'New filesystem write added',
    patterns: [/writeFile(Sync)?\s*\(/, /fs\.createWriteStream/, /open\s*\([^)]*,\s*['"]w['"]\s*\)/] },
  { id: 'CHG-AB-001', category: 'approval-bypass', severity: 'high',
    title: 'Approval-bypass language added',
    patterns: [/disable.{0,25}approval/i, /skip.{0,25}approval/i, /bypass.{0,25}approval/i,
               /do\s+not\s+ask/i, /don't\s+ask/i, /never\s+ask/i, /without\s+asking/i,
               /without\s+confirmation/i, /auto-approv/i, /no\s+human\s+review/i] }
];
var SAFETY_GATE_RE = /ask.{0,25}approval|require.{0,25}confirmation|human.{0,25}review|approval.{0,25}required|confirm\s+with\s+(the\s+)?(user|human)/i;

function scanRisks(before, after) {
  var d = diffLines(before, after);
  var flags = [];
  var seen = {};
  d.addedLines.forEach(function (line, idx) {
    RISK_RULES.forEach(function (rule) {
      for (var p = 0; p < rule.patterns.length; p++) {
        if (rule.patterns[p].test(line)) {
          var key = rule.id + '|' + line.trim();
          if (!seen[key]) {
            seen[key] = true;
            flags.push({ rule: rule.id, category: rule.category, severity: rule.severity,
                         title: rule.title, evidence: line.trim().slice(0, 200),
                         added_line: idx + 1 });
          }
          break;
        }
      }
    });
  });
  // Semantic rule: a safety gate present in `before` that disappears in `after`.
  var beforeGates = String(before || '').split('\n').filter(function (l) { return SAFETY_GATE_RE.test(l); });
  var afterHasGate = SAFETY_GATE_RE.test(String(after || ''));
  if (beforeGates.length && !afterHasGate) {
    flags.push({ rule: 'CHG-AB-002', category: 'approval-bypass', severity: 'high',
                 title: 'Safety gate removed (was present before, gone after)',
                 evidence: beforeGates[0].trim().slice(0, 200), added_line: null });
  }
  var order = { critical: 0, high: 1, medium: 2, low: 3 };
  flags.sort(function (x, y) { return (order[x.severity] - order[y.severity]) || (x.rule < y.rule ? -1 : 1); });
  return { flags: flags, diff: { added: d.added, removed: d.removed } };
}

// ---------- entries ----------
var CHANGE_TYPES = ['prompt_edit', 'skill_update', 'config_change', 'policy_change'];
var DECISIONS = ['approved', 'rejected', 'needs_changes'];

function nowIso() { return new Date().toISOString().replace(/\.\d+Z$/, 'Z'); }

function sealEntry(entry, prevHash) {
  var e = {};
  Object.keys(entry).forEach(function (k) { if (k !== 'entry_hash') e[k] = entry[k]; });
  e.prev_hash = prevHash;
  e.entry_hash = sha256hex(canon(e));
  return e;
}

function buildProposal(o) {
  if (!o || typeof o.proposer !== 'string' || !o.proposer.trim()) throw new Error('proposer is required');
  if (CHANGE_TYPES.indexOf(o.change_type) < 0) throw new Error('change_type must be one of ' + CHANGE_TYPES.join(', '));
  if (typeof o.target !== 'string' || !o.target.trim()) throw new Error('target is required');
  var scan = scanRisks(o.before || '', o.after || '');
  return {
    schema: SCHEMA, protocol: PROTOCOL,
    change_id: 'chg_' + ulid(), entry_type: 'proposal',
    proposer: o.proposer.trim(), proposed_at: nowIso(),
    change_type: o.change_type, target: o.target.trim(),
    rationale: String(o.rationale || ''),
    before: String(o.before || ''), after: String(o.after || ''),
    diff_summary: { added_lines: scan.diff.added, removed_lines: scan.diff.removed },
    risk_flags: scan.flags,
    risk_level: scan.flags.length ? scan.flags[0].severity : 'none'
  };
}

function buildDecision(changeId, o) {
  if (!changeId) throw new Error('change_id is required');
  if (!o || typeof o.decider !== 'string' || !o.decider.trim()) throw new Error('decider is required');
  if (DECISIONS.indexOf(o.decision) < 0) throw new Error('decision must be one of ' + DECISIONS.join(', '));
  return {
    schema: SCHEMA, protocol: PROTOCOL,
    change_id: changeId, entry_type: 'decision',
    decision_id: 'dec_' + ulid(),
    decider: o.decider.trim(), decided_at: nowIso(),
    decision: o.decision, rationale: String(o.rationale || ''),
    supersedes: o.supersedes || null
  };
}

// Append-only: returns new array; never mutates.
function appendEntry(entries, entry) {
  var prev = entries.length ? entries[entries.length - 1].entry_hash : GENESIS;
  return entries.concat([sealEntry(entry, prev)]);
}

function verifyChain(entries) {
  var errors = [], prev = GENESIS;
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i], h = e.entry_hash;
    var recomputed = sealEntry(e, e.prev_hash).entry_hash;
    if (recomputed !== h) errors.push('entry ' + i + ' (' + (e.change_id || '?') + '): hash mismatch');
    if (e.prev_hash !== prev) errors.push('entry ' + i + ': prev_hash linkage broken');
    prev = h;
  }
  return { ok: errors.length === 0, errors: errors, tip: prev, count: entries.length };
}

function changeStatus(entries, changeId) {
  var status = 'proposed', lastDecision = null;
  entries.forEach(function (e) {
    if (e.change_id === changeId && e.entry_type === 'decision') {
      status = e.decision; lastDecision = e;
    }
  });
  return { status: status, lastDecision: lastDecision };
}

function changeTrail(entries, changeId) {
  return entries.filter(function (e) { return e.change_id === changeId; });
}

function exportRecord(entries, changeId) {
  var trail = changeTrail(entries, changeId);
  if (!trail.length) throw new Error('unknown change_id: ' + changeId);
  var v = verifyChain(entries);
  return {
    schema: SCHEMA, protocol: PROTOCOL, exported_at: nowIso(), issuer: ISSUER,
    change_id: changeId, status: changeStatus(entries, changeId).status,
    chain_ok: v.ok, chain_tip: v.tip,
    entries: trail,
    verify_note: 'Recompute each entry_hash as sha256(canonical JSON of the entry minus entry_hash, keys sorted, no whitespace) and walk prev_hash to GENESIS. Advisory review trail, not a sandbox.'
  };
}

return {
  PROTOCOL: PROTOCOL, SCHEMA: SCHEMA, GENESIS: GENESIS, ISSUER: ISSUER,
  CHANGE_TYPES: CHANGE_TYPES, DECISIONS: DECISIONS, RISK_RULES: RISK_RULES,
  sha256hex: sha256hex, canon: canon, ulid: ulid,
  diffLines: diffLines, scanRisks: scanRisks,
  buildProposal: buildProposal, buildDecision: buildDecision,
  appendEntry: appendEntry, sealEntry: sealEntry,
  verifyChain: verifyChain, changeStatus: changeStatus,
  changeTrail: changeTrail, exportRecord: exportRecord
};
}));
