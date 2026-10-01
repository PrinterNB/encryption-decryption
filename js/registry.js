// registry.js — loads FIRST.
// The single source of truth: every algorithm (classical, encoding, modern) registers
// itself here. The picker, the Library pages, key rules, level controls and the
// self-tests are all driven from this data — nothing is duplicated in HTML.
//
// Note on style: plain assignments (no let/const at top level) so that every non-module
// <script> in the page — and the Node test driver — shares the same global scope.

REGISTRY = [];
REG_BY_ID = {};

registerCipher = function(entry) {
  var problems = [];
  if (!entry || typeof entry.id !== "string") problems.push("missing id");
  if (!entry.name) problems.push("missing name");
  if (!entry.category) problems.push("missing category");
  if (!entry.encode || !entry.decode) problems.push("missing encode/decode");
  if (!entry.keySpec) problems.push("missing keySpec");
  if (!entry.selfTest) problems.push("missing selfTest");
  if (REG_BY_ID[entry.id]) { problems.push("duplicate id " + entry.id); }
  if (problems.length) {
    throw new Error("registry: bad entry: " + problems.join(", "));
  }
  if (!entry.levels) entry.levels = null;
  if (!entry.keySpec.required) entry.keySpec.required = false;
  if (!entry.keySpec.validate) entry.keySpec.validate = function() { return null; };
  if (entry.keySpec.required && !entry.keySpec.guidance) entry.keySpec.guidance = "Any key works.";

  REGISTRY.push(entry);
  REG_BY_ID[entry.id] = entry;
};

// ---------- shared helpers ----------
// (kept here so every cipher file and the test harness use the same primitives)

randBytes = function(n) {
  var b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
};

randInt = function(n) { // uniform 0..n-1 via rejection sampling
  if (n <= 1) return 0;
  var limit = 4294967296 - (4294967296 % n);
  var buf = new Uint32Array(1), r;
  do { crypto.getRandomValues(buf); r = buf[0]; } while (r >= limit);
  return r % n;
};

utf8Bytes = function(s) { return new TextEncoder().encode(s); };
utf8Text  = function(bytes) { return new TextDecoder("utf-8").decode(bytes); };

B64ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bytesToB64 = function(bytes) { // our own encoder — used by xor/aes and the Base64 entry
  var out = "";
  for (var i = 0; i < bytes.length; i += 3) {
    var b0 = bytes[i];
    var has1 = i + 1 < bytes.length, has2 = i + 2 < bytes.length;
    var b1 = has1 ? bytes[i + 1] : 0, b2 = has2 ? bytes[i + 2] : 0;
    out += B64ALPHA[b0 >> 2];
    out += B64ALPHA[((b0 & 3) << 4) | (b1 >> 4)];
    out += has1 ? B64ALPHA[((b1 & 15) << 2) | (b2 >> 6)] : "=";
    out += has2 ? B64ALPHA[b2 & 63] : "=";
  }
  return out;
};

b64ToBytes = function(str) {
  var rev = {};
  for (var i = 0; i < 64; i++) rev[B64ALPHA[i]] = i;
  var clean = str.replace(/\s+/g, "").replace(/=+$/, "");
  if (clean.length % 4 === 1) throw new Error("not valid Base64");
  var out = [];
  for (var j = 0; j < clean.length; j += 4) {
    var chunk = clean.slice(j, j + 4);
    if (/[^\S]/.test(chunk)) throw new Error("not valid Base64");
    var acc = 0, bits = 0, ok = true;
    for (var k = 0; k < chunk.length; k++) {
      var c = chunk[k];
      if (!Object.keys(rev).length) {}
      var v = rev[c];
      if (v === undefined) { ok = false; break; }
      acc = (acc << 6) | v; bits += 6;
    }
    if (!ok) throw new Error("not valid Base64");
    for (var m = 0; m < Math.floor(bits / 8); m++) {
      out.push((acc >> (bits - 8 * (m + 1))) & 255);
    }
  }
  return new Uint8Array(out);
};

applyRounds = function(fn, n) { // generic "apply this pass n times" wrapper (levels)
  return function(s, key) {
    for (var i = 0; i < n; i++) s = fn(s, key);
    return s;
  };
};

concatBytes = function(parts) { // safe across realms (typed-array .set rejects foreign subclasses)
  var total = 0;
  for (var i = 0; i < parts.length; i++) total += parts[i].length;
  var out = new Uint8Array(total), at = 0;
  for (var j = 0; j < parts.length; j++) {
    for (var k = 0; k < parts[j].length; k++) out[at + k] = parts[j][k];
    at += parts[j].length;
  }
  return out;
};
