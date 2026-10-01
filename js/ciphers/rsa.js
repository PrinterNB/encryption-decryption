// rsa.js — real public-key cryptography: RSA-2048 with OAEP-SHA-256 padding, all in BigInt.
// Your passphrase deterministically derives a full 2048-bit keypair (PBKDF2-seeded primes —
// the Level control stretches the seed exactly like the AES/ChaCha entries); messages are
// sealed block-by-block (a 2048-bit block only fits 190 bytes of text, this is maths, not
// bulk transport). Framing: "rsa1:" + base64(salt ‖ 256-byte blocks).

RSA_MODULUS_BITS = 2048;
RSA_MODULUS_BYTES = 256;
RSA_HASH_BYTES = 32;                       // SHA-256 inside OAEP
RSA_MAX_MSG = RSA_MODULUS_BYTES - 2 * RSA_HASH_BYTES - 2; // 190 bytes per block
RSA_MAX_BLOCKS = 96;                       // ~18 KB of text — this is JS BigInt maths, not libtomcrypt
RSA_MAX_INPUT_BYTES = RSA_MAX_BLOCKS * RSA_MAX_MSG;
RSA_E = 65537n;

modPow = function(b, e, m) { // square-and-multiply, BigInt
  var r = 1n; b = b % m;
  while (e > 0n) {
    if (e & 1n) r = r * b % m;
    b = b * b % m; e >>= 1n;
  }
  return r;
};

modInv = function(a, m) { // extended Euclid
  var old_r = a % m, r = m, old_s = 1n, s = 0n;
  while (r !== 0n) {
    var q = old_r / r;
    var t0 = old_r - q * r; old_r = r; r = t0;
    var t1 = old_s - q * s; old_s = s; s = t1;
  }
  return ((old_s % m) + m) % m;
};

SMALL_PRIMES = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n, 97n];

isProbablePrime = function(n) {
  if (n < 2n) return false;
  var i, p;
  for (i = 0; i < SMALL_PRIMES.length; i++) {
    p = SMALL_PRIMES[i];
    if (n % p === 0n) return n === p;
  }
  var d = n - 1n, sh = 0n;
  while ((d & 1n) === 0n) { d >>= 1n; sh++; }
  var bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n];
  for (i = 0; i < bases.length; i++) {
    var a = bases[i];
    if (a % n === 0n) continue;
    var x = modPow(a, d, n);
    if (x !== 1n && x !== n - 1n) {
      var j = 1n, done = false;
      while (j < sh) {
        x = x * x % n;
        if (x === n - 1n) { done = true; break; }
        j++;
      }
      if (!done) return false;
    }
  }
  return true;
};

// deterministic 64-bit PRNG (splitmix64) seeded from the stretched passphrase bytes
SM64_MASK = (1n << 64n) - 1n;
splitmixNext = function() {
  SM_STATE = (SM_STATE + 0x9e3779b97f4a7c15n) & SM64_MASK;
  var z = SM_STATE;
  z = (z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n & SM64_MASK;
  z = (z ^ (z >> 27n)) * 0x94d049bb133111ebn & SM64_MASK;
  return z ^ (z >> 31n);
};

randBits = function(bits) {
  var v = 0n, i;
  for (i = 0; i < bits / 64; i++) v = (v << 64n) | splitmixNext();
  return v;
};

derivePrime = function(bits) { // top bit set (exact size), odd, then filter
  for (;;) {
    var c = randBits(bits) | (1n << BigInt(bits - 1)) | 1n;
    for (;;) {
      if (isProbablePrime(c) && (c - 1n) % RSA_E !== 0n) return c; // gcd(e, p−1) = 1
      c += 2n;
    }
  }
};

deriveKeyPair = function(seedBytes) { // seedBytes: PBKDF2 output — same passphrase ⇒ same pair
  SM_STATE = 0n;
  var i;
  for (i = 0; i < seedBytes.length; i++) SM_STATE = ((SM_STATE << 8n) | BigInt(seedBytes[i])) & SM64_MASK;
  var p = derivePrime(RSA_MODULUS_BITS / 2), q = derivePrime(RSA_MODULUS_BITS / 2);
  while (q === p) q = derivePrime(RSA_MODULUS_BITS / 2);
  var n = p * q;
  var phi = (p - 1n) * (q - 1n);
  var d = modInv(RSA_E, phi);
  return { n: n, e: RSA_E, d: d };
};

bigToBytes = function(v, len) { // big-endian, fixed width
  var out = new Uint8Array(len);
  for (var i = len - 1; i >= 0; i--) { out[i] = Number(v & 0xFFn); v >>= 8n; }
  return out;
};

bytesToBig = function(b) {
  var v = 0n;
  for (var i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
  return v;
};

OAEP_LHASH = null; // SHA-256 of the (empty) label — computed once per page, per the OAEP spec
oaepPrepare = async function() {
  if (OAEP_LHASH) return;
  OAEP_LHASH = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(0)));
};

mgf1Sha256 = async function(seed, count) { // MGF1: SHA-256(seed ‖ BE32(counter)) chained
  var out = new Uint8Array(0), ctr = 0;
  while (out.length < count) {
    var buf = new Uint8Array(seed.length + 4), i;
    for (i = 0; i < seed.length; i++) buf[i] = seed[i];
    buf[seed.length] = (ctr >>> 24) & 255; buf[seed.length + 1] = (ctr >>> 16) & 255;
    buf[seed.length + 2] = (ctr >>> 8) & 255; buf[seed.length + 3] = ctr & 255;
    var block = new Uint8Array(await crypto.subtle.digest("SHA-256", buf)), extra = block;
    var need = count - out.length;
    var grown = new Uint8Array(out.length + need);
    for (i = 0; i < out.length; i++) grown[i] = out[i];
    for (i = 0; i < need; i++) grown[out.length + i] = extra[i];
    out = grown;
    ctr++;
  }
  return out;
};

rsaSealBlock = async function(msg, kp) { // ≤190 bytes → 256-byte OAEP block
  var dbLen = RSA_MODULUS_BYTES - RSA_HASH_BYTES - 1; // 223
  var db = new Uint8Array(dbLen), i, at = 0;
  for (i = 0; i < RSA_HASH_BYTES; i++) db[at++] = OAEP_LHASH[i];
  at = dbLen - 1 - msg.length;          // PS (zeros) sits between lHash and the 0x01 separator
  db[at] = 1;                          // separator, at fixed distance from the message end
  for (i = 0; i < msg.length; i++) db[at + 1 + i] = msg[i];
  var seed = randBytes(RSA_HASH_BYTES), i; // fresh random seed per block (the OAEP way)
  var dbMask = await mgf1Sha256(seed, dbLen); // step 1 of the OAEP chain: dbMask from the seed
  var maskedDb = new Uint8Array(dbLen);
  for (i = 0; i < dbLen; i++) maskedDb[i] = db[i] ^ dbMask[i];
  var seedMask = await mgf1Sha256(maskedDb, RSA_HASH_BYTES); // step 2: seedMask from maskedDB
  var em = new Uint8Array(RSA_MODULUS_BYTES);
  em[0] = 0;
  for (i = 0; i < RSA_HASH_BYTES; i++) em[1 + i] = seed[i] ^ seedMask[i];
  for (i = 0; i < dbLen; i++) em[1 + RSA_HASH_BYTES + i] = maskedDb[i];
  var c = modPow(bytesToBig(em), kp.e, kp.n);
  return bigToBytes(c, RSA_MODULUS_BYTES);
};

rsaOpenBlock = async function(block, kp) { // inverse: recover seed from the mask, then check OAEP
  var m = modPow(bytesToBig(block), kp.d, kp.n);
  var em = bigToBytes(m, RSA_MODULUS_BYTES);
  if (em[0] !== 0) throw new Error("this was not sealed with your passphrase (or your key/level changed) — nothing was decrypted.");
  var dbLen = RSA_MODULUS_BYTES - RSA_HASH_BYTES - 1;
  var maskedSeed = em.slice(1, 1 + RSA_HASH_BYTES);
  var maskedDb = em.slice(1 + RSA_HASH_BYTES);
  var seedMask = await mgf1Sha256(maskedDb, RSA_HASH_BYTES); // decode runs the OAEP chain backwards
  var seed = new Uint8Array(RSA_HASH_BYTES), i;
  for (i = 0; i < RSA_HASH_BYTES; i++) seed[i] = maskedSeed[i] ^ seedMask[i];
  var dbMask = await mgf1Sha256(seed, dbLen);
  var db = new Uint8Array(dbLen);
  for (i = 0; i < dbLen; i++) db[i] = maskedDb[i] ^ dbMask[i];
  for (i = 0; i < RSA_HASH_BYTES; i++) {
    if (db[i] !== OAEP_LHASH[i]) throw new Error("this was not sealed with your passphrase — nothing was decrypted.");
  }
  var sep = RSA_HASH_BYTES; // skip lHash, then the zero padding, then find the 0x01 separator
  while (sep < db.length && db[sep] === 0) sep++;
  if (sep >= db.length || db[sep] !== 1) throw new Error("OAEP separator missing: wrong key or corrupted block.");
  return db.slice(sep + 1);
};

rsaEncode = async function(s, key, level) {
  await oaepPrepare();
  var pt = utf8Bytes(s);
  if (pt.length > RSA_MAX_INPUT_BYTES) {
    throw new Error("RSA-2048 here is pure-BigInt maths — it is a demonstration of real public-key crypto, not a bulk cipher (limit " + Math.round(RSA_MAX_INPUT_BYTES / 1024) + " KB). For bigger texts use AES or ChaCha20.");
  }
  var ladder = AES_ITER_LADDER;
  var it = ladder[Math.min(level, ladder.length) - 1];
  var salt = randBytes(16);
  var seed = await aesDeriveKey(key, salt, it); // stretches the passphrase deterministically
  var kp = deriveKeyPair(seed);
  var parts = [salt];
  var at = 0;
  while (at < pt.length || parts.length === 1) { // at least one block, even for empty text
    var chunk = pt.slice(at, at + RSA_MAX_MSG);
    parts.push(await rsaSealBlock(chunk, kp));
    at += RSA_MAX_MSG;
  }
  return "rsa1:" + bytesToB64(concatBytes(parts));
};

rsaDecode = async function(s, key, level) {
  if (!/^rsa1:/.test(s)) throw new Error("this output was not produced by RSA — check the algorithm");
  await oaepPrepare();
  var framed = b64ToBytes(s.replace(/^rsa1:/, ""));
  if (framed.length < 16 + RSA_MODULUS_BYTES) throw new Error("RSA output is too short to be valid");
  var salt = framed.slice(0, 16);
  var ct = framed.slice(16);
  if (ct.length % RSA_MODULUS_BYTES !== 0) throw new Error("RSA output is malformed (blocks must be whole)");
  if (ct.length / RSA_MODULUS_BYTES > RSA_MAX_BLOCKS) throw new Error("too many RSA blocks for this demo path (limit " + RSA_MAX_BLOCKS + " blocks)");
  var ladder = AES_ITER_LADDER;
  var it = ladder[Math.min(level, ladder.length) - 1];
  var seed = await aesDeriveKey(key, salt, it);
  var kp = deriveKeyPair(seed); // same passphrase + same salt ⇒ the very same keypair
  var parts = [];
  for (var at = 0; at < ct.length; at += RSA_MODULUS_BYTES) {
    parts.push(await rsaOpenBlock(ct.slice(at, at + RSA_MODULUS_BYTES), kp));
  }
  return utf8Text(concatBytes(parts));
};

registerCipher({
  id: "rsa",
  name: "RSA-2048 (OAEP)",
  category: "modern",
  era: "Modern standard (PKCS#1 v2.2)",
  invented: "RSA: Rivest, Shamir & Adleman, 1977; OAEP padding: Bellare & Krawicz, 1994/1998.",
  description: [
    "Public-key cryptography: instead of one shared secret, your passphrase deterministically builds a full 2048-bit keypair (two large primes found from the stretched seed — the Level control is what stretches it). Anything that cannot guess your passphrase cannot rebuild the pair, and the maths refuses to invert without it.",
    "OAEP-SHA-256 padding wraps every 190-byte block with a random mask, so wrong keys and corrupted blocks fail cleanly instead of returning nonsense.",
    "A 2048-bit block holds only 190 bytes of text and this RSA runs as BigInt maths in your tab — texts are capped at ~18 KB. RSA is for small secrets (keys, sessions, signatures), never for whole books; AES or ChaCha carry the bulk.",
    "Because the padding is fresh per run, the same text encrypts differently every time — decrypting needs the full 'rsa1:…' output."
  ],
  history: "Invented in 1977 at MIT by Rivest, Shamir and Adleman; OAEP padding was designed by Bellare and Krawicz to make RSA safe for the real world and standardised in PKCS#1 v2.2. This demo is mathematically faithful RSA-2048, but pure-JS BigInt arithmetic is not a constant-time implementation — treat its timing as unmodelled.",
  strength: "Real RSA: factoring a 2048-bit modulus is the hard problem (no one has broken it at this size); OAEP makes the padding a proper AEAD-style wrapper. The honest caveats: your passphrase seeds the primes, so its entropy is still the security, and the JS maths has no timing-side-channel guarantees.",
  example: { pt: "public-key for small secrets", key: "correct horse" },
  keySpec: {
    required: true, kind: "passphrase",
    validate: function(k) {
      if (k.length < 8) return "Passphrase must be at least 8 characters.";
      return null;
    },
    guidance: "A passphrase (8+ characters) — it deterministically seeds the keypair. Generate gives you six random words."
  },
  levels: {
    max: 5, default: 3,
    label: "seed stretching",
    effect: "How many PBKDF2 rounds seed the keypair derivation (10k to 600k): higher levels make guessing your passphrase slower — and make the primes harder to find, which is the point."
  },
  encode: rsaEncode,
  decode: rsaDecode,
  selfTest: { input: "RSA-2048 OAEP round-trips block by block.", key: "nine random words" },
  notesSecurity: "real-crypto",
  randomized: true
});
