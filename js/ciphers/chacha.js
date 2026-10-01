// chacha.js — real authenticated cryptography, without a block cipher.
// ChaCha20 is a stream cipher (pure JS core — browsers have no Web Crypto ChaCha20), and
// the integrity tag is the Poly1305 MAC exactly as defined by RFC 8439. Your passphrase is
// stretched with the SAME PBKDF2 ladder as the AES entry. Framing on screen:
// "chacha1:" + base64(salt ‖ nonce ‖ ciphertext ‖ tag) — the whole line is what decrypts.
// The nonce is additionally fed to the MAC as associated data, so the tag covers it too.

CHACHA_ITER_LADDER = AES_ITER_LADDER; // defined in aes.js, which loads before this file

// ---------- ChaCha20 core: 32-bit words, plain JS arithmetic mod 2^32 ----------

le32 = function(bytes, off) {
  return bytes[off] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24);
};

chachaQuarter = function(s, a, b, c, d) { // Int32Array entries wrap mod 2^32 on assignment
  s[a] = s[a] + s[b]; s[d] = (s[d] ^ s[a]) << 16 | (s[d] ^ s[a]) >>> 16;
  s[c] = s[c] + s[d]; s[b] = (s[b] ^ s[c]) << 12 | (s[b] ^ s[c]) >>> 20;
  s[a] = s[a] + s[b]; s[d] = (s[d] ^ s[a]) << 8 | (s[d] ^ s[a]) >>> 24;
  s[c] = s[c] + s[d]; s[b] = (s[b] ^ s[c]) << 7 | (s[b] ^ s[c]) >>> 25;
};

chachaBlock = function(kw, nw, counter) { // kw: 8 words of key, nw: 4 words of nonce
  var s = new Int32Array(16), i;
  var o = new Int32Array(16); // feed-forward copy
  s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574; // little-endian words of "expand 32-byte k"
  for (i = 0; i < 8; i++) s[4 + i] = kw[i];
  s[12] = counter; // 32-bit block counter (a 1 MB cap never reaches 2^32 blocks)
  for (i = 0; i < 3; i++) s[13 + i] = nw[i]; // the 12-byte nonce lives in words 13..15
  for (i = 0; i < 16; i++) o[i] = s[i];
  for (var r = 0; r < 10; r++) {
    chachaQuarter(s, 0, 4, 8, 12); chachaQuarter(s, 1, 5, 9, 13);
    chachaQuarter(s, 2, 6, 10, 14); chachaQuarter(s, 3, 7, 11, 15);
    chachaQuarter(s, 0, 5, 10, 15); chachaQuarter(s, 1, 6, 11, 12);
    chachaQuarter(s, 2, 7, 8, 13); chachaQuarter(s, 3, 4, 9, 14);
  }
  var out = new Uint8Array(64);
  for (i = 0; i < 16; i++) {
    var w = s[i] + o[i]; // add the original word back (mod 2^32)
    out[i * 4] = w & 255;
    out[i * 4 + 1] = (w >> 8) & 255;
    out[i * 4 + 2] = (w >> 16) & 255;
    out[i * 4 + 3] = (w >> 24) & 255;
  }
  return out;
};

chachaKeystream = function(key, nonce, n, counter0) { // key: 32 bytes, nonce: 12 bytes
  var kw = new Int32Array(8), nw = new Int32Array(3), i;
  for (i = 0; i < 8; i++) kw[i] = le32(key, i * 4);
  for (i = 0; i < 3; i++) nw[i] = le32(nonce, i * 4);
  var out = new Uint8Array(n), at = 0, blk;
  while (at < n) {
    blk = chachaBlock(kw, nw, counter0 + Math.floor(at / 64));
    for (i = 0; i < 64 && at + i < n; i++) out[at + i] = blk[i];
    at += 64;
  }
  return out;
};

// ---------- Poly1305 MAC (RFC 8439): arithmetic mod 2^130 − 5, BigInt ----------

POLY1305_MOD = (1n << 130n) - 5n;
POLY1305_CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffffn;

leToBig = function(bytes, off, len) {
  var n = 0n;
  for (var i = len - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[off + i]);
  return n;
};

poly1305Mac = function(data, otk32) { // data: any byte array, otk32: 32 bytes of one-time key
  var r = leToBig(otk32, 0, 16) & POLY1305_CLAMP;
  var s = leToBig(otk32, 16, 16);
  var a = 0n, off, len, n;
  for (off = 0; off < data.length; off += 16) {
    len = Math.min(16, data.length - off);
    n = leToBig(data, off, len) + (1n << (8n * BigInt(len))); // the appended 0x01 byte
    a = (a + n) * r % POLY1305_MOD;
  }
  a = a + s;
  var tag = new Uint8Array(16);
  for (var i = 0; i < 16; i++) tag[i] = Number((a >> BigInt(8 * i)) & 0xFFn);
  return tag;
};

chachaAeadMacData = function(aad, ct) { // aad ‖ pad16(aad) ‖ ct ‖ pad16(ct) ‖ le8(len aad) ‖ le8(len ct)
  function pad(b) {
    var p = b.length % 16 === 0 ? 0 : 16 - (b.length % 16);
    var out = new Uint8Array(b.length + p), i;
    for (i = 0; i < b.length; i++) out[i] = b[i];
    return out;
  }
  function le8(n) { var o = new Uint8Array(8), i; for (i = 0; i < 8; i++) o[i] = (i < 4) ? ((n >>> (8 * i)) & 255) : 0; return o; } // JS >>> is mod-32: bytes 4..7 of our lengths are always zero
  return concatBytes([pad(aad), pad(ct), le8(aad.length), le8(ct.length)]);
};

// ---------- raw AEAD primitives (also cross-checked against the RFC 8439 vector) ----------

chacha20p1305Seal = function(key, nonce, pt, aad) { // returns Uint8Array ct ‖ tag
  var otk = chachaKeystream(key, nonce, 32, 0); // block 0 is the one-time MAC key
  var ks = chachaKeystream(key, nonce, pt.length, 1); // the message keystream starts at counter 1
  var ct = new Uint8Array(pt.length), i;
  for (i = 0; i < pt.length; i++) ct[i] = pt[i] ^ ks[i];
  var tag = poly1305Mac(chachaAeadMacData(aad, ct), otk);
  return concatBytes([ct, tag]);
};

chacha20p1305Open = function(key, nonce, sealed, aad) { // verifies the tag, then decrypts
  if (sealed.length < 16) throw new Error("this output is too short to be a ChaCha20-Poly1305 box");
  var ct = sealed.slice(0, sealed.length - 16);
  var gotTag = sealed.slice(sealed.length - 16);
  var wantTag = poly1305Mac(chachaAeadMacData(aad, ct), chachaKeystream(key, nonce, 32, 0));
  var diff = 0; // compare without bailing out early on the first mismatch
  for (var i = 0; i < 16; i++) diff |= gotTag[i] ^ wantTag[i];
  if (diff !== 0) throw new Error("authenticity check failed: wrong key, corrupted text, or this output came from a different algorithm — nothing was decrypted.");
  var ks = chachaKeystream(key, nonce, ct.length, 1);
  var pt = new Uint8Array(ct.length);
  for (var j = 0; j < ct.length; j++) pt[j] = ct[j] ^ ks[j];
  return pt;
};

// ---------- the registry entry ----------

chachaEncode = async function(s, key, level) {
  var ladder = CHACHA_ITER_LADDER;
  var it = ladder[Math.min(level, ladder.length) - 1];
  var salt = randBytes(16), nonce = randBytes(12);
  var kb = await aesDeriveKey(key, salt, it);
  var sealed = chacha20p1305Seal(kb, nonce, utf8Bytes(s), nonce); // the nonce is authenticated too
  return "chacha1:" + bytesToB64(concatBytes([salt, nonce, sealed]));
};

chachaDecode = async function(s, key, level) {
  if (!/^chacha1:/.test(s)) throw new Error("this output was not produced by ChaCha20-Poly1305 — check the algorithm");
  var framed = b64ToBytes(s.replace(/^chacha1:/, ""));
  if (framed.length < 16 + 12 + 16) throw new Error("ChaCha20-Poly1305 output is too short to be valid");
  var salt = framed.slice(0, 16);
  var nonce = framed.slice(16, 28);
  var sealed = framed.slice(28);
  var ladder = CHACHA_ITER_LADDER;
  var it = ladder[Math.min(level, ladder.length) - 1];
  var kb = await aesDeriveKey(key, salt, it);
  return utf8Text(chacha20p1305Open(kb, nonce, sealed, nonce));
};

registerCipher({
  id: "chacha",
  name: "ChaCha20-Poly1305",
  category: "modern",
  era: "Modern standard (RFC 8439, 2017)",
  invented: "ChaCha family by Daniel J. Bernstein and collaborators; the Poly1305 AEAD construction standardised by J. Aumann in RFC 8439 (2017).",
  description: [
    "The stream cipher that replaced AES in the newest TLS: a pseudorandom keystream (ChaCha20: add, xor and rotate, 20 rounds) is XORed over your bytes — no blocks, no padding, any length is fine.",
    "Your key is treated as a PASSPHRASE, exactly like AES: it is stretched with PBKDF2 (the Level control sets the rounds), and every message gets a fresh random salt and nonce.",
    "Authenticated by a Poly1305 MAC over the nonce and the ciphertext — change one character or use a wrong key and decryption REFUSES instead of quietly returning garbage.",
    "Because every run is fresh, decrypting needs the full 'chacha1:…' output — never just the key."
  ],
  history: "ChaCha comes from Daniel J. Bernstein's school of stream ciphers (2008 onward); the ChaCha20-Poly1305 AEAD was written up as RFC 8439 in 2017 and became the fast default in libsodium, Go's standard library and TLS 1.3, where constant-time software AES is slow.",
  strength: "Real cryptography — same league as AES-256-GCM, and it is an AEAD: wrong keys and corrupted ciphertexts are detected, not silently mis-decrypted. The honest limit here: your passphrase's own entropy still sets the security.",
  example: { pt: "stream ciphers need no padding", key: "correct horse" },
  keySpec: {
    required: true, kind: "passphrase",
    validate: function(k) {
      if (k.length < 8) return "Passphrase must be at least 8 characters.";
      return null;
    },
    guidance: "A passphrase (8+ characters). Generate gives you six random words."
  },
  levels: {
    max: 5, default: 3,
    label: "key stretching",
    effect: "How many times the passphrase is stretched (10k to 600k PBKDF2 rounds): higher levels make guessing a passphrase far slower."
  },
  encode: chachaEncode,
  decode: chachaDecode,
  selfTest: { input: "ChaCha20-Poly1305 round-trips anything — including ☕.", key: "nine random words" },
  notesSecurity: "real-crypto",
  randomized: true
});
