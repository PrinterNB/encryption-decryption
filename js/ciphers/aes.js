// aes.js — real AES-GCM via the browser's built-in Web Crypto (works on file:// too).
// Your key is a passphrase: a random salt turns it into a 256-bit key (PBKDF2 — the
// Level control sets how many times it is stretched), a random IV protects each
// message, and salt‖iv‖ciphertext is framed in Base64 so decrypt can find it back.

AES_ITER_LADDER = [10000, 50000, 100000, 300000, 600000];

// Some WebCrypto implementations (browsers) want no usages here; Node wants a usages
// set. Try the Node-shaped call first, fall back to the browser-shaped one.
importPbkdf2Key = async function(passphrase) {
  try {
    return await crypto.subtle.importKey("raw", utf8Bytes(passphrase), "PBKDF2", false, ["deriveBits"]);
  } catch (e) {
    return await crypto.subtle.importKey("raw", utf8Bytes(passphrase), "PBKDF2", false);
  }
};

importAesKeyBytes = async function(kb, usage) { // usage: "encrypt" | "decrypt"
  try {
    return await crypto.subtle.importKey("raw", kb, "AES-GCM", false, [usage]);
  } catch (e) {
    return await crypto.subtle.importKey("raw", kb, "AES-GCM", false, { length: 256 });
  }
};

aesDeriveKey = function(passphrase, salt, iterations) {
  return (async function() {
    var baseKey = await importPbkdf2Key(passphrase);
    var raw = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: salt, iterations: iterations, hash: "SHA-256" },
      baseKey, 256
    );
    return new Uint8Array(raw);
  })();
};

aesEncode = async function(s, key, level) {
  var it = AES_ITER_LADDER[Math.min(level, AES_ITER_LADDER.length) - 1];
  var salt = randBytes(16), iv = randBytes(12);
  var kb = await aesDeriveKey(key, salt, it);
  var keyObj = await importAesKeyBytes(kb, "encrypt");
  var pt = utf8Bytes(s);
  var ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, keyObj, pt);
  var framed = concatBytes([salt, iv, new Uint8Array(ct)]);
  return "aes1:" + bytesToB64(framed);
};

aesDecode = async function(s, key, level) {
  if (!/^aes1:/.test(s)) throw new Error("this output was not produced by AES — check the algorithm");
  var framed = b64ToBytes(s.replace(/^aes1:/, ""));
  if (framed.length < 16 + 12 + 16) throw new Error("AES output is too short to be valid");
  var salt = framed.slice(0, 16);
  var iv = framed.slice(16, 28);
  var ct = framed.slice(28);
  var it = AES_ITER_LADDER[Math.min(level, AES_ITER_LADDER.length) - 1];
  var kb = await aesDeriveKey(key, salt, it);
  var keyObj = await importAesKeyBytes(kb, "decrypt");
  var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, keyObj, ct);
  return utf8Text(pt);
};

registerCipher({
  id: "aes",
  name: "AES-256 (GCM)",
  category: "modern",
  era: "Modern standard",
  invented: "Designed 1998/2000 by Joan Daemen & Vincent Rijmen; adopted by NIST (FIPS-197, 2001).",
  description: [
    "The workhorse of real cryptography today: every byte affects every other (substitution, shifting, mixing in a Galois field), for 14 rounds with a 256-bit key.",
    "Your key is treated as a PASSPHRASE. It is stretched by thousands of PBKDF2 rounds with a fresh random salt, and every message gets a fresh random IV — the same text + same key encrypts differently every time.",
    "Built-in authenticity tag: change one character of the ciphertext and decryption FAILS instead of quietly returning garbage — you can always tell a wrong key or a corrupted paste.",
    "Because every run is fresh, decrypting needs the full ciphertext output (the leading 'aes1:…' part) — never just the key."
  ],
  history: "Invented by Joan Daemen and Vincent Rijmen (hence AES); won the NIST contest in 2001 and is now the standard inside TLS, zip files and operating systems worldwide.",
  strength: "Real cryptography. Cracking the key is not the attack to try here — the practical attack is brute-forcing YOUR passphrase, and the Level control makes that slower.",
  example: { pt: "real secrets belong here", key: "correct horse" },
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
    effect: "How many times the passphrase is stretched (10k to 600k rounds): higher levels make guessing a passphrase far slower."
  },
  encode: aesEncode,
  decode: aesDecode,
  selfTest: { input: "AES round-trips anything.", key: "nine random words" },
  notesSecurity: "real-crypto"
});
