// xor.js — repeating-key XOR over raw bytes, Base64-framed output.
// Levels stack rounds: each round's keystream is salted by the round number so
// rounds genuinely compose instead of cancelling.

xorBytes = function(bytes, keyBytes, salt) {
  var out = new Uint8Array(bytes.length);
  for (var i = 0; i < bytes.length; i++) {
    out[i] = bytes[i] ^ keyBytes[i % keyBytes.length] ^ ((salt * 31 + 17) & 255);
  }
  return out;
};

xorEncode = function(s, key, level) {
  var bytes = utf8Bytes(s);
  var kb = utf8Bytes(key);
  for (var round = 1; round <= level; round++) bytes = xorBytes(bytes, kb, round);
  return bytesToB64(bytes);
};

xorDecode = function(s, key, level) {
  var bytes = b64ToBytes(s);
  var kb = utf8Bytes(key);
  for (var round = level; round >= 1; round--) bytes = xorBytes(bytes, kb, round);
  return utf8Text(bytes);
};

registerCipher({
  id: "xor",
  name: "XOR stream (repeating key)",
  category: "classical",
  era: "Modern toy",
  invented: "The simplest stream cipher; every modern stream cipher is its descendant.",
  description: [
    "Each byte of your text is flipped against the repeating key bytes (a 'stream' cipher on raw bytes, so it works on ANY text — accents, emoji, whatever). Output is wrapped in Base64 so it stays pasteable.",
    "The Level control runs several rounds; each round's keystream is salted by the round number, so more rounds mix more thoroughly.",
    "Works on any characters, not just A–Z."
  ],
  history: "XOR is the oldest cipher primitive; the one-time pad (1919, Vernam) is the idealised version — and repeating a short key is exactly the shortcut that makes it breakable.",
  strength: "Weak but byte-level: a repeating short key can be broken with crib-dragging. Levels stop being cheap.",
  example: { pt: "café ☕ bytes", key: "key" },
  keySpec: {
    required: true, kind: "keyword",
    validate: function(k) { return (k.length >= 1) ? null : "Key must be at least one character."; },
    guidance: "Any characters work — even a short word. Longer keys are stronger."
  },
  levels: {
    max: 5, default: 1,
    label: "rounds",
    effect: "Each round re-mixes everything with a round-salted keystream."
  },
  encode: xorEncode,
  decode: xorDecode,
  selfTest: { input: "XOR works on café bytes ☕", key: "any-key" }
});
