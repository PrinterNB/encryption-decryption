// encodings.js — Base64 and Base32: encodings, not secrets. Our own implementation
// (the built-in atob/btoa only cross-checks the Base64 one in the test harness).

B32ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

b32Encode = function(bytes) {
  // stream bits, keeping the accumulator under 13 bits so 32-bit ops never overflow
  var out = "", acc = 0, bits = 0;
  for (var i = 0; i < bytes.length; i++) {
    acc = (acc << 8) | bytes[i]; bits += 8;
    while (bits >= 5) { bits -= 5; out += B32ALPHA[(acc >> bits) & 31]; }
  }
  if (bits > 0) out += B32ALPHA[(acc << (5 - bits)) & 31];
  while (out.length % 8 !== 0) out += "=";
  return out;
};

b32Decode = function(str) {
  if (str.toUpperCase().replace(/[^A-Z2-7=]/g, "").length !== str.toUpperCase().length) {
    throw new Error("not valid Base32");
  }
  var clean = str.toUpperCase().replace(/=+$/, "");
  var acc = 0, bits = 0, out = [];
  for (var i = 0; i < clean.length; i++) {
    var v = B32ALPHA.indexOf(clean[i]);
    if (v === -1) throw new Error("not valid Base32");
    acc = (acc << 5) | v; bits += 5;
    if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 255); acc &= (1 << bits) - 1; }
  }
  return new Uint8Array(out);
};

registerCipher({
  id: "base64",
  name: "Base64",
  category: "encoding",
  era: "Modern standard",
  invented: "1980s (Usenet/MIME); RFC 2045-era base encoding conventions; standardised as RFC 4648 later.",
  description: [
    "Turns ANY bytes into a safe, printable alphabet (64 characters, A–Z, a–z, 0–9, + /). It is an ENCODING: anyone can reverse it instantly — it is not a secret.",
    "Its real job is safe transport: binary or accented text survives any box that only promises to carry plain characters.",
    "No key exists and the Level control is absent by design."
  ],
  history: "A descendant of base conversion — the same reason you count in base 2 and base 16. Base64 made 8-bit bytes safe across old 7-bit networks in the 1980s, and survives on the internet today as image data and key serialisation.",
  strength: "None: it is reversible by anyone. Use it to be safe, never to be secret.",
  example: { pt: "safe transport", key: "" },
  keySpec: { required: false, kind: "none", guidance: "" },
  levels: null,
  encode: function(s, key, level) { return bytesToB64(utf8Bytes(s)); },
  decode: function(s, key, level) { return utf8Text(b64ToBytes(s)); },
  selfTest: { input: "Base64 survives anything, including ☕.", key: "" }
});

registerCipher({
  id: "base32",
  name: "Base32",
  category: "encoding",
  era: "Modern standard",
  invented: "RFC 4648-era base encoding; chosen alphabet avoids ambiguity (no 0/O, 1/I).",
  description: [
    "Like Base64, but restricted to 32 unambiguous characters (A–Z and 2–7) — output is longer but survives even systems that case-fold or confuse 0 with O.",
    "Same rules: an encoding, not a secret."
  ],
  history: "The base-conversion family: base 32 trades length for a deliberately collision-free alphabet, which is why base32 shows up in secret-sharing schemes and short-URL tools.",
  strength: "None: reversible by anyone.",
  example: { pt: "base32 is case-safe", key: "" },
  keySpec: { required: false, kind: "none", guidance: "" },
  levels: null,
  encode: function(s, key, level) { return b32Encode(utf8Bytes(s)); },
  decode: function(s, key, level) { return utf8Text(b32Decode(s)); },
  selfTest: { input: "Case-insensitive safety.", key: "" }
});
