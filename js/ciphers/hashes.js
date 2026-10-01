// hashes.js — one-way digests, not encryption: SHA-256 and SHA-512 straight from the
// browser's Web Crypto. They are here because "really secure" often means "I don't need it
// back, I only need to compare or commit to it". A digest cannot be reversed — that is the
// whole design — so these entries carry `oneWay: true`, which the pipeline and self-tests
// handle instead of a round-trip.

digestHex = async function(algo, s) {
  var d = new Uint8Array(await crypto.subtle.digest(algo, utf8Bytes(s)));
  var hex = "";
  for (var i = 0; i < d.length; i++) {
    var b = d[i].toString(16);
    hex += b.length === 1 ? "0" + b : b;
  }
  return hex;
};

makeHashEntry = function(algo, id, name, bits, expectedVector) {
  return {
    id: id,
    name: name,
    category: "hashing",
    oneWay: true,
    era: "Standard since 2001 (SHA-2 family)",
    invented: "SHA-2 designed by the NSA (1993–2001); SHA-256/SHA-512 are the SHA-2 variants aimed at 32-bit and 64-bit words.",
    description: [
      "A fingerprint, not a secret: the whole text is folded into a fixed " + bits + "-bit value. Two texts collide only by bad luck, so equality checks, integrity checks and dedup all work WITHOUT holding the original.",
      "One-way by design — there is no decryption. The value proves something ABOUT the text; it never carries the text back.",
      "Deterministic: the same text always prints the same digest, on this page and everywhere else (SHA-2 is a standard — you can paste the same text into any other hasher and compare).",
      "Do NOT use a bare hash to store passwords: these digests are fast, and 'fast' means a guessing machine can try billions of them per second. To protect something guessable, stretch it — that is what the Level control does in AES/ChaCha."
    ],
    history: "The SHA family was designed by the NSA (SHA-0/SHA-1 in 1993, fixed as SHA-1 in 1995, extended to SHA-2's 256/384/512-bit variants in 2001). SHA-256 is what integrity lists, signed tokens and version-control systems lean on worldwide.",
    strength: "Real, standard SHA-" + bits + ": no known structural collisions, and a single changed character completely changes the value (avalanche). Honest limits: it is not encryption (a digest is a fingerprint), and against a determined attacker it is only as hard to invert as the text is to GUESS — 'hello' hashes to a value anyone can find by trying 'hello' first.",
    example: { pt: "same text → same digest, always", key: "" },
    keySpec: {
      required: false,
      guidance: "No key — the digest belongs to the text alone."
    },
    encode: async function(s, key, level) { return digestHex(algo, s); },
    decode: function(s, key, level) {
      throw new Error("A digest is one-way — nothing decrypts it. To keep something secret AND reversible, use AES or ChaCha20-Poly1305.");
    },
    selfTest: { input: "abc", key: "", expected: expectedVector },
    notesSecurity: "digest"
  };
};

// known-answer anchors: the official FIPS 180-2 vectors for the input "abc".
// (Also cross-checked against Node's OpenSSL here — a wrong core would fail the self-test.)
registerCipher(makeHashEntry("SHA-256", "sha256", "SHA-256 (digest)", 256,
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
registerCipher(makeHashEntry("SHA-512", "sha512", "SHA-512 (digest)", 512,
  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
