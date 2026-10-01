// bacon.js — Bacon's cipher: every letter becomes a group of 5 a/b characters.
// 26 letters → 32 possible groups, so Francis Bacon merged I/J and U/V pairs
// (the original design hid the a/b pattern typographically).

BACTION_ALPHA = "ABCDEFGHIKLMNOPQRSTVWXYZ"; // 24 letters: J shares I, V shares U

b5bits = function(n) { // n 0..31 -> "aaaaa".."bbbbb"
  var out = "";
  for (var bit = 16; bit >= 1; bit >>= 1) out += (n & bit) ? "b" : "a";
  return out;
};

baconEncode = function(s, key) {
  var up = s.toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I").replace(/U/g, "V");
  if (!up) throw new Error("nothing to encode");
  var out = [];
  for (var i = 0; i < up.length; i++) {
    var idx = BACTION_ALPHA.indexOf(up[i]);
    if (idx === -1) throw new Error("letter not encodable");
    out.push(b5bits(idx));
  }
  return out.join(" ");
};

baconDecode = function(s, key) {
  var groups = s.toLowerCase().replace(/[^ab]/g, "").match(/.{5}/g);
  if (!groups) throw new Error("no a/b groups found");
  if (s.replace(/[^ab]/g, "").length % 5 !== 0) throw new Error("a/b characters must come in groups of five");
  var out = "";
  for (var i = 0; i < groups.length; i++) {
    var n = 0;
    for (var j = 0; j < 5; j++) n = n * 2 + (groups[i][j] === "b" ? 1 : 0);
    if (n >= BACTION_ALPHA.length) throw new Error("group does not map to a letter");
    out += BACTION_ALPHA[n];
  }
  return out;
};

registerCipher({
  id: "bacon",
  name: "Bacon's cipher (5-bit a/b)",
  category: "classical",
  era: "Early modern",
  invented: "Francis Bacon, 1586 ('biliteral' alphabet) — the ancestor of binary encoding.",
  description: [
    "Every letter becomes exactly five characters — a hidden binary alphabet, centuries before anyone said 'bit'. I and J share one pattern; U and V share one, too. Groups of five are shown spaced here for readability.",
    "No key exists: it is an encoding, not a secret. Its point is concealment — Bacon's original design hid the a/b letters inside an innocent-looking paragraph by printing them in two typefaces."
  ],
  history: "Sir Francis Bacon's 'biliteral' alphabet of 1586 anticipated binary by centuries; the classic trick hides the pattern in the choice of typeface, giving a whole innocent page as the real message.",
  strength: "Zero secrecy (no key). Its value was concealment, and as a teaching example of everything-a-letter.",
  example: { pt: "biliteral", key: "" },
  keySpec: { required: false, kind: "none", guidance: "" },
  levels: null,
  encode: baconEncode,
  decode: baconDecode,
  selfTest: { input: "everything is a pattern", key: "", normalized: true },
  ji: true // treat U/V and I/J as equal in the round-trip check
});
