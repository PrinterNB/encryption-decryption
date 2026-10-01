// playfair.js — Playfair: pairs of letters encrypted through a 5×5 key square.
// Note: output is uppercase letters only (J is merged into I; X breaks duplicate pairs
// and pads the end) — the round-trip check normalises case/spacing for this reason.

pfSquare = function(key) {
  var k = (key || "").toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");
  var sq = "", seen = {};
  var pool = k + "ABCDEFGHIKLMNOPQRSTUVWXYZ";
  for (var i = 0; i < pool.length; i++) {
    var ch = pool[i];
    if (ch !== "J" && !seen[ch]) { seen[ch] = true; sq += ch; }
  }
  return sq;
};

pfPrepare = function(s) {
  var L = s.toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");
  var out = "";
  for (var i = 0; i < L.length;) {
    var a = L[i];
    var b = (i + 1 < L.length) ? L[i + 1] : "";
    if (b === "") { out += a + "X"; break; }
    if (b === a) { out += a + "X"; i += 1; }
    else { out += a + b; i += 2; }
  }
  return out;
};

playfairEncode = function(s, key) {
  var sq = pfSquare(key);
  var pairs = pfPrepare(s);
  var out = "";
  for (var i = 0; i < pairs.length; i += 2) {
    var p1 = sq.indexOf(pairs[i]), p2 = sq.indexOf(pairs[i + 1]);
    var r1 = Math.floor(p1 / 5), c1 = p1 % 5, r2 = Math.floor(p2 / 5), c2 = p2 % 5;
    var n1, n2;
    if (r1 === r2) { n1 = r1 * 5 + (c1 + 1) % 5; n2 = r2 * 5 + (c2 + 1) % 5; }
    else if (c1 === c2) { n1 = ((r1 + 1) % 5) * 5 + c1; n2 = ((r2 + 1) % 5) * 5 + c2; }
    else { n1 = r1 * 5 + c2; n2 = r2 * 5 + c1; }
    out += sq[n1] + sq[n2];
  }
  return out;
};

playfairDecode = function(s, key) {
  var sq = pfSquare(key);
  var L = s.toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");
  if (L.length % 2) L += "X"; // tolerate a lost padding character
  var out = "";
  for (var i = 0; i < L.length; i += 2) {
    var p1 = sq.indexOf(L[i]), p2 = sq.indexOf(L[i + 1]);
    if (p1 === -1 || p2 === -1) throw new Error("text contains letters outside the 5×5 square (J or V?)");
    var r1 = Math.floor(p1 / 5), c1 = p1 % 5, r2 = Math.floor(p2 / 5), c2 = p2 % 5;
    var n1, n2;
    if (r1 === r2) { n1 = r1 * 5 + (c1 + 4) % 5; n2 = r2 * 5 + (c2 + 4) % 5; }
    else if (c1 === c2) { n1 = ((r1 + 4) % 5) * 5 + c1; n2 = ((r2 + 4) % 5) * 5 + c2; }
    else { n1 = r1 * 5 + c2; n2 = r2 * 5 + c1; }
    out += sq[n1] + sq[n2];
  }
  return out;
};

registerCipher({
  id: "playfair",
  name: "Playfair cipher",
  category: "classical",
  era: "Modern-classic",
  invented: "1857, Charles Wheatstone (London); popularised by Lord Playfair's name in 1868.",
  description: [
    "Pairs of letters — digraphs — are encrypted through a 5×5 square built from a keyword (the alphabet has 26 letters, so J shares I's cell). Same row → shift right; same column → shift down; otherwise each letter takes the other's column.",
    "Everything comes out as uppercase letters. The round-trip badge therefore judges by letter content, ignoring case and spacing.",
    "Text is prepared for you automatically: repeated letters in a pair get an X between them, and a dangling last letter gets an X pad."
  ],
  history: "Charles Wheatstone invented it in 1857; it took the name of an admirer who 'invented' it again in 1868, and the double name — Wheatstone–Playfair — is now standard.",
  strength: "Strong for its age: up to 25×25/2 digraph alphabets (≈675,000 combinations) and no single-letter frequencies to count. Mechanical digraph analysis (e.g. by the Allies in WW1 and in a 1942 British news headline) breaks it with enough text.",
  example: { pt: "hide the gold", key: "monarchy" },
  keySpec: {
    required: true, kind: "keyword",
    validate: function(k) { return (/[A-Za-z]/.test(k)) ? null : "Key must contain at least one letter."; },
    guidance: "A secret word or phrase; letters only, e.g. 'monarchy'."
  },
  levels: null,
  encode: playfairEncode,
  decode: playfairDecode,
  selfTest: { input: "HIDE THE GOLD AT ONCE!", key: "monarchy", normalized: true },
  ji: true
});
