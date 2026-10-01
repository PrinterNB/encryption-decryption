// keyword.js — Keyword cipher, Mixed-alphabet variant, and Simple Substitution.

buildKeywordAlpha = function(key) { // keyed alphabet: keyword letters first, rest in order
  var k = key.toUpperCase().replace(/[^A-Z]/g, "");
  if (!k) throw new Error("key must contain letters");
  var seen = {}, alpha = "";
  for (var i = 0; i < k.length; i++) {
    if (!seen[k[i]]) { seen[k[i]] = true; alpha += k[i]; }
  }
  for (var c = 65; c <= 90; c++) {
    var ch = String.fromCharCode(c);
    if (!seen[ch]) { seen[ch] = true; alpha += ch; }
  }
  return alpha;
};

buildMixedAlpha = function(key) { // keyword cipher, but the leftover tail is written backwards
  var k = key.toUpperCase().replace(/[^A-Z]/g, "");
  if (!k) throw new Error("key must contain letters");
  var seen = {}, keywordPart = "";
  for (var i = 0; i < k.length; i++) {
    if (!seen[k[i]]) { seen[k[i]] = true; keywordPart += k[i]; }
  }
  var rest = [];
  for (var c = 65; c <= 90; c++) {
    var ch = String.fromCharCode(c);
    if (!seen[ch]) { seen[ch] = true; rest.push(ch); }
  }
  rest.reverse();
  return keywordPart + rest.join("");
};

simpleAlpha = function(key) { // key IS the alphabet: 26 distinct letters
  var k = key.toUpperCase().replace(/[^A-Z]/g, "");
  if (k.length !== 26) throw new Error("a simple-substitution key must be exactly 26 distinct letters");
  var seen = {};
  for (var i = 0; i < 26; i++) {
    if (seen[k[i]]) throw new Error("key contains repeated letters");
    seen[k[i]] = true;
  }
  return k;
};

subEncode = function(s, alpha) {
  var out = "";
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c >= 65 && c <= 90) out += alpha[c - 65];
    else if (c >= 97 && c <= 122) out += alpha[c - 97].toLowerCase();
    else out += s[i];
  }
  return out;
};

subDecode = function(s, alpha) {
  var back = {};
  for (var i = 0; i < 26; i++) back[alpha[i]] = String.fromCharCode(65 + i);
  var out = "";
  for (var j = 0; j < s.length; j++) {
    var c = s.charCodeAt(j);
    if (c >= 65 && c <= 90) out += back[s[j]];
    else if (c >= 97 && c <= 122) out += back[s[j].toUpperCase()].toLowerCase();
    else out += s[j];
  }
  return out;
};

registerCipher({
  id: "keyword",
  name: "Keyword cipher",
  category: "classical",
  era: "Renaissance",
  invented: "Popular from the 1600s on — the standard 'beginner's' substitution.",
  description: [
    "You choose a secret keyword. It forms the start of a scrambled alphabet (new letters only, in the order they appear), and the remaining letters are appended in normal order. Then A is replaced by the alphabet's first letter, B by the second, and so on.",
    "Far easier to key than a fully random alphabet — which is exactly why it is easier to break."
  ],
  history: "The practical compromise between a random alphabet too long to remember and a plain Caesar too easy to break; it appears throughout 17th-century cipher manuals.",
  strength: "Weak. The key is only one word, and the leftover alphabet tail leaks structure — frequency analysis cracks it quickly.",
  example: { pt: "meet at dawn", key: "secret" },
  keySpec: {
    required: true, kind: "keyword",
    validate: function(k) { return (/[A-Za-z]/.test(k)) ? null : "Key must contain at least one letter."; },
    guidance: "One secret word, e.g. 'secret'. Spaces and digits are ignored."
  },
  levels: null,
  encode: function(s, key, level) { return subEncode(s, buildKeywordAlpha(key)); },
  decode: function(s, key, level) { return subDecode(s, buildKeywordAlpha(key)); },
  selfTest: { input: "The keyword guards the gate.", key: "lantern" }
});

registerCipher({
  id: "mixed-alphabet",
  name: "Mixed-alphabet keyword",
  category: "classical",
  era: "Renaissance variant",
  invented: "Variant of the keyword cipher found in later cipher manuals.",
  description: [
    "The keyword cipher, but the remaining letters after the keyword are written in REVERSE order. Still keyed by one word, yet the 'plain tail' that made the plain keyword cipher leaky is now scrambled backwards.",
    "A small step in the right direction — not a large one."
  ],
  history: "Appears alongside the keyword cipher in recreational and pedagogic cipher literature as a 'harder beginner' variant.",
  strength: "Weak, like the keyword cipher. A touch harder to recognise, equally easy to frequency-analyse.",
  example: { pt: "meet at dawn", key: "secret" },
  keySpec: {
    required: true, kind: "keyword",
    validate: function(k) { return (/[A-Za-z]/.test(k)) ? null : "Key must contain at least one letter."; },
    guidance: "One secret word, e.g. 'secret'."
  },
  levels: null,
  encode: function(s, key, level) { return subEncode(s, buildMixedAlpha(key)); },
  decode: function(s, key, level) { return subDecode(s, buildMixedAlpha(key)); },
  selfTest: { input: "Mixed tails hide little.", key: "lantern" }
});

registerCipher({
  id: "simple-substitution",
  name: "Simple substitution (random alphabet)",
  category: "classical",
  era: "Ancient",
  invented: "As old as writing itself — 'the Caesar of the ancients' generalised.",
  description: [
    "Every letter maps to one other letter by a completely shuffled alphabet. The key is that shuffled alphabet itself — 26 letters, each appearing exactly once.",
    "Use 'Generate key' here and SAVE the key: typing a random alphabet is impractical. Newspaper cryptics are made with this cipher."
  ],
  history: "The plain substitution alphabet has been known since antiquity; by the 19th century newspapers adopted it for their puzzle pages, and 'crypto' crosswords are its descendants.",
  strength: "Weak. ~26! alphabets sounds huge, but English letter frequencies and word patterns beat it easily; skilled solvers crack cryptic examples by hand.",
  example: { pt: "meet at dawn", key: "zyxwvutsrqponmlkjihgfedcba" },
  keySpec: {
    required: true, kind: "alphaAlphabet",
    validate: function(k) {
      var up = k.toUpperCase().replace(/[^A-Z]/g, "");
      if (up.length === 26) {
        var seen = {};
        for (var i = 0; i < 26; i++) { if (seen[up[i]]) return "key contains a repeated letter"; seen[up[i]] = true; }
        return null;
      }
      return "The key must be a full alphabet: all 26 letters, no repeats.";
    },
    guidance: "A scrambled alphabet (26 letters, each once). Easiest: generate and save the key."
  },
  levels: null,
  encode: function(s, key, level) { return subEncode(s, simpleAlpha(key)); },
  decode: function(s, key, level) { return subDecode(s, simpleAlpha(key)); },
  selfTest: { input: "Random alphabets beat the mind.", key: "qwertzuiopasdfghjklyxcvbnm" }
});
