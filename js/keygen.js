// keygen.js — random keys that are ALWAYS valid for the cipher being used.
// Pronounceable keywords, digit keys, full alphabets and word-passphrases.

KEYGEN_CONSONANTS = "bcdfghjklmnpqrstvwz";
KEYGEN_VOWELS = "aeiou";

WORDS = [
  "anchor","apple","bridge","canvas","cedar","cobalt","comet","coral","crimson","currant",
  "dapple","delta","ember","fathom","fennel","gantry","garnet","harbor","hazel","indigo",
  "juniper","kettle","lantern","lattice","marble","meadow","nectar","nimbus","opal","otter",
  "pepper","pinnacle","quartz","quiver","ribbon","saffron","sable","saddle","tanger","timber",
  "umbra","urchin","velvet","walnut","willow","xylene","yarrow","zephyr","amber","aspen",
  "basalt","beryl","clover","dune","fern","gale","harvest","ivory","jetty","kelp",
  "lichen","marrow","nectar","ochre","prism","quill","reed","stone","topaz","umber",
  "vine","wald","xeric","yonder","zenith","zinc","agate","birch","cedar","dahl",
  "ember","flint","gneiss","halide","inlet","jasper","kindle","loam","mica","nimbus",
  "onyx","pebble","quartz","raven","silt","tundra","umber","vesper","willow","xyst"
];

genPronounceable = function() { // 2–4 syllables of consonant-vowel pairs
  var n = 2 + randInt(3);
  var out = "";
  for (var i = 0; i < n; i++) {
    out += KEYGEN_CONSONANTS[randInt(KEYGEN_CONSONANTS.length)];
    out += KEYGEN_VOWELS[randInt(KEYGEN_VOWELS.length)];
  }
  return out;
};

genKeyFor = function(kind) {
  if (kind === "number") return String(1 + randInt(25));
  if (kind === "keyword") return genPronounceable();
  if (kind === "numeric") {
    var len = 4 + randInt(5), out = "";
    for (var i = 0; i < len; i++) out += String(randInt(10));
    return out;
  }
  if (kind === "alphaAlphabet") {
    var kw = genPronounceable() + genPronounceable();
    return buildKeywordAlpha(kw);
  }
  if (kind === "passphrase") {
    var ws = [];
    for (var j = 0; j < 6; j++) ws.push(WORDS[randInt(WORDS.length)]);
    return ws.join(" ");
  }
  return "";
};

makeKeycard = function(entryId, key, level) {
  return "card:" + entryId + " key:" + encodeURIComponent(key) + " lvl:" + level;
};

parseKeycard = function(text) {
  var m = text.trim().match(/^card:([\w-]+) key:(.*) lvl:(\d+)$/);
  if (!m) return null;
  return { entryId: m[1], key: decodeURIComponent(m[2]), level: +m[3] };
};
