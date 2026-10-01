// vigenere.js — Vigenère (letter keyword) and Gronsfeld (digit keyword).

vigEncode = function(s, keyword) {
  var k = keyword.toUpperCase().replace(/[^A-Z]/g, "");
  if (!k) throw new Error("key must contain letters");
  var out = "", ki = 0;
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c >= 65 && c <= 90) {
      var sh = k.charCodeAt(ki % k.length) - 65;
      ki++;
      out += String.fromCharCode(65 + (c - 65 + sh) % 26);
    } else if (c >= 97 && c <= 122) {
      var sh2 = k.charCodeAt(ki % k.length) - 65;
      ki++;
      out += String.fromCharCode(97 + (c - 97 + sh2) % 26);
    } else out += s[i];
  }
  return out;
};
vigDecode = function(s, keyword) {
  var k = keyword.toUpperCase().replace(/[^A-Z]/g, "");
  if (!k) throw new Error("key must contain letters");
  var out = "", ki = 0;
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c >= 65 && c <= 90) {
      var sh = k.charCodeAt(ki++ % k.length) - 65;
      out += String.fromCharCode(65 + (c - 65 - sh + 26) % 26);
    } else if (c >= 97 && c <= 122) {
      var sh2 = k.charCodeAt(ki++ % k.length) - 65;
      out += String.fromCharCode(97 + (c - 97 - sh2 + 26) % 26);
    } else out += s[i];
  }
  return out;
};

gronsfeldEncode = function(s, digits) {
  if (!/^\d+$/.test(digits)) throw new Error("key must be digits");
  var out = "", ki = 0;
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c >= 65 && c <= 90) { var sh = +digits.charAt(ki++ % digits.length); out += String.fromCharCode(65 + (c - 65 + sh) % 26); }
    else if (c >= 97 && c <= 122) { var sh2 = +digits.charAt(ki++ % digits.length); out += String.fromCharCode(97 + (c - 97 + sh2) % 26); }
    else out += s[i];
  }
  return out;
};
gronsfeldDecode = function(s, digits) {
  if (!/^\d+$/.test(digits)) throw new Error("key must be digits");
  var out = "", ki = 0;
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c >= 65 && c <= 90) { var sh = +digits.charAt(ki++ % digits.length); out += String.fromCharCode(65 + (c - 65 - sh + 26 * 10) % 26); }
    else if (c >= 97 && c <= 122) { var sh2 = +digits.charAt(ki++ % digits.length); out += String.fromCharCode(97 + (c - 97 - sh2 + 26 * 10) % 26); }
    else out += s[i];
  }
  return out;
};

registerCipher({
  id: "vigenere",
  name: "Vigenère cipher",
  category: "classical",
  era: "Early modern",
  invented: "1586, by Blaise de Vigenère (French cryptographer).",
  description: [
    "A 'polyalphabetic' Caesar: a secret keyword selects which of 26 Caesar alphabets protects each letter, cycling along the text. Different letters are shifted by different amounts — the classic tool that defeats simple frequency counting.",
    "The Level control re-applies the whole cipher, each time with a new alphabet derived from your keyword (keyed passes). Passes stack, but the same word is still the whole key."
  ],
  history: "Blaise de Vigenère described it in his 1586 'Dechreising des Kunst bey Calyckuli', though it is really a clearer way to write his earlier 'quintuple' table. The name stuck to the table instead.",
  strength: "Moderate. Kasiski examination and the index of coincidence break it once the message is longer than about 10× the key length.",
  example: { pt: "ATTACK", key: "KEY" },
  keySpec: {
    required: true, kind: "keyword",
    validate: function(k) { return (/[A-Za-z]/.test(k)) ? null : "Key must contain at least one letter."; },
    guidance: "A secret word or phrase; letters only, e.g. 'lantern'."
  },
  levels: {
    max: 5, default: 1,
    label: "keyed passes",
    effect: "Runs the whole Vigenère pass this many times with the same keyword — stacking multiplies the shift."
  },
  encode: function(s, key, level) {
    var k = key.toUpperCase().replace(/[^A-Z]/g, "");
    for (var p = 0; p < level; p++) s = vigEncode(s, k);
    return s;
  },
  decode: function(s, key, level) {
    var k = key.toUpperCase().replace(/[^A-Z]/g, "");
    for (var p = 0; p < level; p++) s = vigDecode(s, k);
    return s;
  },
  selfTest: { input: "Vigenere beat frequency counts, briefly.", key: "lantern" }
});

registerCipher({
  id: "gronsfeld",
  name: "Gronsfeld cipher",
  category: "classical",
  era: "Early modern",
  invented: "Named for the Danish cryptographer Johan Gronsfeld (c. 1744); a numeric-keyed variant of Vigenère.",
  description: [
    "Vigenère but the key is digits instead of letters: each digit says how far to shift the next letter (0 leaves it unchanged). Digit keys are easy to type and remember — they are also easier to guess.",
    "Good first exposure to polyalphabetic ideas before real Vigenère."
  ],
  history: "Johan Gronsfeld of Copenhagen published this number-key variant in a 1744 pamphlet; the technique is a special case of Vigenère where the key alphabet is 0–9.",
  strength: "Moderate-weak: a 10-key-alphabet Vigenère. Every digit is only 0–9, so its structure is very visible.",
  example: { pt: "ATTACK", key: "314" },
  keySpec: {
    required: true, kind: "numeric",
    validate: function(k) { return (/^\d+$/.test(k)) ? null : "Key must be digits, e.g. 31415."; },
    guidance: "Digits only, e.g. '314159'."
  },
  levels: {
    max: 5, default: 1,
    label: "keyed passes",
    effect: "Runs the whole cipher this many times; passes stack."
  },
  encode: function(s, key, level) { for (var p = 0; p < level; p++) s = gronsfeldEncode(s, key); return s; },
  decode: function(s, key, level) { for (var p = 0; p < level; p++) s = gronsfeldDecode(s, key); return s; },
  selfTest: { input: "Digits disguise nothing.", key: "12345" }
});
