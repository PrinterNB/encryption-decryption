// caesar.js — Caesar cipher + ROT13

caesarMap = function(s, k) {
  var out = "";
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c >= 65 && c <= 90) out += String.fromCharCode(65 + ((c - 65 + k) % 26));
    else if (c >= 97 && c <= 122) out += String.fromCharCode(97 + ((c - 97 + k) % 26));
    else out += s[i];
  }
  return out;
};
caesarEncode = function(s, key) { return caesarMap(s, +key); };
caesarDecode = function(s, key) { return caesarMap(s, 26 - (+key % 26)); };

registerCipher({
  id: "caesar",
  name: "Caesar cipher",
  category: "classical",
  era: "Ancient",
  invented: "Used by Julius Caesar (~1st century BC)",
  description: [
    "Every letter is replaced by the letter a fixed number of places down the alphabet. Letters past Z wrap back to A. Numbers, spaces and punctuation are left untouched, and letter case is preserved.",
    "The Level control stacks the cipher: each pass shifts the output again, so a higher level shifts everything by key × level in total — still one number holds the whole key."
  ],
  history: "Named after Julius Caesar, who reportedly used it to send military dispatches (with his lieutenant Mark, the shift was his favorite number). Its weakness was first exposed by Lu's frequency analysis in The Adventure of the Dancing Ciphers (1880s).",
  strength: "Very weak. Only 25 possible keys — a computer tries them all instantly, and by hand you can crack it in seconds.",
  example: { pt: "Meet at dawn", key: "7" },
  keySpec: {
    required: true, kind: "number",
    validate: function(k) { return (/^\d+$/.test(k) && +k >= 1 && +k <= 25) ? null : "Shift must be a whole number from 1 to 25."; },
    guidance: "The shift amount — a number from 1 to 25, e.g. 7."
  },
  levels: {
    max: 10, default: 1,
    label: "pass count",
    effect: "Applies the shift this many times (stacked Caesar passes)."
  },
  encode: function(s, key, level) { return applyRounds(caesarEncode, level)(s, key); },
  decode: function(s, key, level) { return applyRounds(caesarDecode, level)(s, key); },
  selfTest: { input: "Attack at dawn, 9!", key: "5" }
});

registerCipher({
  id: "rot13",
  name: "ROT13",
  category: "classical",
  era: "Modern hobbyist",
  invented: "1980s Usenet folklore (ROT47 cousin, 1990s)",
  description: [
    "A Caesar shift of exactly 13. Because 13 is half the alphabet, the cipher is its own inverse: encrypting the output again gives you back the original — one button does both jobs.",
    "There is no key to remember, which is why people use it to hide spoilers and punchlines rather than secrets."
  ],
  history: "Not ancient at all — it became popular on early Usenet groups in the 1980s to mark spoilers and answers, which is why it survives as a hobbyist convention.",
  strength: "Same as Caesar but with no key at all: one fixed shift. Purely a spoiler-guard, never secrecy.",
  example: { pt: "Spoiler inside", key: "" },
  keySpec: { required: false, kind: "none", guidance: "" },
  levels: null,
  encode: function(s, key, level) { return caesarEncode(s, "13"); },
  decode: function(s, key, level) { return caesarEncode(s, "13"); },
  selfTest: { input: "Spoiler: the butler did it.", key: "" }
});
