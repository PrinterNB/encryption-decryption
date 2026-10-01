// railfence.js — Rail Fence: write the text zig-zag over N rails, read off row by row.
// Character-for-character (including spaces and punctuation) — round-trips exactly.

railOrder = function(n, rails) {
  var rows = [], row = 0, dir = 1;
  for (var i = 0; i < rails; i++) rows.push([]);
  for (var j = 0; j < n; j++) {
    rows[row].push(j);
    if (row === rails - 1) dir = -1;
    else if (row === 0) dir = 1;
    row += dir;
  }
  var flat = [];
  for (var r = 0; r < rails; r++) flat = flat.concat(rows[r]);
  return flat;
};

rfEncode = function(s, rails) {
  var order = railOrder(s.length, rails), out = "";
  for (var i = 0; i < order.length; i++) out += s[order[i]];
  return out;
};

rfDecode = function(s, rails) {
  var order = railOrder(s.length, rails), out = new Array(s.length);
  for (var i = 0; i < order.length; i++) out[order[i]] = s[i];
  return out.join("");
};

registerCipher({
  id: "railfence",
  name: "Rail Fence (zigzag transposition)",
  category: "classical",
  era: "Early modern",
  invented: "A classic transposition; described in 19th-century cipher manuals and used by Union (US Civil War) ciphers.",
  description: [
    "No letters change! The message is written diagonally up-and-down across a number of 'rails', then read off rail by rail. The receiver writes it back the same way to recover it.",
    "The Level control sets the number of rails — more rails spread every character further from its neighbours."
  ],
  history: "Rail Fence appears through the Union cipher manuals of the 19th century as a cheap field transposition; transposition and substitution together became the basis of 'confusion and diffusion' in modern ciphers.",
  strength: "Weak. Spaces and punctuation survive untouched (a huge tell), and the rails can be guessed instantly. Perfect as a first exposure to transposition.",
  example: { pt: "The price is on the rails", key: "" },
  keySpec: { required: false, kind: "none", guidance: "" },
  levels: {
    max: 8, default: 2,
    label: "rails",
    effect: "Number of rails in the zigzag — more rails, more shuffled."
  },
  encode: function(s, key, level) { return rfEncode(s, level + 1); },
  decode: function(s, key, level) { return rfDecode(s, level + 1); },
  selfTest: { input: "Zig, zag, zig, zag!", key: "" }
});
