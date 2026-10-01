// atbash.js — Atbash: reverse the alphabet (A<->Z, B<->Y ...). Self-inverse, no key.

atbashMap = function(s) {
  var out = "";
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c >= 65 && c <= 90) out += String.fromCharCode(90 - (c - 65));
    else if (c >= 97 && c <= 122) out += String.fromCharCode(122 - (c - 97));
    else out += s[i];
  }
  return out;
};

registerCipher({
  id: "atbash",
  name: "Atbash",
  category: "classical",
  era: "Ancient (Atbash) / recreational",
  invented: "Mentioned in the Book of Atbash (a medieval collection of puzzles); popularised today by the Doctor Who serial 'The Daemons' (1971).",
  description: [
    "The alphabet is written in reverse and used as the substitution: A becomes Z, B becomes Y, and so on. Everything not a letter stays as it is.",
    "The cipher is reciprocal — running it on the output gives you back the input — so encrypting and decrypting are the same operation."
  ],
  history: "A simple mirror-alphabet substitution has been a puzzle staple for centuries; it became famous in pop culture through Doctor Who, where the Silodeon secret was 'hidden' in exactly this way.",
  strength: "Weak: no key exists, so there is exactly one possible cipher text. Trivial to break by eye.",
  example: { pt: "silodeon", key: "" },
  keySpec: { required: false, kind: "none", guidance: "" },
  levels: null,
  encode: function(s, key, level) { return atbashMap(s); },
  decode: function(s, key, level) { return atbashMap(s); },
  selfTest: { input: "The Silodeon is humming.", key: "" }
});
