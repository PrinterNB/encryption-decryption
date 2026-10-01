// autokey.js — Vigenère-style Autokey: after the primer keyword, the PLAINTEXT itself
// continues the key stream, so the key never repeats in blocks.

autokeyEncode = function(s, keyword) {
  var primer = keyword.toUpperCase().replace(/[^A-Z]/g, "");
  if (!primer) throw new Error("key must contain letters");
  var stream = primer;
  var out = "", ki = 0;
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c >= 65 && c <= 90) {
      var sh = stream.charCodeAt(ki++) - 65;
      stream += s[i].toUpperCase(); // the plaintext becomes the key
      out += String.fromCharCode(65 + (c - 65 + sh) % 26);
    } else if (c >= 97 && c <= 122) {
      var sh2 = stream.charCodeAt(ki++) - 65;
      stream += s[i].toUpperCase();
      out += String.fromCharCode(97 + (c - 97 + sh2) % 26);
    } else out += s[i];
  }
  return out;
};

autokeyDecode = function(s, keyword) {
  var stream = keyword.toUpperCase().replace(/[^A-Z]/g, "");
  if (!stream) throw new Error("key must contain letters");
  var out = "", ki = 0;
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c >= 65 && c <= 90) {
      var sh = stream.charCodeAt(ki) - 65;
      var p = (c - 65 - sh + 26 * 10) % 26;
      stream += String.fromCharCode(65 + p); ki++;
      out += String.fromCharCode(65 + p);
    } else if (c >= 97 && c <= 122) {
      var sh2 = stream.charCodeAt(ki) - 65;
      var p2 = (c - 97 - sh2 + 26 * 10) % 26;
      stream += String.fromCharCode(65 + p2); ki++;
      out += String.fromCharCode(97 + p2);
    } else out += s[i];
  }
  return out;
};

registerCipher({
  id: "autokey",
  name: "Autokey cipher (word-keyed)",
  category: "classical",
  era: "Early modern",
  invented: "Blaise de Vigenère, 1568 ('Autokey' described in Dechreising des Kunst bey Calyckuli).",
  description: [
    "Starts like Vigenère with a primer keyword — but then the KEY becomes the plaintext you are encrypting. There is no repeating key block for the Kasiski test to find.",
    "Decrypting needs the same primer keyword, and each recovered letter feeds the key for the next one. Non-letters are left alone and do not join the key stream."
  ],
  history: "Blaise de Vigenère described it in his 1586 book as the 'self-generated key' method. It is the direct ancestor of modern stream ciphers.",
  strength: "Moderate. No repeating key, but repeated plaintext words make repeated ciphertext runs that reveal the shift distance (the Chave de Autoclave attack).",
  example: { pt: "autokey hides repeats", key: "primer" },
  keySpec: {
    required: true, kind: "keyword",
    validate: function(k) { return (/[A-Za-z]/.test(k)) ? null : "Key must contain at least one letter."; },
    guidance: "A primer word (letters only), e.g. 'primer'."
  },
  levels: null,
  encode: autokeyEncode,
  decode: autokeyDecode,
  selfTest: { input: "The key chases the text itself.", key: "primer" }
});
