// verify.js — round-trip checking: decrypt(encrypt(x)) must give back x.
// Some classical ciphers deliberately destroy case/spacing (Playfair, Bacon).
// For those the check compares LETTER CONTENT, and the UI says so honestly.

normalizeText = function(s) {
  return s.toUpperCase().replace(/[^A-Z]/g, "");
};

jiNormalize = function(s) { // for Playfair/Bacon entries: I and J, U and V share cells
  return normalizeText(s).replace(/J/g, "I").replace(/U/g, "V");
};

firstDiff = function(a, b) {
  for (var i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return i;
  }
  return a.length === b.length ? -1 : Math.min(a.length, b.length);
};

compareRoundTrip = function(entry, original, restored) {
  if (original === restored) return { ok: true, mode: "exact" };
  if (entry.ji) {
    var a = jiNormalize(original), b = jiNormalize(restored);
    if (a === b) return { ok: true, mode: "letters" };
    // Playfair pads an odd-length tail with X — a single trailing X is expected, not a bug
    if (a.length % 2 === 1 && b === a + "X") return { ok: true, mode: "letters" };
    return { ok: false, mode: null, where: firstDiff(a, b) };
  }
  if (normalizeText(original) === normalizeText(restored)) return { ok: true, mode: "letters" };
  return { ok: false, mode: null, where: firstDiff(original, restored) };
};
