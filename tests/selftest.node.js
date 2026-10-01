// selftest.node.js — run the engine's registry + every cipher's selfTest under Node.
// Usage: node tests/selftest.node.js
// (The browser harness is tests/selftest.html; this mirrors it for terminal runs.)
// no strict directive needed

var fs = require("fs");
var vm = require("vm");

if (typeof crypto === "undefined" || !crypto.getRandomValues) {
  var webcrypto = require("crypto").webcrypto;
  vm.runInThisContext("crypto = require('crypto').webcrypto;");
}

var files = [
  "../js/registry.js",
  "../js/ciphers/caesar.js",
  "../js/ciphers/atbash.js",
  "../js/ciphers/keyword.js",
  "../js/ciphers/vigenere.js",
  "../js/ciphers/autokey.js",
  "../js/ciphers/playfair.js",
  "../js/ciphers/railfence.js",
  "../js/ciphers/bacon.js",
  "../js/ciphers/xor.js",
  "../js/ciphers/encodings.js",
  "../js/ciphers/aes.js",
  "../js/keygen.js",
  "../js/fileinput.js",
  "../js/verify.js"
];

for (var i = 0; i < files.length; i++) {
  var src = fs.readFileSync(require("path").join(__dirname, files[i]), "utf8");
  vm.runInThisContext(src);
}

(async function() {
  var pass = 0, fail = 0;
  for (var j = 0; j < REGISTRY.length; j++) {
    var entry = REGISTRY[j];
    var st = entry.selfTest;
    var lvl = entry.levels ? entry.levels.default : 1;
    try {
      var ct = await entry.encode(st.input, st.key, lvl);
      var back = await entry.decode(ct, st.key, lvl);
      var cmp = compareRoundTrip(entry, st.input, back);
      if (cmp.ok) { pass++; console.log(entry.id + ": PASS" + (cmp.mode === "exact" ? " (exact)" : " (letters-normalised)")); }
      else { fail++; console.log(entry.id + ": FAIL at position " + cmp.where); }
    } catch (e) {
      fail++;
      console.log(entry.id + ": EXCEPTION " + (e && e.message ? e.message : String(e)));
    }
  }
  console.log((fail === 0 ? "ALL PASS" : "FAILURES: " + fail) + " — " + pass + " passed, " + fail + " failed.");
  process.exitCode = fail === 0 ? 0 : 1;
})();
