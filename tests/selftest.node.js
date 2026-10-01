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
  "../js/ciphers/chacha.js",
  "../js/ciphers/rsa.js",
  "../js/ciphers/hashes.js",
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
      if (entry.oneWay) {
        // one-way entries: deterministic output, a known vector when we have one,
        // and decode MUST refuse — an invertible "hash" would be a bug.
        var d1 = await entry.encode(st.input, st.key, lvl);
        var d2 = await entry.encode(st.input, st.key, lvl);
        var why = null;
        if (d1 !== d2) why = "not deterministic";
        else if (st.expected && d1 !== st.expected) why = "known-vector mismatch";
        else {
          try { await entry.decode(d1, st.key, lvl); why = "decode should have refused"; }
          catch (refusal) { /* good — one-way refused */ }
        }
        if (why) { fail++; console.log(entry.id + ": FAIL (" + why + ")"); }
        else { pass++; console.log(entry.id + ": PASS (one-way, known vector, refuses decrypt)"); }
        continue;
      }
      var ct = await entry.encode(st.input, st.key, lvl);
      if (st.expected && ct !== st.expected) { fail++; console.log(entry.id + ": FAIL (known expected output mismatch)"); continue; }
      var back = await entry.decode(ct, st.key, lvl);
      var cmp = compareRoundTrip(entry, st.input, back);
      if (cmp.ok) { pass++; console.log(entry.id + ": PASS" + (cmp.mode === "exact" ? " (exact)" : " (letters-normalised)")); }
      else { fail++; console.log(entry.id + ": FAIL at position " + cmp.where); }
    } catch (e) {
      fail++;
      console.log(entry.id + ": EXCEPTION " + (e && e.message ? e.message : String(e)));
    }
  }
  // cross-check: our raw ChaCha20-Poly1305 against the RFC 8439 test vector —
  // proves the JS core is the real standard, not merely self-consistent
  try {
    var hx = function(s) {
      var clean = s.replace(/[^0-9a-fA-F]/g, "");
      var a = new Uint8Array(clean.length / 2);
      for (var q = 0; q < a.length; q++) a[q] = parseInt(clean.substr(q * 2, 2), 16);
      return a;
    };
    var eqBytes = function(a, b) {
      if (a.length !== b.length) return false;
      for (var q = 0; q < a.length; q++) if (a[q] !== b[q]) return false;
      return true;
    };
    var k = hx("80:81:82:83:84:85:86:87:88:89:8a:8b:8c:8d:8e:8f:90:91:92:93:94:95:96:97:98:99:9a:9b:9c:9d:9e:9f");
    var n = hx("07:00:00:00:40:41:42:43:44:45:46:47");
    var ad = hx("50:51:52:53:c0:c1:c2:c3:c4:c5:c6:c7");
    var p = hx("4c:61:64:69:65:73:20:61:6e:64:20:47:65:6e:74:6c:65:6d:65:6e:20:6f:66:20:74:68:65:20:63:6c:61:73:73:20:6f:66:20:27:39:39:3a:20:49:66:20:49:20:63:6f:75:6c:64:20:6f:66:66:65:72:20:79:6f:75:20:6f:6e:6c:79:20:6f:6e:65:20:74:69:70:20:66:6f:72:20:74:68:65:20:66:75:74:75:72:65:2c:20:73:75:6e:73:63:72:65:65:6e:20:77:6f:75:6c:64:20:62:65:20:69:74:2e");
    var want = hx("d3:1a:8d:34:64:8e:60:db:7b:86:af:bc:53:ef:7e:c2:a4:ad:ed:51:29:6e:08:fe:a9:e2:b5:a7:36:ee:62:d6:3d:be:a4:5e:8c:a9:67:12:82:fa:fb:69:da:92:72:8b:1a:71:de:0a:9e:06:0b:29:05:d6:a5:b6:7e:cd:3b:36:92:dd:bd:7f:2d:77:8b:8c:98:03:ae:e3:28:09:1b:58:fa:b3:24:e4:fa:d6:75:94:55:85:80:8b:48:31:d7:bc:3f:f4:de:f0:8e:4b:7a:9d:e5:76:d2:65:86:ce:c6:4b:61:16:1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91");
    if (eqBytes(chacha20p1305Seal(k, n, p, ad), want)) { pass++; console.log("chacha20-poly1305 vs RFC 8439 vector: PASS"); }
    else { fail++; console.log("chacha20-poly1305 vs RFC 8439 vector: FAIL"); }
  } catch (e2) {
    fail++; console.log("chacha cross-check: EXCEPTION " + (e2 && e2.message ? e2.message : String(e2)));
  }
  console.log((fail === 0 ? "ALL PASS" : "FAILURES: " + fail) + " — " + pass + " passed, " + fail + " failed.");
  process.exitCode = fail === 0 ? 0 : 1;
})();
