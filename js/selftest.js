// selftest.js — browser harness for tests/selftest.html.
// Loads after every cipher (deferred order), walks the registry, and prints PASS/FAIL.

runSelfTests = function() {
  var out = document.getElementById("results");
  (async function() {
    var lines = [], pass = 0, fail = 0;
    for (var i = 0; i < REGISTRY.length; i++) {
      var entry = REGISTRY[i];
      var st = entry.selfTest;
      var lvl = entry.levels ? entry.levels.default : 1;
      var line = entry.id + ": ";
      try {
        var ct = await entry.encode(st.input, st.key, lvl);
        var back = await entry.decode(ct, st.key, lvl);
        if (st.expected !== undefined && st.expected !== null && ct !== st.expected) {
          fail++; lines.push(line + "FAIL (known expected output mismatch)"); continue;
        }
        var cmp = compareRoundTrip(entry, st.input, back);
        if (cmp.ok) { pass++; lines.push(line + "PASS" + (cmp.mode === "exact" ? " (exact round-trip)" : " (letters-normalised)")); }
        else { fail++; lines.push(line + "FAIL at position " + cmp.where); }
      } catch (e) {
        fail++; lines.push(line + "EXCEPTION: " + (e && e.message ? e.message : String(e)));
      }
    }
    // Base64 cross-check against the platform's own atob/btoa
    try {
      var s = "cross-check with ☕";
      var ours = bytesToB64(utf8Bytes(s));
      var theirs = btoa(unescape(encodeURIComponent(s)));
      if (ours === theirs) { pass++; lines.push("base64 cross-check vs atob/btoa: PASS"); }
      else { fail++; lines.push("base64 cross-check vs atob/btoa: FAIL"); }
    } catch (e) { fail++; lines.push("base64 cross-check: EXCEPTION " + e.message); }

    var summary = (fail === 0 ? "ALL PASS" : "FAILURES: " + fail) + " — " + pass + " passed, " + fail + " failed.";
    out.textContent = lines.join("\n") + "\n\n" + summary;
  })();
};

runSelfTests();
