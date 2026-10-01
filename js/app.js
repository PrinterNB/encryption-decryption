// app.js — the pipeline and the state. ui.js owns the DOM; app.js owns the facts.

STATE = {
  tab: "library",
  entryId: null,
  level: 1,
  key: null,
  keySource: null,        // "typed" | "generated"
  generatedKey: null,
  typedKey: null,
  text: "",
  file: null,            // File object dropped into the input zone
  fileText: null,        // cached read of the file
  output: null,
  outputMeta: null,      // {verified, mode, where, warnings...}
  notice: null           // transient user-facing message {kind, text}
};

noticeForEntrySize = null;

function setNotice(kind, text) { STATE.notice = { kind: kind, text: text }; refreshUI(); }
function clearNotice() { STATE.notice = null; }

selectAlgorithm = function(id) {
  clearNotice(); // an old message disappears when a new action begins
  if (!REG_BY_ID[id]) { setNotice("error", "unknown algorithm: " + id); return; }
  STATE.entryId = id;
  var entry = REG_BY_ID[id];
  STATE.level = entry.levels ? entry.levels.default : 1;
  STATE.key = null; STATE.keySource = null; STATE.generatedKey = null; STATE.typedKey = null;
  STATE.output = null; STATE.outputMeta = null;
  refreshUI();
};

setLevel = function(n) {
  clearNotice();
  var entry = currentEntry();
  if (!entry || !entry.levels) { STATE.level = 1; }
  else STATE.level = Math.max(1, Math.min(entry.levels.max, n));
  refreshUI();
};

currentEntry = function() { return STATE.entryId ? REG_BY_ID[STATE.entryId] : null; };

function validateKey() {
  var entry = currentEntry();
  if (!entry) return "choose an algorithm first";
  if (!entry.keySpec.required) return null;
  if (!STATE.key) return "missing-key";
  return entry.keySpec.validate(STATE.key);
}

setTypedKey = function(k) {
  clearNotice();
  STATE.typedKey = k; STATE.key = k; STATE.keySource = "typed";
  STATE.generatedKey = null;
  var err = validateKey();
  if (err === "missing-key") setNotice("warn", "This algorithm needs a key — type one or generate one.");
  else if (err) setNotice("error", err);
  refreshUI();
};

generateKey = function() {
  clearNotice();
  var entry = currentEntry();
  if (!entry) return;
  if (!entry.keySpec.required) { setNotice("info", "This algorithm uses no key — there is nothing to generate."); return; }
  STATE.generatedKey = genKeyFor(entry.keySpec.kind);
  STATE.key = STATE.generatedKey; STATE.keySource = "generated";
  STATE.typedKey = null;
  setNotice("save", null);
  refreshUI();
};

useKeycard = function(cardText) {
  clearNotice();
  var parsed = parseKeycard(cardText);
  if (!parsed || !REG_BY_ID[parsed.entryId]) { setNotice("error", "That keycard is not recognised."); return; }
  STATE.entryId = parsed.entryId;
  STATE.level = parsed.level;
  STATE.key = parsed.key; STATE.keySource = "card";
  refreshUI();
};

setText = function(t) { clearNotice(); STATE.text = t; STATE.file = null; STATE.fileText = null; refreshUI(); };
dropFile = function(file) {
  clearNotice();
  var entry = currentEntry();
  var max = (entry && entry.category === "modern") ? MAX_BYTES_MODERN : MAX_BYTES_CLASSICAL;
  if (file.size > max) {
    setNotice("error", "That file is too large for this cipher (" + Math.round(file.size / 1024) + " KB; limit " + Math.round(max / 1024) + " KB).");
    return;
  }
  STATE.file = file; STATE.fileText = null;
  setNotice("file-ready", "Reading “" + file.name + "” …");
  refreshUI();
};

clearInput = function() { clearNotice(); STATE.text = ""; STATE.file = null; STATE.fileText = null; refreshUI(); };

runEncrypt = function() { // async — the caller shows nothing until this completes
  clearNotice();
  var entry = currentEntry();
  if (!entry) { setNotice("error", "choose an algorithm first"); return; }
  var err = validateKey();
  if (err === "missing-key") { setNotice("error", "This algorithm needs a key before encrypting."); return null; }
  if (err) { setNotice("error", err); return null; }
  if (STATE.file) {
    return (async function() {
      try {
        if (STATE.fileText === null) STATE.fileText = await readFileText(STATE.file);
        return await finishEncrypt(entry, STATE.fileText);
      } catch (e) {
        setNotice("error", e.message || String(e));
        return null;
      }
    })();
  }
  if (!STATE.text) { setNotice("error", "nothing to encrypt — type text or drop a file."); return null; }
  return finishEncrypt(entry, STATE.text);
};

async function finishEncrypt(entry, input) {
  if (entry.keySpec.required && STATE.key === null) { setNotice("error", "missing key"); return null; }
  try {
    var ct = await entry.encode(input, STATE.key || "", STATE.level);
    STATE.output = ct;
    var restored = await entry.decode(ct, STATE.key || "", STATE.level);
    STATE.outputMeta = compareRoundTrip(entry, input, restored);
  } catch (e) {
    STATE.output = null; STATE.outputMeta = null;
    setNotice("error", (e && e.message) ? e.message : String(e));
    return null;
  }
  refreshUI();
  return STATE.output;
}

runDecrypt = function() {
  clearNotice();
  var entry = currentEntry();
  if (!entry) { setNotice("error", "choose an algorithm first"); return; }
  if (entry.keySpec.required && !STATE.key) { setNotice("error", "This algorithm needs its key to decrypt."); return; }
  var input = STATE.text;
  if (STATE.file) {
    return (async function() {
      try {
        if (STATE.fileText === null) STATE.fileText = await readFileText(STATE.file);
        return await finishDecrypt(entry, STATE.fileText);
      } catch (e) {
        setNotice("error", e.message || String(e));
        return null;
      }
    })();
  }
  if (!input) { setNotice("error", "nothing to decrypt — paste ciphertext here or drop a file with the encrypted text."); return null; }
  return finishDecrypt(entry, input);
};

async function finishDecrypt(entry, input) {
  try {
    var back = await entry.decode(input, STATE.key || "", STATE.level);
    STATE.output = back;
    STATE.outputMeta = { ok: true, mode: null }; // decrypt has nothing to verify against — honesty handled in UI
  } catch (e) {
    STATE.output = null;
    setNotice("error", (e && e.message) ? e.message : String(e));
    return null;
  }
  refreshUI();
  return STATE.output;
}
