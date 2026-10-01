// ui.js — owns the DOM only; all facts live in app.js (STATE). Loaded LAST, so
// everything it calls (registerCipher output, app functions) already exists.

el = function(tag, attrs) { // children may be passed as any number of extra args;
  // strings/numbers become text nodes, arrays are flattened recursively, nulls skipped
  var n = document.createElement(tag);
  if (attrs) { for (var k in attrs) { if (attrs[k] !== null) n.setAttribute(k, String(attrs[k])); } }
  for (var i = 2; i < arguments.length; i++) appendKid(n, arguments[i]);
  return n;
};

appendKid = function(parent, kid) {
  if (kid === null || kid === undefined || kid === false) return;
  if (typeof kid === "string" || typeof kid === "number") { parent.appendChild(document.createTextNode(String(kid))); return; }
  if (Array.isArray(kid)) { for (var j = 0; j < kid.length; j++) appendKid(parent, kid[j]); return; }
  parent.appendChild(kid);
};

btnEl = function(label, handler, cls) {
  var b = el("button", { class: "btn " + (cls || "") }, label);
  b.addEventListener("click", handler);
  return b;
};

copyToClipboard = function(text) { // clipboard with old-browser fallback
  try {
    navigator.clipboard.writeText(text);
  } catch (e) {
    try {
      var t = el("textarea");
      t.value = text;
      document.body.appendChild(t);
      t.select();
      document.execCommand("copy");
      document.body.removeChild(t);
    } catch (e2) { /* nothing we can do — the text is on screen anyway */ }
  }
};

// ---------- persistent, stateful controls (kept across rebuilds) ----------
keyField = el("textarea", { class: "keyinput", rows: 1, spellcheck: false });
cardField = el("textarea", { class: "cardinput", rows: 2, spellcheck: false });
inputField = el("textarea", { class: "inputfield", rows: 6, spellcheck: false });

dropzone = el("div", { class: "dropzone", id: "dropzone" },
  "Drop a text file right here — it never leaves your machine. (Or type text in the box below.)");

function dragHandlers() {
  dropzone.addEventListener("drop", function(ev) {
    var f = ev.dataTransfer && ev.dataTransfer.files.length ? ev.dataTransfer.files[0] : null;
    if (f) dropFile(f);
    try { ev.preventDefault(); } catch (e) {}
  });
  dropzone.addEventListener("dragover", function(ev) {
    try { ev.preventDefault(); } catch (e) {}
  });
  dropzone.addEventListener("dragstart", function(ev) {
    dropzone.setAttribute("data-drag", "1");
  });
}

// ---------- tabs ----------
ROOT = null;
TOOLPANEL = null;
LIBPANEL = null;

tabsBtns = {};
function buildTabs() {
  var bar = el("div", { class: "topbar" },
    el("h1", { class: "brand" }, "Cipherbox"),
    "One page. Every cipher — old ones for learning, new ones for keeping.",
    el("nav", { class: "tabs" },
      btnEl("Encrypt", function() { STATE.tab = "encrypt"; refreshUI(); }, "tabbtn"),
      btnEl("Decrypt", function() { STATE.tab = "decrypt"; refreshUI(); }, "tabbtn"),
      btnEl("Library", function() { STATE.tab = "library"; refreshUI(); }, "tabbtn")
    )
  );
  document.body.appendChild(bar);
}

// ---------- the tool panel (shared by the Encrypt and Decrypt tabs) ----------
CATEGORY_LABELS = { classical: "Classical ciphers (for learning)", encoding: "Encodings (for safe transport)", modern: "Modern cryptography (for real secrets)" };

function renderTool(tab) {
  var entry = currentEntry();
  var kids = [];

  // status line for the current selection
  if (entry) {
    kids.push(el("div", { class: "section-head" }, "Now using: ", entry.name));
  } else {
    kids.push(el("div", { class: "section-head" }, "Pick an algorithm first:"));
  }

  // --- picker ---
  var groups = [];
  ["classical", "encoding", "modern"].forEach(function(cat) {
    var entries = REGISTRY.filter(function(e) { return e.category === cat; });
    if (!entries.length) return;
    groups.push(el("div", { class: "group" },
      el("div", { class: "grouplabel" }, CATEGORY_LABELS[cat]),
      entries.map(function(e) {
        var selected = entry && e.id === entry.id;
        var chip = e.category === "modern" ? "modern" : (e.category === "encoding" ? "encoding" : "classic");
        return btnEl(e.name, function() { selectAlgorithm(e.id); }, selected ? "selected" : "pick " + chip);
      })
    ));
  });
  kids.push(el("div", { class: "picker" }, groups));

  // --- key panel ---
  var keyKids = [];
  if (entry && entry.keySpec.required) {
    if (STATE.key) {
      var src = STATE.keySource === "generated" ? "generated for you — SAVE IT before you decrypt" :
                STATE.keySource === "card" ? "restored from a keycard" : "your typed key";
      keyKids.push(el("div", { class: "keybox" }, "KEY (" + src + "): ", STATE.key,
        btnEl("Copy key", function() { copyToClipboard(STATE.key); }, "copybtn"),
        btnEl("New key", function() { setTypedKey(""); }, "plainbtn")));
    } else {
      keyKids.push(el("div", { class: "keybox" }, "This algorithm needs a key. Type one, or generate one and keep it."));
    }
    keyKids.push(el("div", { class: "keyinput-wrap" },
      el("div", { class: "hint" }, "Type your own key (this exact text becomes the key):"), keyField,
      btnEl("Use this key", function() { setTypedKey(keyField.value.replace(/\r?\n$/, "")); }, "plainbtn")));
    keyKids.push(btnEl("Generate a key", function() { generateKey(); }, "genbtn"));
    keyKids.push(el("div", { class: "keycard-wrap" },
      el("div", { class: "hint" }, "Or paste a keycard you saved from an earlier run here:"), cardField,
      btnEl("Load keycard", function() { useKeycard(cardField.value); }, "plainbtn"),
      btnEl("Copy keycard", function() { if (entry && STATE.key) copyToClipboard(makeKeycard(entry.id, STATE.key, STATE.level)); }, "plainbtn")));
    keyKids.push(el("div", { class: "hint" }, "Key guidance: ", entry.keySpec.guidance));
  } else if (entry) {
    keyKids.push(el("div", { class: "keybox" }, "This algorithm uses no key — ", "the transformation itself is the secret."));
  }
  kids.push(el("div", { class: "keypanel" }, keyKids));

  // --- level panel ---
  if (entry && entry.levels) {
    kids.push(el("div", { class: "levelpanel" },
      "Level ", STATE.level, " / ", entry.levels.max, " (", entry.levels.label, ")",
      btnEl("−", function() { setLevel(STATE.level - 1); }, "stepbtn"),
      btnEl("+", function() { setLevel(STATE.level + 1); }, "stepbtn"),
      btnEl("Reset", function() { setLevel(entry.levels.default); }, "plainbtn"),
      el("div", { class: "hint" }, entry.levels.effect)
    ));
  } else if (entry) {
    kids.push(el("div", { class: "levelpanel" }, "This algorithm has no levels — by design."));
  }

  // --- input panel ---
  var inputKids = [];
  if (STATE.file) {
    inputKids.push(el("div", { class: "filecard" }, "Using file: ", STATE.file.name, " (", Math.max(1, Math.round(STATE.file.size / 1024)), " KB) — clear the input to type text instead."));
  } else {
    inputKids.push(el("div", { class: "inputwrap" },
      el("div", { class: "hint" }, tab === "encrypt" ? "Type or paste the text to encrypt:" : "Paste the ciphertext exactly as it was produced (start of the output box):"),
      inputField));
  }
  inputKids.push(btnEl("Clear input", function() { clearInput(); }, "plainbtn"));
  inputKids.push(dropzone);
  kids.push(el("div", { class: "inputpanel" }, inputKids));

  // --- run + output ---
  var runLabel = tab === "encrypt" ? "Encrypt it" : "Decrypt it";
  kids.push(btnEl(runLabel, function() {
    if (tab === "encrypt") runEncrypt(); else runDecrypt();
  }, "runbtn"));

  if (STATE.output !== null) {
    var outKids = [
      el("div", { class: "hint" }, tab === "encrypt" ? "Ciphertext (copy or save this — it is all you need to decrypt):" : "Recovered text:"),
      el("pre", { class: "outputbox", spellcheck: false }, STATE.output),
      btnEl("Copy output", function() { copyToClipboard(STATE.output); }, "copybtn")
    ];
    if (STATE.outputMeta && STATE.outputMeta.where !== undefined && STATE.outputMeta.where !== -1 && STATE.outputMeta.where !== null) {
      outKids.push(el("div", { class: "badge-red" }, "Round-trip mismatch near position ", STATE.outputMeta.where, " — tell us what you typed, this is a bug to hunt!"));
    } else if (tab === "encrypt" && STATE.outputMeta && STATE.outputMeta.mode === "exact") {
      outKids.push(el("div", { class: "badge-green" }, "Verified: decrypting this output with the same key and level gives back your exact input."));
    } else if (tab === "encrypt" && STATE.outputMeta && STATE.outputMeta.mode === "letters") {
      outKids.push(el("div", { class: "badge-amber" }, "Restored — modulo capitalisation and spacing: this cipher's alphabet cannot represent those, so the check compares letters only."));
    } else if (tab === "decrypt") {
      outKids.push(el("div", { class: "badge-amber" }, "To check this is right, compare it against what you expect to see.", entry && entry.id === "aes" ? " (AES always produces a different ciphertext for the same text — that is why the whole 'aes1:…' line is needed to decrypt.)" : ""));
    }
    kids.push(el("div", { class: "outputpanel" }, outKids));
  } else {
    kids.push(el("div", { class: "outputpanel" }, el("pre", { class: "outputbox" }, "(no output yet — run it)")));
  }

  TOOLPANEL.replaceChildren.apply(TOOLPANEL, [el("div", { class: "tool-inner" }, kids)]);
}

// ---------- library ----------
function renderLibrary() {
  var entries = REGISTRY.slice();
  renderLibraryAsync = (async function() { // returned so callers (debug/tests) can await; failures are surfaced, not swallowed
    var built = [];
    try {
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var ct = "";
      try {
        var lvl = e.levels ? e.levels.default : 1;
        ct = await e.encode(e.example.pt, e.example.key, lvl);
      } catch (err) { ct = "(example omitted)"; }
      built.push(el("div", { class: "card" },
        el("div", { class: "card-head" },
          el("span", { class: "chip " + (e.category === "modern" ? "chip-modern" : e.category === "encoding" ? "chip-enc" : "chip-classic") }, e.category === "modern" ? "modern" : e.category === "encoding" ? "encoding" : "classic"),
          " ", e.name, " · ", e.era
        ),
        el("div", { class: "card-body" },
          (e.description.map(function(p) { return el("p", null, p); })),
          el("p", { class: "hist" }, "History: ", e.history),
          el("p", { class: "strength" }, "Strength: ", e.strength),
          el("p", { class: "example" }, "Worked example — input: ", JSON.stringify(e.example.pt), " key: ", JSON.stringify(e.example.key), " → output: ", JSON.stringify(ct)),
          e.keySpec.required ? el("p", { class: "key" }, "Key: ", e.keySpec.guidance) : el("p", { class: "key" }, "Key: none."),
          e.levels ? el("p", { class: "level" }, "Levels: ", e.levels.label, " (1–", e.levels.max, ") — ", e.levels.effect) : el("p", { class: "level" }, "Levels: none.")
        )
      ));
    }
    LIBPANEL.replaceChildren.apply(LIBPANEL, built);
    } catch (err) { console.error("[cipherbox] library render failed:", err); }
    LIB_RENDERING = false;
  })();
}
LIB_RENDERING = false;

function refreshUI() {
  if (STATE.tab === "library") {
    TOOLPANEL.hidden = true;
    LIBPANEL.hidden = false;
    if (!LIB_RENDERING) { LIB_RENDERING = true; renderLibrary(); }
  } else {
    TOOLPANEL.hidden = false;
    LIBPANEL.hidden = true;
    renderTool(STATE.tab);
  }
  // notices
  var note = STATE.notice ? STATE.notice.text : null;
  if (STATE.notice && STATE.notice.kind === "save" && STATE.generatedKey) note = "SAVE THIS KEY — " + STATE.key + " — write it down before you decrypt. Paste the keycard text to get it back automatically.";
  var nbox = el("div", { class: "notice-" + (STATE.notice ? STATE.notice.kind : "info") }, note || null);
  if (ROOT.lastNotice && ROOT.lastNotice.parentNode === ROOT) ROOT.removeChild(ROOT.lastNotice);
  if (note) { ROOT.appendChild(nbox); ROOT.lastNotice = nbox; }
}

function boot() {
  buildTabs(); // header first so it sits above the app, not after it
  ROOT = el("div", { class: "app" });
  document.body.appendChild(ROOT);
  TOOLPANEL = el("div", { class: "toolpanel" });
  TOOLPANEL.hidden = true;
  ROOT.appendChild(TOOLPANEL);
  LIBPANEL = el("div", { class: "libpanel" });
  ROOT.appendChild(LIBPANEL);
  ROOT.lastNotice = null;
  dragHandlers();
  refreshUI();
}

boot();
