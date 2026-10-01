# Cipherbox — an encryption & decryption website

One static page, no dependencies, no server. Every algorithm runs entirely in your
browser — text and files never leave your machine. Open `index.html` by
double-clicking it, or serve the folder from any static host.

## What it does

- **Catalog of algorithms** — see the Library tab. Classical ciphers for learning
  (Caesar, ROT13, Atbash, keyword/mixed/simple substitution, Vigenère, Gronsfeld,
  Autokey, Playfair, Rail Fence, Bacon) through encodings (Base64, Base32) to
  real modern cryptography (AES-256 GCM via the browser's built-in Web Crypto API).
- **Explanations for each**: how it works, history, worked example, and an honest
  strength note ("breakable by frequency analysis" vs "real cryptography").
- **Keys**: type your own key, or generate a random one that's always valid for
  the cipher (pronounceable words, digit keys, full alphabets, six-word
  passphrases). Generated keys are shown for you to save or copy as a
  paste-back `keycard:` text.
- **Levels**: per-algorithm strength controls — rails for Rail Fence, keyed
  passes for Vigenère/Gronsfeld, rounds for XOR, PBKDF2 stretching for AES.
- **Input**: type text into the box, or drop a file onto the drop zone (capped
  at ~1 MB for the JS ciphers / ~8 MB for the AES path, with a clear refusal).
- **Round-trip verification**: after every Encrypt run, the site immediately
  decrypts its own output; a green "Verified" badge means your key + level +
  ciphertext are sufficient to recover your input. Playfair/Bacon normalise
  case and spacing (their alphabets can't represent those) and say so.

## Running

- **Locally**: double-click `index.html`, or serve the folder with `python -m http.server`.
- **Deployed**: put the folder on GitHub Pages / Netlify / any static host.
- **Self-test**: open `tests/selftest.html` in a browser (prints PASS for every
  registered cipher), or run `node tests/selftest.node.js` in the terminal.

## Architecture (brief)

`js/registry.js` is the single source of truth: each algorithm registers itself
with description/history/strength text, key rules (`keySpec`), level controls
(`levels`), an encode/decode pair, and a `selfTest`. The picker, the Library
cards, and the test harness all render from that data. Cipher modules live in
`js/ciphers/`; `js/app.js` is the pipeline (state + run), `js/ui.js` the DOM,
`styles/app.css` the look, `js/verify.js` the round-trip checker, `js/keygen.js`
valid random keys, `js/fileinput.js` the drop-zone reader. Scripts load in
dependency order via `<script defer>`; no ES modules, so `file://` behaves
exactly like deployed.

## Security caveats (the honest kind)

- Classical ciphers are for learning — they carry a visible "educational, not
  secure" note. A Caesar's output is not a secret.
- AES here is real AES-256-GCM: fresh random salt + IV per run, PBKDF2 key
  stretching (the Level control picks 10k–600k rounds). The security you get
  is bounded by the passphrase you choose.
- Everything is client-side: the browser's DevTools network tab will show you
  nothing is sent anywhere.

## Extending

Add a file under `js/ciphers/`, call `registerCipher({ id, name, category,
description, history, strength, keySpec, levels, encode, decode,
selfTest, ... })`, and list it in `index.html` after `registry.js`. The picker,
the Library, and the self-tests pick it up automatically.
