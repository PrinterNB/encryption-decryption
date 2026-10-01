// fileinput.js — read a File (drag-dropped or chosen) entirely inside the browser.
// No data ever leaves your machine; we only check size first so huge files fail fast.

MAX_BYTES_CLASSICAL = 1000000;  // ~1 MB text ceiling for JS ciphers
MAX_BYTES_MODERN = 8000000;     // ~8 MB for the AES path

readFileText = function(file) { // -> Promise<string>
  var p = new Promise(function(resolve, reject) {
    var r = new FileReader();
    r.onload = function() { resolve(r.result); };
    r.onerror = function() { reject(new Error("the file could not be read (it may have been moved out of the folder)")); };
    r.onabort = function() { reject(new Error("reading was cancelled")); };
    r.readAsText(file);
  });
  return p;
};
