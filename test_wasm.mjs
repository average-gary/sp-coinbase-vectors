#!/usr/bin/env node
// Headless proof of the in-browser path: boot the same Pyodide build index.html
// pins, mount exactly the files index.html fetches, and run the real
// run_tests.main() in CPython/wasm with no bips clone anywhere in reach.
//
//   NODE_PATH=/tmp/node_modules node test_wasm.mjs        # npm i pyodide first
//
// Skips (exit 0) when pyodide is not installed. Exits 1 on any failure. What it
// cannot prove: fetch() vs FS.writeFile — a Pages MIME quirk or a stale cached
// asset still 404s only in a real browser, so load the published page once too.

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const die = (msg) => { console.error(`FAIL: ${msg}`); process.exit(1); };

// Checks that legitimately cannot run in the browser: they need the bips clone,
// git, or subprocess. Anything else going quiet is a check that stopped running.
const MAY_SKIP = ['baseline', 'ordinary_split', 'vanilla_coinbase_reject', 'vendor/', 'index.html'];

let loadPyodide, version;
try {
  // require, not import: ESM ignores NODE_PATH, and pyodide is unlikely to be
  // installed next to this repo. Still finds a local node_modules if there is one.
  ({ loadPyodide, version } = createRequire(import.meta.url)('pyodide'));
} catch {
  console.log('SKIP: pyodide not installed (npm i pyodide, or NODE_PATH=/path/to/node_modules)');
  process.exit(0);
}

const html = fs.readFileSync(path.join(HERE, 'index.html'), 'utf8');
// Without this the test could pass against the npm build while readers load a
// different CDN build, which voids the point of the test.
if (!html.includes(`v${version}`)) {
  die(`index.html does not pin Pyodide v${version} (the installed build), so this `
    + 'test would verify a different build than readers load');
}
const listed = html.match(/const PY_FILES = \[(.*?)\]/s);
if (!listed) die('index.html has no `const PY_FILES = [...]` for the Pyodide run');
// Mount the PAGE's list, never our own: that makes this the runtime proof that
// the page's list is sufficient, with no third copy of the list to keep in sync.
const files = [...listed[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);

const out = [];
const log = (line) => { out.push(line); console.log(line); };
const py = await loadPyodide({ stdout: log, stderr: log });
for (const rel of files) {
  const src = path.join(HERE, rel);
  if (!fs.existsSync(src)) die(`index.html fetches ${rel}, which does not exist`);
  const dst = `/app/${rel}`;
  py.FS.mkdirTree(path.dirname(dst));
  py.FS.writeFile(dst, fs.readFileSync(src));
}

let rc;
try {
  rc = py.runPython(`
import sys
sys.path.insert(0, '/app')
sys.argv = ['run_tests.py']
import run_tests
run_tests.main()
`);
} catch (e) {
  die(`python raised:\n${e.message}`);
}

const named = (prefix) => out.filter((l) => l.startsWith(prefix)).map((l) => l.slice(prefix.length));
const cases = JSON.parse(fs.readFileSync(path.join(HERE, 'coinbase_sp_test_vectors.json'), 'utf8'));
const passed = named('PASS: ');
const want = cases.map((c) => c.case_type).filter((t) => !MAY_SKIP.includes(t));
const notRun = want.filter((t) => !passed.includes(t));
if (notRun.length) die(`cases did not PASS under Pyodide: ${notRun}`);
const badSkip = named('SKIP: ').filter((s) => !MAY_SKIP.some((p) => s.startsWith(p)));
if (badSkip.length) die(`check(s) skipped that should run in the browser: ${badSkip}`);
if (rc !== 0) die(`run_tests.main() returned ${rc}`);
const cpython = py.runPython("__import__('sys').version.split()[0]");
console.log(`\nOK: ${want.length} cases recomputed by CPython ${cpython} on wasm `
  + `(Pyodide ${version}) from the ${files.length} files the page fetches, no bips clone`);
