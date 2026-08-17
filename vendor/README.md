# vendor/ — verbatim upstream copies

Every file here is a byte-identical copy from **bitcoin/bips** at commit
`60f5b33b0a7be3cf09b933d97b78071d684db7d1` (2026-08-12, "Merge pull request
#2252 from jurvis/bip89-deployed"). Nothing was reformatted or edited.

| local path | upstream path |
| --- | --- |
| `bitcoin_utils.py` | `bip-0352/bitcoin_utils.py` |
| `ripemd160.py` | `bip-0352/ripemd160.py` |
| `secp256k1lab/__init__.py` | `bip-0352/secp256k1lab/src/secp256k1lab/__init__.py` |
| `secp256k1lab/secp256k1.py` | `bip-0352/secp256k1lab/src/secp256k1lab/secp256k1.py` |
| `secp256k1lab/util.py` | `bip-0352/secp256k1lab/src/secp256k1lab/util.py` |
| `secp256k1lab/bip340.py` | `bip-0352/secp256k1lab/src/secp256k1lab/bip340.py` |
| `COPYING` | `bip-0352/secp256k1lab/COPYING` |

Upstream's `secp256k1lab/src/secp256k1lab/` nesting exists only for hatchling
packaging, which we do not use, so it is flattened to `secp256k1lab/` here.
`keys.py` and `ecdh.py` are deliberately **not** copied: nothing imports them
(not `sp_coinbase.py`, not `bitcoin_utils.py`, not even upstream `reference.py`,
and `bip340.py` imports only `.secp256k1` and `.util`). `reference.py` is also
deliberately not copied — `run_tests.py` compares against the *unmodified*
upstream file in your clone, and a copy here would destroy that anchor.

## Why this exists

So `sp_coinbase.py` runs with no bips clone on disk, which is the situation
inside Pyodide when `index.html` runs the real Python suite in the browser.
When a clone *is* present it wins: `sp_coinbase.py` puts the clone's paths on
`sys.path` ahead of this directory, so the local test suite keeps executing
upstream's own module objects.

## Licences — there are two

- **MIT** for the four `secp256k1lab/*.py` files: see `COPYING`.
- **MIT** for `ripemd160.py`: it carries its own header (Copyright (c) 2021
  Pieter Wuille) which says "see the accompanying file COPYING". That reference
  resolves because `COPYING` sits beside it. **Do not move `COPYING` into
  `secp256k1lab/`** — it would break both that reference and the attribution.
- **BSD-2-Clause** for `bitcoin_utils.py`, which has no header of its own. It is
  a BIP 352 file, not part of secp256k1lab: `bip-0352.mediawiki` line 11 says
  `License: BSD-2-Clause` and line 28 "This BIP is licensed under the BSD
  2-clause license". Authors: josibake, Ruben Somsen, Sebastian Falbesoner.

secp256k1lab describes itself as insecure — no constant-time guarantees,
trivially vulnerable to side-channel attacks. It is for test vectors and
explanation only. Do not use it with real keys.

## Verifying a copy

    git -C ../../bips show 60f5b33:bip-0352/bitcoin_utils.py | diff - bitcoin_utils.py

`run_tests.py` does this for every file above against your clone's **current
HEAD**, not the pinned commit. So a failure there usually means upstream moved:
re-vendor with `cp` and bump the commit hash at the top of this file.
