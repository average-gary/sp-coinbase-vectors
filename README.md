# Coinbase silent payments — test vectors

Test vectors for a coinbase-scoped [BIP 352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
variant with a **sender-side ECDH/spend key split**, letting a mining pool pay each miner a fresh,
unlinkable address directly in the coinbase.

**Not a specification. Not reviewed. Not implemented anywhere.** This is a construction worked out
on paper and then pinned down in code, so that the spec diff it needs can be written against
something executable.

👉 **[`index.html`](index.html) is a plain-English explainer** of what the variant is and how the
maths works, and it runs the vectors two ways in the browser: **case 12 with no libraries at all**
(~40 lines of `BigInt` curve arithmetic plus the browser's own SHA-256), and — on a button press,
never on load — **this repo's real Python suite**, on a CPython compiled to WebAssembly (Pyodide
from a CDN, plus the `vendor/` copies of the curve library). Start there. (Needs a secure context
for `crypto.subtle`, so serve it over `https://` or `localhost`, not `file://`.)

## The construction

```
input_hash = tagged_hash("SP-Coinbase/Inputs", ser32(H) || ser_P(A_send))
ecdh       = input_hash · a_send · B_scan      # pool side
           = input_hash · b_scan · A_send      # miner side, DH symmetry
t_0        = tagged_hash("SP-Coinbase/SharedSecret", ser_P(ecdh) || ser32(0))
P_0        = B_spend + t_0 · G                 # x-only taproot output key
spend key  = (b_spend + t_0) mod n             # negated to even Y for BIP340
```

Two changes from BIP 352:

1. **The nonce** is the BIP 34 block height `H`, not the lexicographically smallest outpoint — a
   coinbase's prevout is the same constant in every block.
2. **The sender's key is dedicated.** BIP 352 uses the sender's *spending* key for ECDH
   (`bip-0352.mediawiki:244`), because that is the only key an ordinary transaction reveals for
   free. A coinbase reveals none, so the key must be supplied on purpose — and once it is being
   supplied anyway, it may as well be one that holds no money. `a_send` can then be erased after
   the block, and its compromise costs privacy rather than funds.

## Running

Requires Python 3 and a clone of [bitcoin/bips](https://github.com/bitcoin/bips) as a sibling
directory. No packages to install: `secp256k1lab` does the curve maths, taken from the bips clone
when it is there and from [`vendor/`](vendor/) when it is not. The `vendor/` copies are
byte-identical to bips commit [`60f5b33`](https://github.com/bitcoin/bips/commit/60f5b33)
(2026-08-12) and stay that way — `run_tests.py` hashes them against your clone and fails on drift.
`secp256k1lab` is MIT (© The Bitcoin Core developers, and the secp256k1lab developers — see
[`vendor/COPYING`](vendor/COPYING)), as is `ripemd160.py` (© Pieter Wuille); `bitcoin_utils.py` is
BIP 352's own BSD-2-Clause.

```sh
python3 run_tests.py                  # baseline + 11 cases, ~70 s
python3 run_tests.py --skip-baseline  # new cases only, fast
python3 generate_vectors.py           # regenerate the JSON

BIPS_REPO=/path/to/bips python3 run_tests.py   # if bips is elsewhere
```

Without the clone, 9 of the 11 cases still run off `vendor/` — but the run **exits 1**, because
the checks that go quiet are exactly the ones that anchor this variant to upstream BIP 352 (the
baseline, cases 1 and 5, and the `vendor/` drift guard). Pass `--allow-skips` to accept that. The
in-browser run is the same code with the same skips, and exits 0 there: no clone can exist inside
a browser, so `run_tests.py` treats the absence as structural rather than as a mistake
(`sys.platform == "emscripten"`). `test_wasm.mjs` runs that path headlessly:

```sh
npm i pyodide@314.0.4 && node test_wasm.mjs   # SKIPs (exit 0) if pyodide is absent
```

Node is the only prerequisite that isn't already required, and only for that one command. The
version is pinned deliberately: the test asserts the installed build is the same one `index.html`
loads from the CDN, so it refuses to run rather than verify a build no reader will get. An existing
install elsewhere works too — `NODE_PATH=/path/to/node_modules node test_wasm.mjs`. What it cannot
prove: it mounts the files through `FS.writeFile` rather than `fetch()`, so a Pages MIME quirk or a
stale cached asset would still only show up in a real browser.

The bips clone is treated as read-only and is left byte-identical: `sys.dont_write_bytecode` in the
module and `PYTHONDONTWRITEBYTECODE=1` in the baseline subprocess, so importing and running
`reference.py` leaves no `__pycache__` behind.

## Layout

| File | Role |
|---|---|
| `index.html` | Plain-English explainer; §7 is a dependency-free JS reimplementation of case 12, §8 boots CPython/wasm on demand and runs `run_tests.py` itself |
| `sp_coinbase.py` | The construction: `input_hash` variants (sound and broken), sender/scanner derivation, even-Y canonicalization, spend-key assembly |
| `generate_vectors.py` | Deterministic key material and the case builders |
| `coinbase_sp_test_vectors.json` | 11 cases, mirroring `send_and_receive_test_vectors.json`'s schema |
| `run_tests.py` | Assert-based runner — no pytest, no fixtures; exits nonzero naming the failing case |
| `vendor/` | Byte-identical copies of upstream `secp256k1lab`, `bitcoin_utils.py` and `ripemd160.py`, so the suite runs with no clone (which is the browser's situation). MIT + BSD-2-Clause; see [`vendor/README.md`](vendor/README.md). `reference.py` is deliberately **not** copied |
| `test_wasm.mjs` | Headless proof of the browser path: same Pyodide build, same file list, real `run_tests.main()` |
| `.nojekyll` | Keeps GitHub Pages from hiding `vendor/secp256k1lab/__init__.py` (Jekyll drops `_`-prefixed paths) |

## Cases

A baseline runs first: the 28 vendored BIP 352 vectors through **unmodified** `reference.py`. A
failure there is a wiring problem, not a vector problem.

**Positive (1–4)** — the split isolated in an ordinary transaction (with the vanilla fused-key path
asserted to give a *different* output, so the split is provably in effect); the coinbase native
case; an `N = 5` fan-out where each miner finds exactly its own output and a dropped output leaves
the others unaffected; nonce distinctness in both directions.

**Negative controls (5–9)** — each asserts its own failure mode, because a safeguard with no
demonstrated failure mode isn't tested. Unmodified BIP 352 rejecting a coinbase; the constant null
prevout colliding two blocks to one address; the `why_include_A` replay (`:92`) transposed to the
split, and killed by binding `input_hash` to `A_send`; an odd-Y `A_send` with the parity rule
omitted; and the group-linear "compressed list" `A_H = A_0 + H(A_0‖H)·G`, where holding `a_0`
recovers every epoch key and unmasks every past payout.

**Carriers (11–12)** — where `A_send` actually travels.

Case 11 is a **rejected** carrier, kept because the mechanics are worth pinning. A taproot fee
output cannot carry `A_send` (the visible key's discrete log *is* the keypath spend secret, so
visibility and spendability are one property). A bare 1-of-2 multisig carries it mechanically — the
scanner parses key 0 and the construction runs unchanged — but `m = 1` means `a_send` is not merely
unnecessary for spending, it is *sufficient*: whoever obtains the erasable privacy key can take the
pool's fee. `m = 2` fails oppositely, since `a_send` must then sign and so can never be erased. The
rule that survives: **`A_send` must never appear in a script that controls money.**

Case 12 is the leading on-chain carrier: the coinbase scriptSig, carrying `A_send` *as the pool
tag*, which dissolves the byte-budget objection rather than paying it. The runner asserts the
2–100 B consensus budget, the BIP 34 height round-trip, and that the `A_send` region is disjoint
from the miner-rolled extranonce region. Under Stratum V2 that disjointness is structural, not
conventional — see below.

### Stratum V2 fit (case 12)

Checked against the [SV2 spec](https://stratumprotocol.org) 2026-08-16. There is **no pool-tag
field** in SV2; the tag is bytes the pool places in the scriptSig region it controls.

- **Disjointness is enforced by the message format.** For extended channels the coinbase is
  `coinbase_tx_prefix ‖ extranonce_prefix ‖ extranonce ‖ coinbase_tx_suffix` (`05-Mining-Protocol`
  §5.4.1.6). The extranonce is *defined* as the gap between the two pool-set halves, so `A_send`
  placed in `coinbase_tx_suffix` cannot be rolled. Case 12's asserted invariant is structural here.
- **The space is pre-paid.** A Template Provider MUST reserve the worst-case 400 WU / 100 B for
  `scriptSig` unconditionally (`07-Template-Distribution-Protocol`). Using 34 more bytes displaces
  no fee-paying transactions; the opportunity cost was already taken at template-build time.
- **Budget.** 100 B cap − ~4 B BIP 34 height (`NewTemplate.coinbase_prefix`, ≤8 B + length byte)
  − 34 B `push33(A_send)` = **~62 B** left for the full Extended Extranonce, against a protocol
  ceiling of 64 B (`extranonce_prefix` B0_32 + `extranonce` B0_32). Practical allocations are
  8–16 B, so the headroom is 4–8×.
- **Two constraints.** `coinbase_tx_prefix` carries the `scriptSig length`, and all channels in a
  group channel MUST share one full-extranonce size (§5.1.2.1) — so the 34 B shrinks extranonce
  space uniformly for the group. `A_send`'s *length* is constant, so no per-block renegotiation.
- **Out of scope: Job Declaration mode.** Under JD the JDC builds `coinbase_tx_prefix`/`suffix`
  (`06-Job-Declaration-Protocol`), so the pool cannot place `A_send` in the scriptSig — and JD does
  not pay miners per-output anyway (the pool takes one output). This scheme assumes a
  pool-controlled template.

Not verified: empirical mainnet scriptSig occupancy, and whether merge-mining commitments (a
Namecoin-style AuxPoW header is ~44 B) leave room alongside 34 B in practice.

## Known limits

- **The vectors are largely self-consistent.** Generator and runner both derive through
  `sp_coinbase.py`, so the JSON is a regression fixture over that module rather than an independent
  check of it. Three things break the circularity: the baseline exercises unmodified `reference.py`,
  case 2 re-derives `input_hash` and `P_0` from the JSON givens using raw `hashlib`, and
  `index.html` reimplements case 12 in JavaScript — separate curve arithmetic, written from the
  formulas — and reproduces every byte. That rules out arithmetic and serialization mistakes. It
  does not substitute for review: same author, so a misreading of the design would be reproduced
  faithfully in both.
- **The in-browser Python run is reproducibility, not a fourth independent check.** §8 of the page
  runs *this repo's own* `sp_coinbase.py` and `run_tests.py`, unmodified, on CPython/wasm — so any
  misreading of the design is reproduced there byte for byte, exactly as it is at a terminal. It
  breaks no circularity; the JavaScript rewrite in §7 remains the only independently written
  implementation. What it does buy is that a reader with no Python, no clone and no toolchain can
  watch the recorded numbers be recomputed from the inputs instead of taking a committed JSON on
  trust. It also cannot run the checks that matter most for conformance: `reference.py` is
  deliberately not shipped to the browser, so the upstream baseline and cases 1 and 5 `SKIP` there
  (as does the `vendor/` drift guard, which needs the clone). Nine green ticks in a browser is not
  the suite passing.
- **No security proof** for the sender-side split, and none is attempted. Case 9 shows the
  group-linear key list is broken; it does not prove the non-linear branch is unusable — that stays
  a generic-group-model argument.
- **Two decisions are flagged, not settled**: fresh hash tags (`SP-Coinbase/*`) versus reusing
  `BIP0352/*`, and the silent-payments version byte from `bip-0352.mediawiki:152-176`. Both belong
  in a spec diff, not in test vectors.
- **Nothing about the transport** — no stratum plumbing, no key-batch retention model, and no
  treatment of the linkability surface a pool creates by serving different `A_send` lists to
  different miners.
