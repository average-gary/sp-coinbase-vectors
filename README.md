# Coinbase silent payments — test vectors

Test vectors for a coinbase-scoped [BIP 352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
variant with a **sender-side ECDH/spend key split**, letting a mining pool pay each miner a fresh,
unlinkable address directly in the coinbase.

**Not a specification. Not reviewed. Not implemented anywhere.** This is a construction worked out
on paper and then pinned down in code, so that the spec diff it needs can be written against
something executable.

👉 **[`index.html`](index.html) is a plain-English explainer** of what the variant is and how the
maths works. Start there.

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
directory. No third-party packages: the vendored `secp256k1lab` inside the bips repo does the
curve maths.

```sh
python3 run_tests.py                  # baseline + 11 cases, ~70 s
python3 run_tests.py --skip-baseline  # new cases only, fast
python3 generate_vectors.py           # regenerate the JSON

BIPS_REPO=/path/to/bips python3 run_tests.py   # if bips is elsewhere
```

The bips clone is treated as read-only and is left byte-identical: `sys.dont_write_bytecode` in the
module and `PYTHONDONTWRITEBYTECODE=1` in the baseline subprocess, so importing and running
`reference.py` leaves no `__pycache__` behind.

## Layout

| File | Role |
|---|---|
| `index.html` | Plain-English explainer of the variant |
| `sp_coinbase.py` | The construction: `input_hash` variants (sound and broken), sender/scanner derivation, even-Y canonicalization, spend-key assembly |
| `generate_vectors.py` | Deterministic key material and the case builders |
| `coinbase_sp_test_vectors.json` | 11 cases, mirroring `send_and_receive_test_vectors.json`'s schema |
| `run_tests.py` | Assert-based runner — no pytest, no fixtures; exits nonzero naming the failing case |

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

**Carriers (10–11)** — where `A_send` actually travels. A taproot fee output **cannot** carry it
(the visible key's discrete log *is* the keypath spend secret, so visibility and spendability are
one property); a bare 1-of-2 multisig can, at +37 B. And the coinbase scriptSig can carry it *as
the pool tag*, which dissolves the byte-budget objection entirely — the runner asserts the 2–100 B
consensus budget, the BIP 34 height round-trip, and that the `A_send` region is disjoint from the
miner-rolled extranonce region.

## Known limits

- **The vectors are largely self-consistent.** Generator and runner both derive through
  `sp_coinbase.py`, so the JSON is a regression fixture over that module rather than an independent
  check of it. Two things break the circularity: the baseline exercises unmodified `reference.py`,
  and case 2 re-derives `input_hash` and `P_0` from the JSON givens using raw `hashlib`. A second,
  independent implementation is what a real review needs.
- **No security proof** for the sender-side split, and none is attempted. Case 9 shows the
  group-linear key list is broken; it does not prove the non-linear branch is unusable — that stays
  a generic-group-model argument.
- **Two decisions are flagged, not settled**: fresh hash tags (`SP-Coinbase/*`) versus reusing
  `BIP0352/*`, and the silent-payments version byte from `bip-0352.mediawiki:152-176`. Both belong
  in a spec diff, not in test vectors.
- **Nothing about the transport** — no stratum plumbing, no key-batch retention model, and no
  treatment of the linkability surface a pool creates by serving different `A_send` lists to
  different miners.
