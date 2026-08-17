#!/usr/bin/env python3
"""Assert-based runner for coinbase_sp_test_vectors.json, plus the BIP 352
baseline harness check. No pytest, no fixtures: plain asserts in plain
functions. Prints which case failed and exits nonzero on any failure.

Usage: python3 run_tests.py
(Set BIPS_REPO if the bips clone is not a sibling of this directory.)

Every case recomputes all expected values from the "given" block before
comparing, so the JSON alone tells a reviewer what the construction must
produce. Negative controls assert the failure mode itself — a safeguard with
no demonstrated failure mode isn't tested."""

import hashlib
import json
import os
import subprocess
import sys
import traceback
from pathlib import Path

import sp_coinbase as sp
from sp_coinbase import (
    G, GE, Scalar, compressed_list_tweak, derive_receiving, derive_sending,
    even_y, hash_to_scalar, input_hash_coinbase, input_hash_height_only,
    input_hash_wrong_key, lowest_outpoint_from_vin, sender_derive, ser32,
    spend_key, tagged_hash,
)

VECTORS = Path(__file__).parent / "coinbase_sp_test_vectors.json"


# --- baseline: the 28 vendored BIP352 vectors, unmodified reference.py --------
def run_baseline() -> None:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}  # keep the bips clone pristine
    r = subprocess.run([sys.executable, "reference.py", "send_and_receive_test_vectors.json"],
                       capture_output=True, text=True, cwd=sp.BIP0352_DIR, env=env)
    assert r.returncode == 0 and "All tests passed" in r.stdout, (
        f"BIP352 baseline failed (harness problem, not a vector problem):\n{r.stdout}\n{r.stderr}")


# --- shared per-entry checks ----------------------------------------------------
def check_sending(entry: dict) -> None:
    got = derive_sending(entry["given"])
    assert got == entry["expected"], (
        f"sending derivation mismatch:\nrecomputed={json.dumps(got, indent=1)}\n"
        f"expected={json.dumps(entry['expected'], indent=1)}")


def check_receiving(entry: dict) -> None:
    info, found = derive_receiving(entry["given"])
    exp = entry["expected"]
    assert info["input_hash"] == exp["input_hash"], "input_hash mismatch"
    assert info["shared_secret"] == exp["shared_secret"], "shared_secret mismatch"
    assert info["tweak"] == exp["tweak"], "tweak mismatch"
    assert found == exp["outputs"], f"scan result mismatch: {found} != {exp['outputs']}"
    # Independent spendability proof: the full private key (b_spend + t_0)
    # controls the on-chain x-only key, and its schnorr signature verifies.
    b_spend = Scalar.from_bytes_checked(bytes.fromhex(entry["given"]["key_material"]["spend_priv_key"]))
    for o in found:
        d = spend_key(b_spend, Scalar.from_bytes_checked(bytes.fromhex(o["priv_key_tweak"])))
        pub = GE.from_bytes_xonly(bytes.fromhex(o["pub_key"]))
        assert (d * G).to_bytes_xonly() == pub.to_bytes_xonly(), "spend key does not control output"
        assert sp.schnorr_verify(sp.SIGN_MSG, pub.to_bytes_xonly(), bytes.fromhex(o["signature"])), \
            "schnorr signature on spend key does not verify"


# --- case 1 ----------------------------------------------------------------------
def check_ordinary_split(case: dict) -> None:
    for se in case["sending"]:
        check_sending(se)
    for re_ in case["receiving"]:
        check_receiving(re_)
    # The split must be LIVE, not vacuous: vanilla BIP352 derivation (fused
    # a_sum, computed via unmodified reference.get_input_hash) over the same
    # inputs and recipient must give a DIFFERENT output. A harness bug that
    # silently routed ECDH through the input keys would fail here.
    given = case["sending"][0]["given"]
    a_sum = Scalar.sum(*[Scalar.from_bytes_checked(bytes.fromhex(v["private_key"]))
                         for v in given["vin"]])  # both inputs are P2PKH: no x-only negation
    outpoints = [sp.COutPoint(hash=sp.deser_txid(v["txid"]), n=v["vout"]) for v in given["vin"]]
    vanilla_ih = sp.reference.get_input_hash(outpoints, a_sum * G)
    B_scan = GE.from_bytes_compressed(bytes.fromhex(given["recipients"][0]["scan_pub_key"]))
    B_spend = GE.from_bytes_compressed(bytes.fromhex(given["recipients"][0]["spend_pub_key"]))
    vanilla_P0, _, _ = sender_derive(a_sum, B_scan, B_spend, vanilla_ih)
    assert vanilla_P0.to_bytes_xonly().hex() != case["sending"][0]["expected"]["outputs"][0], \
        "variant output equals the vanilla fused-key output — the split is not in effect"
    # a_send must genuinely be unrelated key material
    assert given["a_send"] not in [v["private_key"] for v in given["vin"]]


# --- case 2 ----------------------------------------------------------------------
def check_coinbase(case: dict) -> None:
    for se in case["sending"]:
        check_sending(se)
    for re_ in case["receiving"]:
        check_receiving(re_)
    given = case["sending"][0]["given"]
    assert given["coinbase"]["prevout_txid"] == "00" * 32
    assert given["coinbase"]["prevout_vout"] == 0xFFFFFFFF
    # Independent anchor: recompute the whole derivation a second way, using
    # raw hashlib instead of the sp_coinbase helpers, from JSON givens only.
    def th(tag: str, msg: bytes) -> bytes:
        t = hashlib.sha256(tag.encode()).digest()
        return hashlib.sha256(t + t + msg).digest()
    h, A_x = given["height"], case["sending"][0]["expected"]["A_send"]
    ih = th("SP-Coinbase/Inputs", h.to_bytes(4, "big") + b"\x02" + bytes.fromhex(A_x))
    assert ih.hex() == case["sending"][0]["expected"]["input_hash"], "anchor: input_hash mismatch"
    key = case["receiving"][0]["given"]["key_material"]
    b_scan = Scalar.from_bytes_checked(bytes.fromhex(key["scan_priv_key"]))
    b_spend = Scalar.from_bytes_checked(bytes.fromhex(key["spend_priv_key"]))
    ecdh = hash_to_scalar(ih) * b_scan * GE.from_bytes_xonly(bytes.fromhex(A_x))
    t0 = hash_to_scalar(th("SP-Coinbase/SharedSecret", ecdh.to_bytes_compressed() + (0).to_bytes(4, "big")))
    P0 = b_spend * G + t0 * G
    assert P0.to_bytes_xonly().hex() == case["sending"][0]["expected"]["outputs"][0], \
        "anchor: independent recomputation of P_0 disagrees with the vector"


# --- case 3 ----------------------------------------------------------------------
def check_fan_out(case: dict) -> None:
    for se in case["sending"]:
        check_sending(se)
    outs = case["sending"][0]["expected"]["outputs"]
    assert len(outs) == 5 and len(set(outs)) == 5, "fan-out outputs not pairwise distinct"
    for i, re_ in enumerate(case["receiving"][:5]):
        check_receiving(re_)
        found = re_["expected"]["outputs"]
        assert len(found) == 1, f"miner {i} found {len(found)} outputs, expected exactly 1"
        assert found[0]["pub_key"] == outs[i], f"miner {i} found a different miner's output"
    drop = case["receiving"][5]
    check_receiving(drop)
    assert outs[2] not in drop["given"]["outputs"], "dropped output still present in scenario"
    assert len(drop["given"]["outputs"]) == 5, "drop scenario should have 5 outputs (decoy + 4)"
    assert drop["expected"]["outputs"][0]["pub_key"] == outs[0], \
        "miner 0 lost their output when miner 2's was dropped — :319 contiguity bit anyway"


# --- case 4 ----------------------------------------------------------------------
def check_nonce_distinctness(case: dict) -> None:
    for se in case["sending"]:
        check_sending(se)
    e0, e1, e2 = [se["expected"] for se in case["sending"]]
    assert e0["input_hash"] != e1["input_hash"] and e0["outputs"] != e1["outputs"], \
        "same a_send at two heights produced the same output"
    assert e0["input_hash"] != e2["input_hash"] and e0["outputs"] != e2["outputs"], \
        "two a_send at the same height produced the same output"


# --- case 5 ----------------------------------------------------------------------
def check_vanilla_coinbase_reject(case: dict) -> None:
    from bitcoin_utils import CTxInWitness, VinInfo, from_hex
    vin_d = case["sending"][0]["given"]["vin"][0]
    vin = VinInfo(
        outpoint=sp.COutPoint(hash=sp.deser_txid(vin_d["txid"]), n=vin_d["vout"]),
        scriptSig=bytes.fromhex(vin_d["scriptSig"]),
        txinwitness=CTxInWitness().deserialize(from_hex(vin_d["txinwitness"])),
        prevout=bytes.fromhex(vin_d["prevout"]["scriptPubKey"]["hex"]),
    )
    # The original blocker, executable: every branch of get_pubkey_from_input
    # (reference.py:37-88) tests vin.prevout, and a coinbase has none.
    pk = sp.reference.get_pubkey_from_input(vin)
    assert pk.infinity, "coinbase input yielded a pubkey — the BIP352 blocker has changed"
    # ...so the :193 eligibility gate ('at least one input from the Inputs For
    # Shared Secret Derivation list') fails: sender generates no outputs,
    # receiver skips the transaction entirely.
    assert case["sending"][0]["expected"] == {"input_pub_keys": [], "outputs": [[]]}
    assert case["receiving"][0]["expected"]["outputs"] == []


# --- case 6 ----------------------------------------------------------------------
def check_constant_nonce_collision(case: dict) -> None:
    for se in case["sending"]:
        check_sending(se)
    e0, e1 = [se["expected"] for se in case["sending"]]
    # The 2026-07-29 note's claim, executed: constant null prevout as nonce ->
    # two different blocks collide to the same P_0 (forced address reuse).
    assert e0["input_hash"] == e1["input_hash"], "constant-outpoint nonce varied across blocks?!"
    assert e0["outputs"] == e1["outputs"], "expected collision (address reuse) not demonstrated"
    # Control: the height nonce rerandomizes across blocks.
    fixed = derive_sending({**case["sending"][1]["given"], "nonce_rule": "height"})
    assert fixed["outputs"] != e0["outputs"], "control failed: height nonce did not rerandomize"


# --- case 7 ----------------------------------------------------------------------
def check_input_hash_replay(case: dict) -> None:
    e = case["sending"]
    for se in e:
        check_sending(se)
    # Recompute the attack scalars from scratch: a_send' = input_hash * a_send / input_hash'
    a0_used = even_y(Scalar.from_bytes_checked(bytes.fromhex(e[0]["given"]["a_send"])))[0]
    ih1 = hash_to_scalar(bytes.fromhex(e[0]["expected"]["input_hash"]))
    ih2a = hash_to_scalar(input_hash_height_only(e[1]["given"]["height"]))
    a_att_a = ih1 * a0_used / ih2a
    assert a_att_a.to_bytes().hex() == e[1]["given"]["a_send"], \
        "entry 1's a_send is not the :92 formula output"
    A_other = GE.from_bytes_xonly(bytes.fromhex(e[2]["given"]["bound_key"]))
    ih2b = hash_to_scalar(input_hash_wrong_key(e[2]["given"]["height"], A_other))
    a_att_b = ih1 * a0_used / ih2b
    assert a_att_b.to_bytes().hex() == e[2]["given"]["a_send"], \
        "entry 2's a_send is not the :92 formula output"
    # The demonstrated failures: replayed shared secret -> forced address reuse.
    assert e[1]["expected"]["shared_secrets"] == e[0]["expected"]["shared_secrets"]
    assert e[1]["expected"]["outputs"] == e[0]["expected"]["outputs"], \
        "7a collision (key omitted from input_hash) not demonstrated"
    assert e[2]["expected"]["shared_secrets"] == e[0]["expected"]["shared_secrets"]
    assert e[2]["expected"]["outputs"] == e[0]["expected"]["outputs"], \
        "7b collision (input_hash bound to wrong key) not demonstrated"
    # The control: binding input_hash to A_send kills the transplanted attack.
    assert e[3]["expected"]["input_hash"] != e[1]["expected"]["input_hash"]
    assert e[3]["expected"]["outputs"] != e[0]["expected"]["outputs"], \
        "control failed: correct binding to A_send still collided"


# --- case 8 ----------------------------------------------------------------------
def check_odd_y_scan_miss(case: dict) -> None:
    for se in case["sending"]:
        check_sending(se)
    for re_ in case["receiving"]:
        check_receiving(re_)
    raw = Scalar.from_bytes_checked(bytes.fromhex(case["sending"][0]["given"]["a_send"]))
    assert not (raw * G).has_even_y(), "vector precondition violated: raw a_send must have odd Y"
    # Negation does not change x: the wire key is byte-identical across the two
    # entries; only the scalar convention differs.
    assert case["sending"][0]["expected"]["A_send"] == case["sending"][1]["expected"]["A_send"]
    # Mechanism: the negation-omitted sender committed to ser_P of the odd-Y
    # point (0x03||x); the scanner canonicalizes the x-only wire key (0x02||x).
    h = case["sending"][0]["given"]["height"]
    A_wire = GE.from_bytes_xonly(bytes.fromhex(case["sending"][0]["expected"]["A_send"]))
    assert input_hash_coinbase(h, A_wire).hex() != case["sending"][0]["expected"]["input_hash"]
    assert case["receiving"][0]["expected"]["outputs"] == [], "negation-omitted scan must miss"
    assert len(case["receiving"][1]["expected"]["outputs"]) == 1, "even-Y-rule scan must hit"


# --- case 9 ----------------------------------------------------------------------
def check_forward_secrecy_compression(case: dict) -> None:
    for se in case["sending"]:
        check_sending(se)
    for re_ in case["receiving"]:
        check_receiving(re_)  # the honest path still works under the strawman
    a_0 = Scalar.from_bytes_checked(bytes.fromhex(case["setup"]["a_0"]))
    A_0 = GE.from_bytes_xonly(bytes.fromhex(case["setup"]["A_0"]))
    for se in case["sending"]:
        h = se["given"]["height"]
        # Attacker holds only a_0 plus public data (A_0, H, the published list).
        a_rec = even_y(a_0 + compressed_list_tweak(A_0, h))[0]
        assert a_rec.to_bytes().hex() == se["given"]["a_send"], "epoch secret not recovered"
        assert (a_rec * G).to_bytes_xonly().hex() == se["expected"]["A_send"], "A_H not recovered"
        # ...and every past ecdh follows: retroactive detection of the payout.
        B_scan = GE.from_bytes_compressed(bytes.fromhex(se["given"]["recipients"][0]["scan_pub_key"]))
        B_spend = GE.from_bytes_compressed(bytes.fromhex(se["given"]["recipients"][0]["spend_pub_key"]))
        P_rec, ecdh_rec, _ = sender_derive(a_rec, B_scan, B_spend, input_hash_coinbase(h, a_rec * G))
        assert ecdh_rec.to_bytes_compressed().hex() == se["expected"]["shared_secrets"][0]
        assert P_rec.to_bytes_xonly().hex() == se["expected"]["outputs"][0], \
            "recovered key failed to detect the past output"


# --- case 11 ---------------------------------------------------------------------
def check_multisig_fee_output(case: dict) -> None:
    for se in case["sending"]:
        check_sending(se)
    for re_ in case["receiving"]:
        check_receiving(re_)  # scan + miner spend sig, with A_send parsed from the script
    se = case["sending"][0]
    script = bytes.fromhex(se["expected"]["fee_output_scriptPubKey"])
    # Script shape: OP_1 <33> <33> OP_2 OP_CHECKMULTISIG, 71 bytes (+37 B vs a
    # P2TR fee output = 148 WU).
    #
    # REJECTED CARRIER — the assertions below pin the mechanics, which do work; the
    # verdict is recorded in the case comment. m = 1 means any ONE listed key
    # authorizes a spend, so a_send is not merely unnecessary for spending, it is
    # SUFFICIENT: whoever obtains the erasable privacy key can take the pool's fee.
    # That voids the property the sender-side split exists for (losing a_send costs
    # privacy, never funds). m = 2 fails oppositely — a_send must sign, so it cannot
    # be erased. Nothing here can assert that defect: it is a fact about script
    # semantics, not about the derivation. Making it executable would mean an ECDSA
    # spend of this output under a_send alone; not built, because the carrier is
    # dropped in favour of the scriptSig (case 12) and the out-of-band list.
    assert len(script) == 71 and script[0] == 0x51 and script[69:71] == b"\x52\xae"
    keys = sp.parse_p2ms_1_of_2(script)
    # A_send survives the scriptPubKey round-trip byte-exactly and is the same
    # canonical even-Y point the derivation commits to (key_index convention).
    assert keys[0].to_bytes_xonly().hex() == se["expected"]["A_send"], \
        "A_send did not survive the scriptPubKey round-trip"
    A_pool = GE.from_bytes_compressed(bytes.fromhex(se["given"]["fee_output"]["pool_pub_key"]))
    assert keys[1] == A_pool, "pool spend key not at key_index 1"
    assert keys[0] != keys[1], "A_send and A_pool must be independent key material"
    # The fee output is the carrier, NOT a scan candidate: it is not among the
    # miner's taproot outputs.
    assert script.hex() not in se["expected"]["outputs"]


# --- case 12 ---------------------------------------------------------------------
def check_coinbase_scriptsig_carrier(case: dict) -> None:
    for se in case["sending"]:
        check_sending(se)
    for re_ in case["receiving"]:
        check_receiving(re_)  # scan + miner spend sig, A_send parsed from the scriptSig
    se = case["sending"][0]
    script = bytes.fromhex(se["expected"]["coinbase_scriptSig"])
    height = se["given"]["height"]
    offset = case["receiving"][0]["given"]["A_send_source"]["offset"]
    # Consensus budget: coinbase scriptSig is 2-100 B. Layout tiles exactly:
    # [height push][extranonce][push33 A_send] — "we don't need anything else".
    assert 2 <= len(script) <= 100, "coinbase scriptSig outside the 2-100 B consensus budget"
    hp = sp.ser_bip34_height(height)
    assert script.startswith(hp), "scriptSig must open with the BIP34 height push"
    # Height round-trip: little-endian minimally-encoded on the wire, ser32
    # big-endian inside input_hash — and the PARSED height reproduces the vector.
    n = script[0]
    assert int.from_bytes(script[1:1 + n], "little") == height, "BIP34 height push mismatch"
    A_send = sp.parse_A_send_from_scriptsig(script, offset)
    assert input_hash_coinbase(int.from_bytes(script[1:1 + n], "little"), A_send).hex() \
        == se["expected"]["input_hash"], "scriptSig-parsed (height, A_send) must reproduce input_hash"
    # A_send survives the scriptSig round-trip byte-exactly.
    assert A_send.to_bytes_xonly().hex() == se["expected"]["A_send"]
    # Lesson 4, executable: the A_send region is disjoint from the miner-rolled
    # extranonce region, so rolling can never rebuild the outputs.
    ex_len = len(bytes.fromhex(se["given"]["scriptsig_carrier"]["extranonce"]))
    ex_range, key_range = range(len(hp), len(hp) + ex_len), range(offset, offset + 34)
    assert not set(ex_range) & set(key_range), "A_send overlaps the rolled extranonce bytes"
    assert len(hp) + ex_len == offset and offset + 34 == len(script), "layout must tile exactly"
    # The pool's fee output is an arbitrary P2TR key and is NOT the carrier:
    # it sits in the scan set as a decoy and is not matched.
    assert len(case["receiving"][0]["expected"]["outputs"]) == 1


CHECKS = {
    "ordinary_split": check_ordinary_split,
    "coinbase": check_coinbase,
    "fan_out": check_fan_out,
    "nonce_distinctness": check_nonce_distinctness,
    "vanilla_coinbase_reject": check_vanilla_coinbase_reject,
    "constant_nonce_collision": check_constant_nonce_collision,
    "input_hash_replay": check_input_hash_replay,
    "odd_y_scan_miss": check_odd_y_scan_miss,
    "forward_secrecy_compression": check_forward_secrecy_compression,
    "multisig_fee_output": check_multisig_fee_output,
    "coinbase_scriptSig_carrier": check_coinbase_scriptsig_carrier,
}


# --- index.html carries its own copy of case 12, for the in-browser demo ------
def check_html_vector_in_sync(cases: list) -> None:
    """The explainer runs case 12 in JavaScript against hardcoded values. If the
    vectors are regenerated with different key material, that copy goes stale and
    the page would show a green tick for numbers nobody checks. Pin it here."""
    html = (Path(__file__).resolve().parent / "index.html").read_text()
    case = next(c for c in cases if c["case_type"] == "coinbase_scriptSig_carrier")
    se, re_ = case["sending"][0], case["receiving"][0]
    for name, want in [
        ("a_send", se["given"]["a_send"]),
        ("scan_priv", re_["given"]["key_material"]["scan_priv_key"]),
        ("spend_pub", se["given"]["recipients"][0]["spend_pub_key"]),
        ("extranonce", se["given"]["scriptsig_carrier"]["extranonce"]),
        ("A_send", se["expected"]["A_send"]),
        ("input_hash", se["expected"]["input_hash"]),
        ("secret", se["expected"]["shared_secrets"][0]),
        ("tweak", se["expected"]["tweaks"][0]),
        ("output", se["expected"]["outputs"][0]),
        ("scriptSig", se["expected"]["coinbase_scriptSig"]),
    ]:
        assert f"'{want}'" in html, f"index.html is stale: {name} no longer matches the vector"
    assert f"height: {se['given']['height']}," in html, "index.html height is stale"
    assert f"offset: {re_['given']['A_send_source']['offset']}," in html, "index.html offset is stale"


def main() -> int:
    failures = 0
    if "--skip-baseline" in sys.argv:
        print("SKIP: baseline (--skip-baseline)")
    else:
        try:
            run_baseline()
            print("PASS: baseline — 28 vendored BIP352 vectors, unmodified reference.py")
        except Exception:
            failures += 1
            print("FAIL: baseline — 28 vendored BIP352 vectors, unmodified reference.py")
            traceback.print_exc()
    cases = json.loads(VECTORS.read_text())
    for case in cases:
        try:
            CHECKS[case["case_type"]](case)
            print(f"PASS: {case['case_type']}")
        except Exception:
            failures += 1
            print(f"FAIL: {case['case_type']} — {case['comment'][:100]}")
            traceback.print_exc()
    try:
        check_html_vector_in_sync(cases)
        print("PASS: index.html demo values in sync with case 12")
    except Exception:
        failures += 1
        print("FAIL: index.html demo values in sync with case 12")
        traceback.print_exc()
    if failures:
        print(f"\n{failures} check(s) FAILED")
        return 1
    print("\nAll tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
