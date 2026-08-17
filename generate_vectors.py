#!/usr/bin/env python3
"""Generates coinbase_sp_test_vectors.json. Re-run after any change to
sp_coinbase.py. All key material is deterministically derived from labels via
tagged hashes — reproducible, and obviously not real keys.

The JSON mirrors bip-0352/send_and_receive_test_vectors.json's schema
(comment / sending.given / sending.expected / receiving) so a silent-payments
implementer can review the numbers without reading this harness. Deviations:
no bech32m addresses (raw B_scan/B_spend hex instead, see DECISION 3 in
sp_coinbase.py), and case-level extras ("case_type", "setup",
"expected_failure") for the negative controls."""

import json
from pathlib import Path

from sp_coinbase import (
    BIP0352_DIR, G, GE, Scalar, even_y, hash_to_scalar, input_hash_height_only,
    input_hash_wrong_key, tagged_hash, derive_sending, derive_receiving,
    compressed_list_tweak,
)

H1, H2 = 840000, 840001
OUT = Path(__file__).parent / "coinbase_sp_test_vectors.json"


def det_scalar(label: str, want_odd_y: bool = None) -> Scalar:
    """Deterministic key material for reproducible vectors."""
    for i in range(1024):
        s = Scalar.from_bytes_checked(tagged_hash("sp-coinbase-vectors/keygen", f"{label}:{i}".encode()))
        if int(s) == 0:
            continue
        if want_odd_y is None or ((s * G).has_even_y() != want_odd_y):
            return s
    raise RuntimeError(f"no suitable scalar for {label}")


def pubs(b_scan: Scalar, b_spend: Scalar) -> dict:
    return {"scan_pub_key": (b_scan * G).to_bytes_compressed().hex(),
            "spend_pub_key": (b_spend * G).to_bytes_compressed().hex()}


def key_material(b_scan: Scalar, b_spend: Scalar) -> dict:
    return {"scan_priv_key": b_scan.to_bytes().hex(), "spend_priv_key": b_spend.to_bytes().hex()}


# --- deterministic shared key material ----------------------------------------
MINERS = [(det_scalar(f"miner{i}-scan"), det_scalar(f"miner{i}-spend")) for i in range(1, 6)]
A_SEND_MAIN = det_scalar("a-send-main")
A_SEND_ALT = det_scalar("a-send-alt")
A_SEND_ODD = det_scalar("a-send-odd", want_odd_y=True)  # case 8 precondition
FEE_KEY = even_y(det_scalar("pool-fee-key"))[0]         # static pool key, case 7b
DECOY = even_y(det_scalar("pool-fee-output"))[0] * G    # txOut[0] fee output, case 3
POOL_SPEND = det_scalar("pool-spend-key")               # a_pool, case 11 (compressed key, any parity)

# vin material copied verbatim from bip-0352/send_and_receive_test_vectors.json
# case 0 ("Simple send: two inputs") — recognizable provenance for reviewers.
BIP352_VIN = json.loads((BIP0352_DIR / "send_and_receive_test_vectors.json").read_text())[0]["sending"][0]["given"]["vin"]

COINBASE = {"prevout_txid": "00" * 32, "prevout_vout": 4294967295}


def sending_entry(given: dict) -> dict:
    return {"given": given, "expected": derive_sending(given)}


def receiving_entry(given: dict) -> dict:
    info, found = derive_receiving(given)
    return {"given": given, "expected": {**info, "outputs": found}}


# --- case 1: the split in an ordinary transaction ------------------------------
def case1() -> dict:
    given = {
        "nonce_rule": "outpoint_l",
        "vin": BIP352_VIN,
        "a_send": A_SEND_MAIN.to_bytes().hex(),
        "apply_even_y_rule": True,
        "recipients": [pubs(*MINERS[0])],
    }
    se = sending_entry(given)
    re_ = receiving_entry({
        "vin": BIP352_VIN,
        "A_send": se["expected"]["A_send"],
        "outputs": se["expected"]["outputs"],
        "key_material": key_material(*MINERS[0]),
    })
    return {
        "comment": "Case 1 — sender-side ECDH/spend key split in an ORDINARY transaction. "
                   "a_send is unrelated to the input private keys (they sign; only a_send does ECDH). "
                   "Nonce stays BIP352-style outpoint_L so the split is isolated from coinbase "
                   "mechanics. Sender-derived P_0 must equal receiver-scanned P_0.",
        "case_type": "ordinary_split",
        "sending": [se],
        "receiving": [re_],
    }


# --- case 2: coinbase — null prevout, BIP 34 height as nonce -------------------
def case2() -> dict:
    given = {
        "nonce_rule": "height",
        "coinbase": {**COINBASE, "height": H1},
        "height": H1,
        "a_send": A_SEND_MAIN.to_bytes().hex(),
        "apply_even_y_rule": True,
        "recipients": [pubs(*MINERS[0])],
    }
    se = sending_entry(given)
    re_ = receiving_entry({
        "height": H1,
        "A_send": se["expected"]["A_send"],
        "outputs": se["expected"]["outputs"],
        "key_material": key_material(*MINERS[0]),
    })
    return {
        "comment": "Case 2 — the construction in its native scope: coinbase input (null prevout "
                   "00..00:ffffffff), BIP 34 block height as the derivation nonce, A_send served "
                   "out of band. input_hash = tagged_hash('SP-Coinbase/Inputs', ser32(H) || "
                   "ser_P(A_send)); ecdh = input_hash*a_send*B_scan = input_hash*b_scan*A_send. "
                   "Derivation and scanning must agree, and the output must be spendable "
                   "(b_spend + t_0 signs).",
        "case_type": "coinbase",
        "sending": [se],
        "receiving": [re_],
    }


# --- case 3: fan-out, N = 5 distinct scan keys ---------------------------------
def case3() -> dict:
    given = {
        "nonce_rule": "height",
        "coinbase": {**COINBASE, "height": H1,
                     "note": "txOut[0] is the pool's own fee output (decoy below); txOut[1..5] pay miners"},
        "height": H1,
        "a_send": A_SEND_MAIN.to_bytes().hex(),
        "apply_even_y_rule": True,
        "recipients": [pubs(*m) for m in MINERS],
    }
    se = sending_entry(given)
    all_outputs = [DECOY.to_bytes_xonly().hex()] + se["expected"]["outputs"]
    receiving = []
    for i, m in enumerate(MINERS):
        receiving.append(receiving_entry({
            "height": H1, "A_send": se["expected"]["A_send"],
            "outputs": all_outputs, "key_material": key_material(*m),
        }))
    # Drop-output scenario: miner j = 2's output removed (dust-filtered, say);
    # miner i = 0 must still find their own. Contrast with bip-0352.mediawiki:319 —
    # no k++ chain across distinct scan keys, so no contiguity dependency.
    j, i = 2, 0
    dropped = [o for idx, o in enumerate(all_outputs) if idx != j + 1]  # +1: decoy at index 0
    drop_entry = receiving_entry({
        "height": H1, "A_send": se["expected"]["A_send"],
        "outputs": dropped, "key_material": key_material(*MINERS[i]),
    })
    drop_entry["comment"] = f"output for miner index {j} dropped from the tx; miner index {i} must still find theirs"
    receiving.append(drop_entry)
    return {
        "comment": "Case 3 — one-payer fan-out: N = 5 miners, distinct scan keys, one a_send, one "
                   "height. Each miner sits alone in its :304 group at k = 0, so each finds exactly "
                   "its own output and zero others (the txOut[0] fee output is a decoy). The final "
                   "receiving entry drops one miner's output and confirms another miner is "
                   "unaffected — the :319 contiguity footgun does not apply to this shape.",
        "case_type": "fan_out",
        "sending": [se],
        "receiving": receiving,
    }


# --- case 4: nonce distinctness, both directions -------------------------------
def case4() -> dict:
    base = {"nonce_rule": "height", "apply_even_y_rule": True, "recipients": [pubs(*MINERS[0])]}
    e_same_key_h1 = sending_entry({**base, "height": H1, "a_send": A_SEND_MAIN.to_bytes().hex()})
    e_same_key_h2 = sending_entry({**base, "height": H2, "a_send": A_SEND_MAIN.to_bytes().hex()})
    e_alt_key_h1 = sending_entry({**base, "height": H1, "a_send": A_SEND_ALT.to_bytes().hex()})
    return {
        "comment": "Case 4 — nonce distinctness, both directions. Entries 0 vs 1: same a_send at "
                   "heights H and H+1 must give distinct outputs. Entries 0 vs 2: same height with "
                   "two different a_send must give distinct outputs. (input_hash commits to both H "
                   "and A_send, so either difference alone rerandomizes.)",
        "case_type": "nonce_distinctness",
        "sending": [e_same_key_h1, e_same_key_h2, e_alt_key_h1],
        "receiving": [],
    }


# --- case 5: NEGATIVE — vanilla BIP 352 rejects a coinbase ---------------------
def case5() -> dict:
    coinbase_vin = {
        "txid": COINBASE["prevout_txid"],
        "vout": COINBASE["prevout_vout"],
        # BIP 34 height push (840000) followed by a pool tag; no pubkey anywhere
        "scriptSig": "0340d10c" + b"/sp-coinbase-vectors/".hex(),
        # coinbase witness carries the 32-byte reserved value, still no pubkey
        "txinwitness": "01" + "20" + "00" * 32,
        # a coinbase spends no prevout: there is no scriptPubKey to read a key from
        "prevout": {"scriptPubKey": {"hex": ""}},
    }
    decoys = [DECOY.to_bytes_xonly().hex(),
              (even_y(det_scalar("case5-decoy"))[0] * G).to_bytes_xonly().hex()]
    return {
        "comment": "Case 5 — NEGATIVE CONTROL: unmodified BIP 352 on a coinbase. "
                   "get_pubkey_from_input finds no pubkey (no prevout scriptPubKey, no witness "
                   "key, no scriptSig key — reference.py:37-88, every branch tests vin.prevout), "
                   "so the eligibility gate at bip-0352.mediawiki:193 ('at least one input from "
                   "the Inputs For Shared Secret Derivation list') fails: the sender generates no "
                   "outputs and the receiver skips the transaction. This makes the original "
                   "blocker executable.",
        "case_type": "vanilla_coinbase_reject",
        "sending": [{"given": {"vin": [coinbase_vin], "recipients": []},
                     "expected": {"input_pub_keys": [], "outputs": [[]]}}],
        "receiving": [{"given": {"vin": [{k: v for k, v in coinbase_vin.items()}],
                                 "outputs": decoys,
                                 "key_material": key_material(*MINERS[0]),
                                 "labels": []},
                       "expected": {"outputs": []}}],
    }


# --- case 6: NEGATIVE — constant null outpoint as nonce collides ---------------
def case6() -> dict:
    base = {"nonce_rule": "constant_null_outpoint", "apply_even_y_rule": True,
            "recipients": [pubs(*MINERS[0])], "a_send": A_SEND_MAIN.to_bytes().hex()}
    e_h1 = sending_entry({**base, "height": H1})
    e_h2 = sending_entry({**base, "height": H2})
    return {
        "comment": "Case 6 — NEGATIVE CONTROL: the 2026-07-29 note's claim, executed. If the "
                   "coinbase's constant null prevout (00..00:ffffffff) is used as the nonce "
                   "instead of the BIP 34 height, input_hash is identical in every block and two "
                   "different blocks collide to the SAME P_0 — forced address reuse. The fix "
                   "(height nonce) is asserted as a control in the runner.",
        "case_type": "constant_nonce_collision",
        "expected_failure": "sending[0].expected.outputs == sending[1].expected.outputs "
                            "(identical across heights: address reuse)",
        "sending": [e_h1, e_h2],
        "receiving": [],
    }


# --- case 7: NEGATIVE — :92 replay when input_hash is bound to the wrong key ---
def grind_attack(a_used0: Scalar, ih1: bytes, rule: str, bound_key: GE = None):
    """Attacker computes a_send' = input_hash * a_send / input_hash' (the :92
    formula transposed to the sender-side split). The even-Y rule still applies
    on the wire, so grind the height until the attack scalar is the canonical
    one — proving the attack survives the parity rule, not hides behind it."""
    h = H2
    while True:
        ih2 = input_hash_height_only(h) if rule == "height_only_unbound" else input_hash_wrong_key(h, bound_key)
        a_att = hash_to_scalar(ih1) * a_used0 / hash_to_scalar(ih2)
        if (a_att * G).has_even_y():
            return h, a_att
        h += 1


def case7() -> dict:
    a_used0 = even_y(A_SEND_MAIN)[0]
    e0 = sending_entry({"nonce_rule": "height", "height": H1,
                        "a_send": A_SEND_MAIN.to_bytes().hex(),
                        "apply_even_y_rule": True, "recipients": [pubs(*MINERS[0])]})
    ih1 = bytes.fromhex(e0["expected"]["input_hash"])
    fee_point = FEE_KEY * G
    h_a, a_att_a = grind_attack(a_used0, ih1, "height_only_unbound")
    h_b, a_att_b = grind_attack(a_used0, ih1, "wrong_key", bound_key=fee_point)
    # 7a: input_hash commits to NO key. Attacker's scalar replays the shared secret.
    e1 = sending_entry({"nonce_rule": "height_only_unbound", "height": h_a,
                        "a_send": a_att_a.to_bytes().hex(),
                        "apply_even_y_rule": True, "recipients": [pubs(*MINERS[0])]})
    # 7b: input_hash commits to a static third key (pool fee key), not A_send. Same replay.
    e2 = sending_entry({"nonce_rule": "wrong_key", "height": h_b,
                        "bound_key": fee_point.to_bytes_xonly().hex(),
                        "a_send": a_att_b.to_bytes().hex(),
                        "apply_even_y_rule": True, "recipients": [pubs(*MINERS[0])]})
    # Control: same attack scalar, but input_hash correctly bound to A_send. Now
    # input_hash' depends on a_send'*G itself — a fixed point the attacker cannot
    # solve without a dlog — and the transplanted scalar no longer collides.
    e3 = sending_entry({"nonce_rule": "height", "height": h_a,
                        "a_send": a_att_a.to_bytes().hex(),
                        "apply_even_y_rule": True, "recipients": [pubs(*MINERS[0])]})
    return {
        "comment": "Case 7 — NEGATIVE CONTROL: the why_include_A attack (bip-0352.mediawiki:92) "
                   "transposed to the split. If input_hash omits the key (entry 1) or commits to a "
                   "static third key like the pool fee key (entry 2), a sender choosing "
                   "a_send' = input_hash*a_send/input_hash' forces the SAME shared secret at a "
                   "different height — address reuse. The attack scalar is ground to even Y so the "
                   "parity rule cannot be blamed. Entry 3 is the control: with input_hash bound to "
                   "A_send, the transplanted scalar produces a different output (the real attack "
                   "would require solving a_send' = f(a_send'*G), a dlog fixed point). Binding to "
                   "A_send kills the replay.",
        "case_type": "input_hash_replay",
        "expected_failure": "entries 1 and 2 collide with entry 0 (reuse); entry 3 (correct "
                            "binding) must NOT collide",
        "sending": [e0, e1, e2, e3],
        "receiving": [],
    }


# --- case 8: NEGATIVE — odd-Y A_send, negation omitted, scan misses ------------
def case8() -> dict:
    # Broken: sender skips the even-Y rule. The wire still carries only x, so
    # the scanner lifts the even-Y representative — a different point AND a
    # different ser_P inside input_hash. Scan must miss.
    se_broken = sending_entry({"nonce_rule": "height_even_y_omitted", "height": H1,
                               "a_send": A_SEND_ODD.to_bytes().hex(),
                               "apply_even_y_rule": False, "recipients": [pubs(*MINERS[0])]})
    re_broken = receiving_entry({"height": H1, "A_send": se_broken["expected"]["A_send"],
                                 "outputs": se_broken["expected"]["outputs"],
                                 "key_material": key_material(*MINERS[0])})
    # Fixed: same raw key, rule applied. Wire bytes are IDENTICAL (negation does
    # not change x); only the scalar convention differs. Scan must hit.
    se_fixed = sending_entry({"nonce_rule": "height", "height": H1,
                              "a_send": A_SEND_ODD.to_bytes().hex(),
                              "apply_even_y_rule": True, "recipients": [pubs(*MINERS[0])]})
    re_fixed = receiving_entry({"height": H1, "A_send": se_fixed["expected"]["A_send"],
                                "outputs": se_fixed["expected"]["outputs"],
                                "key_material": key_material(*MINERS[0])})
    return {
        "comment": "Case 8 — NEGATIVE CONTROL: A_send is x-only on the wire, so the even-Y rule "
                   "(bip-0352.mediawiki:299 transposed to the sender key) is load-bearing. The raw "
                   "a_send below has odd Y. Entry 0 omits the negation: the sender's ECDH point is "
                   "the odd-Y point and its ser_P inside input_hash starts 0x03, while the scanner "
                   "canonicalizes the x-only wire key to even Y (0x02) — scan misses. Entry 1 "
                   "applies the rule: identical wire bytes (x is unchanged by negation), scan hits. "
                   "The runner asserts the raw key's Y is odd, so the vector's precondition is "
                   "checked, not assumed.",
        "case_type": "odd_y_scan_miss",
        "expected_failure": "receiving[0] finds nothing (scan miss) with negation omitted; "
                            "receiving[1] finds the output with the rule applied",
        "sending": [se_broken, se_fixed],
        "receiving": [re_broken, re_fixed],
    }


# --- case 9: NEGATIVE — compressed A_send list destroys forward secrecy --------
def case9() -> dict:
    a_0 = even_y(det_scalar("a0-compressed-list"))[0]
    A_0 = a_0 * G
    sending, receiving = [], []
    for h in (H1, H2):
        a_H = even_y(a_0 + compressed_list_tweak(A_0, h))[0]
        se = sending_entry({"nonce_rule": "height", "height": h, "a_send": a_H.to_bytes().hex(),
                            "apply_even_y_rule": True, "recipients": [pubs(*MINERS[0])]})
        sending.append(se)
        receiving.append(receiving_entry({"height": h, "A_send": se["expected"]["A_send"],
                                          "outputs": se["expected"]["outputs"],
                                          "key_material": key_material(*MINERS[0])}))
    return {
        "comment": "Case 9 — NEGATIVE CONTROL: the forward-secrecy dichotomy of Lesson 8, "
                   "executable. If the published per-height list is compressed as "
                   "A_H = A_0 + H(A_0 || H)*G, then a_H = a_0 + H(A_0 || H): the scheme is "
                   "group-LINEAR, so compromising a_0 recovers every epoch secret a_H and every "
                   "past ecdh — retroactive deanonymization of every payout, exactly the failure "
                   "the split was meant to fix. The runner recovers a_H from a_0 and public data "
                   "alone, re-derives the shared secret, and detects the past output. NOTE: this "
                   "demonstrates the linear case is broken; it does NOT prove the non-linear case "
                   "(e.g. hash-to-curve) is unusable — that case fails differently (nobody, "
                   "sender included, knows the dlog). The fix is an uncompressed list: 33 B per "
                   "epoch over the stratum channel.",
        "case_type": "forward_secrecy_compression",
        "expected_failure": "a_0 alone recovers every a_H (runner asserts a_recovered * G == A_H "
                            "and re-derives the exact on-chain output)",
        "setup": {
            "compression_rule": "A_H = A_0 + tagged_hash('SP-Coinbase/CompressedList', ser_P(A_0) || ser32(H)) * G",
            "a_0": a_0.to_bytes().hex(),
            "A_0": A_0.to_bytes_xonly().hex(),
        },
        "sending": sending,
        "receiving": receiving,
    }


# --- case 11: A_send carried by the fee output as a bare 1-of-2 multisig ------
def case11() -> dict:
    pool_pub = (POOL_SPEND * G).to_bytes_compressed().hex()
    given = {
        "nonce_rule": "height",
        "coinbase": {**COINBASE, "height": H1,
                     "note": "txOut[0] IS the carrier: OP_1 <A_send> <A_pool> OP_2 "
                             "OP_CHECKMULTISIG, paying the pool's fee to itself"},
        "height": H1,
        "a_send": A_SEND_MAIN.to_bytes().hex(),
        "apply_even_y_rule": True,
        "recipients": [pubs(*MINERS[0])],
        "fee_output": {"script_type": "p2ms_1_of_2", "pool_pub_key": pool_pub},
    }
    se = sending_entry(given)
    re_ = receiving_entry({
        "height": H1,
        "A_send_source": {"type": "fee_output_scriptPubKey",
                          "scriptPubKey": se["expected"]["fee_output_scriptPubKey"],
                          "key_index": 0},
        "outputs": se["expected"]["outputs"],
        "key_material": key_material(*MINERS[0]),
    })
    return {
        "comment": "Case 11 — REJECTED CARRIER: A_send conveyed by the pool's own fee output as a "
                   "bare 1-of-2 multisig, txOut[0] = OP_1 <A_send> <A_pool> OP_2 OP_CHECKMULTISIG. "
                   "The mechanics work and this case pins them: the scanner parses key 0 and runs "
                   "the unchanged construction, A_send survives the scriptPubKey round-trip "
                   "byte-exactly, and the miner's scan + spend path is untouched. The VERDICT is "
                   "nevertheless reject, and the reason is the one this case was originally written "
                   "to dodge. m = 1 means a_send is not merely unnecessary for spending — it is "
                   "SUFFICIENT. Anyone who obtains the erasable privacy key can sign for the pool's "
                   "fee output and take it. That is the same defect that rules out a taproot "
                   "carrier (a P2TR output exposes one group element whose dlog is the keypath "
                   "spend secret, so visibility and spendability are one property); bare multisig "
                   "separates the two mechanically but not economically, because a_send still "
                   "authorizes money. The whole point of the sender-side split is that losing "
                   "a_send costs privacy and never funds, and this carrier voids it. Raising to "
                   "m = 2 fails the other way: a_send must then sign, so it cannot be erased until "
                   "the fee is spent, which destroys the forward secrecy the split exists for. No "
                   "value of m works. Cost was +37 B ≈ 148 WU vs a P2TR fee output; that number is "
                   "now moot. Surviving carriers: the out-of-band list (0 on-chain bytes), the "
                   "witness-commitment optional-data field at bip-0141.mediawiki:74 (132 WU), and "
                   "the coinbase scriptSig as the pool tag (case 12) — all three keep a_send out of "
                   "every scriptPubKey, so it authorizes nothing.",
        "case_type": "multisig_fee_output",
        "sending": [se],
        "receiving": [re_],
    }


# --- case 12: A_send in the coinbase scriptSig, AS the pool tag ----------------
def case12() -> dict:
    from sp_coinbase import ser_bip34_height
    extranonce = bytes.fromhex("0102030405060708")  # 8 B, miner-rolled region [4, 12)
    a_send_offset = len(ser_bip34_height(H1)) + len(extranonce)  # = 12
    given = {
        "nonce_rule": "height",
        "coinbase": {**COINBASE, "height": H1,
                     "note": "scriptSig = height push || extranonce || push33(A_send); the "
                             "A_send push IS the pool tag — nothing else. Fee output pays the "
                             "pool to an ordinary P2TR key (decoy below), unconstrained."},
        "height": H1,
        "a_send": A_SEND_MAIN.to_bytes().hex(),
        "apply_even_y_rule": True,
        "recipients": [pubs(*MINERS[0])],
        "scriptsig_carrier": {"extranonce": extranonce.hex()},
    }
    se = sending_entry(given)
    re_ = receiving_entry({
        "height": H1,
        "A_send_source": {"type": "coinbase_scriptSig",
                          "scriptSig": se["expected"]["coinbase_scriptSig"],
                          "offset": a_send_offset},
        # the pool's fee output is an arbitrary P2TR key; it is a scan decoy,
        # not the carrier — payment and conveyance are decoupled
        "outputs": [DECOY.to_bytes_xonly().hex()] + se["expected"]["outputs"],
        "key_material": key_material(*MINERS[0]),
    })
    return {
        "comment": "Case 12 — A_send carried by the coinbase scriptSig, AS the pool tag: "
                   "scriptSig = BIP34 height push || extranonce || push33(A_send), 46 B total, "
                   "nothing else. The tag slot itself carries the key, so the scriptSig budget "
                   "contention dissolves (no separate 15-40 B pool string). With the pubkey list "
                   "served publicly — which the design already requires against the "
                   "list-partition attack — 'block H's tag == entry H of pool X's published "
                   "list' is unforgeable attribution, so the pool keeps a public identity without "
                   "a human-readable string. The runner asserts the consensus budget (2-100 B), "
                   "the BIP34 height push round-trip (little-endian on the wire, ser32 "
                   "big-endian inside input_hash), that the A_send region is DISJOINT from the "
                   "miner-rolled extranonce region (Lesson 4: rolling never rebuilds outputs), "
                   "and that A_send parses byte-exactly. Tradeoffs are attribution-shaped, not "
                   "cryptographic: explorers lose the ASCII tag, and public hashrate attribution "
                   "now flows through the list. Merged-mining commitments, where used, still "
                   "need their own bytes.",
        "case_type": "coinbase_scriptSig_carrier",
        "sending": [se],
        "receiving": [re_],
    }


def main() -> None:
    cases = [case1(), case2(), case3(), case4(), case5(), case6(), case7(), case8(), case9(),
             case11(), case12()]
    OUT.write_text(json.dumps(cases, indent=1, ensure_ascii=False) + "\n")
    for c in cases:
        n_out = sum(len(s["expected"].get("outputs", [])) for s in c["sending"])
        print(f"{c['case_type']}: {len(c['sending'])} sending, {len(c['receiving'])} receiving, {n_out} derived outputs")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
