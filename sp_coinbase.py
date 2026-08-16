#!/usr/bin/env python3
"""
Coinbase-scoped silent-payments variant with a sender-side ECDH/spend key split.

Construction under test (from wiki note 2026-08-14-ll-coinbase-silent-payments-ecdh-nonce,
Lesson 8; inventory candidate coinbase-native-stealth-payout):

    input_hash = tagged_hash(TAG_INPUTS, ser32(H) || ser_P(A_send))   # coinbase scope
    ecdh       = input_hash * a_send * B_scan        # sender (pool) side
               = input_hash * b_scan * A_send        # receiver (miner) side, DH symmetry
    t_0        = tagged_hash(TAG_SECRET, ser_P(ecdh) || ser32(0))
    P_0        = B_spend + t_0 * G                   # x-only taproot output key
    spend key  = (b_spend + t_0) mod n               # negated if odd Y, per BIP340

a_send is dedicated ephemeral ECDH key material with NO spending role, drawn
from a batch indexed by block height and published out of band (stratum); the
on-chain fallback is the witness-commitment output's optional-data field
(bip-0141.mediawiki:74, byte 39 onward). It is unrelated to any input/signing
key — the split that BIP 352 deliberately fuses at bip-0352.mediawiki:244.

Every recipient holds a distinct B_scan, so each sits alone in its
bip-0352.mediawiki:304 group at k = 0: no k++ loop, and the :319 contiguity
footgun has nothing to bite on (exercised by the fan-out drop case).

FLAGGED DECISIONS (surfaced, not settled):

1. Hash tags. Fresh tags "SP-Coinbase/Inputs" and "SP-Coinbase/SharedSecret"
   instead of reusing "BIP0352/Inputs" and "BIP0352/SharedSecret". Reusing the
   BIP 352 tags would invite cross-protocol shared-secret confusion: identical
   key material under both protocols would produce identical tag-prefixed hash
   inputs, so a coinbase payment and an ordinary payment could derive the same
   shared secret. Fresh tags domain-separate the variant. This is a
   recommendation, flagged per instructions — not a silently made choice.
2. A_send is carried x-only (32 bytes) on the wire (stratum list, or the
   witness-commitment optional-data fallback). Parity must therefore be
   canonicalized exactly as bip-0352.mediawiki:299 prescribes for taproot keys:
   the sender uses the even-Y representative (negate a_send if a_send*G has odd
   Y), and ser_P(A_send) inside input_hash is the compressed form of that
   even-Y point (0x02 || x). Test case 8 pins this rule by demonstrating the
   scan miss when negation is omitted.
3. No bech32m address encoding anywhere: vectors carry raw (B_scan, B_spend)
   hex. Choosing a silent-payments version byte from the table at
   bip-0352.mediawiki:152-176 is an unresolved question, not a detail to invent.
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Never write __pycache__ into the bips clone — it must stay pristine.
sys.dont_write_bytecode = True

# --- import the vendored BIP352 reference implementation and secp256k1lab ----
BIPS_REPO = Path(os.environ.get("BIPS_REPO", Path(__file__).resolve().parent.parent / "bips"))
BIP0352_DIR = BIPS_REPO / "bip-0352"
sys.path.insert(0, str(BIP0352_DIR))
import reference  # noqa: F401  # importing it puts secp256k1lab/src on sys.path itself
from bitcoin_utils import COutPoint, deser_txid, ser_uint32  # noqa: E402
from secp256k1lab.bip340 import schnorr_sign, schnorr_verify  # noqa: E402
from secp256k1lab.secp256k1 import G, GE, Scalar  # noqa: E402
from secp256k1lab.util import hash_sha256, tagged_hash  # noqa: E402

# --- protocol constants ------------------------------------------------------
# DECISION 1 (flagged): fresh tags, domain-separating this variant from BIP 352.
TAG_INPUTS = "SP-Coinbase/Inputs"
TAG_SECRET = "SP-Coinbase/SharedSecret"
# Tag for the BROKEN compressed-list strawman of case 9. It is part of the
# strawman, not of the construction, so it gets its own tag.
TAG_COMPRESSED_LIST = "SP-Coinbase/CompressedList"

K = 0  # every recipient is alone in its scan-key group; k is always 0

# Same fixed message/aux as reference.py, so signatures are comparable in style.
SIGN_MSG = hash_sha256(b"message")
SIGN_AUX = hash_sha256(b"random auxiliary data")


def ser32(i: int) -> bytes:
    # ser_32, most significant byte first (bip-0352.mediawiki:140)
    return ser_uint32(i)


def hash_to_scalar(b: bytes) -> Scalar:
    """BIP352 validity rule (:303, :312): fail if 0 or >= group order."""
    s = Scalar.from_bytes_checked(b)  # raises ValueError if >= n
    if int(s) == 0:
        raise ValueError("hash produced zero scalar")
    return s


def even_y(a: Scalar) -> Tuple[Scalar, bool]:
    """DECISION 2: even-Y canonicalization of a_send (:299 transposed).

    Returns (scalar_to_use, negated?). The point a_send*G is what A_send means;
    only its x coordinate is ever conveyed, so the even-Y representative is the
    canonical one on both sides.
    """
    return (a, False) if (a * G).has_even_y() else (-a, True)


def ser_P_canonical(A: GE) -> bytes:
    """Compressed encoding of the canonical (even-Y) A_send: 0x02 || x."""
    assert A.has_even_y(), "canonical A_send must have even Y"
    return A.to_bytes_compressed()


# --- input_hash variants ------------------------------------------------------
def input_hash_coinbase(height: int, A_send: GE) -> bytes:
    """THE construction: BIP 34 height as nonce, committed to A_send."""
    return tagged_hash(TAG_INPUTS, ser32(height) + ser_P_canonical(A_send))


def input_hash_ordinary(outpoint_l: COutPoint, A_send: GE) -> bytes:
    """Case 1 only: BIP352-style smallest-outpoint nonce, still committed to
    A_send. Isolates the ECDH/spend key split from coinbase mechanics."""
    return tagged_hash(TAG_INPUTS, outpoint_l.serialize() + ser_P_canonical(A_send))


def input_hash_coinbase_uncanon(height: int, A_raw: GE) -> bytes:
    """Case 8 broken path: sender skipped the even-Y rule, so ser_P commits to
    the actual (odd-Y) point while the scanner canonicalizes the x-only wire key."""
    return tagged_hash(TAG_INPUTS, ser32(height) + A_raw.to_bytes_compressed())


# --- broken variants, which exist only to be demonstrated broken --------------
def input_hash_constant_outpoint(A_send: GE) -> bytes:
    """BROKEN (case 6): the coinbase's constant null prevout as nonce. It is
    identical in every block, so two different blocks derive the same P_0."""
    null_outpoint = COutPoint(hash=b"\x00" * 32, n=0xFFFFFFFF)
    return tagged_hash(TAG_INPUTS, null_outpoint.serialize() + ser_P_canonical(A_send))


def input_hash_height_only(height: int) -> bytes:
    """BROKEN (case 7a): the nonce commits to no key at all, so the :92 replay
    transposes verbatim (a_send' = input_hash * a_send / input_hash')."""
    return tagged_hash(TAG_INPUTS, ser32(height))


def input_hash_wrong_key(height: int, A_other: GE) -> bytes:
    """BROKEN (case 7b): the nonce commits to a static third key (e.g. the
    pool's fee key) instead of the ECDH key actually used in the product, so
    the :92 replay transposes verbatim."""
    return tagged_hash(TAG_INPUTS, ser32(height) + ser_P_canonical(A_other))


# --- core derivation ----------------------------------------------------------
def tweak_from_ecdh(ecdh: GE) -> Scalar:
    return hash_to_scalar(tagged_hash(TAG_SECRET, ecdh.to_bytes_compressed() + ser32(K)))


def sender_derive(a_send: Scalar, B_scan: GE, B_spend: GE, input_hash: bytes) -> Tuple[GE, GE, Scalar]:
    """Pool side: ecdh = input_hash * a_send * B_scan."""
    ih = hash_to_scalar(input_hash)
    ecdh = ih * a_send * B_scan
    t_0 = tweak_from_ecdh(ecdh)
    return B_spend + t_0 * G, ecdh, t_0


def scanner_derive(b_scan: Scalar, B_spend: GE, A_send: GE, input_hash: bytes) -> Tuple[GE, GE, Scalar]:
    """Miner side: ecdh = input_hash * b_scan * A_send. Equal to the sender's by
    DH symmetry, provided both sides use the canonical even-Y A_send."""
    ih = hash_to_scalar(input_hash)
    ecdh = ih * b_scan * A_send
    t_0 = tweak_from_ecdh(ecdh)
    return B_spend + t_0 * G, ecdh, t_0


def scan_outputs(b_scan: Scalar, B_spend: GE, A_send: GE, input_hash: bytes,
                 outputs_xonly: List[bytes]) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    """One candidate at k = 0, membership check against the tx's taproot output
    keys. No k++ loop: distinct scan keys put each miner in a group of one."""
    P_0, ecdh, t_0 = scanner_derive(b_scan, B_spend, A_send, input_hash)
    found = []
    for out in outputs_xonly:
        if P_0.to_bytes_xonly() == out:
            found.append({"pub_key": P_0.to_bytes_xonly().hex(), "priv_key_tweak": t_0.to_bytes().hex()})
    info = {"input_hash": input_hash.hex(), "shared_secret": ecdh.to_bytes_compressed().hex(),
            "tweak": t_0.to_bytes().hex()}
    return found, info


def spend_key(b_spend: Scalar, t_0: Scalar) -> Scalar:
    """(b_spend + t_0) mod n, negated to even Y for BIP340 signing."""
    d = b_spend + t_0
    return d if (d * G).has_even_y() else -d


def sign_found(b_spend: Scalar, found: List[Dict[str, str]]) -> List[Dict[str, str]]:
    for o in found:
        d = spend_key(b_spend, Scalar.from_bytes_checked(bytes.fromhex(o["priv_key_tweak"])))
        o["signature"] = schnorr_sign(SIGN_MSG, d.to_bytes(), SIGN_AUX).hex()
    return found


# --- compressed-list strawman (case 9, demonstrated broken) -------------------
def compressed_list_tweak(A_0: GE, height: int) -> Scalar:
    """BROKEN strawman: A_H = A_0 + H(A_0 || H) * G is group-linear, so
    a_H = a_0 + H(A_0 || H) and whoever holds a_0 recovers every epoch key."""
    return hash_to_scalar(tagged_hash(TAG_COMPRESSED_LIST, ser_P_canonical(A_0) + ser32(height)))


# --- A_send conveyance: coinbase scriptSig, as the pool tag itself (case 12) ---
# scriptSig = BIP34 height push || extranonce || OP_PUSH33 A_send — nothing else.
# The A_send push REPLACES the human-readable pool tag: with the pubkey list
# served publicly (which the design already requires against the list-partition
# attack), "block H's tag == entry H of pool X's list" is unforgeable
# attribution, so the tag slot carries the key and the budget contention
# dissolves. Hard rule (Lesson 4): A_send must never overlap the extranonce
# bytes miners roll — the two regions must be disjoint for the whole template.
def ser_bip34_height(height: int) -> bytes:
    """Minimally-encoded, sign-safe little-endian height push (BIP 34)."""
    b = height.to_bytes(max(1, (height.bit_length() + 7) // 8), "little")
    if b[-1] & 0x80:
        b += b"\x00"
    return bytes([len(b)]) + b


def build_coinbase_scriptsig(height: int, extranonce: bytes, A_send: GE) -> bytes:
    """Height push || extranonce || push33(A_send). Layout regions tile exactly:
    [0, len(height_push)) | [len(height_push), +len(extranonce)) | push33 to end."""
    return ser_bip34_height(height) + extranonce + b"\x21" + A_send.to_bytes_compressed()


def parse_A_send_from_scriptsig(script: bytes, offset: int) -> GE:
    assert script[offset] == 0x21, "expected a 33-byte push at the A_send offset"
    return GE.from_bytes_compressed(script[offset + 1:offset + 34])


# --- A_send conveyance: bare 1-of-2 multisig fee output (case 11) -------------
# The pool's fee output (txOut[0]) as `OP_1 <A_send> <A_pool> OP_2 CHECKMULTISIG`.
# Bare multisig is the one output type whose scriptPubKey REVEALS its keys, and
# 1-of-2 means either key's holder alone can sign — so the scanner reads A_send
# from the output set it already reads, the pool spends with a_pool only, and
# a_send is erasable at block-found. (A taproot output cannot do this: it
# exposes exactly one group element, and that element's discrete log IS the
# keypath spending secret — visibility and spendability are the same property.)
P2MS_1_OF_2_SCRIPT_LEN = 71  # 1 + (1+33) + (1+33) + 1 + 1


def build_p2ms_1_of_2(A_send: GE, A_pool: GE) -> bytes:
    """OP_1 <A_send> <A_pool> OP_2 OP_CHECKMULTISIG. Position 0 carries A_send
    by convention; position 1 is the pool's long-lived spend key."""
    return (b"\x51" + b"\x21" + A_send.to_bytes_compressed()
            + b"\x21" + A_pool.to_bytes_compressed() + b"\x52\xae")


def parse_p2ms_1_of_2(script: bytes) -> List[GE]:
    assert len(script) == P2MS_1_OF_2_SCRIPT_LEN, "not a 71-byte 1-of-2 multisig script"
    assert script[0] == 0x51, "expected OP_1 (m = 1: a single signer authorizes)"
    assert script[1] == 0x21 and script[35] == 0x21, "expected two 33-byte key pushes"
    assert script[69] == 0x52 and script[70] == 0xAE, "expected OP_2 OP_CHECKMULTISIG"
    return [GE.from_bytes_compressed(script[2:35]), GE.from_bytes_compressed(script[36:69])]


def A_send_from_conveyance(given: Dict[str, Any]) -> GE:
    """Where the scanner gets A_send from. 'xonly' = the stratum list / witness
    -commitment forms (32 B wire, even-Y canonical). 'fee_output_scriptPubKey'
    = case 11's bare 1-of-2 multisig: parse key at key_index from the script."""
    if "A_send" in given:
        return GE.from_bytes_xonly(bytes.fromhex(given["A_send"]))
    src = given["A_send_source"]
    if src["type"] == "fee_output_scriptPubKey":
        keys = parse_p2ms_1_of_2(bytes.fromhex(src["scriptPubKey"]))
        return keys[src["key_index"]]
    assert src["type"] == "coinbase_scriptSig"
    return parse_A_send_from_scriptsig(bytes.fromhex(src["scriptSig"]), src["offset"])


# --- harness: given -> expected, shared by the generator and the runner -------
def lowest_outpoint_from_vin(vin: List[Dict[str, Any]]) -> COutPoint:
    outpoints = [COutPoint(hash=deser_txid(v["txid"]), n=v["vout"]) for v in vin]
    return sorted(outpoints, key=lambda op: op.serialize())[0]


def derive_sending(given: Dict[str, Any]) -> Dict[str, Any]:
    rule = given["nonce_rule"]
    a_raw = Scalar.from_bytes_checked(bytes.fromhex(given["a_send"]))
    a_send, negated = even_y(a_raw) if given.get("apply_even_y_rule", True) else (a_raw, False)
    A_send = a_send * G

    if rule == "height":
        ih = input_hash_coinbase(given["height"], A_send)
    elif rule == "outpoint_l":
        ih = input_hash_ordinary(lowest_outpoint_from_vin(given["vin"]), A_send)
    elif rule == "constant_null_outpoint":
        ih = input_hash_constant_outpoint(A_send)
    elif rule == "height_only_unbound":
        ih = input_hash_height_only(given["height"])
    elif rule == "wrong_key":
        A_other = GE.from_bytes_xonly(bytes.fromhex(given["bound_key"]))
        ih = input_hash_wrong_key(given["height"], A_other)
    elif rule == "height_even_y_omitted":
        # case 8 broken path: commit to the actual odd-Y point
        ih = input_hash_coinbase_uncanon(given["height"], A_send)
    else:
        raise ValueError(f"unknown nonce_rule {rule}")

    expected: Dict[str, Any] = {
        "A_send": A_send.to_bytes_xonly().hex(),
        "a_send_negated": negated,
        "input_hash": ih.hex(),
        "shared_secrets": [],
        "tweaks": [],
        "outputs": [],
    }
    if rule == "outpoint_l":
        expected["outpoint_l"] = lowest_outpoint_from_vin(given["vin"]).serialize().hex()
    if "fee_output" in given:
        # case 11: txOut[0] carries A_send as a bare 1-of-2 multisig alongside
        # the pool's spend key
        A_pool = GE.from_bytes_compressed(bytes.fromhex(given["fee_output"]["pool_pub_key"]))
        expected["fee_output_scriptPubKey"] = build_p2ms_1_of_2(A_send, A_pool).hex()
    if "scriptsig_carrier" in given:
        # case 12: the coinbase scriptSig carries A_send as the pool tag itself;
        # the fee output is then unconstrained
        expected["coinbase_scriptSig"] = build_coinbase_scriptsig(
            given["height"], bytes.fromhex(given["scriptsig_carrier"]["extranonce"]), A_send).hex()
    for r in given["recipients"]:
        B_scan = GE.from_bytes_compressed(bytes.fromhex(r["scan_pub_key"]))
        B_spend = GE.from_bytes_compressed(bytes.fromhex(r["spend_pub_key"]))
        P_0, ecdh, t_0 = sender_derive(a_send, B_scan, B_spend, ih)
        expected["shared_secrets"].append(ecdh.to_bytes_compressed().hex())
        expected["tweaks"].append(t_0.to_bytes().hex())
        expected["outputs"].append(P_0.to_bytes_xonly().hex())
    return expected


def derive_receiving(given: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    A_send = A_send_from_conveyance(given)
    b_scan = Scalar.from_bytes_checked(bytes.fromhex(given["key_material"]["scan_priv_key"]))
    b_spend = Scalar.from_bytes_checked(bytes.fromhex(given["key_material"]["spend_priv_key"]))
    if "height" in given:
        ih = input_hash_coinbase(given["height"], A_send)
    else:
        ih = input_hash_ordinary(lowest_outpoint_from_vin(given["vin"]), A_send)
    outputs_xonly = [bytes.fromhex(o) for o in given["outputs"]]
    found, info = scan_outputs(b_scan, b_spend * G, A_send, ih, outputs_xonly)
    return info, sign_found(b_spend, found)
