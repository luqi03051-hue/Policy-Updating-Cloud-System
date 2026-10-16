# -*- coding: utf-8 -*-
"""
Regression tests for the security problems found in the previous PoC:
  1. ciphertext carried E_T (s_r)            -> plaintext recoverable from mpk + record
  2. user key carried α (master secret)
  3. user key covered every attribute index -> any user could claim any attributes
  4. ρ derived per policy                    -> same name mapped to different indices
  5. msk shipped together with mpk to the cloud
"""

import json
from pathlib import Path

import pytest


def _all_text(root: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in root.rglob("*.json"))


def _charm_strings(obj):
    """All base64 group-element encodings inside a serialized blob."""
    if isinstance(obj, dict):
        if "__charm__" in obj:
            yield obj["__charm__"]
        else:
            for v in obj.values():
                yield from _charm_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _charm_strings(v)


def test_cloud_store_contains_no_E_T(system, cloud):
    from owner_encrypt import owner_encrypt
    from owner_upkeygen import owner_upkeygen
    from cloud_update import apply_update

    res = owner_encrypt(system["mpk_blob"], cloud["store"], cloud["secrets"], b"m", "(attA OR (attB AND attC))")
    oid = res["object_id"]
    owner_upkeygen(system["mpk_blob"], cloud["store"], cloud["secrets"], oid,
                   "((2, attA, attD, attE) OR (attB AND attC))")
    # inspect the cloud *before* CTUpdate (record v1 + tk) and after (v2)
    before = _all_text(cloud["root"] / "store")
    apply_update(cloud["store"], oid)
    after = _all_text(cloud["root"] / "store")

    secrets = [json.loads(p.read_text()) for p in (cloud["root"] / "owner_secrets").rglob("*.json")]
    assert len(secrets) == 2
    for s in secrets:
        for elem in _charm_strings(s["E_T"]):
            assert elem not in before and elem not in after, "an s_j value leaked into the cloud store"
    assert "_debug" not in before + after and "s_map" not in before + after


def test_plaintext_not_recoverable_from_public_data(system, cloud):
    """The old attack: K = C0 / Z^{s_r} needs s_r, which must no longer be anywhere public."""
    from abe_core import deserialize_any
    from owner_encrypt import owner_encrypt

    res = owner_encrypt(system["mpk_blob"], cloud["store"], cloud["secrets"], b"m", "(attB AND attC)")
    rec = cloud["store"].get_record(res["object_id"])
    CT = deserialize_any(system["group"], rec["ct_abe"])

    def scalars(o):
        if isinstance(o, dict):
            for v in o.values():
                yield from scalars(v)
        elif hasattr(o, "type") and str(o.type) in ("0", "ZR"):
            yield o
    assert list(scalars(CT)) == []  # no Z_p elements at all in the ciphertext


def test_user_key_has_no_master_secret(system):
    sk_blob = json.loads(Path(system["user_key"]("attA")).read_text())
    assert "_meta" not in json.dumps(sk_blob)
    msk_elems = set(_charm_strings(system["msk_blob"]["msk"]))
    assert msk_elems.isdisjoint(set(_charm_strings(sk_blob)))


def test_user_key_covers_only_A_and_defaults(system):
    from abe_core import load_user_key
    ell = system["abe"].ell
    sk = load_user_key(system["user_key"]("attA", "attC"), system["group"])
    real = sorted(int(i) for i in sk["k"] if int(i) <= ell)
    rho = system["mpk"]["rho"]
    assert real == sorted([rho["attA"], rho["attC"]])
    for i, comp in sk["k"].items():
        assert i not in comp["c"], "sk_t must not contain h_t^{r q(t)}"


def test_cannot_claim_attributes_not_in_key(system, cloud):
    """Previously: --attrs attB,attC with a key for attA decrypted (attB AND attC)."""
    from client_decrypt import client_decrypt
    from owner_encrypt import owner_encrypt

    res = owner_encrypt(system["mpk_blob"], cloud["store"], cloud["secrets"], b"only B and C",
                        "(attB AND attC)")
    sk_A = system["user_key"]("attA")
    # tamper the key file's attribute list: the components for B and C simply do not exist
    forged = json.loads(Path(sk_A).read_text())
    forged["sk"]["attrs"] = ["attA", "attB", "attC"]
    forged_path = cloud["root"] / "forged.json"
    forged_path.write_text(json.dumps(forged))
    for path in (sk_A, str(forged_path)):
        with pytest.raises((PermissionError, ValueError)):
            client_decrypt(system["mpk_blob"], cloud["store"], path, res["object_id"])


def test_rho_is_global(system, cloud):
    """One key works across differently shaped policies (ρ no longer depends on the policy)."""
    from client_decrypt import client_decrypt
    from owner_encrypt import owner_encrypt

    sk = system["user_key"]("attC")
    for pol in ["attC", "(attA OR attC)", "((attA AND attB) OR (1, attG, attC))", "(attF OR attE OR attC)"]:
        res = owner_encrypt(system["mpk_blob"], cloud["store"], cloud["secrets"], pol.encode(), pol)
        assert client_decrypt(system["mpk_blob"], cloud["store"], sk, res["object_id"]) == pol.encode()


def test_non_authority_roles_refuse_msk(system):
    from abe_core import load_public
    with pytest.raises(ValueError):
        load_public({**system["mpk_blob"], **system["msk_blob"]})


def test_tampered_c_aes_detected(system, cloud):
    from cryptography.exceptions import InvalidTag
    from client_decrypt import client_decrypt
    from object_store import record_key
    from owner_encrypt import owner_encrypt

    res = owner_encrypt(system["mpk_blob"], cloud["store"], cloud["secrets"], b"payload", "attA")
    key = record_key(res["object_id"], 1)
    rec = cloud["store"].get_json(key)
    ct = bytearray(__import__("base64").b64decode(rec["c_aes"]["ct_b64"]))
    ct[0] ^= 1
    rec["c_aes"]["ct_b64"] = __import__("base64").b64encode(bytes(ct)).decode()
    cloud["store"].put_json(key, rec)
    with pytest.raises(InvalidTag):
        client_decrypt(system["mpk_blob"], cloud["store"], system["user_key"]("attA"), res["object_id"])
