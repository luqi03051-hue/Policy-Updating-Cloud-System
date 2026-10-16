# -*- coding: utf-8 -*-
"""Owner UPKeyGen -> cloud CTUpdate -> user decrypt, through the real role functions."""

import pytest


def _enc(system, cloud, policy, data=b"hello world"):
    from owner_encrypt import owner_encrypt
    return owner_encrypt(system["mpk_blob"], cloud["store"], cloud["secrets"], data, policy)["object_id"]


def _update(system, cloud, oid, new_policy, keep_history=False, **kw):
    from cloud_update import apply_update
    from owner_upkeygen import owner_upkeygen
    info = owner_upkeygen(system["mpk_blob"], cloud["store"], cloud["secrets"], oid, new_policy, **kw)
    res = apply_update(cloud["store"], oid, keep_history=keep_history)
    return info, res


def _can(system, cloud, oid, *attrs, version=None):
    from client_decrypt import client_decrypt
    try:
        return client_decrypt(system["mpk_blob"], cloud["store"], system["user_key"](*attrs), oid, version)
    except PermissionError:
        return None


def test_attributes2existing(system, cloud):
    oid = _enc(system, cloud, "(attA OR (attB AND attC))")
    assert _can(system, cloud, oid, "attB", "attD") is None
    c_aes_v1 = cloud["store"].get_record(oid)["c_aes"]

    info, res = _update(system, cloud, oid, "(attA OR (2, attB, attC, attD))", mode="Attributes2Existing")
    assert (info["mode"], info["target_subtree"], res["new_version"]) == ("Attributes2Existing", "T1", 2)
    assert _can(system, cloud, oid, "attB", "attD") == b"hello world"
    assert _can(system, cloud, oid, "attA") == b"hello world"
    assert _can(system, cloud, oid, "attB") is None
    assert cloud["store"].get_record(oid)["c_aes"] == c_aes_v1  # no data re-encryption


def test_attributes2new(system, cloud):
    # paper Fig. 4: attA is replaced by a new (2, attA, attD, attE) gate
    oid = _enc(system, cloud, "(attA OR (attB AND attC))")
    info, _ = _update(system, cloud, oid, "((2, attA, attD, attE) OR (attB AND attC))", mode="Attributes2New")
    assert (info["mode"], info["target_subtree"], info["new_subtree"]) == ("Attributes2New", "Tr", "T2")
    assert _can(system, cloud, oid, "attA") is None
    assert _can(system, cloud, oid, "attA", "attE") == b"hello world"
    assert _can(system, cloud, oid, "attB", "attC") == b"hello world"
    # the new subtree's s_t is in the owner's E_T for v2
    E_T2 = cloud["secrets"].get_json(f"{oid}/E_T_v2.json")["E_T"]
    assert set(E_T2) == {"Tr", "T1", "T2"}


def test_threshold_change_on_gate_with_gate_children(system, cloud):
    oid = _enc(system, cloud, "(1, attA, (attC AND attD))")
    info, _ = _update(system, cloud, oid, "(2, attA, attB, (attC AND attD))")
    assert info["reissued_child_components"] == ["T1"]
    assert _can(system, cloud, oid, "attA") is None
    assert _can(system, cloud, oid, "attA", "attC", "attD") == b"hello world"
    assert _can(system, cloud, oid, "attA", "attB") == b"hello world"


def test_chained_updates(system, cloud):
    oid = _enc(system, cloud, "(attA OR (attB AND attC))")
    _update(system, cloud, oid, "((2, attA, attD, attE) OR (attB AND attC))")
    _update(system, cloud, oid, "((3, attA, attD, attE) OR (attB AND attC))")
    _, res = _update(system, cloud, oid, "((3, attA, attD, attE) OR (attB AND attC AND attF))")
    assert res["new_version"] == 4
    assert _can(system, cloud, oid, "attA", "attE") is None
    assert _can(system, cloud, oid, "attA", "attD", "attE") == b"hello world"
    assert _can(system, cloud, oid, "attB", "attC") is None
    assert _can(system, cloud, oid, "attB", "attC", "attF") == b"hello world"


def test_old_version_replaced_by_default(system, cloud):
    from object_store import record_key, update_key_key
    oid = _enc(system, cloud, "(attA OR (attB AND attC))")
    _update(system, cloud, oid, "((attA AND attG) OR (attB AND attC))")  # tighten: attA alone no longer enough
    assert not cloud["store"].exists(record_key(oid, 1))
    assert not cloud["store"].exists(update_key_key(oid, 1))
    assert _can(system, cloud, oid, "attA") is None  # tightened policy really applies


def test_keep_history_option(system, cloud):
    oid = _enc(system, cloud, "(attA OR (attB AND attC))")
    _update(system, cloud, oid, "(attA OR (2, attB, attC, attD))", keep_history=True)
    assert _can(system, cloud, oid, "attB", "attD", version=1) is None
    assert _can(system, cloud, oid, "attB", "attD", version=2) == b"hello world"


def test_duplicate_event_is_noop(system, cloud):
    from cloud_update import apply_update
    oid = _enc(system, cloud, "(attA OR (attB AND attC))")
    _update(system, cloud, oid, "(attA OR (2, attB, attC, attD))")
    assert apply_update(cloud["store"], oid, base_version=1)["status"] == "skipped"


def test_pending_update_key_needs_force(system, cloud):
    from owner_upkeygen import owner_upkeygen
    oid = _enc(system, cloud, "(attA OR (attB AND attC))")
    args = (system["mpk_blob"], cloud["store"], cloud["secrets"], oid, "(attA OR (2, attB, attC, attD))")
    owner_upkeygen(*args)
    with pytest.raises(FileExistsError):
        owner_upkeygen(*args)
    owner_upkeygen(*args, force=True)


@pytest.mark.parametrize("new_policy,msg", [
    ("(attA OR (attB AND attC))", "nothing to update"),
    ("(attA OR attB)", "more than one gate"),                                   # removes a gate
    ("((attA OR (attB AND attC)) AND attD)", "Root-gate"),                      # RootEtAND
    ("((2, attA, attD) OR (attB AND attC AND attE))", "more than one gate"),    # two gates at once
    ("(attA OR (attB AND attC) OR ((attD OR attE) AND attF))", "nested gates"),
])
def test_unsupported_updates_rejected(system, cloud, new_policy, msg):
    from owner_upkeygen import owner_upkeygen
    oid = _enc(system, cloud, "(attA OR (attB AND attC))")
    with pytest.raises(ValueError, match=msg):
        owner_upkeygen(system["mpk_blob"], cloud["store"], cloud["secrets"], oid, new_policy)


def test_mode_assertion(system, cloud):
    from owner_upkeygen import owner_upkeygen
    oid = _enc(system, cloud, "(attA OR (attB AND attC))")
    with pytest.raises(ValueError, match="Detected update mode"):
        owner_upkeygen(system["mpk_blob"], cloud["store"], cloud["secrets"], oid,
                       "(attA OR (2, attB, attC, attD))", mode="Attributes2New")
