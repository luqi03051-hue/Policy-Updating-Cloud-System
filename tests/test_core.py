# -*- coding: utf-8 -*-
"""Scheme correctness: Enc/Dec over AND / OR / threshold / nested trees."""

import pytest

POLICIES = [
    # policy, attribute set, should decrypt
    ("(attA OR (attB AND attC))", ["attA"], True),
    ("(attA OR (attB AND attC))", ["attB", "attC"], True),
    ("(attA OR (attB AND attC))", ["attB"], False),
    ("attA", ["attA"], True),                       # single attribute (was broken before)
    ("attA", ["attB"], False),
    ("attA OR attB OR attC", ["attC"], True),       # flattened 1-of-3
    ("attA AND attB AND attC", ["attA", "attB"], False),
    ("attA AND attB AND attC", ["attA", "attB", "attC"], True),
    ("(2, attA, attB, attC, attD)", ["attA", "attD"], True),
    ("(2, attA, attB, attC, attD)", ["attB"], False),
    # paper Fig. 2: (attA OR (2, (attD, (attB AND attC), (2, attE, attF, attG))))
    ("(attA OR (2, attD, (attB AND attC), (2, attE, attF, attG)))", ["attC", "attD", "attE", "attF"], True),
    ("(attA OR (2, attD, (attB AND attC), (2, attE, attF, attG)))", ["attD", "attE"], False),
    ("(attA OR (2, attD, (attB AND attC), (2, attE, attF, attG)))", ["attB", "attC", "attF", "attG"], True),
]


@pytest.mark.parametrize("policy,attrs,expected", POLICIES)
def test_enc_dec_matrix(system, policy, attrs, expected):
    from abe_core import load_user_key
    from charm.toolbox.pairinggroup import GT

    group, abe, mpk = system["group"], system["abe"], system["mpk"]
    sk = load_user_key(system["user_key"](*attrs), group)
    M = group.random(GT)
    CT, E_T = abe.encrypt(M, mpk, policy)
    if expected:
        assert abe.decrypt(mpk, sk, CT) == M
    else:
        with pytest.raises(PermissionError):
            abe.decrypt(mpk, sk, CT)


def test_encrypt_returns_E_T_separately(system):
    from charm.toolbox.pairinggroup import GT
    group, abe, mpk = system["group"], system["abe"], system["mpk"]
    CT, E_T = abe.encrypt(group.random(GT), mpk, "(attA OR (attB AND attC))")
    assert set(E_T) == {"Tr", "T1"}
    assert set(CT) == {"scheme", "ell", "policy", "tree", "C0", "ct_T"}


@pytest.mark.parametrize("bad", ["", "attZ", "(attA OR", "(3, attA, attB)", "attA - attB", "(attA AND attA)"])
def test_invalid_policies_rejected(system, bad):
    from charm.toolbox.pairinggroup import GT
    group, abe, mpk = system["group"], system["abe"], system["mpk"]
    with pytest.raises(ValueError):
        abe.encrypt(group.random(GT), mpk, bad)


def test_keygen_rejects_unknown_attribute(system):
    with pytest.raises(ValueError):
        system["abe"].keygen(system["msk"], system["mpk"], ["attA", "notInUniverse"])
