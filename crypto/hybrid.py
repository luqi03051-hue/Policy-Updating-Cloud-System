# -*- coding: utf-8 -*-
"""
hybrid.py — KEM/DEM glue: the ABE scheme encapsulates a random GT element K,
AES-256-GCM encrypts the actual data under DEK = SHA-256(serialize(K)).
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from abe_core import b64d, b64e


def kdf_from_gt(group: Any, K_gt: Any) -> bytes:
    return hashlib.sha256(group.serialize(K_gt)).digest()


def aes_gcm_encrypt(plaintext: bytes, key32: bytes, aad: bytes) -> Dict[str, str]:
    nonce = os.urandom(12)
    ct = AESGCM(key32).encrypt(nonce, plaintext, aad)
    return {"alg": "AES-256-GCM", "nonce_b64": b64e(nonce), "ct_b64": b64e(ct)}


def aes_gcm_decrypt(blob: Dict[str, str], key32: bytes, aad: bytes) -> bytes:
    return AESGCM(key32).decrypt(b64d(blob["nonce_b64"]), b64d(blob["ct_b64"]), aad)
