# -*- coding: utf-8 -*-
"""
Shared fixtures. Tests need Charm-Crypto + PBC; they are skipped automatically if charm is missing
(run them inside the Docker image, or after installing PBC + charm locally).
"""

import os
import sys
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CRYPTO = ROOT / "crypto"
if str(CRYPTO) not in sys.path:
    sys.path.insert(0, str(CRYPTO))

warnings.filterwarnings("ignore", message=".*SS512.*")

try:
    import charm  # noqa: F401
    HAS_CHARM = True
except Exception:
    HAS_CHARM = False


def pytest_collection_modifyitems(config, items):
    if HAS_CHARM:
        return
    skip = pytest.mark.skip(reason="charm-crypto not installed (run inside the Docker image)")
    for item in items:
        item.add_marker(skip)


UNIVERSE = ["attA", "attB", "attC", "attD", "attE", "attF", "attG"]


@pytest.fixture(scope="session")
def system(tmp_path_factory):
    """Authority setup once per session: returns mpk blob, msk blob and a key factory."""
    from abe_core import build_abe, serialize_any

    group, abe = build_abe("SS512", len(UNIVERSE))
    mpk, msk = abe.setup(UNIVERSE)
    mpk_blob = {"curve": "SS512", "ell": len(UNIVERSE), "mpk": serialize_any(group, mpk)}
    msk_blob = {"curve": "SS512", "ell": len(UNIVERSE), "msk": serialize_any(group, msk)}
    keydir = tmp_path_factory.mktemp("users")
    cache = {}

    def user_key(*attrs):
        """Return path of a sk.json for this attribute set (cached)."""
        from abe_core import save_json
        name = "_".join(sorted(attrs)) or "none"
        if name not in cache:
            sk = abe.keygen(msk, mpk, list(attrs))
            path = keydir / f"{name}.json"
            save_json(str(path), {"curve": "SS512", "ell": len(UNIVERSE), "attrs": sk["attrs"],
                                  "sk": serialize_any(group, sk)})
            cache[name] = str(path)
        return cache[name]

    return {"group": group, "abe": abe, "mpk": mpk, "msk": msk,
            "mpk_blob": mpk_blob, "msk_blob": msk_blob, "user_key": user_key}


@pytest.fixture()
def cloud(tmp_path, system):
    """A fresh cloud store (local dir) with mpk published, plus the owner's secrets dir."""
    from object_store import MPK_KEY, FileStore
    store = FileStore(str(tmp_path / "store"))
    store.put_json(MPK_KEY, system["mpk_blob"])
    secrets = FileStore(str(tmp_path / "owner_secrets"))
    return {"store": store, "secrets": secrets, "root": tmp_path}
