# -*- coding: utf-8 -*-
"""The command-line tools, run as separate processes like in demo.sh."""

import json
import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
# Source tree: scripts live in crypto/. Docker image: they are copied flat into /var/task.
CRYPTO = _ROOT / "crypto" if (_ROOT / "crypto").is_dir() else _ROOT


def run(*args, ok=True):
    p = subprocess.run([sys.executable, *args], cwd=CRYPTO, capture_output=True, text=True,
                       env={**os.environ, "PYTHONWARNINGS": "ignore"})  # keep PYTHONPATH (charm in the image)
    if ok:
        assert p.returncode == 0, p.stderr
    return p


def test_cli_roundtrip(tmp_path):
    keys, store, sec = tmp_path / "keys", tmp_path / "store", tmp_path / "owner_secrets"
    run("ta_local.py", "setup", "--universe", "attA,attB,attC,attD", "--mpk-out", f"{keys}/mpk.json",
        "--msk-out", f"{keys}/authority/msk.json", "--publish", str(store))
    assert "msk" not in json.loads((store / "config" / "mpk.json").read_text())
    run("ta_local.py", "keygen", "--mpk", f"{keys}/mpk.json", "--msk", f"{keys}/authority/msk.json",
        "--attrs", "attB,attD", "--out", f"{keys}/users/bd.json")

    out = run("owner_encrypt.py", "--store", str(store), "--secrets-dir", str(sec),
              "--policy", "(attA OR (attB AND attC))", "--plaintext", "hello world").stdout
    oid = json.loads(out)["object_id"]

    denied = run("client_decrypt.py", "--store", str(store), "--sk", f"{keys}/users/bd.json",
                 "--object-id", oid, ok=False)
    assert denied.returncode == 3

    run("owner_upkeygen.py", "--store", str(store), "--secrets-dir", str(sec), "--object-id", oid,
        "--new-policy", "(attA OR (2, attB, attC, attD))", "--mode", "Attributes2Existing")
    res = json.loads(run("cloud_update.py", "--store", str(store), "--object-id", oid).stdout)
    assert res["new_version"] == 2

    pt = run("client_decrypt.py", "--store", str(store), "--sk", f"{keys}/users/bd.json", "--object-id", oid).stdout
    assert pt.strip() == "hello world"
