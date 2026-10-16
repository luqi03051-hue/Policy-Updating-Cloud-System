# -*- coding: utf-8 -*-
"""Lambda handler against a mocked S3 bucket (moto). Skipped if moto is not installed."""

import importlib
import json

import pytest

moto = pytest.importorskip("moto")


@pytest.fixture()
def s3_env(monkeypatch, system):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with moto.mock_aws():
        import boto3
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="abe-demo")
        import app
        importlib.reload(app)
        app._s3 = client
        yield client, app


def _event(bucket, key):
    return {"Records": [{"s3": {"bucket": {"name": bucket}, "object": {"key": key}}}]}


@pytest.mark.parametrize("prefix", ["", "tenant1"])
def test_s3_triggered_ctupdate(system, tmp_path, s3_env, prefix):
    client, app = s3_env
    from client_decrypt import client_decrypt
    from object_store import MPK_KEY, FileStore, S3Store
    from owner_encrypt import owner_encrypt
    from owner_upkeygen import owner_upkeygen

    store = S3Store("abe-demo", prefix, client=client)
    store.put_json(MPK_KEY, system["mpk_blob"])
    secrets = FileStore(str(tmp_path / "owner_secrets"))

    oid = owner_encrypt(system["mpk_blob"], store, secrets, b"from s3", "(attA OR (attB AND attC))")["object_id"]
    info = owner_upkeygen(system["mpk_blob"], store, secrets, oid, "(attA OR (2, attB, attC, attD))")
    full_key = f"{prefix}/{info['update_key']}" if prefix else info["update_key"]

    out = app.handler(_event("abe-demo", full_key), None)
    assert out["status"] == "ok", out
    assert out["results"][0]["new_version"] == 2

    sk = system["user_key"]("attB", "attD")
    assert client_decrypt(system["mpk_blob"], store, sk, oid) == b"from s3"

    # duplicate delivery of the same event: no-op
    again = app.handler(_event("abe-demo", full_key), None)
    assert again["results"][0]["status"] == "skipped"

    # nothing secret in the bucket
    keys = [o["Key"] for o in client.list_objects_v2(Bucket="abe-demo").get("Contents", [])]
    blob = "".join(client.get_object(Bucket="abe-demo", Key=k)["Body"].read().decode() for k in keys)
    assert '"msk"' not in blob and "E_T" not in blob and "_debug" not in blob


def test_non_update_keys_are_ignored(s3_env):
    _client, app = s3_env
    out = app.handler(_event("abe-demo", "objects/x/v1.json"), None)
    assert out["status"] == "ok" and "skipped" in out["results"][0]
