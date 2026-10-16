# -*- coding: utf-8 -*-
"""
ta_local.py — Authority (runs locally, fully trusted)

  setup  : Setup(λ, U) -> mpk.json (public) + msk.json (Authority only)
  keygen : KeyGen(mpk, msk, A) -> user secret key file (hand to the user out-of-band)

Examples
  python ta_local.py setup --universe attA,attB,attC,attD,attE \
      --mpk-out keys/mpk.json --msk-out keys/authority/msk.json [--publish store/]
  python ta_local.py keygen --mpk keys/mpk.json --msk keys/authority/msk.json \
      --attrs attA,attB --out keys/users/alice.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from abe_core import (build_abe, deserialize_any, load_json, save_json, serialize_any)
from object_store import MPK_KEY, make_store


def cmd_setup(args: argparse.Namespace) -> None:
    universe = [a.strip() for a in args.universe.split(",") if a.strip()]
    ell = args.ell or len(universe)
    group, abe = build_abe(args.curve, ell)
    mpk, msk = abe.setup(universe)

    mpk_blob = {"curve": args.curve, "ell": ell, "mpk": serialize_any(group, mpk)}
    save_json(args.mpk_out, mpk_blob)
    save_json(args.msk_out, {"curve": args.curve, "ell": ell, "msk": serialize_any(group, msk)})
    try:
        os.chmod(args.msk_out, 0o600)
    except OSError:
        pass

    if args.publish:
        make_store(args.publish).put_json(MPK_KEY, mpk_blob)

    print(json.dumps({
        "role": "authority", "op": "setup", "curve": args.curve, "ell": ell,
        "universe": universe, "mpk": args.mpk_out, "msk": args.msk_out,
        "published_to": args.publish or None,
    }, ensure_ascii=False))


def cmd_keygen(args: argparse.Namespace) -> None:
    mpk_blob = load_json(args.mpk)
    msk_blob = load_json(args.msk)
    if (mpk_blob["curve"], mpk_blob["ell"]) != (msk_blob["curve"], msk_blob["ell"]):
        raise SystemExit("mpk.json and msk.json come from different Setup runs.")
    group, abe = build_abe(mpk_blob["curve"], int(mpk_blob["ell"]))
    mpk = deserialize_any(group, mpk_blob["mpk"])
    msk = deserialize_any(group, msk_blob["msk"])

    attrs = [a.strip() for a in args.attrs.split(",") if a.strip()]
    sk = abe.keygen(msk, mpk, attrs)
    save_json(args.out, {"curve": mpk_blob["curve"], "ell": mpk_blob["ell"],
                         "attrs": sk["attrs"], "sk": serialize_any(group, sk)})
    try:
        os.chmod(args.out, 0o600)
    except OSError:
        pass
    print(json.dumps({"role": "authority", "op": "keygen", "attrs": sk["attrs"], "out": args.out}))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Authority: Setup / KeyGen")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("setup", help="Setup(λ, U) -> mpk, msk")
    s.add_argument("--universe", required=True, help="Comma-separated attribute universe U, e.g. attA,attB,attC")
    s.add_argument("--ell", type=int, default=0, help="ℓ (>= |U|; default |U|). Larger ℓ reserves no names.")
    s.add_argument("--curve", default="SS512")
    s.add_argument("--mpk-out", default="keys/mpk.json")
    s.add_argument("--msk-out", default="keys/authority/msk.json")
    s.add_argument("--publish", default="", help="Also write mpk to this store (dir or s3://bucket/prefix)")
    s.set_defaults(func=cmd_setup)

    k = sub.add_parser("keygen", help="KeyGen(mpk, msk, A) -> sk_A")
    k.add_argument("--mpk", default="keys/mpk.json")
    k.add_argument("--msk", default="keys/authority/msk.json")
    k.add_argument("--attrs", required=True, help="User attribute set A, e.g. attA,attB")
    k.add_argument("--out", required=True)
    k.set_defaults(func=cmd_keygen)

    args = ap.parse_args(argv)
    try:
        args.func(args)
    except (ValueError, KeyError, FileNotFoundError) as e:
        print(f"[authority] error: {e}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
