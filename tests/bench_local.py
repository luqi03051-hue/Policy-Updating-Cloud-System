# -*- coding: utf-8 -*-
"""
bench_local.py — rough timings for the paper's experiment axes (not a pytest file).

  python tests/bench_local.py [--ell 20] [--reps 5]

Prints:
  1. hybrid encrypt time vs file size (ABE cost is constant, AES grows)
  2. Enc / Dec time vs number of attributes in an n-of-n AND policy
  3. UPKeyGen + CTUpdate time vs number of attributes (Attributes2Existing, add one attribute)
"""

import argparse
import os
import statistics
import sys
import time
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "crypto"))
warnings.filterwarnings("ignore")

from charm.toolbox.pairinggroup import GT  # noqa: E402

from abe_core import CTUpdate, UPKeyGen, build_abe  # noqa: E402
from hybrid import aes_gcm_encrypt, kdf_from_gt  # noqa: E402


def ms(fn, reps):
    out = []
    for _ in range(reps):
        t = time.perf_counter()
        r = fn()
        out.append((time.perf_counter() - t) * 1000)
    return statistics.median(out), r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ell", type=int, default=20)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--curve", default="SS512")
    a = ap.parse_args()

    universe = [f"att{i}" for i in range(1, a.ell + 1)]
    group, abe = build_abe(a.curve, a.ell)
    mpk, msk = abe.setup(universe)

    print(f"curve={a.curve} ell={a.ell} reps={a.reps} (median ms)\n")
    print("1) hybrid encrypt vs file size (policy: att1 AND att2)")
    for size in [1 << 10, 100 << 10, 1 << 20, 10 << 20]:
        data = os.urandom(size)

        def enc():
            K = group.random(GT)
            aes_gcm_encrypt(data, kdf_from_gt(group, K), b"oid")
            return abe.encrypt(K, mpk, "att1 AND att2")
        t, _ = ms(enc, a.reps)
        print(f"   {size >> 10:>6} KB : {t:8.1f}")

    print("\n2) Enc / Dec vs attributes in policy (n-of-n AND)")
    for n in [2, 5, 10, min(15, a.ell - 1)]:
        attrs = universe[:n]
        policy = " AND ".join(attrs)
        sk = abe.keygen(msk, mpk, attrs)
        K = group.random(GT)
        t_enc, (CT, _E) = ms(lambda: abe.encrypt(K, mpk, policy), a.reps)
        t_dec, _ = ms(lambda: abe.decrypt(mpk, sk, CT), a.reps)
        print(f"   n={n:>2} : enc {t_enc:7.1f}   dec {t_dec:7.1f}")

    print("\n3) UPKeyGen + CTUpdate vs attributes (add one attribute, Attributes2Existing)")
    for n in [2, 5, 10, min(15, a.ell - 1)]:
        old = "(" + ", ".join([f"{n}"] + universe[:n]) + ")"
        new = "(" + ", ".join([f"{n}"] + universe[: n + 1]) + ")"
        CT, E_T = abe.encrypt(group.random(GT), mpk, old)
        t_up, (tk, _E2) = ms(lambda: UPKeyGen(abe, mpk, E_T, CT["tree"], new), a.reps)
        t_ct, _ = ms(lambda: CTUpdate(CT, tk), a.reps)
        print(f"   n={n:>2} : UPKeyGen {t_up:7.1f}   CTUpdate {t_ct:7.1f}")


if __name__ == "__main__":
    main()
