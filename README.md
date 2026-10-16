# PU-CP-ABE: IoT-Cloud Data Sharing with Efficient Policy Updating

Proof-of-concept of *"IoT-Cloud Data Sharing and Access Control System With Efficient Policy Updating"*
(paper in `paper/`), deployed with AWS S3 + Lambda.

* **Hybrid encryption** — AES-256-GCM encrypts the data; the PU-CP-ABE scheme encapsulates the data key.
* **Policy updating without re-encryption** — the owner sends a constant-size update key; the cloud
  rewrites only the affected subtree ciphertext. `C_AES` is never touched.
* **Role separation as in the paper** — the cloud (Lambda) runs only `CTUpdate` and never sees
  `msk`, `E_T`, user keys, data keys or plaintext.

## Roles and scripts

| Role | Paper algorithms | Script | Holds |
|---|---|---|---|
| Authority (local) | Setup, KeyGen | `crypto/ta_local.py` | `msk.json` |
| Data owner (local) | Enc, UPKeyGen | `crypto/owner_encrypt.py`, `crypto/owner_upkeygen.py` | plaintext, `owner_secrets/…/E_T_v<N>.json` |
| Cloud (AWS Lambda) | CTUpdate | `crypto/app.py` → `crypto/cloud_update.py` | `mpk`, ciphertexts, update keys |
| Data user (local) | Dec | `crypto/client_decrypt.py` | own key file |

Shared code: `crypto/abe_core.py` (scheme), `crypto/hybrid.py` (KDF + AES-GCM),
`crypto/object_store.py` (local directory or S3 with the same key layout).

## Quick start

```bash
# Docker (builds the Lambda image and runs every role in its own container)
bash examples/demo.sh

# or without Docker, if PBC + charm-crypto are installed locally
RUNNER=local bash examples/demo.sh
```

The demo encrypts under `(attA OR (attB AND attC))`, then performs one update of each supported type:

| Step | Policy | alice {A} | carol {B,C} | bob {B,D} |
|---|---|---|---|---|
| v1 | `(attA OR (attB AND attC))` | ✓ | ✓ | ✗ |
| v2 — Attributes2Existing on T1 | `(attA OR (2, attB, attC, attD))` | ✓ | ✓ | ✓ |
| v3 — Attributes2New on Tr | `((2, attA, attD, attE) OR (2, attB, attC, attD))` | ✗ | ✓ | ✓ |

## Manual workflow

```bash
cd crypto
# Authority
python ta_local.py setup  --universe attA,attB,attC,attD,attE --mpk-out ../keys/mpk.json \
                          --msk-out ../keys/authority/msk.json --publish ../store
python ta_local.py keygen --mpk ../keys/mpk.json --msk ../keys/authority/msk.json \
                          --attrs attB,attD --out ../keys/users/bob.json
# Data owner
python owner_encrypt.py   --store ../store --secrets-dir ../owner_secrets \
                          --policy "(attA OR (attB AND attC))" --plaintext "hello world"
python owner_upkeygen.py  --store ../store --secrets-dir ../owner_secrets --object-id <ID> \
                          --new-policy "(attA OR (2, attB, attC, attD))"
# Cloud (in AWS this is the Lambda, triggered by the upload of the update key)
python cloud_update.py    --store ../store --object-id <ID>
# Data user
python client_decrypt.py  --store ../store --sk ../keys/users/bob.json --object-id <ID>
```

`--store` also accepts `s3://bucket[/prefix]`. Exit codes of `client_decrypt.py`: 0 ok, 3 access
denied, 4 integrity failure, 2 other errors.

Supported updates: **Attributes2Existing** and **Attributes2New** (one gate per update key, detected
automatically from the new policy). Root-gate updates (RootEtOR/RootEtAND/RootEtThreshold) are not
implemented.

## Tests

```bash
pip install -r requirements-dev.txt
pytest                   # 47 tests: scheme, security regressions, updates, Lambda (moto), CLI
python tests/bench_local.py --ell 20
```

Tests are skipped automatically when charm-crypto is not installed; inside the image:
`docker run --rm --entrypoint /bin/bash abe-lambda:poc2 -lc "cd /var/task && python -m pytest -q tests"`.

## Documentation

* `docs/CHANGES.md` — what changed relative to the earlier PoC and why (中文)
* `docs/algorithm_overview.md` — paper algorithms ↔ code, data formats
* `docs/security_model.md` — trust model, IND-sCPA game, implementation-level guarantees
* `docs/deployment.md` — ECR / Lambda / S3 trigger / IAM

## Layout

```
crypto/            abe_core.py hybrid.py object_store.py
                   ta_local.py owner_encrypt.py owner_upkeygen.py cloud_update.py client_decrypt.py app.py
tests/             conftest.py test_core.py test_security.py test_policy_update.py test_lambda.py test_cli.py bench_local.py
docker/Dockerfile  Lambda image (Python 3.10 + GMP + PBC + charm v0.63)
examples/demo.sh   end-to-end demo (Docker or local)
docs/              see above
paper/             the paper
event.json         sample S3 event for the Lambda console
```

Runtime data (`keys/`, `owner_secrets/`, `store/`, `demo_data/`) is git-ignored; never commit it.
