# Deployment Guide — PU-CP-ABE on AWS Lambda (Docker)

## 1. Who runs what

The deployment follows the paper's system model (Sec. II-A / III-A):

```
 Authority (local)            Data owner (local)                 Cloud (AWS)                        Data user (local)
 ─────────────────            ───────────────────                ─────────────                      ─────────────────
 Setup  -> mpk, msk           Enc(M) -> C_AES, CT_ABE, E_T        S3: config/ objects/ updates/       Dec with sk_A
 KeyGen -> sk_A  ──out-of-band──────────────────────────────────────────────────────────────────────▶ (sk_A)
 mpk ──────────────▶ s3://bucket/config/mpk.json
                              upload v1 ─────────────────────▶   objects/<id>/v1.json  ◀── download ── user
                              keep E_T locally
                              UPKeyGen(E_T) -> tk
                              upload tk ─────────────────────▶   updates/<id>/tk_v1.json
                                                                   │ S3 ObjectCreated
                                                                   ▼
                                                                 Lambda app.handler: CTUpdate
                                                                   → objects/<id>/v2.json (C_AES unchanged)
                                                                   → deletes v1 + tk_v1
```

The cloud is honest-but-curious: it only ever holds mpk, ciphertexts and update keys.
`msk`, `E_T`, user keys, DEKs and plaintext never reach AWS.

## 2. Why a container image

Pairing operations come from PBC (C, needs GMP) wrapped by charm-crypto. Both must be compiled for
the Lambda runtime, so the function ships as a container image (`docker/Dockerfile`). The image also
pins OpenSSL 1.1 for charm's extension (see comments in the Dockerfile).

Cold start: ~5–6 s for the first invocation after idle (image pull); warm invocations of CTUpdate take
tens of milliseconds. Use Provisioned Concurrency if update latency matters.

## 3. Build and push

```bash
# from the project root
docker build -f docker/Dockerfile -t abe-lambda:poc2 .

aws ecr create-repository --repository-name abe-lambda
aws ecr get-login-password | docker login --username AWS --password-stdin <ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com
docker tag abe-lambda:poc2 <ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/abe-lambda:poc2
docker push <ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/abe-lambda:poc2
```

## 4. Create the Lambda function

* Package type: **Image**, the URI above; handler is the image CMD `app.handler`.
* Memory 512–1024 MB, timeout 30 s.
* Environment: `KEEP_HISTORY=0` (default; set `1` only for demos — old versions stay readable under the old policy).

Execution role (least privilege, replace `BUCKET`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["s3:GetObject"],
     "Resource": ["arn:aws:s3:::BUCKET/config/*", "arn:aws:s3:::BUCKET/objects/*", "arn:aws:s3:::BUCKET/updates/*"]},
    {"Effect": "Allow", "Action": ["s3:PutObject"],
     "Resource": ["arn:aws:s3:::BUCKET/objects/*"]},
    {"Effect": "Allow", "Action": ["s3:DeleteObject"],
     "Resource": ["arn:aws:s3:::BUCKET/objects/*", "arn:aws:s3:::BUCKET/updates/*"]},
    {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::BUCKET"]},
    {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"}
  ]
}
```

`s3:ListBucket` lets `head_object` return 404 instead of 403 for missing keys.

## 5. S3 trigger

Event notification on the bucket:

* Event type: `s3:ObjectCreated:*`
* Prefix: `updates/` (or `<prefix>/updates/` if you use a key prefix)
* Suffix: `.json`
* Destination: the Lambda function

The handler parses `updates/<object_id>/tk_v<N>.json`, so one function serves every object. A key
prefix before `updates/` is honoured, so several tenants can share a bucket under different prefixes.

## 6. Running the roles against S3

Every CLI accepts `--store s3://BUCKET[/prefix]` instead of a local directory (credentials come from
the usual AWS environment/profile):

```bash
# Authority (once)
python crypto/ta_local.py setup --universe attA,attB,attC,attD,attE \
    --mpk-out keys/mpk.json --msk-out keys/authority/msk.json --publish s3://BUCKET
python crypto/ta_local.py keygen --mpk keys/mpk.json --msk keys/authority/msk.json \
    --attrs attB,attD --out keys/users/bob.json            # deliver out-of-band

# Data owner
python crypto/owner_encrypt.py --store s3://BUCKET --secrets-dir owner_secrets \
    --policy "(attA OR (attB AND attC))" --in-file report.pdf
python crypto/owner_upkeygen.py --store s3://BUCKET --secrets-dir owner_secrets \
    --object-id <ID> --new-policy "(attA OR (2, attB, attC, attD))"
#   -> uploading tk triggers the Lambda; no further owner action

# Data user
python crypto/client_decrypt.py --store s3://BUCKET --sk keys/users/bob.json --object-id <ID> --out report.pdf
```

Local testing of the handler without AWS: `pytest tests/test_lambda.py` (uses moto to mock S3).
`event.json` is a sample S3 event for `sam local invoke` / the Lambda console test tab — replace the
object id.

## 7. Operational notes

* **Owner secrets.** `owner_secrets/` is as sensitive as the data: losing `E_T` means the object can no
  longer be updated (it can still be re-encrypted from the plaintext); leaking it lets the holder
  recover K. Back it up encrypted; never put it in S3.
* **Stale/duplicate events.** S3 delivers at least once. A tk for an old version is skipped; the
  owner cannot create a tk while one is pending unless `--force` is used.
* **Universe changes.** ρ is fixed at Setup. Adding attribute names requires a new Setup (or a TA
  procedure that assigns unused indices ≤ ℓ and republishes mpk — not implemented).
* **Curve.** `SS512` gives ~80-bit security (charm warns about it). Kept for parity with the paper's
  experiments; choose a larger curve for anything beyond a PoC.
* **Transport/at rest.** HTTPS to S3, SSE-S3 or SSE-KMS on the bucket, CloudTrail for audit.
