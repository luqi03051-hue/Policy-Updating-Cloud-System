#!/usr/bin/env bash
set -euo pipefail
###############################################################################
# cloud_demo.sh — the full flow against the real S3 bucket + Lambda.
#
# Authority / owner / user run locally (in the image, so no local charm needed);
# the cloud step (CTUpdate) is done by Lambda, triggered by the update-key upload.
#
# Usage (WSL, project root):  bash scripts/cloud_demo.sh      (override: BUCKET=... bash ...)
# Local secrets go to ./cloud_data/  (msk, user keys, owner E_T) — never uploaded.
###############################################################################

REGION="${REGION:-ap-southeast-2}"
BUCKET="${BUCKET:-abe-pucpabe-luqi}"
FN="${FN:-abe-ctupdate}"
IMAGE="${IMAGE:-abe-lambda:poc2}"
DATA="${DATA:-$PWD/cloud_data}"
S="s3://$BUCKET"
export AWS_DEFAULT_REGION="$REGION" AWS_PAGER=""

say() { printf "\n\033[1m%s\033[0m\n" "$*"; }
mkdir -p "$DATA/keys/authority" "$DATA/keys/users" "$DATA/owner_secrets"

# Everything that talks to AWS runs inside the image (boto3 + the mounted ~/.aws credentials),
# so the host only needs Docker — not the host aws CLI or its configuration.
dk() {
  local envs=(-e PYTHONWARNINGS=ignore -e AWS_DEFAULT_REGION="$REGION"
              -e AWS_SHARED_CREDENTIALS_FILE=/aws/credentials -e AWS_CONFIG_FILE=/aws/config)
  for v in AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN; do
    [[ -n "${!v:-}" ]] && envs+=(-e "$v")
  done
  docker run --rm -i "${envs[@]}" -v "$HOME/.aws:/aws:ro" \
    -v "$DATA/keys:/data/keys" -v "$DATA/owner_secrets:/data/owner_secrets" \
    --entrypoint python "$IMAGE" "$@"
}
abe() { dk "/var/task/$1" "${@:2}"; }   # run a project script

# Prints "<latest_version> <tk_pending 0|1>" for $OID; tk_v<base> pending means Lambda has not consumed it.
cloud_state() {
  dk -c '
import json, sys, boto3
b, oid, base = sys.argv[1], sys.argv[2], sys.argv[3]
s3 = boto3.client("s3")
try:
    lv = json.loads(s3.get_object(Bucket=b, Key=f"objects/{oid}/latest.json")["Body"].read())["latest_version"]
except Exception as e:
    print(f"ERR {type(e).__name__}: {e}", file=sys.stderr); lv = -1
try:
    s3.head_object(Bucket=b, Key=f"updates/{oid}/tk_v{base}.json"); tk = 1
except Exception:
    tk = 0
print(lv, tk)' "$BUCKET" "$OID" "$1"
}

list_bucket() {
  dk -c '
import sys, boto3
for o in boto3.client("s3").list_objects_v2(Bucket=sys.argv[1]).get("Contents", []):
    print("   %9d  %s" % (o["Size"], o["Key"]))' "$BUCKET"
}

try_decrypt() {  # <user> <ok|denied>
  local out rc
  set +e; out="$(abe client_decrypt.py --store "$S" --sk "/data/keys/users/$1.json" --object-id "$OID" 2>&1)"; rc=$?; set -e
  printf "   %-6s -> %s" "$1" "$out"
  if   [[ "$2" == ok && $rc -eq 0 ]] || [[ "$2" == denied && $rc -eq 3 ]]; then echo "   ✓"
  else echo "   ✗ UNEXPECTED (rc=$rc)"; exit 1; fi
}

wait_version() {  # wait until Lambda has turned v$(($1-1)) into v$1
  local want="$1" base=$(( $1 - 1 )) t0=$SECONDS lv tk
  while (( SECONDS - t0 < 120 )); do
    read -r lv tk < <(cloud_state "$base")
    if [[ "$lv" == "$want" ]]; then echo "   Lambda produced v$want after $((SECONDS - t0)) s"; return; fi
    sleep 3
  done
  echo "   ✗ timeout after 120 s: latest_version=$lv, update key tk_v$base still pending=$tk"
  if [[ "$tk" == 1 ]]; then
    echo "   → the update key was never consumed: the S3 trigger did not fire, or Lambda failed."
    echo "     Check: S3 → $BUCKET → Properties → Event notifications (prefix updates/, suffix .json → $FN)"
  else
    echo "   → the update key was consumed but no new version appeared: Lambda ran and failed."
  fi
  echo "     Lambda logs: console → Lambda → $FN → Monitor → View CloudWatch logs"
  aws logs tail "/aws/lambda/$FN" --since 10m --region "$REGION" 2>/dev/null || true
  exit 1
}

say "1) [Authority] Setup + publish mpk to $S/config/mpk.json"
abe ta_local.py setup --universe attA,attB,attC,attD,attE,attF,attG \
  --mpk-out /data/keys/mpk.json --msk-out /data/keys/authority/msk.json --publish "$S"

say "2) [Authority] KeyGen: alice{A} carol{B,C} bob{B,D}"
for u in "alice attA" "carol attB,attC" "bob attB,attD"; do
  set -- $u
  abe ta_local.py keygen --mpk /data/keys/mpk.json --msk /data/keys/authority/msk.json --attrs "$2" --out "/data/keys/users/$1.json"
done

say "3) [Owner] encrypt locally, upload v1 — (attA OR (attB AND attC))"
OUT="$(abe owner_encrypt.py --store "$S" --secrets-dir /data/owner_secrets \
        --policy "(attA OR (attB AND attC))" --plaintext "hello from AWS Lambda")"
echo "$OUT"
OID="$(printf "%s" "$OUT" | python3 -c 'import json,sys;print(json.loads(sys.stdin.read().strip().splitlines()[-1])["object_id"])')"

say "4) [Users] v1"
try_decrypt alice ok; try_decrypt carol ok; try_decrypt bob denied

say "5) [Owner] UPKeyGen -> upload tk (this upload triggers the Lambda)"
abe owner_upkeygen.py --store "$S" --secrets-dir /data/owner_secrets --object-id "$OID" \
  --new-policy "(attA OR (2, attB, attC, attD))" --mode Attributes2Existing
wait_version 2

say "6) [Users] v2 — Attributes2Existing"
try_decrypt alice ok; try_decrypt bob ok

say "7) [Owner] UPKeyGen (Attributes2New) -> Lambda"
abe owner_upkeygen.py --store "$S" --secrets-dir /data/owner_secrets --object-id "$OID" \
  --new-policy "((2, attA, attD, attE) OR (2, attB, attC, attD))" --mode Attributes2New
wait_version 3

say "8) [Users] v3 — Attributes2New"
try_decrypt alice denied; try_decrypt bob ok; try_decrypt carol ok

say "9) Lambda log (CTUpdate records; needs logs permission for the local identity — optional)"
aws logs tail "/aws/lambda/$FN" --since 10m --format short --region "$REGION" 2>/dev/null \
  | grep -E '"operation"|REPORT' || echo "   (could not read logs from here — see Lambda → Monitor → CloudWatch logs)"

say "10) What is in the cloud"
LISTING="$(list_bucket)"
echo "$LISTING"
if echo "$LISTING" | grep -vE 'config/mpk.json|objects/' | grep -q .; then echo "   unexpected objects in bucket"; exit 1; fi
echo "   bucket holds only mpk + latest ciphertext; msk / E_T / user keys stay in $DATA ✓"

say "✅ Cloud demo completed. object_id = $OID"
