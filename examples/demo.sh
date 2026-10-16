#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# demo.sh — PU-CP-ABE end-to-end demo with the paper's role separation
#
#   Authority : Setup, KeyGen                    (sees msk)
#   Owner     : Enc, UPKeyGen                    (sees plaintext + E_T, never msk)
#   Cloud     : CTUpdate                         (sees only mpk, ciphertexts, update keys)
#   User      : Dec                              (sees own sk)
#
# In Docker mode every role runs in its own container and is given ONLY its own folders:
#   authority -> keys/, store/          owner -> store/, owner_secrets/
#   cloud     -> store/                 user  -> store/, keys/users/ (read-only)
#
# Usage (from the project root):
#   bash examples/demo.sh                 # Docker (default)
#   RUNNER=local bash examples/demo.sh    # plain python3, PBC + charm installed locally
#
# Optional env: IMAGE_TAG=abe-lambda:poc2  DATA_DIR=./demo_data  RUN_TESTS=1  SKIP_BUILD=1
#               DOCKERFILE=docker/Dockerfile.update  BASE=pv-lambda:latest   (incremental build)
###############################################################################

RUNNER="${RUNNER:-docker}"
IMAGE_TAG="${IMAGE_TAG:-abe-lambda:poc2}"
PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DATA_DIR="${DATA_DIR:-$PROJECT_DIR/demo_data}"

UNIVERSE="attA,attB,attC,attD,attE,attF,attG"
POLICY_V1="(attA OR (attB AND attC))"
POLICY_V2="(attA OR (2, attB, attC, attD))"                    # Attributes2Existing on T1
POLICY_V3="((2, attA, attD, attE) OR (2, attB, attC, attD))"   # Attributes2New on Tr

say()  { printf "\n\033[1m%s\033[0m\n" "$*"; }
die()  { printf "\nERROR: %s\n" "$*" >&2; exit 1; }

# Host path -> path docker.exe understands (Git Bash on Windows needs a Windows path).
to_docker_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf "%s" "$1"; fi
}

if [[ "$RUNNER" == "docker" ]]; then
  command -v docker >/dev/null 2>&1 || die "docker not found (or use RUNNER=local)"
  export MSYS_NO_PATHCONV=1   # stop Git Bash from rewriting /data/... container paths
  K=/data/keys; S=/data/store; O=/data/owner_secrets
else
  K="$DATA_DIR/keys"; S="$DATA_DIR/store"; O="$DATA_DIR/owner_secrets"
fi

# run_as <role> <script.py> [args...]
run_as() {
  local role="$1" script="$2"; shift 2
  if [[ "$RUNNER" != "docker" ]]; then
    (cd "$PROJECT_DIR/crypto" && PYTHONWARNINGS=ignore python3 "$script" "$@")
    return
  fi
  local mounts=()
  case "$role" in
    authority) mounts+=(-v "$(to_docker_path "$DATA_DIR/keys"):/data/keys"
                        -v "$(to_docker_path "$DATA_DIR/store"):/data/store") ;;
    owner)     mounts+=(-v "$(to_docker_path "$DATA_DIR/store"):/data/store"
                        -v "$(to_docker_path "$DATA_DIR/owner_secrets"):/data/owner_secrets") ;;
    cloud)     mounts+=(-v "$(to_docker_path "$DATA_DIR/store"):/data/store") ;;
    user)      mounts+=(-v "$(to_docker_path "$DATA_DIR/store"):/data/store"
                        -v "$(to_docker_path "$DATA_DIR/keys/users"):/data/keys/users:ro") ;;
    *) die "unknown role $role" ;;
  esac
  docker run --rm -i -e PYTHONWARNINGS=ignore "${mounts[@]}" \
    --entrypoint python "$IMAGE_TAG" "/var/task/$script" "$@"
}

# try_decrypt <user> <expect: ok|denied>
try_decrypt() {
  local user="$1" expect="$2" out rc
  set +e
  out="$(run_as user client_decrypt.py --store "$S" --sk "$K/users/$user.json" --object-id "$OID" 2>&1)"
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then printf "   %-6s -> decrypted: %s" "$user" "$out"; else printf "   %-6s -> %s" "$user" "$out"; fi
  if   [[ "$expect" == ok     && $rc -eq 0 ]]; then echo "   ✓"
  elif [[ "$expect" == denied && $rc -eq 3 ]]; then echo "   ✓ (expected)"
  else echo "   ✗ UNEXPECTED (rc=$rc)"; exit 1; fi
}

json_field() { python3 -c 'import json,sys; print(json.loads(sys.stdin.read().strip().splitlines()[-1])[sys.argv[1]])' "$1"; }

###############################################################################
if [[ "$RUNNER" == "docker" && "${SKIP_BUILD:-0}" != "1" ]]; then
  say "0) Build image $IMAGE_TAG"
  docker build --provenance=false -f "${DOCKERFILE:-$PROJECT_DIR/docker/Dockerfile}" \
    ${BASE:+--build-arg BASE=$BASE} -t "$IMAGE_TAG" "$PROJECT_DIR"
fi

say "1) Fresh demo data in $DATA_DIR"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR/keys/users" "$DATA_DIR/keys/authority" "$DATA_DIR/store" "$DATA_DIR/owner_secrets"

say "2) [Authority] Setup — U = {$UNIVERSE}; mpk is published to the cloud store, msk stays local"
run_as authority ta_local.py setup --universe "$UNIVERSE" \
  --mpk-out "$K/mpk.json" --msk-out "$K/authority/msk.json" --publish "$S"

say "3) [Authority] KeyGen for three users"
run_as authority ta_local.py keygen --mpk "$K/mpk.json" --msk "$K/authority/msk.json" --attrs attA      --out "$K/users/alice.json"
run_as authority ta_local.py keygen --mpk "$K/mpk.json" --msk "$K/authority/msk.json" --attrs attB,attC --out "$K/users/carol.json"
run_as authority ta_local.py keygen --mpk "$K/mpk.json" --msk "$K/authority/msk.json" --attrs attB,attD --out "$K/users/bob.json"

say "4) [Owner] Encrypt locally and upload — policy $POLICY_V1"
OID="$(run_as owner owner_encrypt.py --store "$S" --secrets-dir "$O" \
        --policy "$POLICY_V1" --plaintext "hello world" | tee /dev/stderr | json_field object_id)"
say "   object_id = $OID"

say "5) [Users] Decrypt v1"
try_decrypt alice ok
try_decrypt carol ok
try_decrypt bob   denied

say "6) [Owner] UPKeyGen: $POLICY_V1  ->  $POLICY_V2"
run_as owner owner_upkeygen.py --store "$S" --secrets-dir "$O" --object-id "$OID" \
  --new-policy "$POLICY_V2" --mode Attributes2Existing

say "7) [Cloud] CTUpdate (what the Lambda does on the S3 event) — C_AES untouched"
run_as cloud cloud_update.py --store "$S" --object-id "$OID"

say "8) [Users] Decrypt v2"
try_decrypt alice ok
try_decrypt bob   ok

say "9) [Owner] UPKeyGen: $POLICY_V2  ->  $POLICY_V3"
run_as owner owner_upkeygen.py --store "$S" --secrets-dir "$O" --object-id "$OID" \
  --new-policy "$POLICY_V3" --mode Attributes2New

say "10) [Cloud] CTUpdate"
run_as cloud cloud_update.py --store "$S" --object-id "$OID"

say "11) [Users] Decrypt v3"
try_decrypt alice denied
try_decrypt bob   ok
try_decrypt carol ok

say "12) What each party holds"
( cd "$DATA_DIR" && find . -type f | sort | sed 's/^/   /' )
if grep -rqE '"msk"|E_T|_debug|s_map' "$DATA_DIR/store"; then die "secret material found in the cloud store"; fi
echo "   cloud store contains no msk / E_T / user keys ✓"

if [[ "${RUN_TESTS:-0}" == "1" ]]; then
  say "Optional) pytest"
  if [[ "$RUNNER" == "docker" ]]; then
    docker run --rm -i --entrypoint /bin/bash "$IMAGE_TAG" -lc "cd /var/task && python -m pytest -q tests"
  else
    (cd "$PROJECT_DIR" && python3 -m pytest -q tests)
  fi
fi

say "✅ Demo completed. object_id = $OID"
