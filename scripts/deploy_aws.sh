#!/usr/bin/env bash
set -euo pipefail
###############################################################################
# deploy_aws.sh — push the image and wire up S3 -> Lambda (CTUpdate). Idempotent.
#
# Creates NEW resources (does not touch the previous PoC's function/bucket):
#   ECR   : $REPO:$TAG                    (existing repo is reused)
#   S3    : $BUCKET                       config/  objects/  updates/
#   IAM   : role $ROLE                    least-privilege S3 + CloudWatch Logs
#   Lambda: $FN                           image, triggered by updates/*.json
#
# Usage (WSL, from the project root, after the local tests pass):
#   bash scripts/deploy_aws.sh
# Override any variable, e.g.  TAG=pv7 bash scripts/deploy_aws.sh
###############################################################################

REGION="${REGION:-ap-southeast-2}"
ACCOUNT="${ACCOUNT:-$(aws sts get-caller-identity --query Account --output text)}"
LOCAL_IMAGE="${LOCAL_IMAGE:-abe-lambda:poc2}"
REPO="${REPO:-abe-lambda_backup}"
TAG="${TAG:-pv6}"
FN="${FN:-abe-ctupdate}"
ROLE="${ROLE:-abe-ctupdate-role}"
BUCKET="${BUCKET:-abe-pucpabe-luqi}"
REGISTRY="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com"
IMAGE="$REGISTRY/$REPO:$TAG"
export AWS_DEFAULT_REGION="$REGION" AWS_PAGER=""

say() { printf "\n\033[1m%s\033[0m\n" "$*"; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

say "Account $ACCOUNT  region $REGION"
echo "  image : $IMAGE"
echo "  bucket: s3://$BUCKET"
echo "  lambda: $FN   role: $ROLE"

# ---------------------------------------------------------------- 1) ECR push
say "1) Push image to ECR"
docker image inspect "$LOCAL_IMAGE" >/dev/null 2>&1 || { echo "local image $LOCAL_IMAGE not found — build it first"; exit 1; }
aws ecr describe-repositories --repository-names "$REPO" >/dev/null 2>&1 \
  || aws ecr create-repository --repository-name "$REPO" >/dev/null
aws ecr get-login-password | docker login --username AWS --password-stdin "$REGISTRY" >/dev/null
docker tag "$LOCAL_IMAGE" "$IMAGE"
docker push "$IMAGE" | tail -1

# ---------------------------------------------------------------- 2) S3 bucket
say "2) S3 bucket"
if aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  echo "  exists"
else
  aws s3 mb "s3://$BUCKET" --region "$REGION"
fi
aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption --bucket "$BUCKET" --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# ---------------------------------------------------------------- 3) IAM role
say "3) IAM role (least privilege)"
cat > "$TMP/trust.json" <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF
cat > "$TMP/s3.json" <<EOF
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::$BUCKET/config/*","arn:aws:s3:::$BUCKET/objects/*","arn:aws:s3:::$BUCKET/updates/*"]},
 {"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::$BUCKET/objects/*"},
 {"Effect":"Allow","Action":"s3:DeleteObject","Resource":["arn:aws:s3:::$BUCKET/objects/*","arn:aws:s3:::$BUCKET/updates/*"]},
 {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::$BUCKET"}]}
EOF
NEW_ROLE=0
if ! aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  aws iam create-role --role-name "$ROLE" --assume-role-policy-document "file://$TMP/trust.json" >/dev/null
  NEW_ROLE=1
fi
aws iam attach-role-policy --role-name "$ROLE" \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam put-role-policy --role-name "$ROLE" --policy-name abe-s3 --policy-document "file://$TMP/s3.json"
ROLE_ARN="arn:aws:iam::$ACCOUNT:role/$ROLE"
[[ $NEW_ROLE -eq 1 ]] && { echo "  waiting for the new role to propagate..."; sleep 15; }

# ---------------------------------------------------------------- 4) Lambda
say "4) Lambda function"
if aws lambda get-function --function-name "$FN" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "$FN" --image-uri "$IMAGE" >/dev/null
  aws lambda wait function-updated --function-name "$FN"
  aws lambda update-function-configuration --function-name "$FN" --role "$ROLE_ARN" \
    --timeout 60 --memory-size 1024 --environment "Variables={KEEP_HISTORY=0}" >/dev/null
  echo "  updated"
else
  for i in 1 2 3 4 5; do   # a freshly created role can take a little while to be assumable
    if aws lambda create-function --function-name "$FN" --package-type Image \
         --code "ImageUri=$IMAGE" --role "$ROLE_ARN" --architectures x86_64 \
         --timeout 60 --memory-size 1024 --environment "Variables={KEEP_HISTORY=0}" >/dev/null 2>"$TMP/err"; then
      echo "  created"; break
    fi
    grep -q "cannot be assumed" "$TMP/err" || { cat "$TMP/err"; exit 1; }
    echo "  role not ready yet, retry $i/5"; sleep 10
  done
fi
aws lambda wait function-updated --function-name "$FN"

# ---------------------------------------------------------------- 5) S3 trigger
say "5) S3 trigger: ObjectCreated on updates/*.json -> $FN"
aws lambda add-permission --function-name "$FN" --statement-id s3invoke-"$BUCKET" \
  --action lambda:InvokeFunction --principal s3.amazonaws.com \
  --source-arn "arn:aws:s3:::$BUCKET" --source-account "$ACCOUNT" >/dev/null 2>&1 \
  || echo "  invoke permission already present"
FN_ARN="arn:aws:lambda:$REGION:$ACCOUNT:function:$FN"
cat > "$TMP/notif.json" <<EOF
{"LambdaFunctionConfigurations":[{"Id":"abe-ctupdate","LambdaFunctionArn":"$FN_ARN",
 "Events":["s3:ObjectCreated:*"],
 "Filter":{"Key":{"FilterRules":[{"Name":"prefix","Value":"updates/"},{"Name":"suffix","Value":".json"}]}}}]}
EOF
aws s3api put-bucket-notification-configuration --bucket "$BUCKET" --notification-configuration "file://$TMP/notif.json"

# ---------------------------------------------------------------- 6) smoke test
say "6) Smoke test: invoke the function directly (no-op event)"
aws lambda invoke --function-name "$FN" --cli-binary-format raw-in-base64-out \
  --payload '{"Records":[{"s3":{"bucket":{"name":"'"$BUCKET"'"},"object":{"key":"objects/none/v1.json"}}}]}' \
  "$TMP/out.json" >/dev/null
cat "$TMP/out.json"; echo
grep -q '"status": "ok"' "$TMP/out.json" || { echo "smoke test failed — check: aws logs tail /aws/lambda/$FN"; exit 1; }

say "✅ Deployed.  Next:  BUCKET=$BUCKET bash scripts/cloud_demo.sh"
