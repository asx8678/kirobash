#!/usr/bin/env bash
# Set up a separate, read-only AWS CLI profile for Kiro (run this YOURSELF).
#
# Kiro will use ~/.aws-kiro (AWS_CONFIG_FILE / AWS_SHARED_CREDENTIALS_FILE) instead of ~/.aws,
# with an identity that can only read. Give that identity:
#   - the AWS managed policy  arn:aws:iam::aws:policy/ReadOnlyAccess
#   - plus the explicit-deny policy in safety/aws-readonly-deny.json (blocks reading secrets,
#     decrypting parameters, and S3 object contents).
# For EKS clusters, map the identity to view-only:
#   aws eks create-access-entry --cluster-name <c> --principal-arn <role/user arn>
#   aws eks associate-access-policy --cluster-name <c> --principal-arn <arn> \
#       --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy --access-scope type=cluster
# (or simply use safety/make-readonly-kubeconfig.sh, which works for EKS too).
#
# Usage:
#   ./setup-aws-readonly.sh --sso                       # IAM Identity Center: pick a read-only permission set
#   ./setup-aws-readonly.sh --access-key --region eu-west-1   # keys of a dedicated read-only IAM user
#   ./setup-aws-readonly.sh --role arn:aws:iam::123:role/kiro-reader --source-profile <profile-in-~/.aws>
set -euo pipefail

dir="${KIRO_AWS_DIR:-$HOME/.aws-kiro}"; mode=""; region=""; role=""; src=""
while [ $# -gt 0 ]; do
  case "$1" in
    --sso) mode=sso; shift ;;
    --access-key) mode=key; shift ;;
    --role) mode=role; role="$2"; shift 2 ;;
    --source-profile) src="$2"; shift 2 ;;
    --region) region="$2"; shift 2 ;;
    --dir) dir="$2"; shift 2 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done
[ -n "$mode" ] || { sed -n '2,19p' "$0"; exit 1; }

mkdir -p "$dir"; chmod 700 "$dir"
export AWS_CONFIG_FILE="$dir/config" AWS_SHARED_CREDENTIALS_FILE="$dir/credentials"
touch "$AWS_CONFIG_FILE" "$AWS_SHARED_CREDENTIALS_FILE"; chmod 600 "$AWS_CONFIG_FILE" "$AWS_SHARED_CREDENTIALS_FILE"
profile=kiro-ro

case "$mode" in
  sso)
    aws configure sso --profile "$profile" ;;
  key)
    printf 'Access key ID: '; read -r akid
    printf 'Secret access key (hidden): '; read -rs sak; echo
    aws configure set aws_access_key_id "$akid" --profile "$profile"
    aws configure set aws_secret_access_key "$sak" --profile "$profile"
    unset sak ;;
  role)
    [ -n "$src" ] || { echo "--role needs --source-profile (a profile in your normal ~/.aws)"; exit 1; }
    # Kiro must not see your normal credentials, so the role's session is minted now and stored as static
    # short-lived keys (12h max). Re-run this script when they expire.
    creds="$(AWS_CONFIG_FILE="$HOME/.aws/config" AWS_SHARED_CREDENTIALS_FILE="$HOME/.aws/credentials" \
      aws sts assume-role --role-arn "$role" --role-session-name kiro-ro --duration-seconds 43200 \
      --profile "$src" --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken,Expiration]' -o text)"
    set -- $creds
    aws configure set aws_access_key_id "$1" --profile "$profile"
    aws configure set aws_secret_access_key "$2" --profile "$profile"
    aws configure set aws_session_token "$3" --profile "$profile"
    echo "Session credentials expire at $4" ;;
esac
[ -n "$region" ] && aws configure set region "$region" --profile "$profile"
aws configure set cli_pager "" --profile "$profile"
# make kiro-ro the default profile inside this config dir
python3 - "$AWS_CONFIG_FILE" "$AWS_SHARED_CREDENTIALS_FILE" <<'PY' 2>/dev/null || true
import configparser, sys
for path, sect in ((sys.argv[1], "profile kiro-ro"), (sys.argv[2], "kiro-ro")):
    c = configparser.RawConfigParser(); c.read(path)
    if c.has_section(sect):
        if not c.has_section("default"): c.add_section("default")
        for k, v in c.items(sect): c.set("default", k, v)
        with open(path, "w") as fh: c.write(fh)
PY

echo; echo "Checking what this identity can do (profile: $profile in $dir)"
aws sts get-caller-identity --profile "$profile" --output table
printf '  describe instances: '; aws ec2 describe-instances --max-items 1 --profile "$profile" >/dev/null 2>&1 && echo ok || echo "DENIED (is ReadOnlyAccess attached?)"
printf '  terminate (dry-run): '
if aws ec2 terminate-instances --instance-ids i-00000000000000000 --dry-run --profile "$profile" 2>&1 | grep -q DryRunOperation; then
  echo "ALLOWED  <-- this identity can terminate instances; fix its policies before using it with Kiro"
else echo "denied (good)"; fi
printf '  read a secret: '
if aws secretsmanager list-secrets --max-results 1 --query 'SecretList[0].ARN' -o text --profile "$profile" 2>/dev/null | grep -q arn; then
  arn="$(aws secretsmanager list-secrets --max-results 1 --query 'SecretList[0].ARN' -o text --profile "$profile")"
  aws secretsmanager get-secret-value --secret-id "$arn" --profile "$profile" >/dev/null 2>&1 && echo "ALLOWED  <-- attach aws-readonly-deny.json" || echo "denied (good)"
else echo "no secrets to test"; fi
echo; echo "Start Kiro with the kiro-safe launcher; it points AWS_CONFIG_FILE at $dir."
