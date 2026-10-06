#!/usr/bin/env bash
# Set up a separate, read-only Azure CLI profile for Kiro (run this YOURSELF).
#
# Kiro will use ~/.azure-kiro instead of ~/.azure, logged in as an identity that
# only has the Reader role. Reader can list/show resources but cannot create,
# change or delete anything, and cannot read storage keys or Key Vault secrets.
#
# Option A (recommended): a service principal with Reader.
#   An admin creates it once:
#     az ad sp create-for-rbac --name kiro-reader --role Reader \
#        --scopes /subscriptions/<sub-id> [/subscriptions/<other-sub-id> ...]
#   Then run:  ./setup-azure-readonly.sh --sp <appId> --tenant <tenantId>
#
# Option B: a separate low-privilege user account (Reader only):
#   ./setup-azure-readonly.sh --user --tenant <tenantId>
set -euo pipefail

dir="${KIRO_AZURE_CONFIG_DIR:-$HOME/.azure-kiro}"; mode=""; app=""; tenant=""
while [ $# -gt 0 ]; do
  case "$1" in
    --sp) mode=sp; app="$2"; shift 2 ;;
    --user) mode=user; shift ;;
    --tenant) tenant="$2"; shift 2 ;;
    --dir) dir="$2"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done
[ -n "$mode" ] && [ -n "$tenant" ] || { sed -n '2,17p' "$0"; exit 1; }

mkdir -p "$dir"; chmod 700 "$dir"
export AZURE_CONFIG_DIR="$dir"

if [ "$mode" = sp ]; then
  printf 'Client secret for %s (input hidden): ' "$app"; read -rs secret; echo
  az login --service-principal -u "$app" -p "$secret" --tenant "$tenant" --only-show-errors >/dev/null
  unset secret
  assignee="$app"
else
  az login --tenant "$tenant" --use-device-code --only-show-errors >/dev/null
  assignee="$(az ad signed-in-user show --query id -o tsv)"
fi

echo "Logged in. Profile: $AZURE_CONFIG_DIR"
echo "Role assignments for this identity:"
az role assignment list --assignee "$assignee" --all --query "[].{role:roleDefinitionName, scope:scope}" -o table
if az role assignment list --assignee "$assignee" --all --query "[].roleDefinitionName" -o tsv \
   | grep -qvxE 'Reader|Monitoring Reader|Log Analytics Reader|Azure Kubernetes Service RBAC Reader|Cost Management Reader'; then
  echo
  echo "WARNING: this identity has roles beyond read-only. Remove them, or Kiro will be able to change resources." >&2
fi
echo
echo "Start Kiro with this profile via the kiro-safe launcher."
