#!/usr/bin/env bash
# Create a read-only kubeconfig for Kiro (run this YOURSELF, with your admin access).
#
# Creates ServiceAccount kiro-readonly/kiro bound to the built-in ClusterRole "view"
# (read most resources; cannot read Secrets, cannot change anything), mints a
# time-limited token and writes a kubeconfig that contains only that identity.
#
# Usage:
#   ./make-readonly-kubeconfig.sh --context <admin-context> [--duration 168h] [--out ~/.kube/kiro-readonly.yaml]
# Run once per cluster; contexts are added to the same output file.
set -euo pipefail

ctx=""; dur="168h"; out="$HOME/.kube/kiro-readonly.yaml"
while [ $# -gt 0 ]; do
  case "$1" in
    --context) ctx="$2"; shift 2 ;;
    --duration) dur="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done
[ -n "$ctx" ] || { echo "--context is required (see: kubectl config get-contexts)" >&2; exit 1; }

k() { kubectl --context "$ctx" "$@"; }
ns=kiro-readonly; sa=kiro

echo "Creating read-only identity in context '$ctx'..."
k create namespace "$ns" --dry-run=client -o yaml | k apply -f - >/dev/null
k -n "$ns" create serviceaccount "$sa" --dry-run=client -o yaml | k apply -f - >/dev/null
k create clusterrolebinding kiro-readonly-view --clusterrole=view \
  --serviceaccount="$ns:$sa" --dry-run=client -o yaml | k apply -f - >/dev/null

token="$(k -n "$ns" create token "$sa" --duration="$dur")"
server="$(kubectl config view --minify --context "$ctx" -o jsonpath='{.clusters[0].cluster.server}')"
ca="$(kubectl config view --raw --minify --context "$ctx" -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"

name="${ctx}-kiro-ro"
mkdir -p "$(dirname "$out")"; touch "$out"; chmod 600 "$out"
cafile="$(mktemp)"; trap 'rm -f "$cafile"' EXIT
if [ -n "$ca" ]; then
  printf '%s' "$ca" | base64 -d > "$cafile"
  kubectl config --kubeconfig "$out" set-cluster "$name" --server "$server" --certificate-authority "$cafile" --embed-certs >/dev/null
else
  kubectl config --kubeconfig "$out" set-cluster "$name" --server "$server" >/dev/null
fi
kubectl config --kubeconfig "$out" set-credentials "$name" --token "$token" >/dev/null
kubectl config --kubeconfig "$out" set-context "$name" --cluster "$name" --user "$name" >/dev/null
kubectl config --kubeconfig "$out" use-context "$name" >/dev/null

echo "Wrote context '$name' to $out (token valid for $dur; the API server may cap this)."
echo "Check:"
printf '  can list pods:   '; KUBECONFIG="$out" kubectl auth can-i list pods -A || true
printf '  can delete pods: '; KUBECONFIG="$out" kubectl auth can-i delete pods -A || true
printf '  can read secrets:'; KUBECONFIG="$out" kubectl auth can-i get secrets -A || true
echo "Expected: yes / no / no. Re-run this script when the token expires."
