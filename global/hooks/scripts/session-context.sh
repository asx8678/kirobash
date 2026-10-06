#!/usr/bin/env bash
# SessionStart hook: print the active infrastructure targets into the agent's context.
# Read-only, no credits. Keep the output short: every line is in context for the whole session.
have() { command -v "$1" >/dev/null 2>&1; }
ro=""
echo "## session targets"
if have kubectl; then
  ctx="$(timeout 3 kubectl config current-context 2>/dev/null || echo none)"
  echo "kubernetes: context=$ctx${KUBECONFIG:+ kubeconfig=$KUBECONFIG}"
  case "${KUBECONFIG:-}" in *kiro-readonly*) ro="$ro k8s";; esac
fi
if have az; then
  sub="$(timeout 5 az account show --query '[name, user.name]' -o tsv 2>/dev/null | tr '\t' ' ' | paste -sd' ' -)"
  echo "azure: ${sub:-not logged in}${AZURE_CONFIG_DIR:+ profile=$AZURE_CONFIG_DIR}"
  case "${AZURE_CONFIG_DIR:-}" in *kiro*) ro="$ro azure";; esac
fi
if have aws; then
  arn="$(timeout 5 aws sts get-caller-identity --query Arn -o text 2>/dev/null || echo 'none/offline')"
  echo "aws: ${arn}${AWS_CONFIG_FILE:+ config=$AWS_CONFIG_FILE}"
  case "${AWS_CONFIG_FILE:-}" in *kiro*) ro="$ro aws";; esac
fi
# the guard's effective settings (validated; the environment can only tighten them)
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
conf() { python3 "$here/kiro_guard.py" --conf-get "$1" 2>/dev/null || echo "$2"; }
mode="$(conf GUARD_MODE destructive)"
sb="$(conf RUN_SANDBOX off)"; [ "$sb" = off ] && sb="" || sb="; kiro-run sandbox: $sb"
echo "kiro-guard: ${mode} mode${sb}; read-only credentials:${ro:- NONE (admin credentials in use — prepare changes, do not run them)}"
cm="$(conf CODE_MODE enforce)"
case "$cm" in
  enforce) echo "code mode: enforced — one command per direct shell call; several commands, a loop or inline code go in one program: kiro-run --bash <<'EOF' ... EOF (python without --bash; import kt)" ;;
  inline)  echo "code mode: inline code (python3 -c, bash -c, heredocs into interpreters) goes through kiro-run <<'EOF' ... EOF" ;;
esac
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "git: branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null) dirty=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ') files"
fi
exit 0
