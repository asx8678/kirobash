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
mode="$(sed -n 's/^GUARD_MODE=//p' "$HOME/.kiro/hooks/scripts/kiro-guard.conf" 2>/dev/null)"
echo "kiro-guard: ${mode:-destructive} mode; read-only credentials:${ro:- NONE (admin credentials in use — prepare changes, do not run them)}"
cm="$(sed -n 's/^CODE_MODE=//p' "$HOME/.kiro/hooks/scripts/kiro-guard.conf" 2>/dev/null)"; cm="${KIRO_CODE_MODE:-${cm:-enforce}}"
case "$cm" in
  enforce) echo "code mode: enforced — one command per direct shell call; several commands, a loop or inline code go in one program: kiro-run --bash <<'EOF' ... EOF (python without --bash; import kt)" ;;
  inline)  echo "code mode: inline code (python3 -c, bash -c, heredocs into interpreters) goes through kiro-run <<'EOF' ... EOF" ;;
esac
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "git: branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null) dirty=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ') files"
fi
exit 0
