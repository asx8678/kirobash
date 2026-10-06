#!/usr/bin/env bash
# kiro-guard wrapper: Kiro CLI v3 PreToolUse hook.
# Exit 0 = allow, exit 2 = block (Kiro shows stderr to the agent).
# Fails closed: any unexpected error becomes a block for command-carrying tools.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
payload="$(cat)"

if command -v python3 >/dev/null 2>&1; then
  printf '%s' "$payload" | python3 "$dir/kiro_guard.py"
  rc=$?
  case "$rc" in
    0|2) exit "$rc" ;;
    *) echo "kiro-guard: internal error (rc=$rc); blocking to be safe." >&2; exit 2 ;;
  esac
fi

# Fallback without python3: conservative text scan of the whole payload.
# Over-blocks rather than under-blocks.
re='(kubectl|oc|kubecolor)[^"]*[[:space:]](delete|drain|replace|edit)([[:space:]]|")'
re+='|helm[^"]*[[:space:]](uninstall|delete)([[:space:]]|")'
re+='|az[[:space:]][^"]*[[:space:]](delete|delete-batch|purge|deallocate|stop|reimage|redeploy|regenerate[a-z-]*|revoke|failover|remove)([[:space:]]|")'
re+='|--mode[= ]+[Cc]omplete|azd[[:space:]]+down|(terraform|tofu|terragrunt)[^"]*[[:space:]](destroy|apply)([[:space:]]|")'
re+='|pulumi[[:space:]]+(destroy|up)|(Remove|Stop|Reset)-Az|-X[[:space:]]*DELETE|--request[= ]DELETE'
re+='|aws[[:space:]][^"]*[[:space:]](delete|terminate|deregister|purge|reboot|stop|batch-delete|schedule-key-deletion)[a-z-]*([[:space:]]|")'
re+='|aws[[:space:]]+s3[[:space:]]+(rm|rb)([[:space:]]|")|aws[[:space:]]+s3[[:space:]]+sync[^"]*--delete|aws[[:space:]]+ssm[[:space:]]+send-command'
re+='|eksctl[[:space:]]+delete|cdk[[:space:]]+(destroy|deploy)|sam[[:space:]]+(delete|deploy|sync)|kops[[:space:]]+delete|aws-nuke'
re+='|\.kiro/(hooks|settings|lib)|kiro[-_]guard|\.local/bin/kiro-|\.(kube|azure|aws)/'
if printf '%s' "$payload" | grep -Eq "$re"; then
  echo "BLOCKED by kiro-guard (fallback mode, python3 not found): the command looks destructive or touches Kiro guard files. Do not work around this; give the user the exact command to run themselves." >&2
  # the user sees none of this: the agent reports it, as the one kind of line a reply shows in red
  printf 'The user cannot see this message. End your reply with this block (it shows red):\n```diff\n- BLOCKED by kiro-guard: <the command> (not run)\n```\n' >&2
  exit 2
fi
exit 0
