#!/usr/bin/env bash
# kiro-pack doctor: checks that the pack is installed and that the guardrails actually hold.
# Safe to run any time; makes no changes.
set -u
K="$HOME/.kiro"; ok=0; warn=0; fail=0
KIRO_TESTED=2.26.1     # the Kiro CLI version this pack was measured on (tool names, hook payloads, result limits)
# on a terminal the verdicts are coloured (green, yellow, red); piped or with NO_COLOR they are plain
if [ -t 1 ] && [ -z "${NO_COLOR+x}" ]; then cg=$'\033[38;5;121m'; cy=$'\033[38;5;221m'; cr=$'\033[1;97;41m'; cz=$'\033[0m'; else cg=""; cy=""; cr=""; cz=""; fi
export NO_COLOR=1      # the kiro-run probes below compare plain output
pass() { echo "  ${cg}ok${cz}    $1"; ok=$((ok+1)); }
warnf() { echo "  ${cy}WARN${cz}  $1"; warn=$((warn+1)); }
failf() { echo "  ${cr}FAIL${cz}  $1"; fail=$((fail+1)); }
have() { command -v "$1" >/dev/null 2>&1; }

echo "== files"
for f in hooks/kiro-guard.json hooks/validate-on-save.json hooks/session-context.json hooks/skill-router.json hooks/scripts/kiro_guard.py \
         hooks/scripts/kiro-guard.sh hooks/scripts/validate-on-save.sh hooks/scripts/session-context.sh \
         settings/permissions.yaml settings/kiroignore agents/fact-check.json steering/00-working-style.md \
         skills/infra-checks/SKILL.md skills/code-review/SKILL.md skills/code-mode/SKILL.md skills/plan/SKILL.md skills/troubleshoot/SKILL.md \
         skills/spec-check/SKILL.md skills/large-task/SKILL.md \
         agents/scout.json agents/skeptic.json agents/auditor.json lib/kt.py lib/kt.bash lib/kiro_redact.py lib/kiro_page.py \
         lib/kiro_sandbox.py lib/kiro_runlog.py lib/kiro_jobs.py; do
  [ -f "$K/$f" ] && pass "$f" || failf "$f missing (run install.sh)"
done
for j in "$K"/hooks/*.json "$K"/agents/*.json; do
  [ -f "$j" ] || continue
  python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$j" 2>/dev/null && pass "valid JSON: $(basename "$j")" || failf "invalid JSON: $j"
done
python3 -c "import yaml,sys; d=yaml.safe_load(open(sys.argv[1])); assert d and d.get('rules')" "$K/settings/permissions.yaml" 2>/dev/null \
  && pass "permissions.yaml parses ($(grep -c 'capability:' "$K/settings/permissions.yaml") rules)" || warnf "permissions.yaml missing/invalid or PyYAML not installed"
command -v kiro-run >/dev/null 2>&1 && pass "kiro-run on PATH" || warnf "kiro-run not on PATH (add ~/.local/bin to PATH)"
# Kiro skips a skill whose front matter is not valid YAML (an unquoted "word: text" in the description is enough)
skill_ok() {
  python3 -c 'import re, sys, yaml
fm = yaml.safe_load(re.match(r"^---\n(.*?)\n---\n", open(sys.argv[1], encoding="utf-8").read(), re.S).group(1))
ok = fm["name"] == sys.argv[2] and re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", fm["name"]) and 1 <= len(fm["description"]) <= 1024
sys.exit(0 if ok else 1)' "$1" "$2" 2>/dev/null
}
for sk in "$K"/skills/*/SKILL.md; do
  [ -f "$sk" ] || continue
  n="$(basename "$(dirname "$sk")")"
  skill_ok "$sk" "$n" && pass "skill loads: $n" || failf "skill $n has invalid front matter; Kiro will skip it ($sk)"
done
if command -v kiro-run >/dev/null 2>&1; then
  t="$(mktemp -d)"; out="$(cd "$t" && printf 'import kt\nprint(len(kt.files()))\n' | kiro-run 2>&1)"; rm -rf "$t"
  [ "$out" = 0 ] && pass "kiro-run runs a program with the kt helpers" || failf "kiro-run could not run a kt program: $out"
fi
have python3 && pass "python3 present (full guard)" || warnf "python3 missing: guard runs in weaker grep fallback mode"
words=$(cat "$K"/steering/*.md 2>/dev/null | wc -w | tr -d ' '); [ "${words:-0}" -le 1650 ] && pass "always-on steering: $words words" || warnf "always-on steering is large: $words words (loaded every turn)"

echo "== versions and upgrades"
gpy="$K/hooks/scripts/kiro_guard.py"
# Kiro: a newer release may rename tools or change hook payloads, which is what the unknown-tool check below catches
if have kiro-cli; then
  kv="$(kiro-cli --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"
  if [ -z "$kv" ]; then warnf "could not read the Kiro CLI version (kiro-cli --version)"
  elif [ "$kv" = "$KIRO_TESTED" ]; then pass "Kiro CLI $kv (the version the pack was measured on)"
  elif [ "$(printf '%s\n%s\n' "$kv" "$KIRO_TESTED" | sort -V | tail -n 1)" = "$kv" ]; then
    warnf "Kiro CLI $kv is newer than $KIRO_TESTED, which the pack was measured on: hooks and tool names may differ — watch the unknown-tool line below"
  else warnf "Kiro CLI $kv is older than $KIRO_TESTED, which the pack was measured on: update Kiro (hooks and permissions need the v3 engine)"; fi
else
  echo "  info  kiro-cli not on PATH: Kiro version not checked"
fi
# settings the guard knows but the installed file does not mention (their defaults apply, unexplained)
if [ -f "$gpy" ]; then
  miss="$(python3 - "$gpy" "$K/hooks/scripts/kiro-guard.conf" 2>/dev/null <<'PY'
import os, re, sys
sys.path.insert(0, os.path.dirname(sys.argv[1])); sys.argv = sys.argv[:1] + sys.argv[2:]
import kiro_guard
have = set(re.findall(r"(?m)^([A-Z][A-Z0-9_]*)=", open(sys.argv[1]).read())) if os.path.isfile(sys.argv[1]) else set()
print(" ".join(k for k in kiro_guard.CONF_DEFAULTS if k not in have))
PY
)"
  [ -z "$miss" ] && pass "kiro-guard.conf names every setting the guard knows" \
    || warnf "kiro-guard.conf does not mention: $miss (their defaults apply; re-run install.sh to add them with their explanation)"
fi
# permission rules: the pack's deny rules should all be there, and rules that look like older copies of the pack's
# (same capability, effect and first pattern, different list) are probably left by an earlier install
if [ -f "$K/settings/permissions.yaml" ] && python3 -c 'import yaml' 2>/dev/null; then
  rep="$(python3 - "$K/settings/permissions.yaml" "$K/settings/.kiro-pack-rules.yaml" 2>/dev/null <<'PY'
import os, sys, yaml
cur = (yaml.safe_load(open(sys.argv[1])) or {}).get("rules") or []
pack = (yaml.safe_load(open(sys.argv[2])) or {}).get("rules") or [] if os.path.isfile(sys.argv[2]) else []
def key(r):
    m = r.get("match") if isinstance(r, dict) else None
    return (r.get("capability"), r.get("effect"), m[0] if isinstance(m, list) and m else m) if isinstance(r, dict) else None
gone = [r for r in pack if isinstance(r, dict) and r.get("effect") == "deny" and r not in cur]
old = [r for r in cur if r not in pack and any(key(r) == key(p) for p in pack)]
print("%d\t%d\t%d" % (len(pack), len(gone), len(old)))
PY
)"
  IFS=$'\t' read -r npack ngone nold <<< "${rep:-0	0	0}"
  if [ "${npack:-0}" = 0 ]; then
    warnf "no record of the pack's permission rules yet (~/.kiro/settings/.kiro-pack-rules.yaml): re-run install.sh"
  else
    [ "${ngone:-0}" = 0 ] && pass "permissions.yaml has every deny rule of the pack" \
      || warnf "permissions.yaml lacks $ngone deny rule(s) of the pack (removed by hand?); re-add them from global/permissions.yaml.tmpl"
    [ "${nold:-0}" = 0 ] || warnf "permissions.yaml has $nold rule(s) that look like older copies of the pack's (same capability, effect and first pattern): review and delete the ones that are not yours"
  fi
fi
# tools the guard did not recognise: their paths were still checked, but a renamed tool may need a rule update
logf="$(env -u KIRO_LOG_FILE python3 "$gpy" --conf-get LOG_FILE 2>/dev/null)"; logf="${logf:-$K/kiro-guard.log}"
if [ -f "$logf" ]; then
  since="$(date -d '30 days ago' +%Y-%m-%dT%H:%M:%S 2>/dev/null || date -v-30d +%Y-%m-%dT%H:%M:%S 2>/dev/null)"
  unk="$(awk -F'\t' -v s="${since:-0}" '$2 == "UNKNOWN-TOOL" && $1 >= s { print $3 }' "$logf" | sort -u | head -n 12 | paste -sd, - | sed 's/,/, /g')"
  [ -z "$unk" ] && pass "the guard recognised every tool Kiro called (last 30 days)" \
    || warnf "the guard saw tools it does not know (last 30 days): $unk — paths were still checked; a Kiro update may have renamed tools"
fi

echo "== guard behaviour"
g="$K/hooks/scripts/kiro-guard.sh"
export KIRO_LOG_FILE=/dev/null   # these probes are not real events: keep them out of the audit log
# effective settings: validated by the guard itself, the environment can only tighten them
cget() { python3 "$K/hooks/scripts/kiro_guard.py" --conf-get "$1" 2>/dev/null || echo "$2"; }
chk="$(python3 "$K/hooks/scripts/kiro_guard.py" --check-conf 2>/dev/null)"
if [ -z "$chk" ]; then pass "kiro-guard.conf: every setting is valid"
else
  while IFS=$'\t' read -r lvl msg; do
    [ "$lvl" = FAIL ] && failf "kiro-guard.conf: $msg" || warnf "kiro-guard.conf: $msg"
  done <<< "$chk"
fi
probe() { python3 -c 'import json,os,sys; print(json.dumps({"hook_event_name":"PreToolUse","tool_name":"execute_bash","cwd":os.getcwd(),"tool_input":{"command":sys.argv[1]}}))' "$1" | bash "$g" >/dev/null 2>&1; echo $?; }
[ "$(probe 'az group delete -n x --yes')" = 2 ] && pass "blocks: az group delete" || failf "does NOT block az group delete"
[ "$(probe 'aws eks delete-cluster --name x')" = 2 ] && pass "blocks: aws eks delete-cluster" || failf "does NOT block aws eks delete-cluster"
[ "$(probe 'terraform destroy')" = 2 ] && pass "blocks: terraform destroy" || failf "does NOT block terraform destroy"
[ "$(probe 'kubectl get pods -A')" = 0 ] && pass "allows: kubectl get pods" || failf "blocks harmless kubectl get pods"
# Kiro shows the user "Tool execution failed" and nothing of the guard's message, so the block asks for a red line in the reply
python3 -c 'import json,os; print(json.dumps({"hook_event_name":"PreToolUse","tool_name":"execute_bash","cwd":os.getcwd(),"tool_input":{"command":"terraform destroy"}}))' | bash "$g" 2>&1 >/dev/null | grep -q '^- BLOCKED by kiro-guard: terraform destroy' \
  && pass "must-see: a block tells the agent to report it to the user as a red line" || failf "a block does not ask the agent to tell the user (the user sees only 'Tool execution failed')"
printf '{"hook_event_name":"PreToolUse","tool_name":"fs_append","tool_input":{"path":"%s/hooks/scripts/kiro-guard.conf","text":"GUARD_MODE=off"}}' "$K" | bash "$g" >/dev/null 2>&1; [ $? = 2 ] && pass "blocks: write tool editing the guard config" || failf "guard config is not protected from write tools"
eng=$(sed -n 's/.*"chat.agentEngine"[^"]*"\([^"]*\)".*/\1/p' "$K/settings/cli.json" 2>/dev/null); [ "$eng" = v3 ] && pass "default engine: v3" || warnf "chat.agentEngine is '${eng:-unset}': hooks and permissions.yaml only apply on the v3 engine (run: kiro-cli settings chat.agentEngine v3)"
cm=$(cget CODE_MODE enforce)
[ "$(probe 'KIRO_GUARD_MODE=off kiro-cli chat --no-interactive hello')" = 2 ] && [ "$(probe 'kiro-cli chat --trust-all-tools hello')" = 2 ] \
  && [ "$(probe 'kiro-cli settings chat.agentEngine v2')" = 2 ] \
  && pass "blocks: another Kiro session with trusted tools or KIRO_* variables, and changes to Kiro settings" \
  || failf "the agent can start Kiro with the guard off or trusted tools, or change Kiro's settings"
nl='
'
if [ "$cm" = enforce ]; then
  [ "$(probe 'git status && git diff --stat')" = 2 ] && pass "code mode: a multi-command line is sent to kiro-run" || failf "code mode: multi-command lines are not redirected"
fi
if [ "$cm" = enforce ] || [ "$cm" = inline ]; then
  [ "$(probe "python3 -c 'print(1)'")" = 2 ] && pass "code mode: inline code is sent to kiro-run" || failf "code mode: inline code is not redirected"
fi
[ "$(probe 'cd src && go test ./... | tail -20')" = 0 ] && pass "code mode: a single command runs directly" || failf "code mode: single commands are being redirected"
[ "$(probe "kiro-run --bash <<'EOF'${nl}git push origin main${nl}EOF")" = 2 ] && pass "programs: a step that needs approval is refused inside kiro-run" || failf "kiro-run programs can push/apply without approval"
if command -v kiro-run >/dev/null 2>&1; then
  t="$(mktemp -d)"; mkdir -p "$t/helm/app" "$t/secrets"; printf 'replicas: 1\n' > "$t/helm/app/values.yaml"; printf 'password: Dr-Check-Value-1\n' > "$t/secrets/s.yaml"
  out="$(cd "$t" && printf 'import kt\nkt.show("helm/app/values.yaml")\nprint(open("secrets/s.yaml").read())\nkt.show("secrets/s.yaml")\n' | kiro-run 2>&1)"; rc=$?; rm -rf "$t"
  [ "$rc" = 0 ] && pass "programs: a folder named helm/ and a secrets file do not stop a program" || failf "kiro-run refused a local, read-only program (exit $rc)"
  case "$out" in *Dr-Check-Value-1*) failf "kiro-run let a value from a secrets file through" ;; *"password: [redacted]"*) pass "programs: values from secrets files come out as [redacted]" ;; *) failf "kiro-run did not mask the secrets file: $out" ;; esac
  if [ "$(cget RUN_ALLOW_ADMIN 0)" = 1 ]; then
    warnf "RUN_ALLOW_ADMIN=1 in kiro-guard.conf: programs run cluster and cloud commands with whatever credentials are active"
  else
    t="$(mktemp -d)"; (cd "$t" && printf 'kubectl get pods -A\n' | env -u KUBECONFIG kiro-run --bash >/dev/null 2>&1); rc=$?; rm -rf "$t"
    [ "$rc" = 77 ] && pass "programs: a real cluster command needs read-only credentials" || failf "kiro-run ran kubectl without read-only credentials (exit $rc)"
  fi
fi
# the sandbox (RUN_SANDBOX): bubblewrap from a system path only, and it has to really start here
sb=$(cget RUN_SANDBOX off)
if [ "$sb" != off ]; then
  bw=""; for b in /usr/bin/bwrap /bin/bwrap; do [ -x "$b" ] && { bw="$b"; break; }; done
  why=""
  [ "$(uname -s)" = Linux ] || why="the sandbox needs Linux"
  [ -z "$why" ] && [ -z "$bw" ] && why="bubblewrap is not installed in /usr/bin or /bin"
  [ -z "$why" ] && ! python3 -I "$K/lib/kiro_sandbox.py" bpf >/dev/null 2>&1 && why="no seccomp filter for $(uname -m)"
  [ -z "$why" ] && ! "$bw" --ro-bind / / --unshare-all --die-with-parent --new-session --proc /proc --dev /dev -- /bin/true >/dev/null 2>&1 \
    && why="bubblewrap cannot start here (user namespaces disabled, or an AppArmor rule)"
  if [ -z "$why" ]; then pass "sandbox: RUN_SANDBOX=$sb, bubblewrap starts (network: $(cget RUN_SANDBOX_NET deny))"
  elif [ "$sb" = require ]; then failf "sandbox: RUN_SANDBOX=require but $why: every kiro-run program is refused"
  else warnf "sandbox: RUN_SANDBOX=auto but $why: programs run without it"; fi
fi
if command -v kiro-run >/dev/null 2>&1; then
  t="$(mktemp -d)"; out="$(cd "$t" && printf 'print(1)\n' | env -u NO_COLOR kiro-run 2>&1 | head -n 1)"; rm -rf "$t"
  case "$out" in *"◆ code mode"*) pass "colours: a program's result opens with the code-mode banner (NO_COLOR=1 turns colours off)" ;; *) warnf "kiro-run prints no code-mode banner: $out" ;; esac
fi
[ "$(probe "kiro-run <<'EOF'${nl}import kt${nl}kt.tree()${nl}EOF")" = 0 ] && pass "programs: a read-only program is allowed" || failf "read-only kiro-run programs are blocked"
if command -v kiro-run >/dev/null 2>&1; then
  t="$(mktemp -d)"; out="$(cd "$t" && printf 'for i in range(240): print("row %%03d " %% i + "x" * 200)\n' | kiro-run 2>&1)"
  id="$(printf '%s\n' "$out" | sed -n 's/.*kiro-run --more \([0-9-]*\) 2$/\1/p' | head -1)"
  [ "${#out}" -lt 30000 ] && [ -n "$id" ] && (cd "$t" && kiro-run --more "$id" 2 2>/dev/null | grep -q "part 2 of 2") \
    && pass "programs: long output comes in parts that fit one tool result (kiro-run --more)" || failf "kiro-run returned ${#out} characters at once: Kiro cuts results of 30,000 or more"
  rm -rf "$t"
fi
sr=$(cget SECRET_READS mask)
if [ "$sr" = mask ]; then
  t="$(mktemp -d)"; printf '{"hook": "https://x.example/invoke?v=1&sig=Dr0ctorCheckValue1234567890ab"}\n' > "$t/hooks.json"; printf 'nothing here\n' > "$t/plain.txt"
  rd() { printf '{"hook_event_name":"PreToolUse","tool_name":"read_file","cwd":"%s","tool_input":{"path":"%s"}}' "$t" "$1" | bash "$g" 2>&1; echo "rc=$?"; }
  a="$(rd hooks.json)"; b="$(rd plain.txt)"; rm -rf "$t"
  case "$a" in *Dr0ctorCheckValue*) failf "the guard's own message leaked a secret value" ;; *"kt.read("*"rc=2") pass "reads: a file that holds a secret value is read masked (kt.read), not by the read tool" ;; *) failf "the read tool can show a file that holds a secret value" ;; esac
  [ "$b" = "rc=0" ] && pass "reads: files without secrets are read as usual" || failf "the read tool is blocked for a harmless file: $b"
else
  warnf "SECRET_READS=$sr: reads are not checked for secret values"
fi
wo=$(cget WEB_OUTBOUND block)
if [ "$wo" = block ]; then
  wq() { python3 -c 'import json,os,sys; print(json.dumps({"hook_event_name":"PreToolUse","tool_name":"web_search","cwd":os.getcwd(),"tool_input":{"query":sys.argv[1]}}))' "$1" | bash "$g" >/dev/null 2>&1; echo $?; }
  [ "$(wq 'dial tcp 10.20.30.40:5432 i/o timeout')" = 2 ] && [ "$(wq "permission denied $HOME/.ssh/config")" = 2 ] \
    && pass "web: a search that carries a private address or a local path is refused" || failf "web searches can send private addresses and local paths"
  [ "$(wq 'kubernetes 1.31 release notes policy/v1beta1')" = 0 ] && pass "web: version and documentation searches go through" || failf "web: a plain version search is refused"
else
  warnf "WEB_OUTBOUND=$wo: web searches and fetches are not checked for data from this machine"
fi
python3 -c 'import json, sys; a = json.load(open(sys.argv[1])); d = {r["capability"] for r in a["permissions"]["rules"] if r["effect"] == "deny"}
sys.exit(0 if {"fs_read", "shell"} <= d and "read" not in a["tools"] else 1)' "$K/agents/fact-check.json" 2>/dev/null \
  && pass "fact-check: web only, it cannot read files it could send" || warnf "fact-check can read files (an older copy: run install.sh)"
r="$K/hooks/scripts/skill-router.sh"
if [ -f "$r" ]; then
  [ "$(printf '{"hook_event_name":"UserPromptSubmit","prompt":"review this repo"}' | bash "$r" | grep -c '^## Method\|^## Output')" = 2 ] && [ -z "$(printf '{"hook_event_name":"UserPromptSubmit","prompt":"fix the typo"}' | bash "$r")" ] \
    && pass "skill-router: a review prompt gets the code-review skill, others are left alone" || failf "skill-router does not give review prompts the code-review skill"
  printf '{"hook_event_name":"UserPromptSubmit","prompt":"why is the deployment failing?"}' | bash "$r" | grep -q '"role": "fact-check"' \
    && printf '{"hook_event_name":"UserPromptSubmit","prompt":"plan the upgrade to 1.31"}' | bash "$r" | grep -q '"role": "skeptic"' \
    && [ -z "$(printf '{"hook_event_name":"UserPromptSubmit","prompt":"run terraform plan"}' | bash "$r")" ] \
    && pass "skill-router: a failure gets the troubleshoot skill, a change to plan gets the plan skill" || failf "skill-router does not route troubleshooting or planning prompts"
fi
team_ok=1; for a in fact-check scout skeptic $([ -f "$K/agents/auditor.json" ] && echo auditor); do
  python3 -c 'import json, sys; a = json.load(open(sys.argv[1])); assert a["name"] == sys.argv[2] and a["permissions"]["rules"] and a["prompt"]' "$K/agents/$a.json" "$a" 2>/dev/null || team_ok=0
  if python3 -c 'import yaml' 2>/dev/null; then       # a merged permissions.yaml lists match entries one per line
    python3 -c 'import sys, yaml
rules = (yaml.safe_load(open(sys.argv[1])) or {}).get("rules") or []
sys.exit(0 if any(r.get("capability") == "subagent" and r.get("effect") == "allow" and sys.argv[2] in (r.get("match") or []) for r in rules) else 1)' \
      "$K/settings/permissions.yaml" "$a" 2>/dev/null || team_ok=0
  else
    grep -A8 'capability: subagent' "$K/settings/permissions.yaml" 2>/dev/null | grep -q "$a" || team_ok=0
  fi
done
[ "$team_ok" = 1 ] && pass "team: the helper agents are installed and run without a prompt" || failf "a helper agent is missing, invalid or not allowed in permissions.yaml (run install.sh)"
echo "  info  GUARD_MODE=$(cget GUARD_MODE destructive)  CODE_MODE=$cm  SECRET_READS=$sr  RUN_SANDBOX=$(cget RUN_SANDBOX off)  RUN_ALLOW_ADMIN=$(cget RUN_ALLOW_ADMIN 0)"

echo "== credentials (the layer that cannot be bypassed)"
if have kubectl; then
  ro="${KIRO_KUBECONFIG:-$HOME/.kube/kiro-readonly.yaml}"
  if [ -f "$ro" ]; then
    d=$(KUBECONFIG="$ro" timeout 10 kubectl auth can-i delete pods -A 2>/dev/null); s=$(KUBECONFIG="$ro" timeout 10 kubectl auth can-i get secrets -A 2>/dev/null)
    [ "$d" = no ] && pass "read-only kubeconfig cannot delete pods" || warnf "read-only kubeconfig: delete pods = '${d:-unreachable}'"
    [ "$s" = no ] && pass "read-only kubeconfig cannot read secrets" || warnf "read-only kubeconfig: get secrets = '${s:-unreachable}'"
  else warnf "no read-only kubeconfig ($ro). Run safety/make-readonly-kubeconfig.sh"; fi
  cur=$(kubectl config current-context 2>/dev/null); [ -n "$cur" ] && echo "  info  current context (your shell): $cur"
fi
if have az; then
  d="${KIRO_AZURE_CONFIG_DIR:-$HOME/.azure-kiro}"
  if [ -d "$d" ] && [ -n "$(ls -A "$d" 2>/dev/null)" ]; then
    roles=$(AZURE_CONFIG_DIR="$d" timeout 20 az role assignment list --all --assignee "$(AZURE_CONFIG_DIR="$d" az account show --query user.name -o tsv 2>/dev/null)" --query "[].roleDefinitionName" -o tsv 2>/dev/null | sort -u | paste -sd, -)
    if [ -n "$roles" ]; then
      echo "$roles" | tr ',' '\n' | grep -qvE '^(Reader|Monitoring Reader|Log Analytics Reader|Azure Kubernetes Service RBAC Reader|Cost Management Reader|Security Reader)$' \
        && warnf "Azure kiro profile has write-capable roles: $roles" || pass "Azure kiro profile roles: $roles"
    else warnf "could not list roles for the Azure kiro profile (not logged in?)"; fi
  else warnf "no Azure read-only profile ($d). Run safety/setup-azure-readonly.sh"; fi
fi
if have aws; then
  d="${KIRO_AWS_DIR:-$HOME/.aws-kiro}"
  if [ -s "$d/config" ]; then
    out=$(AWS_CONFIG_FILE="$d/config" AWS_SHARED_CREDENTIALS_FILE="$d/credentials" timeout 20 aws ec2 terminate-instances --instance-ids i-00000000000000000 --dry-run 2>&1)
    echo "$out" | grep -q DryRunOperation && failf "AWS kiro profile CAN terminate instances — fix its policies" || pass "AWS kiro profile cannot terminate instances"
  else warnf "no AWS read-only profile ($d). Run safety/setup-aws-readonly.sh"; fi
fi
[ -n "${AWS_ACCESS_KEY_ID:-}${AWS_PROFILE:-}" ] && warnf "AWS admin credentials/profile are set in this shell; start Kiro with kiro-safe so they are stripped"

sc="$cg"; [ "$warn" -gt 0 ] && sc="$cy"; [ "$fail" -gt 0 ] && sc="$cr"
echo "== summary: ${sc}$ok ok, $warn warnings, $fail failures${cz}"
[ "$fail" -eq 0 ]
