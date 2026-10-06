#!/usr/bin/env bash
# kiro-pack doctor: checks that the pack is installed and that the guardrails actually hold.
# Safe to run any time; makes no changes.
set -u
K="$HOME/.kiro"; ok=0; warn=0; fail=0
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
         agents/scout.json agents/skeptic.json lib/kt.py lib/kt.bash lib/kiro_redact.py lib/kiro_page.py; do
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
words=$(cat "$K"/steering/*.md 2>/dev/null | wc -w | tr -d ' '); [ "${words:-0}" -le 1550 ] && pass "always-on steering: $words words" || warnf "always-on steering is large: $words words (loaded every turn)"

echo "== guard behaviour"
g="$K/hooks/scripts/kiro-guard.sh"
export KIRO_LOG_FILE=/dev/null   # these probes are not real events: keep them out of the audit log
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
cm=$(sed -n 's/^CODE_MODE=//p' "$K/hooks/scripts/kiro-guard.conf" 2>/dev/null); cm="${KIRO_CODE_MODE:-${cm:-enforce}}"
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
  t="$(mktemp -d)"; (cd "$t" && printf 'kubectl get pods -A\n' | env -u KUBECONFIG -u KIRO_RUN_ALLOW_ADMIN kiro-run --bash >/dev/null 2>&1); rc=$?; rm -rf "$t"
  [ "$rc" = 77 ] && pass "programs: a real cluster command needs read-only credentials" || failf "kiro-run ran kubectl without read-only credentials (exit $rc)"
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
sr=$(sed -n 's/^SECRET_READS=//p' "$K/hooks/scripts/kiro-guard.conf" 2>/dev/null); sr="${KIRO_SECRET_READS:-${sr:-mask}}"
if [ "$sr" = mask ]; then
  t="$(mktemp -d)"; printf '{"hook": "https://x.example/invoke?v=1&sig=Dr0ctorCheckValue1234567890ab"}\n' > "$t/hooks.json"; printf 'nothing here\n' > "$t/plain.txt"
  rd() { printf '{"hook_event_name":"PreToolUse","tool_name":"read_file","cwd":"%s","tool_input":{"path":"%s"}}' "$t" "$1" | bash "$g" 2>&1; echo "rc=$?"; }
  a="$(rd hooks.json)"; b="$(rd plain.txt)"; rm -rf "$t"
  case "$a" in *Dr0ctorCheckValue*) failf "the guard's own message leaked a secret value" ;; *"kt.read("*"rc=2") pass "reads: a file that holds a secret value is read masked (kt.read), not by the read tool" ;; *) failf "the read tool can show a file that holds a secret value" ;; esac
  [ "$b" = "rc=0" ] && pass "reads: files without secrets are read as usual" || failf "the read tool is blocked for a harmless file: $b"
else
  warnf "SECRET_READS=$sr: reads are not checked for secret values"
fi
r="$K/hooks/scripts/skill-router.sh"
if [ -f "$r" ]; then
  [ "$(printf '{"hook_event_name":"UserPromptSubmit","prompt":"review this repo"}' | bash "$r" | grep -c '^## Method\|^## Output')" = 2 ] && [ -z "$(printf '{"hook_event_name":"UserPromptSubmit","prompt":"fix the typo"}' | bash "$r")" ] \
    && pass "skill-router: a review prompt gets the code-review skill, others are left alone" || failf "skill-router does not give review prompts the code-review skill"
  printf '{"hook_event_name":"UserPromptSubmit","prompt":"why is the deployment failing?"}' | bash "$r" | grep -q '"role": "fact-check"' \
    && printf '{"hook_event_name":"UserPromptSubmit","prompt":"plan the upgrade to 1.31"}' | bash "$r" | grep -q '"role": "skeptic"' \
    && [ -z "$(printf '{"hook_event_name":"UserPromptSubmit","prompt":"run terraform plan"}' | bash "$r")" ] \
    && pass "skill-router: a failure gets the troubleshoot skill, a change to plan gets the plan skill" || failf "skill-router does not route troubleshooting or planning prompts"
fi
team_ok=1; for a in fact-check scout skeptic; do
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
[ "$team_ok" = 1 ] && pass "team: fact-check, scout and skeptic are installed and run without a prompt" || failf "a helper agent is missing, invalid or not allowed in permissions.yaml (run install.sh)"
mode=$(sed -n 's/^GUARD_MODE=//p' "$K/hooks/scripts/kiro-guard.conf" 2>/dev/null); echo "  info  GUARD_MODE=${mode:-destructive}  CODE_MODE=$cm  SECRET_READS=$sr"

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
