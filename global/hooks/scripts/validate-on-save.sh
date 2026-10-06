#!/usr/bin/env bash
# Kiro v3 PostFileSave hook: (1) secret scan on every saved file, (2) cheapest validator for its type.
# Exit 0 with no output -> nothing added to the agent's context (costs nothing).
# Non-zero with stderr  -> the agent sees the first errors right away.
set -u
file="${1:-}"
if [ -z "$file" ] || [[ "$file" == *"{{"* ]]; then       # no path argument: Kiro passes it as file_path in the STDIN payload
  payload="$(cat)"; file=""
  if command -v jq >/dev/null 2>&1; then
    file="$(printf '%s' "$payload" | jq -r '.file_path // .filePath // .path // .tool_input.path // .tool_input.file_path // (.tool_input.operations[0].path) // empty' 2>/dev/null | head -n1)"
  elif command -v python3 >/dev/null 2>&1; then
    file="$(printf '%s' "$payload" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("file_path") or d.get("filePath") or d.get("path") or "")' 2>/dev/null)"
  fi
fi
[ -n "$file" ] && [ -f "$file" ] || exit 0
have() { command -v "$1" >/dev/null 2>&1; }

# ---- 1. secret scan (line numbers only; values are never echoed back) ----
case "$file" in
  *example*|*sample*|*fixture*|*testdata*|*mock*|*.md|*.lock|*lock.json|*.sum) ;;
  *)
    if [ "$(wc -c < "$file")" -lt 2000000 ]; then
      fixed="$(grep -nE \
        -e 'AKIA[0-9A-Z]{16}' -e 'ASIA[0-9A-Z]{16}' \
        -e '-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----' \
        -e 'ghp_[A-Za-z0-9]{36}' -e 'github_pat_[A-Za-z0-9_]{22,}' -e 'gh[os]_[A-Za-z0-9]{36}' \
        -e 'xox[abprs]-[0-9A-Za-z-]{10,}' -e 'sk-ant-[A-Za-z0-9_-]{20,}' \
        -e 'AccountKey=[A-Za-z0-9+/=]{60,}' -e 'SharedAccessKey=[A-Za-z0-9+/=]{30,}' \
        -e '[?&]sv=20[0-9]{2}-[0-9]{2}-[0-9]{2}.*&sig=[A-Za-z0-9%+/=]{20,}' \
        -e 'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}' \
        -e '(client-key-data|client-certificate-data): *[A-Za-z0-9+/=]{100,}' \
        -e '(aws_secret_access_key|AWS_SECRET_ACCESS_KEY) *[=:] *.?[A-Za-z0-9/+=]{40}' "$file" 2>/dev/null)"
      generic="$(grep -niE \
        -e '(client[_-]?secret|api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|pwd) *[=:] *["'"'"']?[A-Za-z0-9~._+/=-]{16,}["'"'"']?' "$file" 2>/dev/null \
        | grep -vE '\$\{|\$\(|\$[A-Za-z_]|\{\{|<[A-Za-z_]|%\(|%\{|var\.|ref\(|secretKeyRef|valueFrom|keyvault|secretsmanager|ssm:|vault:|example|placeholder|changeme|dummy|xxxx|\*\*\*|REDACTED|lookup\(|data\.|random_|\.id\b|_id *[=:]|password_hash|password_file|password_policy|_version|_length|_date|_url' )"
      hits="$(printf '%s\n%s\n' "$fixed" "$generic" | grep -E '^[0-9]+:' )"
      if [ -n "$hits" ]; then
        { echo "secret-scan: $file contains what looks like a credential on line(s): $(printf '%s\n' "$hits" | cut -d: -f1 | sort -un | paste -sd, -)"
          echo "Do not commit it. Replace the value with a variable, a Key Vault / Secrets Manager reference, or an env var, and tell the user the secret may need rotating."; } >&2
        exit 1
      fi
    fi ;;
esac

# ---- 2. validators ----
out=""; rc=0
run() { out="$("$@" 2>&1)"; rc=$?; }
case "$file" in
  *.tf|*.tfvars)  have terraform && run terraform fmt -check -diff -no-color "$file" ;;
  *.bicep)        if have az; then run az bicep build --file "$file" --stdout --only-show-errors; [ "$rc" -eq 0 ] && out=""; fi ;;
  *.sh|*.bash)    if have shellcheck; then run shellcheck -f gcc -S warning "$file"; else run bash -n "$file"; fi ;;
  *.yml|*.yaml)   if have yamllint; then run yamllint -f parsable -d relaxed "$file"
                  elif have python3; then run python3 -c 'import sys,yaml; list(yaml.safe_load_all(open(sys.argv[1])))' "$file"; fi ;;
  *.json)         have jq && run jq empty "$file" ;;
  *.py)           if have ruff; then run ruff check --quiet "$file"; else run python3 -m py_compile "$file"; fi ;;
  *Dockerfile*)   have hadolint && run hadolint "$file" ;;
  *.ps1)          have pwsh && run pwsh -NoProfile -Command "[System.Management.Automation.Language.Parser]::ParseFile('$file',[ref]\$null,[ref]\$e)|Out-Null; if(\$e){\$e|%{\"\$(\$_.Extent.StartLineNumber): \$(\$_.Message)\"}; exit 1}" ;;
esac
if [ "$rc" -ne 0 ]; then
  { echo "validate-on-save: $file failed:"; printf '%s\n' "$out" | head -n 25; } >&2
  exit 1
fi
exit 0
