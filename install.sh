#!/usr/bin/env bash
# Kiro CLI v3 pack: steering + skills + hooks + permissions + safety tooling.
#   ./install.sh            install / update everything into ~/.kiro (global, applies to every repo)
#   ./install.sh --no-test  skip the guard self-test
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
K="$HOME/.kiro"
stamp="$(date +%Y%m%d-%H%M%S)"
backup="$K/backup-$stamp"

backup_file() {  # move an existing file aside before replacing it
  if [ -e "$1" ]; then mkdir -p "$backup"; cp -a "$1" "$backup/"; fi
}

mkdir -p "$K/steering" "$K/skills" "$K/hooks/scripts" "$K/settings" "$K/agents" "$K/lib" "$HOME/.local/bin"

# Retire files from earlier versions of this pack
for f in 00-efficiency.md 10-problem-solving.md 20-output-quality.md 30-devops-validation.md 30-auto-checks.md; do
  if [ -f "$K/steering/$f" ]; then backup_file "$K/steering/$f"; rm -f "$K/steering/$f"; fi
done

# Steering + skills
for f in "$here"/global/steering/*.md; do backup_file "$K/steering/$(basename "$f")"; cp "$f" "$K/steering/"; done
for d in "$here"/global/skills/*/; do
  name="$(basename "$d")"; [ -d "$K/skills/$name" ] && { mkdir -p "$backup/skills"; cp -a "$K/skills/$name" "$backup/skills/"; }
  rm -rf "$K/skills/$name"; cp -R "$d" "$K/skills/$name"
done

# Hooks (global: apply to every workspace)
for f in "$here"/global/hooks/*.json; do backup_file "$K/hooks/$(basename "$f")"; cp "$f" "$K/hooks/"; done
for f in "$here"/global/hooks/scripts/*; do
  [ -f "$f" ] || continue                       # skip __pycache__ and other directories
  base="$(basename "$f")"
  if [ "$base" = "kiro-guard.conf" ] && [ -f "$K/hooks/scripts/$base" ]; then continue; fi  # keep your settings
  cp "$f" "$K/hooks/scripts/"
done
chmod +x "$K/hooks/scripts/"*.sh "$K/hooks/scripts/kiro_guard.py"

# Helper library for kiro-run programs (kt) and the output redaction filter
cp "$here"/global/lib/*.py "$here"/global/lib/*.bash "$K/lib/"

# Agents (fact-check etc.)
for f in "$here"/global/agents/*.json; do backup_file "$K/agents/$(basename "$f")"; cp "$f" "$K/agents/"; done

# kiroignore (append missing lines)
if [ -f "$K/settings/kiroignore" ]; then
  grep -vxFf "$K/settings/kiroignore" "$here/global/kiroignore" >> "$K/settings/kiroignore" || true
else
  cp "$here/global/kiroignore" "$K/settings/kiroignore"
fi

# permissions.yaml
rendered="$(mktemp)"; sed "s|__HOME__|$HOME|g" "$here/global/permissions.yaml.tmpl" > "$rendered"
perm="$K/settings/permissions.yaml"
if [ ! -f "$perm" ]; then
  cp "$rendered" "$perm"; echo "permissions: installed $perm"
elif python3 -c 'import yaml' 2>/dev/null; then
  backup_file "$perm"
  python3 - "$perm" "$rendered" <<'PY'
import sys, yaml
cur_path, new_path = sys.argv[1], sys.argv[2]
cur = yaml.safe_load(open(cur_path)) or {}
new = yaml.safe_load(open(new_path)) or {}
rules = cur.get("rules") or []
for r in new.get("rules", []):
    if r not in rules:
        rules.append(r)
cur["rules"] = rules
with open(cur_path, "w") as fh:
    fh.write("# merged with kiro-pack rules; previous version backed up\n")
    yaml.safe_dump(cur, fh, sort_keys=False, default_flow_style=False)
print("permissions: merged pack rules into", cur_path)
PY
else
  cp "$rendered" "$K/settings/permissions.kiro-pack.yaml"
  echo "permissions: $perm exists and PyYAML is missing; merge $K/settings/permissions.kiro-pack.yaml into it by hand." >&2
fi
rm -f "$rendered"

# Launcher + doctor
cp "$here/safety/kiro-safe" "$HOME/.local/bin/kiro-safe"; chmod +x "$HOME/.local/bin/kiro-safe"
cp "$here/safety/doctor.sh" "$HOME/.local/bin/kiro-doctor"; chmod +x "$HOME/.local/bin/kiro-doctor"
cp "$here/safety/kiro-run" "$HOME/.local/bin/kiro-run"; chmod +x "$HOME/.local/bin/kiro-run"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "NOTE: add ~/.local/bin to PATH so Kiro can call kiro-run/kiro-safe" ;; esac

[ -d "$backup" ] && echo "Backups of replaced files: $backup"

if [ "${1:-}" != "--no-test" ] && command -v python3 >/dev/null 2>&1; then
  echo; echo "Self-testing kiro-guard, the helper library and kiro-run..."
  python3 "$here/tests/test_guard.py"
  python3 "$here/tests/test_lib.py"
  bash "$here/tests/test_kiro_run.sh"
fi

cat <<EOF

Installed. Next steps:
  1. Read-only credentials (strongest protection):
       $here/safety/make-readonly-kubeconfig.sh --context <your-admin-context>
       $here/safety/setup-azure-readonly.sh --sp <appId> --tenant <tenantId>
       $here/safety/setup-aws-readonly.sh --sso            (attach ReadOnlyAccess + safety/aws-readonly-deny.json)
     then start Kiro with:  kiro-safe        (in ~/.local/bin)
  2. Effort defaults: merge global/settings/cli.json.example into ~/.kiro/settings/cli.json
     (check model IDs with: kiro-cli chat --list-models).
  3. Make v3 the default engine if it is not already:  kiro-cli settings chat.agentEngine v3
     Then start a session (kiro-safe, or kiro-cli) and run /context (expect the four steering files),
     /hooks (expect kiro-guard, session-context and skill-router; validate-on-save ships disabled) and /agent
     (expect fact-check; edit ~/.kiro/agents/fact-check.json if Haiku has a different id).
  4. If you used the previous pack per repo, delete <repo>/.kiro/hooks/validate-on-save.* and
     <repo>/.kiro/steering/auto-checks.md (now global; otherwise it runs twice).
  5. Run kiro-doctor any time to verify the guardrails still hold.
Guard log: ~/.kiro/kiro-guard.log     Guard settings: ~/.kiro/hooks/scripts/kiro-guard.conf
EOF
