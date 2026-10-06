#!/usr/bin/env bash
# Behavioural tests for safety/kiro-run. Run: bash tests/test_kiro_run.sh
set -u
here="$(cd "$(dirname "$0")/.." && pwd)"; run="$here/safety/kiro-run"
T="$(mktemp -d)"; export HOME="$T"; mkdir -p "$HOME/.kiro" "$T/proj"; cd "$T/proj"; git init -q .
unset KUBECONFIG AZURE_CONFIG_DIR AWS_CONFIG_FILE KIRO_RUN_ALLOW_ADMIN KIRO_LIB KIRO_GUARD_PY KIRO_GUARD_MODE KIRO_CODE_MODE KIRO_SECRET_READS KIRO_RUN_SANDBOX KIRO_RUN_SANDBOX_NET KIRO_LOG_FILE
export NO_COLOR=1      # plain output for the checks below; the colours have their own checks (env -u NO_COLOR)
fails=0; n=0
check() { n=$((n+1)); if [ "$2" = "$3" ]; then :; else echo "FAIL [$1]: expected '$2' got '$3'"; fails=$((fails+1)); fi; }

out=$(printf 'print(sum(range(10)))\n' | bash "$run"); check "python stdin" "45" "$out"
out=$(printf 'echo a; echo b | tr b c\n' | bash "$run" --bash); check "bash stdin" "a
c" "$out"
printf 'import sys\nprint("file", sys.argv[0].endswith(".py"))\n' > s.py; out=$(bash "$run" s.py); check "file mode" "file True" "$out"
printf 'import time\ntime.sleep(5)\n' | bash "$run" --timeout 1 >/dev/null 2>&1; check "timeout rc" "124" "$?"
out=$(printf 'for i in range(300): print(i)\n' | bash "$run" --lines 20 | tail -1); case "$out" in *"280 more lines"*) check "truncation" ok ok ;; *) check "truncation" "280 more lines" "$out" ;; esac
out=$(printf 'for i in range(300): print(i)\n' | bash "$run" --raw | wc -l | tr -d ' '); check "raw" "300" "$out"
printf 'import subprocess\nsubprocess.run(["kubectl","get","pods"])\n' | bash "$run" >/dev/null 2>&1; check "k8s without RO creds refused" "77" "$?"
printf 'import boto3\n' | bash "$run" >/dev/null 2>&1; check "aws without RO creds refused" "77" "$?"
printf 'echo $(az account show)\n' | bash "$run" --bash >/dev/null 2>&1; check "azure without RO creds refused" "77" "$?"
out=$(printf 'print("kubectl would run here")\n' | KUBECONFIG="$HOME/.kube/kiro-readonly.yaml" bash "$run" 2>&1); check "k8s with RO creds runs" "kubectl would run here" "$out"
printf 'import subprocess\nsubprocess.run(["kubectl","get","pods"])\n' | KIRO_RUN_ALLOW_ADMIN=1 bash "$run" >/dev/null 2>&1; check "KIRO_RUN_ALLOW_ADMIN in the environment no longer lifts the refusal" "77" "$?"
printf 'import yaml\nprint("yaml fine")\n' | bash "$run" >/dev/null; check "non-cloud program needs no creds" "0" "$?"
printf 'raise SystemExit(3)\n' | bash "$run" >/dev/null 2>&1; check "exit code passthrough" "3" "$?"
printf 'import sys\nprint("err", file=sys.stderr)\n' | bash "$run" 2>/dev/null | grep -q err; check "stderr merged into output" "0" "$?"
grep -qx '.kiro/scratch/' .git/info/exclude; check "scratch excluded from git" "0" "$?"
[ "$(ls .kiro/scratch/*.py | wc -l | tr -d ' ')" -ge 5 ]; check "programs kept in scratch" "0" "$?"
grep -q 'kiro-run' "$HOME/.kiro/kiro-guard.log"; check "audit log written" "0" "$?"
bash "$run" </dev/null >/dev/null 2>&1; check "empty program -> error" "65" "$?"
bash "$run" --bogus </dev/null >/dev/null 2>&1; check "unknown option" "64" "$?"
# --- saved tools, helper library, redaction ---
mkdir -p .kiro/scratch/tools; printf 'import sys\nprint("args:", sys.argv[1:])\n' > .kiro/scratch/tools/t.py
out=$(bash "$run" .kiro/scratch/tools/t.py a "b c" --flag); check "args go to the saved tool" "args: ['a', 'b c', '--flag']" "$out"
printf 'echo "sh-args: $1/$2"\n' > t.sh; out=$(bash "$run" --lines 5 t.sh x y); check "options before the file, args after" "sh-args: x/y" "$out"
mkdir -p src; printf 'def alpha():\n    return 1\n\nclass Beta:\n    pass\n' > src/m.py; printf 'TOKEN=abc\n' > .env; git add -A >/dev/null 2>&1
out=$(printf 'import kt\nprint(kt.files("*.py"))\n' | bash "$run"); check "kt.files lists the repo without the scratch folder" "['s.py', 'src/m.py']" "$out"
out=$(printf 'import kt\nprint(kt.files(".env*"), kt.ignored(".env"))\nkt.show(".env")\n' | bash "$run" | tr '\n' '|'); check "kt lists no secrets file and shows one only with its values masked" "[] True|.env:1-1 (of 1 lines) — secrets file: values are masked|     1  TOKEN=[redacted]   <- unclear, 3 chars|" "$out"
out=$(printf 'import kt\nkt.outline("src/*.py")\n' | bash "$run" | tr '\n' '|'); check "kt.outline" "src/m.py (5 lines)|     1  def alpha():|     4  class Beta:|" "$out"
out=$(printf 'import kt\nkt.grep("return", "src/**/*.py")\n' | bash "$run"); check "kt.grep" "src/m.py:2:     return 1" "$out"
out=$(printf 'python3 -m kt files "m.py"\n' | bash "$run" --bash); check "kt from a bash program" "src/m.py" "$out"
out=$(printf 'import kt\nrc, _ = kt.sh("echo one; echo two; exit 3", tail=1)\nprint(rc)\n' | bash "$run" | tr '\n' '|'); check "kt.sh caps output and returns the exit code" '$ echo one; echo two; exit 3 -> exit 3 (last 1 of 2 lines)|  two|3|' "$out"
out=$(printf 'import os\nprint("t=" + os.environ["MY_API_TOKEN"])\n' | MY_API_TOKEN=s3cr3t-value-123456 bash "$run" | head -1); check "secret env value redacted" "t=[redacted]" "$out"
printf 'print("password = hunter2hunter2hunter2")\nprint("AKIAABCDEFGHIJKLMNOP")\n' | bash "$run" > r.txt; grep -q 'hunter2\|AKIAABCDEFGH' r.txt; check "secret patterns redacted" "1" "$?"
grep -q '2 secret values masked' r.txt; check "masking is reported" "0" "$?"
grep -rq 's3cr3t-value-123456\|hunter2' .kiro/scratch/*.out; check "saved output is redacted too" "1" "$?"
printf 'raise SystemExit(4)\n' | bash "$run" >/dev/null 2>&1; check "exit code survives the redaction pipe" "4" "$?"
bash "$run" --timeout abc </dev/null >/dev/null 2>&1; check "non-numeric --timeout" "64" "$?"
out=$(printf 'for i in range(300): print(i)\n' | bash "$run" | tail -1); case "$out" in *"50 more lines"*) check "default cap is 250 lines" ok ok ;; *) check "default cap is 250 lines" "50 more lines" "$out" ;; esac

# --- cloud check: what a program really runs decides, not the words in it ---
mkdir -p helm/app/templates aws k8s; printf 'replicaCount: 1\n' > helm/app/values.yaml; printf 'kind: Deployment\n' > k8s/deploy.yaml
out=$(printf 'import kt\nfor p in ["helm/app/values.yaml", "k8s/deploy.yaml"]:\n    kt.show(p)\nprint("aws azure kubectl kubernetes")\n' | bash "$run" 2>&1 | tail -1); check "paths and words named helm/aws/k8s are not cloud use" "aws azure kubectl kubernetes" "$out"
out=$(printf 'cd helm && ls app && cat ../k8s/deploy.yaml\n' | bash "$run" --bash 2>&1 | tail -1); check "a folder called helm in a bash program" "kind: Deployment" "$out"
out=$(printf '(helm lint helm/app; helm template r helm/app) >/dev/null 2>&1 || true\necho local-chart-checks-ran\n' | bash "$run" --bash 2>&1 | tail -1); check "helm lint/template need no cluster credentials" "local-chart-checks-ran" "$out"
printf 'kubectl get pods -A | head\n' | bash "$run" --bash > refusal.txt 2>&1; check "a real kubectl command is still refused" "77" "$?"
grep -q 'kubectl get pods -A' refusal.txt && grep -q 'Take it out' refusal.txt; check "the refusal names the command and says how to go on" "0" "$?"
# --- colour is for the person watching: Kiro shows the colour codes of tool output as they are ---
esc=$(printf '\033'); col() { env -u NO_COLOR bash "$run" "$@"; }
printf 'kubectl get pods -A | head\n' | col --bash 2>&1 | head -1 | grep -q "^${esc}\[1;97;41m kiro-run: refused ${esc}\[0m — "; check "the refusal label is white on red" "0" "$?"
out=$(head -1 refusal.txt); case "$out" in "kiro-run: refused — "*) check "NO_COLOR gives the plain label" ok ok ;; *) check "NO_COLOR gives the plain label" "kiro-run: refused — ..." "$out" ;; esac
out=$(printf 'import time\ntime.sleep(5)\n' | col --timeout 1 2>&1 | tail -1); check "a timeout is white on red too" "${esc}[1;97;41m kiro-run: killed after 1s timeout ${esc}[0m" "$out"
printf 'print(6 * 7)\n' | col > banner.txt 2>&1
head -1 banner.txt | grep -Eq "^${esc}\[1;38;5;212m◆ code mode${esc}\[0;38;5;87m python · [0-9]+(ms|\.[0-9]s)${esc}\[0m$"; check "a program's result opens with the code-mode banner (pink, cyan)" "0" "$?"
check "the output follows the banner unchanged" "42" "$(sed -n 2p banner.txt)"; check "the banner is one line" "2" "$(wc -l < banner.txt | tr -d ' ')"
out=$(printf 'print("password = hunter2hunter2hunter2")\n' | col 2>/dev/null | sed -n 1p); case "$out" in *"${esc}[38;5;221m· 1 secret value masked${esc}[0m") check "the banner says in yellow that secret values were masked" ok ok ;; *) check "the banner says in yellow that secret values were masked" "· 1 secret value masked" "$out" ;; esac
out=$(printf 'echo plain\n' | col --bash --raw | grep -c "$esc"); check "--raw output is never decorated" "0" "$out"
out=$(printf 'print("fine")\n' | bash "$run" 2>&1 | grep -c "$esc"); check "NO_COLOR: no colour codes and no banner" "0" "$out"
printf 'import kt\nkt.sh("helm -n prod list")\n' | bash "$run" >/dev/null 2>&1; check "helm against a cluster is refused" "77" "$?"
printf 'K=kubectl; echo "$K"\n' | bash "$run" --bash >/dev/null 2>&1; check "a tool name held in a variable is seen" "77" "$?"
out=$(printf 'K=kubectl; echo "$K"\n' | KUBECONFIG="$HOME/.kube/kiro-readonly.yaml" bash "$run" --bash 2>&1); check "runs once read-only credentials are active" "kubectl" "$out"
printf 'echo t.sh >/dev/null\n' > plain.sh; bash "$run" plain.sh aws s3 ls >/dev/null 2>&1; check "a cloud command passed as arguments to a saved tool" "77" "$?"

# --- secrets never stop a program; their values never come out ---
mkdir -p config/secrets; printf '<Secrets>\n  <!-- admin key -->\n  <ApiKey>Zx9-Qp4_Lm2k</ApiKey>\n  <Db ConnectionString="Server=db.internal;Password=pw1;" />\n  <User>bob</User>\n</Secrets>\n' > config/secrets/app.xml
out=$(printf 'print(open(".env").read().strip())\n' | bash "$run" | head -1); check "a secrets file printed verbatim is masked line by line" "TOKEN=[redacted]" "$out"
out=$(printf 'import kt\nkt.show("config/secrets/app.xml")\n' | bash "$run" | tr '\n' '|'); check "kt.show gives the structure of a secrets file and what each value looks like" 'config/secrets/app.xml:1-6 (of 6 lines) — secrets file: values are masked|     1  <Secrets>|     2    <!-- admin key -->|     3    <ApiKey>[redacted]</ApiKey>   <- real-looking, 12 chars|     4    <Db ConnectionString="[redacted]" />   <- real-looking, 32 chars|     5    <User>[redacted]</User>   <- unclear, 3 chars|     6  </Secrets>|' "$out"
out=$(printf 'import re\nt = open("config/secrets/app.xml").read()\nprint("preview:", re.search("<ApiKey>(.*?)<", t).group(1)[:9], "/", re.search("String=.(.*?);P", t).group(1))\n' | bash "$run" | head -1); check "a piece of a secret printed to judge it is masked as well" "preview: [redacted] / [redacted]" "$out"

# --- reading a batch of files: one run, shown whole; bash programs have the kt commands ---
mkdir -p big; for i in 1 2 3 4; do seq 1 120 | sed "s/^/line $i./" > big/f$i.txt; done
out=$(printf 'import kt\nkt.read("big/*.txt")\n' | bash "$run" | tail -1); check "kt.read of 480 lines is shown whole, not cut at the cap" "--- read 4 files, 480 lines" "$out"
out=$(printf 'kt read big/f1.txt big/f2.txt | tail -1\nkt.show big/f3.txt 2 3 | tail -1\nkt files "f4.txt"\n' | bash "$run" --bash | tr '\n' '|'); check "bash programs have kt and kt.<name> commands" "--- read 2 files, 240 lines|     3  line 3.3|big/f4.txt|" "$out"
out=$(printf 'for i in 1 2 3 4; do cat big/f$i.txt; done\n' | bash "$run" --bash | tail -1); case "$out" in *"230 more lines not shown (cap: 250). To read files use kt.read"*) check "cat in a loop is cut and told about kt.read" ok ok ;; *) check "cat in a loop is cut and told about kt.read" "cap message" "$out" ;; esac
out=$(printf 'import re\nt = open("config/secrets/app.xml").read()\nprint("key is", re.search("<ApiKey>(.*?)<", t).group(1), "and the server is db.internal")\n' | bash "$run" | head -1); check "a value taken out of a secrets file is masked wherever it is printed" "key is [redacted] and the server is db.internal" "$out"
out=$(printf 'cat config/secrets/app.xml\n' | bash "$run" --bash | grep -c 'Zx9-Qp4_Lm2k\|pw1\|bob'); check "cat of a secrets file leaks nothing" "0" "$out"
printf 'API_TOKEN=Zx9Qp4Lm2kV7Rt3Ws8Nb\nREGION=westeurope\n' > app.env; printf 'jobs:\n  deploy:\n    token: Zx9Qp4Lm2kV7Rt3Ws8Nb\n    dbPassword: Summer2024!\n' > ci.yaml
out=$(printf 'cat app.env; kt read app.env\n' | bash "$run" --bash | grep -c 'Zx9Qp4Lm2kV7Rt3Ws8Nb'); check "a file named *.env is a secrets file: its token never comes out" "0" "$out"
out=$(printf 'cat ci.yaml\n' | bash "$run" --bash | tr '\n' '|'); check "a token and a short password in an ordinary file are masked by their key" 'jobs:|  deploy:|    token: [redacted]|    dbPassword: [redacted]|[kiro-run: 2 secret values masked as [redacted] in this output]|' "$out"; rm -f app.env ci.yaml
out=$(printf 'import kt\nprint(kt.tree())\n' | bash "$run"); case "$out" in *"hidden by .kiroignore, 2 files: .env (secrets), config/secrets/app.xml (secrets)"*) check "tree names the hidden files" ok ok ;; *) check "tree names the hidden files" "hidden by .kiroignore, 2 files ..." "$out" ;; esac
case "$out" in *"{'files'"*) check "print(kt.tree()) does not dump the returned data" "no dict" "dict printed" ;; *) check "print(kt.tree()) does not dump the returned data" ok ok ;; esac
case "$out" in *"s.py"*"t.sh"*) check "tree lists the file names of a small project" ok ok ;; *) check "tree lists the file names of a small project" "names" "$out" ;; esac
out=$(printf 'print("id AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh ok src/Very/Long/Path/To/SomeFile2.go")\n' | bash "$run" | head -1); check "a long random token is masked, a path is not" "id [redacted] ok src/Very/Long/Path/To/SomeFile2.go" "$out"

# --- a program that hangs: cut before Kiro kills the call, and what it printed still comes back ---
out=$(printf 'print("before the hang")\nimport time\ntime.sleep(5)\n' | bash "$run" --timeout 1 2>/dev/null | head -1); check "a program that hangs still returns what it printed" "before the hang" "$out"
[ "$(sed -n 's/^timeout_s=\([0-9]*\);.*/\1/p' "$run")" -lt 120 ]; check "the default timeout is under the 120 s at which Kiro kills a shell call" "0" "$?"
out=$(printf 'import kt\nrc, _ = kt.sh("sleep 5", timeout=1)\nprint("next check still runs, rc", rc)\n' | bash "$run" | tail -1); check "kt.sh cuts one hanging check and the program goes on" "next check still runs, rc 124" "$out"

# --- one tool result holds about 28,000 characters: longer output comes in parts ---
mkdir -p lots; for i in 1 2 3 4 5 6; do seq 1 300 | sed "s/^/x = 'file $i, a line of source long enough to matter'  # /" > lots/m$i.py; done
printf 'import kt\nkt.read("lots/*.py")\n' | bash "$run" > p1.txt
[ "$(wc -m < p1.txt)" -lt 30000 ]; check "a long read returns one part that fits a tool result" "0" "$?"
id=$(sed -n 's/.*kiro-run --more \([0-9-]*\) 2$/\1/p' p1.txt | head -1)
grep -q "part 1 of 5" p1.txt && grep -q "ONE step" p1.txt && [ -n "$id" ] && grep -q "kiro-run --more $id 5" p1.txt; check "part 1 names the calls that fetch the others" "0" "$?"
ok=0; for k in 2 3 4 5; do bash "$run" --more "$id" $k > p$k.txt 2>&1 </dev/null || ok=1; [ "$(wc -m < p$k.txt)" -lt 30000 ] || ok=1; done; check "every later part comes back with --more and fits too" "0" "$ok"
tail -1 p5.txt | grep -q "part 5 of 5 — end of the output"; check "the last part says it is the last" "0" "$?"
cat > join.py <<'JOIN'
import glob, re
full = max((open(f).read() for f in glob.glob(".kiro/scratch/run-*.out")), key=len)
got = "".join(re.sub(r"\[kiro-run: part \d+ of \d+[\s\S]*\Z", "", open("p%d.txt" % k).read()) for k in (1, 2, 3, 4, 5))
print(got == full and "--- read 6 files, 1800 lines" in got)
JOIN
out=$(python3 join.py); check "the parts put together are the whole output" "True" "$out"; rm -f join.py p?.txt
bash "$run" --more "$id" 9 >/dev/null 2>more.err </dev/null; check "a part that does not exist" "66" "$?"
grep -q "the others are: 2 3 4 5" more.err; check "... says which parts there are" "0" "$?"; rm -f more.err
bash "$run" --more "../../etc/passwd" 2 >/dev/null 2>&1 </dev/null; check "--more takes a run id, not a path" "64" "$?"
bash "$run" --more "" 2 >/dev/null 2>&1 </dev/null; check "--more without an id is an error, not a program read from stdin" "64" "$?"
bash "$run" --more 20200101-000000-1 2 >/dev/null 2>&1 </dev/null; check "--more for an unknown run" "66" "$?"
out=$(printf 'print("z" * 70000)\n' | bash "$run" | wc -m | tr -d ' '); [ "$out" -lt 30000 ]; check "one enormous line is cut into parts as well" "0" "$?"
out=$(printf 'for i in range(400): print("row", i, "y" * 150)\n' | bash "$run" --lines 300 | tail -6 | tr '\n' ' '); case "$out" in *"part 1 of 2"*) check "the line cap applies first, then the parts" ok ok ;; *) check "the line cap applies first, then the parts" "part 1 of 2" "$out" ;; esac
out=$(printf 'for i in range(40): print("row", i, "y" * 150)\n' | KIRO_RUN_CHARS=3000 bash "$run" | grep -c "kiro-run --more"); check "KIRO_RUN_CHARS sets the size of a part" "2" "$out"
out=$(printf 'for i in range(300): print(i)\n' | bash "$run" --raw | wc -l | tr -d ' '); check "--raw is still everything" "300" "$out"

# --- kt.sh in a bash program: every line, the real exit code, a time limit ---
out=$(printf 'kt.sh "seq 1 100" | grep -c .\n' | bash "$run" --bash); check "bash kt.sh prints all of the output (not the last 40 lines)" "100" "$out"
out=$(printf 'kt.sh "exit 3"; echo "rc=$?"\n' | bash "$run" --bash); check "bash kt.sh keeps the exit code" "rc=3" "$out"
out=$(printf 'KT_SH_TIMEOUT=1 kt.sh "sleep 5"; echo "rc=$?"\nkt sh "echo via kt sh"\n' | bash "$run" --bash 2>&1 | tr '\n' '|'); check "bash kt.sh stops a hanging command and says so; kt sh is the same" "[kt.sh: stopped after 1s: sleep 5]|rc=124|via kt sh|" "$out"

# --- the survey, and both sides of a script call ---
mkdir -p ci ops; printf 'param (\n  [string[]] $keys,\n  [string[]] $envs\n)\nWrite-Host $keys[$envs.Length]\n' > ops/clean.ps1
printf 'steps:\n  - task: PowerShell@2\n    inputs:\n      filePath: ops/clean.ps1\n      arguments: -keys a,b,c -envs x,y\n  - script: echo ok\n' > ci/nightly.yml
out=$(printf 'import kt\nkt.calls()\n' | bash "$run"); case "$out" in *"ops/clean.ps1 (5 lines) declares:"*'$keys 5'*"called from ci/nightly.yml:4"*"arguments: -keys a,b,c -envs x,y"*) check "kt.calls puts a script's parameters next to what its caller passes" ok ok ;; *) check "kt.calls puts a script's parameters next to what its caller passes" "declares + caller" "$out" ;; esac
out=$(printf 'kt survey | grep -c "^#####"\n' | bash "$run" --bash); check "kt survey: layout, secrets, risky, calls, tools (from bash too)" "5" "$out"
out=$(printf 'import kt\nkt.review("ops/*.ps1")\n' | bash "$run"); n1=$(printf '%s\n' "$out" | wc -l | tr -d ' ')
case "$out" in *"##### layout"*"##### source"*"=== ops/clean.ps1 (5 lines) ==="*"##### working notes: fill this in"*"  ops/clean.ps1 <- ci/nightly.yml:4 :"*) check "kt.review: survey, source and the next steps in one run" ok ok ;; *) check "kt.review: survey, source and the next steps in one run" "survey + source + next" "$(printf '%s' "$out" | tail -5)" ;; esac
case "$out" in *"more lines not shown"*) check "kt.review is not cut at the line cap ($n1 lines)" "whole" "cut" ;; *) check "kt.review is not cut at the line cap" ok ok ;; esac
# --- settings come from kiro-guard.conf as installed; no environment variable weakens kiro-run ---------
# mkhome DIR [NAME=VALUE...]: a home with the pack installed the way install.sh lays it out
mkhome() {
  local h="$1" kv; shift
  mkdir -p "$h/.local/bin" "$h/.kiro/lib" "$h/.kiro/hooks/scripts"
  cp "$run" "$h/.local/bin/kiro-run"; cp "$here"/global/lib/*.py "$here"/global/lib/*.bash "$h/.kiro/lib/"
  cp "$here/global/hooks/scripts/kiro_guard.py" "$here/global/hooks/scripts/kiro-guard.conf" "$h/.kiro/hooks/scripts/"
  for kv in "$@"; do sed -i "s|^${kv%%=*}=.*|$kv|" "$h/.kiro/hooks/scripts/kiro-guard.conf"; done
}
# waitfor FILE REGEX: the record is written in the background, just after kiro-run returns
waitfor() { local i; for i in $(seq 1 50); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
H1="$T/h-admin"; mkhome "$H1" RUN_ALLOW_ADMIN=1
out=$(printf 'import shutil, subprocess\nif shutil.which("kubectl"): subprocess.run(["kubectl", "version", "--client"], capture_output=True)\nprint("admin ok")\n' | HOME="$H1" bash "$H1/.local/bin/kiro-run" 2>&1); check "RUN_ALLOW_ADMIN=1 in kiro-guard.conf lets a cloud program run" "admin ok" "$out"
H2="$T/h-plain"; mkhome "$H2"
printf 'import subprocess\nsubprocess.run(["kubectl","get","pods"])\n' | HOME="$H2" bash "$H2/.local/bin/kiro-run" >/dev/null 2>&1; check "installed: a cloud program without read-only credentials is refused" "77" "$?"
out=$(printf 'print("password = hunter2hunter2hunter2")\n' | KIRO_LIB="$T/nolib" bash "$run" | head -1); check "KIRO_LIB cannot swap out the masking filter" "password = [redacted]" "$out"
printf 'import sys\n' > "$T/fake_guard.py"
printf 'import subprocess\nsubprocess.run(["kubectl","get","pods"])\n' | KIRO_GUARD_PY="$T/fake_guard.py" bash "$run" >/dev/null 2>&1; check "KIRO_GUARD_PY cannot swap out the cloud check" "77" "$?"
rm -f "$H2/.kiro/lib/kiro_redact.py"
printf 'print("x")\n' | HOME="$H2" bash "$H2/.local/bin/kiro-run" > nored.txt 2>&1; check "no masking filter: nothing runs" "78" "$?"
grep -q "masking filter is missing" nored.txt; check "... and it says why" "0" "$?"
mkdir -p "$T/nopy"; for t in bash readlink dirname basename; do ln -sf "$(command -v $t)" "$T/nopy/$t"; done
printf 'print("x")\n' | PATH="$T/nopy" bash "$run" >/dev/null 2>&1; check "no python3: nothing runs (the output could not be masked)" "78" "$?"

# --- a failed run shows its error and its exit code; a long one its start and its end ---------------
out=$(printf 'for i in range(400): print("row", i)\nraise ValueError("the real cause")\n' | bash "$run"); rc=$?
check "a failed run keeps its exit code" "1" "$rc"
case "$out" in *"row 0"*"lines not shown; the last 60 lines follow"*"ValueError: the real cause"*"[kiro-run: exit 1; full output: "*"instead of running the program again]") check "a long failed run shows its start, its last lines (the traceback) and the exit code" ok ok ;; *) check "a long failed run shows its start, its last lines (the traceback) and the exit code" "head + tail + exit" "$(printf '%s' "$out" | tail -3)" ;; esac
[ "$(printf '%s\n' "$out" | wc -l)" -le 255 ]; check "... within the line cap" "0" "$?"
out=$(printf 'print("x")\nraise SystemExit(3)\n' | bash "$run" | tail -1); check "a short failed run ends with its exit code" "[kiro-run: exit 3]" "$out"
out=$(printf 'print("z" * 90000)\nraise SystemExit(2)\n' | bash "$run" | wc -m | tr -d ' '); [ "$out" -lt 30000 ]; check "a failed run with an enormous line still fits one result" "0" "$?"
out=$(printf 'for i in range(300): print(i)\n' | bash "$run" | tail -1); case "$out" in *"rather than running the program again]"*) check "the cap message says to read the saved output, not to run it again" ok ok ;; *) check "the cap message says to read the saved output, not to run it again" "read the saved output" "$out" ;; esac
case "$out" in *"re-run with --lines"*) check "... and no longer suggests --lines" "absent" "present" ;; *) check "... and no longer suggests --lines" ok ok ;; esac
out=$(printf 'print("ok")\n' | bash "$run" | grep -c 'kiro-run: exit'); check "a run that succeeds shows no exit line" "0" "$out"

# --- what a program starts ends with it ------------------------------------------------------------
s=$SECONDS; out=$(printf 'import subprocess\nsubprocess.Popen(["sleep", "8"], start_new_session=True)\nprint("done")\n' | bash "$run" --timeout 3 2>&1)
[ $((SECONDS - s)) -lt 5 ]; check "a detached child does not hold the result back (sleep 8, --timeout 3)" "0" "$?"
case "$out" in *"stopped 1 process the program left running"*) check "... it is stopped, and the result says so" ok ok ;; *) check "... it is stopped, and the result says so" "stopped 1 process" "$out" ;; esac
s=$SECONDS; printf 'sleep 6.5 &\necho started\n' | bash "$run" --bash --timeout 3 >/dev/null 2>&1
[ $((SECONDS - s)) -lt 5 ]; check "a background job of a bash program does not hold the result back" "0" "$?"
pgrep -f 'sleep 6.5' >/dev/null; check "... and does not outlive the run" "1" "$?"
s=$SECONDS; printf 'import subprocess, time\nsubprocess.Popen(["sleep", "31.5"])\ntime.sleep(20)\n' | bash "$run" --timeout 1 >/dev/null 2>&1; check "a timeout still exits 124" "124" "$?"
[ $((SECONDS - s)) -lt 5 ]; check "... promptly" "0" "$?"
pgrep -f 'sleep 31.5' >/dev/null; check "a timeout ends the processes the program started" "1" "$?"

# --- bash programs are syntax-checked first: nothing runs when one line is wrong -----------------------
printf 'echo first step ran > marker.txt\nif then\n' | bash "$run" --bash > syn.txt 2>&1; check "a bash syntax error is exit 65" "65" "$?"
[ -e marker.txt ]; check "... and the lines before the error did not run" "1" "$?"
grep -q "syntax error — nothing was executed" syn.txt && grep -q "line 2" syn.txt; check "... and the message says so with bash's own words" "0" "$?"

# --- what a failed run changed; one record per run; the audit log ------------------------------------
printf 'tracked\n' > keep.txt; git add keep.txt >/dev/null 2>&1
out=$(printf 'open("keep.txt", "a").write("more\\n")\nopen("newfile.txt", "w").write("x")\nraise SystemExit(1)\n' | bash "$run")
case "$out" in *"changed before it failed: keep.txt, newfile.txt — inspect before running it again]"*) check "a failed run lists the files it changed" ok ok ;; *) check "a failed run lists the files it changed" "keep.txt, newfile.txt" "$(printf '%s' "$out" | tail -2)" ;; esac
rm -f newfile.txt; git checkout -q keep.txt 2>/dev/null
printf 'print("no change")\nraise SystemExit(1)\n' | bash "$run" | grep -c 'changed before it failed' > cnt.txt; check "... and nothing when it changed nothing" "0" "$(cat cnt.txt)"
J=.kiro/scratch/runs.jsonl
printf '# Q: the unique question\nprint("OUTPUT-MARKER-77")\n' | bash "$run" >/dev/null
waitfor "$J" '"question": "Q: the unique question"'; check "every run is recorded with the question it answers" "0" "$?"
grep -q 'OUTPUT-MARKER-77"' "$J"; check "... and never with its output" "1" "$?"
printf 'import subprocess\nsubprocess.run(["kubectl","get","pods"])\n' | bash "$run" >/dev/null 2>&1
waitfor "$J" '"outcome": "refused"'; check "a refused run is recorded too" "0" "$?"
printf 'import time\ntime.sleep(3)\n' | bash "$run" --timeout 1 >/dev/null 2>&1
waitfor "$J" '"outcome": "timed_out"'; check "a timed-out run is recorded as such" "0" "$?"
waitfor "$J" '"outcome": "syntax"'; check "a syntax error is recorded as such" "0" "$?"
python3 -c 'import json,sys; [json.loads(l) for l in open(sys.argv[1])]' "$J"; check "runs.jsonl is valid JSON lines" "0" "$?"
python3 -c 'import json,sys; r=[json.loads(l) for l in open(sys.argv[1])]; k={"v","id","ts","cwd","git_head","lang","prog","sha256","question","outcome","rc","ms","timeout_s","lines_out","parts","masked","sandbox"}; sys.exit(0 if all(k <= set(x) for x in r) else 1)' "$J"; check "each record has the agreed fields" "0" "$?"
G="$HOME/.kiro/kiro-guard.log"
waitfor "$G" 'REFUSED	kiro-run	rc=77'; check "a refused run is in the audit log" "0" "$?"
printf 'import sys\nprint(len(sys.argv))\n' > argtool.py; bash "$run" argtool.py "password=hunter2hunter2hunter2" >/dev/null
waitfor "$G" 'argtool.py password=\[redacted\]'; check "arguments are masked in the audit log" "0" "$?"
grep -q 'hunter2hunter2' "$G" "$J"; check "... and in the run record" "1" "$?"

# --- background jobs: started detached, output fetched masked, exit code at the end --------------------
out=$(printf '# Q: a long suite\nimport time\nfor i in range(4):\n    print("step", i, flush=True); time.sleep(0.4)\nprint("password = hunter2hunter2hunter2")\nraise SystemExit(3)\n' | bash "$run" --bg); rc=$?
id=$(printf '%s' "$out" | sed -n 's/.*job \([0-9-]*\) started.*/\1/p'); check "--bg returns at once with a job id" "0:yes" "$rc:$([ -n "$id" ] && echo yes)"
out=$(bash "$run" --jobs); case "$out" in *"$id  running"*'"Q: a long suite"'*) check "--jobs lists it, running, with its question" ok ok ;; *) check "--jobs lists it, running, with its question" "running" "$out" ;; esac
out=$(bash "$run" --wait "$id" 10); rc=$?; check "--wait returns the job's exit code once it ended" "3" "$rc"
case "$out" in *"step 0"*"step 3"*"password = [redacted]"*"ended: exit 3"*) check "--wait shows the output, masked, and how it ended" ok ok ;; *) check "--wait shows the output, masked, and how it ended" "steps + masked + exit" "$out" ;; esac
[ ! -e ".kiro/scratch/jobs/$id.raw" ] && ! grep -q hunter2 ".kiro/scratch/jobs/$id.out"; check "once it ended, only the masked output is kept" "0" "$?"
out=$(bash "$run" --wait "$id" 1 | tail -1); case "$out" in *"ended: exit 3"*) check "--wait again: nothing new, same end" ok ok ;; *) check "--wait again: nothing new, same end" "ended" "$out" ;; esac
out=$(printf 'print("a", flush=True)\nimport time\ntime.sleep(30)\n' | bash "$run" --bg); id2=$(printf '%s' "$out" | sed -n 's/.*job \([0-9-]*\) started.*/\1/p')
out=$(bash "$run" --wait "$id2" 1); case "$out" in "a"*"still running"*"kiro-run --wait $id2"*) check "--wait on a running job: its new output, and how to wait again" ok ok ;; *) check "--wait on a running job: its new output, and how to wait again" "a ... still running" "$out" ;; esac
out=$(bash "$run" --stop "$id2"); case "$out" in *"stopped"*) check "--stop stops it" ok ok ;; *) check "--stop stops it" stopped "$out" ;; esac
bash "$run" --wait "$id2" 1 >/dev/null; check "--wait on a stopped job is not a success" "1" "$?"
pgrep -f "run-$id2" >/dev/null; check "... and nothing of it is left running" "1" "$?"
for k in 1 2 3 4; do printf 'import time\ntime.sleep(20)  # job %s\n' "$k" | bash "$run" --bg >/dev/null; done
printf 'print(1)\n' | bash "$run" --bg >/dev/null 2>&1; check "at most 4 jobs run at once" "75" "$?"
for j in $(ls .kiro/scratch/jobs/*.json | sed 's|.*/||; s|\.json$||'); do bash "$run" --stop "$j" >/dev/null; done
bash "$run" --wait 20200101-000000-1 1 >/dev/null 2>&1; check "--wait for an unknown job" "66" "$?"
bash "$run" --wait "../x" >/dev/null 2>&1; check "--wait takes a job id, not a path" "64" "$?"
printf 'print(1)\n' | bash "$run" --bg --timeout 4000 >/dev/null 2>&1; check "a job runs at most 3600 s" "64" "$?"
printf 'import subprocess\nsubprocess.run(["kubectl","get","pods"])\n' | bash "$run" --bg >/dev/null 2>&1; check "--bg applies the same cloud check" "77" "$?"

# --- scratch cleanup: runs and finished jobs older than 7 days go; saved tools, recent files, a running
# job and anything outside .kiro/scratch stay -----------------------------------------------------------
C="$T/clean"; mkdir -p "$C/.kiro/scratch/tools" "$C/.kiro/scratch/jobs"; (cd "$C" && git init -q .)
( cd "$C/.kiro/scratch" && for f in run-20200101-000000-1.py run-20200101-000000-1.out run-20200101-000000-1.snap tools/old-tool.py; do echo x > "$f"; done
  echo x > run-20990101-000000-9.out; echo 0 > jobs/20200101-000000-2.rc; echo '{}' > jobs/20200101-000000-2.json; echo x > jobs/20200101-000000-2.out )
echo note > "$C/.kiro/notes.md"
sleep 30 & live=$!
( cd "$C" && python3 "$here/global/lib/kiro_jobs.py" register .kiro/scratch/jobs 20200101-000000-3 "$live" 60 python x.py )
touch -d '10 days ago' "$C"/.kiro/scratch/run-2020* "$C"/.kiro/scratch/tools/old-tool.py "$C"/.kiro/scratch/jobs/* "$C/.kiro/notes.md"
out=$(cd "$C" && printf 'print("ok")\n' | bash "$run" 2>&1)
left="$(cd "$C/.kiro" && ls scratch/run-2020* scratch/jobs/20200101-000000-2.* 2>/dev/null | wc -l | tr -d ' ')"
check "cleanup: runs and finished jobs older than 7 days are removed" "ok 0" "$out $left"
kept=0; for f in scratch/tools/old-tool.py scratch/run-20990101-000000-9.out scratch/jobs/20200101-000000-3.json notes.md; do [ -e "$C/.kiro/$f" ] && kept=$((kept+1)); done
check "cleanup: saved tools, recent runs, a running job and files outside scratch stay" "4" "$kept"
kill "$live" 2>/dev/null
python3 -c 'import json; print("\n".join(json.dumps({"id": str(i), "pad": "x" * 900}) for i in range(5200)))' > "$C/.kiro/scratch/runs.jsonl"
(cd "$C" && printf '# Q: the newest record\nprint(2)\n' | bash "$run" >/dev/null 2>&1)
for i in $(seq 1 50); do tail -1 "$C/.kiro/scratch/runs.jsonl" | grep -q 'the newest record' && break; sleep 0.1; done
out="$(wc -l < "$C/.kiro/scratch/runs.jsonl" | tr -d ' '):$(tail -1 "$C/.kiro/scratch/runs.jsonl" | grep -c 'the newest record')"
check "runs.jsonl keeps the newest 5,000 records" "5000:1" "$out"

# --- output cap: what a program prints is kept up to the cap; a runaway printer is stopped -------------
out=$(cd "$C" && printf 'import sys\nsys.stdout.write(("y" * 99 + "\\n") * 30000)\nprint("done")\n' | KIRO_RUN_CAP_MB=1 bash "$run" 2>&1 | tail -1)
case "$out" in "[kiro-run: output cut at 1 MB: print findings"*) check "cap: output past the cap is cut, and the run says so" ok ok ;; *) check "cap: output past the cap is cut, and the run says so" "cut at 1 MB" "$out" ;; esac
o="$(ls -t "$C"/.kiro/scratch/run-*.out | head -1)"; [ "$(wc -c < "$o")" -le 1048576 ]; check "cap: the saved output is cut too" "0" "$?"
s=$SECONDS; out=$(cd "$C" && printf 'while True:\n    print("z" * 200)\n' | KIRO_RUN_CAP_MB=1 bash "$run" --timeout 30 2>&1 | tr '\n' ' ')
case "$out" in *"output cut at 1 MB; the program was stopped"*) check "cap: a runaway printer is stopped" ok ok ;; *) check "cap: a runaway printer is stopped" "stopped" "${out: -300}" ;; esac
[ $((SECONDS - s)) -lt 10 ]; check "cap: ... within seconds, not at its timeout" "0" "$?"
out=$(cd "$C" && printf 'print(1)\n' | KIRO_RUN_CAP_MB=999 bash "$run" 2>&1); check "cap: the environment can only lower it" "1" "$out"
grep -q '^cap_mb=20 ' "$run"; check "cap: 20 MB by default" "0" "$?"
out=$(cd "$C" && printf 'while True:\n    print("j" * 200, flush=True)\n' | KIRO_RUN_CAP_MB=1 bash "$run" --bg --timeout 60); jid=$(printf '%s' "$out" | sed -n 's/.*job \([0-9-]*\) started.*/\1/p')
out=$(cd "$C" && bash "$run" --wait "$jid" 15 | tail -2 | tr '\n' ' ')
case "$out" in *"output cut at 1 MB; the job was stopped"*"exit"*) check "cap: a background job that prints too much is stopped" ok ok ;; *) check "cap: a background job that prints too much is stopped" "cut + exit" "$out" ;; esac

# --- hints: one line for errors whose fix is not in the traceback (only the edges of the output are read)
hint() { printf '%b' "$1" > "$T/h.out"; python3 "$here/global/lib/kiro_hint.py" "$T/h.out" "$2" "$3"; }
case "$(hint "OSError: [Errno 30] Read-only file system: '/home/u/x'\n" 1 deny)" in *"sandbox keeps everything outside the project read-only"*) check "hint: read-only file system in the sandbox" ok ok ;; *) check "hint: read-only file system in the sandbox" hint "" ;; esac
check "hint: read-only file system outside the sandbox: none" "" "$(hint "OSError: [Errno 30] Read-only file system\n" 1 off)"
case "$(hint "urllib.error.URLError: <urlopen error [Errno -3] Temporary failure in name resolution>\n" 1 deny)" in *"no network"*"direct command"*) check "hint: no network in the sandbox" ok ok ;; *) check "hint: no network in the sandbox" hint "" ;; esac
check "hint: network error with the network allowed: none" "" "$(hint "Temporary failure in name resolution\n" 1 allow)"
case "$(hint "PermissionError: [Errno 1] Operation not permitted\n  at socket.connect\n" 1 deny)" in *"no network"*) check "hint: a refused socket in the sandbox" ok ok ;; *) check "hint: a refused socket in the sandbox" hint "" ;; esac
check "hint: a refused chmod is not a network problem" "" "$(hint "PermissionError: [Errno 1] Operation not permitted: 'f'\n" 1 deny)"
case "$(hint "ModuleNotFoundError: No module named 'yaml'\n" 1 off)" in *"'yaml'"*"installs are refused"*) check "hint: a missing module" ok ok ;; *) check "hint: a missing module" hint "" ;; esac
case "$(hint "AttributeError: module 'kt' has no attribute 'outlines'\n" 1 off)" in *"did you mean kt.outline?"*) check "hint: a kt name that does not exist" ok ok ;; *) check "hint: a kt name that does not exist" "kt.outline" "$(hint "AttributeError: module 'kt' has no attribute 'outlines'\n" 1 off)" ;; esac
case "$(hint "    kt.grep(r'x', context=1)\nTypeError: grep() got an unexpected keyword argument 'context'\n" 1 off)" in *"kt.grep(pattern"*) check "hint: a kt call with a wrong argument shows its signature" ok ok ;; *) check "hint: a kt call with a wrong argument shows its signature" "kt.grep(pattern" "$(hint "    kt.grep(r'x', context=1)\nTypeError: grep() got an unexpected keyword argument 'context'\n" 1 off)" ;; esac
check "hint: the same error from another function: none" "" "$(hint "    foo(context=1)\nTypeError: grep() got an unexpected keyword argument 'context'\n" 1 off)"
case "$(hint "" 124 off)" in *"kiro-run --bg"*) check "hint: a timeout points to --bg" ok ok ;; *) check "hint: a timeout points to --bg" hint "" ;; esac
check "hint: an ordinary error: none" "" "$(hint "ValueError: bad input\n" 1 off)"
check "hint: at most two" "2" "$(hint "Read-only file system\nTemporary failure in name resolution\nModuleNotFoundError: No module named 'x'\n" 124 deny | wc -l | tr -d ' ')"
python3 -c 'import sys; sys.stdout.write(("filler line\n" * 3000) + "OSError: [Errno 30] Read-only file system\n" + ("filler line\n" * 3000))' > "$T/h.out"
check "hint: only the first and last 8 KB are read" "" "$(python3 "$here/global/lib/kiro_hint.py" "$T/h.out" 1 deny)"
out=$(cd "$C" && printf 'import no_such_module_x\n' | bash "$run" 2>&1 | tail -1)
case "$out" in "[kiro-run hint: no module named 'no_such_module_x'"*) check "hint: a failed run ends with its hint" ok ok ;; *) check "hint: a failed run ends with its hint" hint "$out" ;; esac

# --- repeat guard: the same program on an unchanged workspace, again and again -----------------------
R="$T/rep"; mkdir -p "$R"; (cd "$R" && git init -q . && echo a > f.txt)
r() { (cd "$R" && printf '# Q: same\nprint("same")\n' | bash "$run" 2>&1); }
r >/dev/null; r >/dev/null
(cd "$R" && bash "$run" --jobs >/dev/null)
out=$(r); case "$out" in *"run 3 times in a row on an unchanged workspace; at 6 it will be refused"*) check "repeat: a warning at the 3rd identical run (--jobs between does not count)" ok ok ;; *) check "repeat: a warning at the 3rd identical run (--jobs between does not count)" warning "$out" ;; esac
r >/dev/null; r >/dev/null
out=$(r); rc=$?
case "$rc:$out" in "76:"*"adds no information"*"Nothing was run"*) check "repeat: refused at the 6th" ok ok ;; *) check "repeat: refused at the 6th" "76 refused" "$rc:$out" ;; esac
r >/dev/null; check "repeat: ... and after" "76" "$?"
waitfor "$R/.kiro/scratch/runs.jsonl" '"outcome": "repeat"'; check "repeat: the refusal is recorded" "0" "$?"
echo b > "$R/f.txt"; check "repeat: a change to the workspace starts the count anew" "same" "$(r)"
(cd "$R" && printf '# Q: other\nprint("other")\n' | bash "$run" >/dev/null 2>&1); check "repeat: another program starts it anew too" "same" "$(r)"
N="$T/nogit"; mkdir -p "$N"; for i in 1 2 3 4 5; do (cd "$N" && printf 'print(5)\n' | bash "$run" >/dev/null 2>&1); done
(cd "$N" && printf 'print(5)\n' | bash "$run" >/dev/null 2>&1); check "repeat: outside git, the 6th identical run is refused too" "76" "$?"

# --- the sandbox (RUN_SANDBOX in kiro-guard.conf): bubblewrap from /usr/bin or /bin only ---------------
out=$(cd "$T" && mkdir -p sbhome/.ssh && HOME="$T/sbhome" python3 "$here/global/lib/kiro_sandbox.py" args "$T/proj" "$T/proj/.kiro/scratch" deny p.py "$here/global/lib" | tr '\0' ' ')
case "$out" in *"--tmpfs $T/sbhome/.ssh"*) check "sandbox: credential folders are hidden" ok ok ;; *) check "sandbox: credential folders are hidden" "--tmpfs ~/.ssh" "$out" ;; esac
case "$out" in *"--share-net"*) check "sandbox: NET=deny shares no network" "no --share-net" "$out" ;; *) check "sandbox: NET=deny shares no network" ok ok ;; esac
case "$(HOME="$T/sbhome" python3 "$here/global/lib/kiro_sandbox.py" args "$T/proj" "$T/proj/.kiro/scratch" allow p.py "$here/global/lib" | tr '\0' ' ')" in *"--share-net"*) check "sandbox: NET=allow shares the network" ok ok ;; *) check "sandbox: NET=allow shares the network" "--share-net" "" ;; esac
H3="$T/h-req"; mkhome "$H3" RUN_SANDBOX=require; sed -i 's|^bwrap_paths=.*|bwrap_paths="/nonexistent/bwrap"|' "$H3/.local/bin/kiro-run"
printf 'print("x")\n' | HOME="$H3" bash "$H3/.local/bin/kiro-run" > req.txt 2>&1; check "RUN_SANDBOX=require without bubblewrap: refused" "79" "$?"
grep -q "nothing was run" req.txt; check "... and it says nothing was run" "0" "$?"
H4="$T/h-auto"; mkhome "$H4" RUN_SANDBOX=auto; sed -i 's|^bwrap_paths=.*|bwrap_paths="/nonexistent/bwrap"|' "$H4/.local/bin/kiro-run"
out=$(printf 'print("ran")\n' | HOME="$H4" bash "$H4/.local/bin/kiro-run" 2>&1 | tr '\n' '|'); check "RUN_SANDBOX=auto without bubblewrap: runs and says so" "ran|[kiro-run: ran without the sandbox: bubblewrap is not installed (/nonexistent/bwrap)]|" "$out"
B=""; for b in /usr/bin/bwrap /bin/bwrap; do [ -x "$b" ] && { B="$b"; break; }; done
if [ -n "$B" ] && "$B" --ro-bind / / --unshare-all --die-with-parent --proc /proc --dev /dev -- /bin/true 2>/dev/null; then
  H5="$T/h-sb"; mkhome "$H5" RUN_SANDBOX=require; mkdir -p "$H5/.ssh"; echo k > "$H5/.ssh/id_test"
  cat > sbprobe.py <<'SB'
# Q: what can a sandboxed program do?
import os, socket, kt
def w(p):
    try:
        open(p, "w").write("x"); return "rw"
    except OSError:
        return "ro"
print("project", w("sb-new.txt"), "scratch", w(".kiro/scratch/sb-ok"), "git", w(".git/sb-evil"), "kiro", w(".kiro/sb-evil"))
print("ssh", os.listdir(os.path.expanduser("~/.ssh")))
try:
    socket.create_connection(("1.1.1.1", 443), timeout=2); print("net open")
except OSError:
    print("net closed")
try:
    socket.socket(socket.AF_UNIX); print("unix open")
except OSError:
    print("unix closed")
rc, _ = kt.sh("git status --short", tail=1)
print("git", rc)
SB
  out=$(HOME="$H5" bash "$H5/.local/bin/kiro-run" sbprobe.py 2>&1 | grep -v '^\$ \|^  ' | tr '\n' '|')
  check "sandbox: project and scratch writable; .git and .kiro read-only; credentials hidden; no network, no sockets; git works" "project rw scratch rw git ro kiro ro|ssh []|net closed|unix closed|git 0|" "$out"
  [ -e sb-new.txt ] && [ ! -e .git/sb-evil ]; check "sandbox: the project write is real, the .git write did not happen" "0" "$?"; rm -f sb-new.txt
  out=$(printf 'print(1)\n' | HOME="$H5" env -u NO_COLOR bash "$H5/.local/bin/kiro-run" 2>&1 | head -1); case "$out" in *"· sandbox"*) check "sandbox: the banner says so" ok ok ;; *) check "sandbox: the banner says so" "· sandbox" "$out" ;; esac
  s=$SECONDS; printf 'import subprocess\nsubprocess.Popen(["sleep", "9"], start_new_session=True)\n' | HOME="$H5" bash "$H5/.local/bin/kiro-run" --timeout 3 >/dev/null 2>&1; [ $((SECONDS - s)) -lt 5 ]; check "sandbox: a detached child ends with the run" "0" "$?"
  waitfor .kiro/scratch/runs.jsonl '"sandbox": "deny"'; check "sandbox: the record says the run was sandboxed" "0" "$?"
  # the layout of a real machine: the project inside $HOME, both outside /tmp (whose private copy would
  # hide everything and prove nothing), and a credential dotfile that is a symlink, as on WSL
  V="$(mktemp -d -p /var/tmp kiro-sbx.XXXXXX 2>/dev/null)"
  if [ -n "$V" ]; then
    H6="$V/home"; mkhome "$H6" RUN_SANDBOX=require; mkdir -p "$H6/.ssh" "$H6/dotfiles" "$H6/proj"
    echo k > "$H6/.ssh/id_test"; echo "//registry/:_authToken=sbx-secret-1" > "$H6/dotfiles/npmrc"; ln -s "$H6/dotfiles/npmrc" "$H6/.npmrc"
    cat > "$H6/proj/p.py" <<'SB'
import os
def w(p):
    try:
        open(p, "a").write(""); return "rw"
    except OSError:
        return "ro"
h = os.path.expanduser("~")
print("home", w(os.path.join(h, "x")), "conf", w(os.path.join(h, ".kiro/hooks/scripts/kiro-guard.conf")), "proj", w("ok.txt"))
print("ssh", os.listdir(os.path.join(h, ".ssh")))
try:
    print("npmrc", "leaked" if "sbx-secret-1" in open(os.path.join(h, ".npmrc")).read() else "hidden")
except OSError:
    print("npmrc hidden")
SB
    out=$(cd "$H6/proj" && git init -q . && HOME="$H6" bash "$H6/.local/bin/kiro-run" p.py 2>&1 | tr '\n' '|')
    check "sandbox, project inside \$HOME: \$HOME and kiro-guard.conf read-only, credentials hidden also behind a symlink" "home ro conf ro proj rw|ssh []|npmrc hidden|" "$out"
    rm -rf "$V"
  fi
else
  echo "(bubblewrap not usable here: the live sandbox checks are skipped)"
fi

rm -rf "$T"
if [ "$fails" -eq 0 ]; then echo "kiro-run: all $n checks passed"; else echo "kiro-run: $fails of $n FAILED"; exit 1; fi
