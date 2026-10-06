#!/usr/bin/env bash
# Behavioural tests for safety/kiro-run. Run: bash tests/test_kiro_run.sh
set -u
here="$(cd "$(dirname "$0")/.." && pwd)"; run="$here/safety/kiro-run"
T="$(mktemp -d)"; export HOME="$T"; mkdir -p "$HOME/.kiro" "$T/proj"; cd "$T/proj"; git init -q .
unset KUBECONFIG AZURE_CONFIG_DIR AWS_CONFIG_FILE KIRO_RUN_ALLOW_ADMIN
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
out=$(printf 'print("admin ok")\n' | KIRO_RUN_ALLOW_ADMIN=1 bash "$run" 2>&1); check "allow-admin override" "admin ok" "$out"
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
rm -rf "$T"
if [ "$fails" -eq 0 ]; then echo "kiro-run: all $n checks passed"; else echo "kiro-run: $fails of $n FAILED"; exit 1; fi
