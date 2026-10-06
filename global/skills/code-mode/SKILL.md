---
name: code-mode
description: "How to work code-first in Kiro with kiro-run - the shape of a program, the kt helper library, and ready-made patterns for surveying a repo, pulling out just the code you need, testing a hypothesis with an experiment, comparing versions, running linters and tests with capped output, triaging logs and Terraform plans, fanning out over clusters, subscriptions and accounts, bulk edits, and saving reusable tools. Load it before writing a kiro-run program longer than a few lines, or when unsure whether something should be a program."
---

# Code mode (kiro-run)

Kiro has no programmatic tool calling, so `kiro-run` is the executor: one shell call, program on stdin, limits applied, only the result comes back. Measured: a 15-file Helm check cost ~9,000 tokens by reading and ~100 by script; a six-cluster `kubectl get pods -A` fan-out ~110,000 by tool calls and ~230 by script. A program is also the cheapest way to be right: an experiment that takes ten lines settles what three paragraphs of reasoning only guess at.

## Shape of a program
```bash
kiro-run <<'EOF'
# Q: which values files lack resources.limits?
import glob, yaml
for f in sorted(glob.glob("charts/*/values.yaml")):
    v = yaml.safe_load(open(f)) or {}
    if not v.get("resources", {}).get("limits"):
        print(f"{f}: no resources.limits")
EOF
```
- First line: the question the program answers. Last lines: findings only (one per line, or a small JSON/table, or counts). Aim under 50 lines of output; 250 lines is the cap (`--lines N` to change it) and the full output stays in `.kiro/scratch/*.out` to grep.
- One result holds about 28,000 characters. A longer one (a deliberate `kt.read`) comes in parts: part 1 ends with the `kiro-run --more ID N` calls for the others. Issue them all together in one step and read every part before concluding.
- Answer the whole question in one run: several checks in one program beat several programs.
- Let the first exception surface (its traceback is the debugging information); no blanket `try/except: pass`.
- Options go first: `--bash`, `--timeout 300`, `--lines N`, `--raw`. A saved program runs as `kiro-run file.py args`. The default timeout is 100 s, just under the 120 s after which Kiro kills a shell call; with a longer `--timeout`, give the shell tool call the same timeout.

## kt: helpers every program can import
They cap what they print and keep secrets out of it. Each prints its findings and returns the data, so call them bare (`kt.tree()`, not `print(kt.tree())`); pass `quiet=True` to get only the data.

| call | gives |
|---|---|
| `kt.survey()` | the first look at a repo in one call: `kt.tree`, `kt.secrets`, `kt.risky`, `kt.calls` and `kt.tools` (which of the stack's checkers are installed) |
| `kt.review()` or `kt.review("charts/**")` | step one of a code review, of the whole project or of one part: the survey, then `kt.read()`, then the working notes to fill in before testing |
| `kt.tree(depth=2)` | folders, files, lines by file type, and the names of the files `.kiroignore` hides |
| `kt.read("**/*")` or `kt.read(["a.py", "src/**"])` | whole files, numbered, one after another: read a batch in ONE run (shown whole, not cut at the cap; long data files are named, not printed) |
| `kt.secrets()` | committed secrets by file, line and kind, never the value; which secrets files git tracks and whether their values look real |
| `kt.risky()` | lines that are often a problem in this stack (tokens in URLs, cluster-wide RBAC, single replicas, TLS checks off, silenced errors, deletes, force flags, PowerShell variables never assigned): candidates to confirm |
| `kt.calls()` | scripts run from other files, both sides of each call: the parameters and environment the script reads, and the pipeline step, Makefile line or Dockerfile entry that passes them |
| `kt.files("**/*.tf")` | list of matching files (a glob without `/` matches at any depth) |
| `kt.grep(r"regex", "**/*.go", ctx=1, max_hits=60)` | `path:line: text` for each hit |
| `kt.outline("internal/**/*.go")` | functions, types, resources with line numbers |
| `kt.show("path", 120, 160)` or `kt.show("path", around=140)` | numbered lines of a range (the whole file, up to 400 lines, without one); a secrets file comes with every value masked |
| `kt.sh("go vet ./...", tail=40)` | exit code and the last lines of a command; returns `(rc, output)` |

In a bash program the same helpers are commands: `kt survey`, `kt read 'src/**' max_lines=800`, `kt grep 'regex' '**/*.go' ctx=1`, `kt show path 120 160`, and `kt.sh "cmd"`, which runs the command with a 60-second limit and prints all of its output (so you can pipe it into `grep`). Python syntax such as `kt.sh("...")` is a syntax error in a bash program.

To read code, use `kt.read`: several files per run, shown whole. Printing files with `cat` or `kt.show` in a loop is cut at the 250-line cap and costs a turn for every piece.

## Moves worth making
**Survey before you read** — a new repo, a review, "how does X work"
```bash
kiro-run <<'EOF'
# Q: what is in this repo, where is the weight, what state is it in?
import kt
kt.survey()
kt.outline("**/*.go", max_lines=120)
kt.sh("git log --oneline -8")
EOF
```
**Extract, don't read** — pull out the functions you need instead of opening whole files
```bash
kiro-run <<'EOF'
# Q: show only the request handling of the proxy
import kt
for path, line, sig in kt.outline("internal/egress/*.go", quiet=True):
    if "http" in sig or "open(" in sig:
        kt.show(path, line, line + 45)
EOF
```
**Experiment before you claim** — when a conclusion rests on how a library, flag or runtime behaves, run it
```bash
kiro-run <<'EOF'
# Q: does http.Request.Write send an absolute-form request line for a proxied request?
import os, tempfile, kt
d = tempfile.mkdtemp()
open(os.path.join(d, "go.mod"), "w").write("module x\ngo 1.21\n")
open(os.path.join(d, "main.go"), "w").write('''package main
import ("bufio"; "net/http"; "os"; "strings")
func main() {
    r, _ := http.ReadRequest(bufio.NewReader(strings.NewReader("GET http://example.com/a?x=1 HTTP/1.1\\r\\nHost: h\\r\\n\\r\\n")))
    r.Write(os.Stdout)
}''')
kt.sh("go run .", cwd=d, tail=6)
EOF
```
**Check everything at once** — the project's own linters and tests, only what failed
```bash
kiro-run --timeout 300 <<'EOF'
# Q: what do the project's checks say, and where are the risky constructs?
import kt
for cmd in ("go vet ./...", "gofmt -l .", "go test -short ./... 2>&1 | grep -v '^ok'"):
    kt.sh(cmd, tail=15)
kt.grep(r"exec\.Command|os\.(Remove|Chmod)|InsecureSkipVerify|unsafe\.", "**/*.go", ctx=1, max_hits=40)
EOF
```
**Compare** — two environments, two branches, before and after
```bash
kiro-run --bash <<'EOF'
# Q: what differs between staging and prod values, and between this branch and main?
diff -u configurations/envs/staging/deployment.yaml configurations/envs/prod/deployment.yaml | grep '^[+-]' | head -40
git diff --stat origin/main...HEAD | tail -15
EOF
```
**Build a tool** — when you will ask the same kind of question again, save the program with the write tool under `.kiro/scratch/tools/` (git ignores that folder) and reuse it
```bash
kiro-run .kiro/scratch/tools/callers.py parseConfig "**/*.go"
```
where `callers.py` is `import sys, kt` followed by `kt.grep(r"\b%s\(" % sys.argv[1], sys.argv[2], max_hits=80)`. Look in `.kiro/scratch/tools/` before writing a new one.

## Infrastructure patterns
**Clusters — fan out over contexts, filter in jq**
```bash
kiro-run --bash <<'EOF'
for c in $(kubectl config get-contexts -o name); do
  kubectl --context "$c" get pods -A -o json 2>/dev/null | jq -r --arg c "$c" \
    '.items[] | select(any(.status.containerStatuses[]?; .ready|not))
     | "\($c) \(.metadata.namespace)/\(.metadata.name) restarts=\(.status.containerStatuses[0].restartCount) \(.status.containerStatuses[0].state|keys[0])"'
done
EOF
```
**Azure — one `az` call per scope with `--query`, aggregate in Python**
```bash
kiro-run <<'EOF'
import json, subprocess
subs = json.loads(subprocess.check_output(["az", "account", "list", "--query", "[].{id:id,name:name}", "-o", "json"]))
for s in subs:
    vms = json.loads(subprocess.check_output(["az", "vm", "list", "--subscription", s["id"], "-d",
          "--query", "[?powerState=='VM running' && tags.owner==null].{n:name,rg:resourceGroup}", "-o", "json"]))
    for v in vms: print(f"{s['name']}: {v['rg']}/{v['n']} running, no owner tag")
EOF
```
**AWS — boto3 paginators, print only the exceptions**
```bash
kiro-run <<'EOF'
import boto3
for region in ("eu-west-1", "eu-central-1"):
    ec2 = boto3.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_instances").paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
        for r in page["Reservations"]:
            for i in r["Instances"]:
                tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
                if "Owner" not in tags: print(region, i["InstanceId"], i["InstanceType"], tags.get("Name", "-"))
EOF
```
**Terraform — triage a plan as JSON instead of reading it**
```bash
kiro-run --bash <<'EOF'
terraform plan -no-color -lock=false -out=.kiro/scratch/tf.plan >/dev/null
terraform show -json .kiro/scratch/tf.plan | jq -r '.resource_changes[] | select(.change.actions != ["no-op"]) | "\(.change.actions|join(",")) \(.address)"' | sort | uniq -c | sort -rn
terraform show -json .kiro/scratch/tf.plan | jq -r '.resource_changes[] | select(.change.actions|index("delete")) | "DELETE \(.address)"'
EOF
```
**Logs / events — count before you read**
```bash
kiro-run --bash <<'EOF'
kubectl -n prod logs deploy/api --since=2h --all-containers 2>/dev/null | grep -iE 'error|exception|timeout' \
  | sed -E 's/[0-9a-f]{8,}|[0-9]{2,}/N/g' | sort | uniq -c | sort -rn | head -20
EOF
```
**Bulk mechanical edit — do it in code, show the diff stat**
```bash
kiro-run <<'EOF'
import pathlib, re, subprocess
n = 0
for f in pathlib.Path("charts").rglob("values.yaml"):
    s = f.read_text(); t = re.sub(r"image:\n(\s+)repository: old-registry/", r"image:\n\1repository: registry.internal/", s)
    if t != s: f.write_text(t); n += 1
print(f"changed {n} files"); print(subprocess.run(["git", "diff", "--stat"], capture_output=True, text=True).stdout)
EOF
```

## Rules
- Programs read, compute and make local file edits. Nothing inside a program can ask the user, so the guard refuses a program that contains a step needing approval (`git push`, `kubectl apply`, `helm upgrade`, `terraform apply`, publish, install, `ssh`, printing the environment). Take that step out, run the rest again, and issue the step alone as a direct command; infrastructure changes are still prepared for the user as explicit commands.
- Secrets never stop a program. `kt` listings and searches leave secrets files out (`kt.tree` names them), `kt.show` prints one with every value masked, and `kiro-run` replaces secret values with `[redacted]` in everything any program prints: environment values, the values in the project's secrets files, keys, tokens and signed URLs. Work with the structure (which keys exist, which file holds them) and never try to recover a masked value.
- Outside a program nothing masks. So the guard sends the read tool, the search tool and a direct `cat`, `head` or `grep` through `kiro-run` whenever what they would return holds a secret value; its message contains the program to run (`kt.read`, `kt.grep`, or the same command). Everything else is read and searched as usual.
- `kiro-run` refuses a program that really runs a cluster or cloud command (`kubectl`, `helm list`, `az`, `aws`, boto3 ...) while no read-only credentials are active. Folder names such as `helm/` and local commands such as `helm lint`, `helm template` or `az bicep build` are fine. The refusal names the command: take it out, run the rest of the program again, and issue that command alone as a direct call. Tell the user once that `kiro-safe` enables the fan-out patterns.
- A refusal or a block concerns one step. It is never a reason to drop code mode for the rest of the task, and never something to work around.
