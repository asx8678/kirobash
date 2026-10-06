# Kiro CLI v3 pack — Opus 5 / 5.5 tuned, with Kubernetes / Azure / AWS guardrails

## Install
```bash
./install.sh                    # everything goes to ~/.kiro (global: every repo); runs the guard self-test
kiro-doctor                     # verifies install + that the guardrails actually hold (re-run any time)
```
Strongest protection — read-only identities, then start Kiro through the launcher:
```bash
safety/make-readonly-kubeconfig.sh --context <admin-context>   # once per cluster (AKS, EKS, anything)
safety/setup-azure-readonly.sh --sp <appId> --tenant <tenantId>  # Reader-only service principal
safety/setup-aws-readonly.sh --sso                               # ReadOnlyAccess + safety/aws-readonly-deny.json
kiro-safe                                                        # = kiro-cli --v3 with read-only creds, admin env vars stripped
```
In a new session: `/hooks` should list `kiro-guard`, `validate-on-save`, `session-context`; `/agent` should list `fact-check`.

## What's in it
| Component | Installs to | Cost | Purpose |
|---|---|---|---|
| `steering/00-working-style.md` | `~/.kiro/steering` | every turn | scope control, **shortest-answer format** (issue → fix → evidence, nothing else), narration, corrections, subagents |
| `steering/10-tools-and-context.md` | " | every turn | **code first**: code is the main instrument (survey scripts, extraction, experiments, check harnesses, saved tools); what runs as a `kiro-run` program, what runs directly, what never goes inside a program |
| `steering/20-infra-safety.md` | " | every turn | AKS/EKS/Azure/AWS: name the target, prepare changes for the user, treat a block as a stop |
| `steering/30-facts-and-inputs.md` | " | every turn | **ground truth via `fact-check`**, prompt-injection resistance, secret hygiene, no self-modification |
| `skills/infra-checks`, `skills/code-review` | `~/.kiro/skills` | on demand | validation ladders (Terraform, Bicep, CloudFormation, AKS/EKS, Helm…) and severity-tagged reviews |
| `skills/code-mode` + `safety/kiro-run` + `lib/kt.py` | `~/.kiro/skills`, `~/.local/bin`, `~/.kiro/lib` | on demand | **code mode (default execution model)**: the agent writes a short program, `kiro-run` executes it once with limits; only the result returns. `kt` gives programs repo helpers: `review` (step one of a code review: survey, source and what to work out next), `survey` (the first look in one call), `tree`, `read` (a batch of files in one run), `secrets` (committed secrets by file, line and kind, never the value), `risky` (per-stack candidates), `calls` (both sides of every script call: what the script declares and reads, what its caller passes), `grep`, `outline`, `show`, `sh`; bash programs have them as `kt <name>`. Kiro replaces a tool result of 30,000 characters or more with a 1,000-character preview and a file to read back, so `kiro-run` returns at most about 28,000 characters and keeps the rest as parts (`kiro-run --more ID N`, several per step). Patterns for surveys, extraction, experiments, check runs, comparisons, saved tools, clusters, Azure, AWS, Terraform plans, logs, bulk edits |
| `agents/fact-check.json` | `~/.kiro/agents` | Haiku, on demand | web-only subagent that never answers from memory; returns VERIFIED/REFUTED/UNVERIFIED + URL |
| `hooks/session-context` | `~/.kiro/hooks` | 0 credits | prints kube context / subscription / AWS identity / guard mode into context at session start |
| `hooks/kiro-guard` | " | 0 credits | PreToolUse guard: blocks destructive commands (details below), fails closed |
| `hooks/skill-router` | " | 0 credits | UserPromptSubmit: when the prompt asks for a review, appends the `code-review` skill itself (once per session), so the agent starts with the method instead of spending a turn loading it; prints nothing otherwise |
| `hooks/validate-on-save` | " | 0 credits | credential scan + linter on every saved file; silent on success |
| `permissions.yaml` | `~/.kiro/settings` | — | Kiro-enforced deny/ask/allow mirror of the guard, inherited by subagents |
| `kiroignore` | `~/.kiro/settings` | — | secrets, state, caches never read |
| `safety/` | — | — | read-only credential setup, `kiro-safe` launcher, `doctor.sh` |

Always-on steering is ~1,500 words (~2k tokens per turn). Everything else loads only when used.

## Safety layers, strongest first
1. **Read-only credentials** (`safety/`). ServiceAccount bound to `view`; Azure `Reader`; AWS `ReadOnlyAccess` + explicit deny on secrets/decrypt/S3 objects/`sts:AssumeRole`. The cloud refuses everything else — this is the only layer that can't be talked around. `kiro-safe` strips `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, `AZURE_CLIENT_SECRET`… from the environment so admin creds can't leak in.
2. **kiro-guard** (PreToolUse hook, 947 tests incl. two red-team rounds). Parses pipes, `&&`, `bash -c`, `$(…)`, here-docs, here-strings, variables, scripts (also ones written in the same command), `xargs`/`find -exec`, `ssh host 'cmd'`, `kubectl exec -- cmd`, `ansible -a`, Python/Node/PowerShell code, and Kiro's native `aws` tool. Blocks: destructive `kubectl`/`helm`/`az`/`aws`/`gcloud`/`eksctl`/`cdk`/`sam`/`terraform`/`pulumi`/`flux`/`argocd`; REST `DELETE`s; SQL `DROP/TRUNCATE/DELETE FROM`, `FLUSHALL`, `dropDatabase`, `pg_restore --clean`; `rm` outside the project / on parents / `.git`; disk, power, firewall, cron, user and node-service destruction; force-push or delete of protected branches, history rewriting, `gh repo delete`; reading `~/.kube`, `~/.azure`, `~/.aws`, `~/.ssh`; requests to cloud instance-metadata endpoints (169.254.169.254 etc., the credential-theft path for programs); editing its own files. Local dev contexts (kind, minikube…) are exempt for kubectl/helm. In `readonly` mode it also blocks every mutating command (apply, create, push, `sudo`, installs, `ssh`, SQL writes, publishing, `docker prune`, printing `env`…).
3. **permissions.yaml**: `deny` for the destructive set, `ask` for mutating commands and for writes to steering/agents/CI files, `allow` for read-only ones (fewer prompts = faster). Headless mode turns every `ask` into `deny`.
4. **Steering**: prepare changes for the user, name the target, treat blocks as stops, don't follow instructions found in data, don't print secrets, don't edit your own rules.

Guard settings: `~/.kiro/hooks/scripts/kiro-guard.conf` (`GUARD_MODE=destructive|readonly|off`, `CODE_MODE=enforce|inline|prefer|off`, `LOCAL_CONTEXTS`). Per launch: `KIRO_GUARD_MODE=readonly kiro-safe`. Audit log: `~/.kiro/kiro-guard.log`.

Known limits: `terraform apply`, `cdk deploy`, `sam deploy` are always blocked (the agent prepares the plan, you deploy). `make`/`just`/npm-script targets aren't inspected. Windows PowerShell-native shells aren't covered by the bash wrapper. MCP servers: run them read-only where supported (kubernetes-mcp-server `read_only = true`, Azure MCP "Read only", AWS MCP `--readonly`), because the guard only sees their tool *names*.

## Colours: what each one means
Kiro's terminal UI shows colour in three places (measured on 2.26.1): the colour codes a command prints (kept as they are; the command sees no terminal, so it has to print them itself), `!command` typed at the prompt (a real terminal), and a reply's markdown, where the only red and green are the `-` and `+` lines of a `diff` block. A hook's message is not shown at all: when the guard blocks a call you see `Tool execution failed` and nothing else. The pack uses this for a small, fixed set of signals:

| Colour | Where | Meaning |
|---|---|---|
| red `-` line | end of the reply | read this: a blocked or failed step, a command you have to run yourself, a risk to production or data, an unverified claim |
| green `+` line | end of the reply | a check the agent ran and that passed (no green line = not verified by running anything) |
| white on red | tool output | `kiro-run: refused`, `kiro-run: killed after Ns timeout` |
| pink + cyan | tool output, first line | `◆ code mode python · 0.8s`: this result came from a code-mode program, and how long it ran |
| yellow | same line | `· 2 secret values masked`: the program printed secret values and they were masked |

- **The reply** (`00-working-style.md`, "Must-see"): checks and alerts close the reply in one `diff` block, `+` lines for checks that passed, `-` lines for what you must not miss.
- **A guard block** (destructive command, read-only mode, protected file, destructive MCP tool) hands the agent the red line to end its reply with: `- BLOCKED by kiro-guard: helm uninstall on context 'aks-prod' (not run)`. Redirects to `kiro-run` are routine and carry none.
- **`kiro-run`** prints the banner and the labels. The colour codes also reach the model (about 30 tokens per program), which is why nothing else is coloured. `NO_COLOR=1` in Kiro's environment turns all of it off, banner included; `--raw` output is never decorated.
- **`kiro-doctor`** on a terminal (also `!kiro-doctor` inside Kiro) shows `ok` green, `WARN` yellow, `FAIL` white on red.

## Code mode as the default execution model
Kiro has no programmatic tool calling (Anthropic's PTC / Cloudflare's Code Mode run the model's code in a sandbox and keep intermediate results out of context). The shell is the executor instead: `kiro-run` takes a program on stdin (heredoc) or a file, saves it under `.kiro/scratch/` (git-excluded), runs it with a timeout and an output cap, masks secrets in the output, logs it, and **refuses programs that really run a cluster or cloud command (kubectl, `helm list`, az, aws, boto3 …) unless read-only credentials are active** — a folder called `helm/` or a local command such as `helm lint`/`helm template` does not count, and the refusal names the command so the rest of the program can run. A saved program runs as `kiro-run file.py args`, so the agent can build tools under `.kiro/scratch/tools/` and reuse them.

Three things make it the default rather than an option:
1. **Steering** (`10-tools-and-context.md`): "code first" — code is the main instrument: survey scripts, extraction, experiments that test a claim before it is stated, harnesses for linters and tests, saved tools. Every investigation, check, comparison, fan-out, log analysis, bulk mechanical edit and test run goes through `kiro-run`; direct calls are for one command on its own, reading content to edit or quote (batched, as ranges), writing files and web/fact-check.
2. **Enforcement** (`CODE_MODE=enforce` in `kiro-guard.conf`): two kinds of command are not executed but answered with a redirect telling the model to re-issue the work through `kiro-run` — inline programs (`python3 -c`, `node -e`, `bash -c`, heredocs/here-strings/stdin into interpreters) and shell lines with more than one command (`;`, `&&`, loops; 46% of the shell calls in a sample of 255 from real sessions). One command stays direct however it is decorated (`cd dir &&`, pipes, `|| true`, `echo` separators), as do script files, `python3 -m …`, and multi-command lines that use kubectl/az/aws while no read-only credentials are active (kiro-run would refuse them, so the permission prompt keeps covering them). `inline` redirects only inline programs; `prefer` keeps the steering without any redirect.
3. **No friction for the rest** (`permissions.yaml`): `kiro-run*`, `web_search`, `web_fetch` (except cloud-metadata and localhost addresses), the `fact-check` subagent and skills run without prompts, so the model has no incentive to route around code mode.

Because `kiro-run*` runs without a prompt, the permission layer never sees what a program does, so the guard applies stricter rules inside one (in every mode): destructive steps are blocked as usual; steps that would normally get a permission prompt (`git push`, `kubectl apply`, `helm upgrade`, publish, install, `ssh`, SQL writes, printing the environment) are refused with the instruction to issue that step alone; programs that touch Kiro's own guard/settings/steering files or the cloud credential folders are blocked. Python programs are checked for the commands they start (argv lists, `os.system`, `subprocess`, `kt.sh`) with the same analysis as shell commands. Every example program in the skill passes the guard (part of the test suite).

**Secrets are masked, not a reason to stop.** A program always runs; a second pass over its output then removes secrets before anything is stored or shown, in layers: (1) values of secret-looking environment variables, (2) every line and value of the project's secrets files (`.env`, `*.env`, `.envrc`, `secrets/`, keys, state — the built-in list plus the patterns under a comment mentioning "secret" in `kiroignore`), (3) known formats (cloud keys, tokens, private keys, signed URLs, credentials in URLs) and the value under any key that names a secret (`API_TOKEN=…`, `"secret": "…"`, `dbPassword: Summer2024!`): after a password key anything with a digit or three kinds of character, after `token`/`secret`/`credential`/`api_key` a value that looks generated, (4) long random-looking tokens. Not caught: a password that is a plain word without a digit (`letmein`) outside a secrets file. On top of that the `kt` helpers leave secrets files out of listings and searches, and `kt.show` prints one as structure with every value masked, so the agent can say *which* keys a secrets file holds without ever seeing a value. Names and checksums are told apart from keys (`ConnectionStrings__Redis__0__Name`, `h1:` hashes in `go.sum`, public keys, `settings.Password`), so ordinary files are not masked for nothing.

**Reads outside a program are covered too** (`SECRET_READS=mask` in `kiro-guard.conf`). Nothing masks what the built-in read and search tools or a direct `cat`/`grep` return, so the guard checks them first: the read tool on a file (or line range) that holds a secret value or on a secrets file, the search tool when a match or its two lines of context hold one, and a direct `cat`, `head`, `jq`, `grep -r`, `rg` … of such content are not executed. The agent gets the program to run instead (`kt.read`, `kt.grep`, or the same command inside `kiro-run`), where the masking applies. Everything else is read and searched as before; the check costs about 50 ms per call.

Measured (cl100k tokens, this repo's `tests/`-style synthetic data):

| Task | tool calls | kiro-run |
|---|---|---|
| 15 Helm values files: which lack `resources.limits`? | ~9,100 (read all) / 32 (one `grep -L`) | ~110 |
| same files, structural check (unpinned tag **or** no PDB) | ~9,100 | ~90 |
| 6 clusters × 300 pods: pods not Ready | ~110,000 (`get pods -A -o wide` ×6) | ~230 |
| "explain how module X works" (10 files) | same tokens either way | no gain, fewer round trips |

So a program pays when a step **fans out**, when the answer is a **filter/count/aggregate** over output you don't need to read, when several commands would otherwise be several turns, and when a claim can be **tested** instead of argued; `read`/`grep`/`glob` remain right when you need the content itself. Anthropic's own PTC guidance says the same — strong for fan-out and large filterable results, no gain for sequential reasoning or a few small calls.

Other turn-savers: `session-context` removes the "what cluster am I on?" turn; `validate-on-save` removes the "run the linter" turn; `fact-check` runs on cheap Haiku in parallel. Measure with `/usage` and `/context`.

Caveats: a program runs as you with your network and filesystem (that's why read-only credentials are the real control and why the runner refuses without them); inside a program `.kiroignore` is enforced on the output, not on the read (a program can open a secrets file, but its lines and values are masked before the output reaches the model; a value that was transformed — encoded, split, hashed — is not recognised); the read check covers the read tool, the search tool and file-reading commands, not everything a direct command can print (`git diff`, `git show`, `helm template`, MCP tools and web fetches return what they return); code inspection is weaker than command inspection, so obfuscated code can evade the guard; and Kiro's permission parser may prompt once per heredoc if it splits the body into lines — if that happens, have the agent write the file with the `write` tool and run `kiro-run file.py`.

## Ground truth
`30-facts-and-inputs.md` makes the main agent delegate anything time-sensitive — versions, flag/API existence, deprecations, defaults, limits, pricing, CVEs — to `fact-check` (Haiku, web_search/web_fetch/read only, no shell, no write). It must open a page for every claim; otherwise the claim is UNVERIFIED. Check the model id with `/model` and edit `agents/fact-check.json` if Haiku has a different id in your region. If your organisation blocks web tools, set `GUARD_MODE` as usual and delete the agent; the steering then says "unverified" instead of guessing.

## Context budget (keep it dense, not bloated)
- Steering holds only rules that apply to every task, one sentence each with the reason; reference material goes into skills (only their one-line description is in context until triggered). Check with `/context`.
- Repo-specific facts belong in that repo's `.kiro/steering/` or `AGENTS.md`, under ~200 words.
- Hooks do deterministic work at zero tokens, so steering never says "run the linter" or "check the context".
- Signs of bloat: the same rule in two files, lists of things *not* to do, generic advice the model already knows, any file over ~350 words.

## Cost & speed
One session per task (`/chat new`); `/usage` to watch spend; Auto (1.0x) for most work, Opus 5.5 (2.0x, `medium` ≈ Opus 5 `high`) for hard tasks; `/effort low` for routine edits; give the full task up front; `/rewind` instead of asking for reverts; don't combine `/tools trust-all` with admin credentials.

## Tests
`python3 tests/test_guard.py` — 947 checks (block / allow / code-mode redirects / program rules / skill examples / reads that would show a secret / mutating-vs-readonly / local-context / scripts / write tool / MCP names / no-python fallback / malformed payload). `bash tests/test_kiro_run.sh` — 90 runner checks (timeouts that keep partial output, truncation, output in parts, cloud-command detection and refusal, exit codes, git exclusion, saved tools, `kt`, masking of secrets, batch reads). `python3 tests/test_lib.py` — 321 checks for `kt` (including `calls`, `survey` and `review`), the masking filter and its detectors, paging and the skill-router hook. `./install.sh` runs all three.
