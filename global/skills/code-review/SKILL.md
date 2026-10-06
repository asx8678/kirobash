---
name: code-review
description: Review a diff, pull request, module, file or whole repository for bugs, security issues and infrastructure misconfiguration. Use when the user asks to review, audit or look over code, a PR, a Terraform/Bicep/CloudFormation/Helm/Kubernetes change or a pipeline definition.
---

# Code review

Report every real issue you find, each tagged with severity and confidence, and let the user filter. Reviews that are told to report only high-severity issues tend to drop real findings, so do the filtering in the output format rather than in what you look for.

## Method

Four steps, in this order. A repo of a few thousand lines takes four or five turns.

1. **Survey and read: one program.**
   ```python
   import kt
   kt.review()   # the survey (layout, committed secrets, risky constructs, script calls, tools installed), then every source file, numbered, secrets masked
   ```
   A long result comes in parts: issue all the `kiro-run --more` calls part 1 names in one step, and read every part before you judge anything. A repo too large to read whole: `kt.review()` prints the files the survey points at first and lists the rest by folder (NOT READ YET). Do not read on yourself, which multiplies the cost of every later turn: hand the folders that matter to `scout` helpers in ONE `orchestrate_subagent` call, in the same step as your working notes, at most four stages, one folder each:
   `{"name": "templates", "role": "scout", "prompt_template": "Review the folder templates/ of this repository for bugs, security issues and misconfiguration. Run kt.review(\"templates/**\") in one kiro-run program, read every part, fill in its working notes. Return each FINDING as: path:line, the quoted line, what is wrong, High, Medium or Low, and for High or Medium what you checked that could make it harmless. At most 40 lines."}`
   Open every High or Medium line a scout returns (`kt.show`) before it goes into the review; a finding without a quoted line is dropped. Folders nobody read go under **Not reviewed**, for the user to ask about next, and so does the folder of a scout that failed or returned nothing (say so: `scout failed`); re-run that scout alone once, never the scouts that answered. Do not open files one at a time. For a diff or PR, read the changed files whole and the files they call: `kt.review(["a.py", "dir/**"])`.

2. **Trace and triage, in writing.** This is where the findings come from. The output of `kt.review()` ends with a form built from this repo: its script calls, its destructive steps, the survey's candidate groups and its files. Fill it in as your reply, one line per entry, before any test (these are working notes, not the review):
   - *calls*: the values the caller really passes (count them per argument) against the lines where the script indexes or reads them: OK or MISMATCH;
   - *deletes*: what selects the items; what that selection is when an earlier call fails or returns nothing; what is printed against what is done. Follow each property back to the object it is read from, and each flag to where it is reset. A delete that runs on a list built from failed or partial calls is a High finding;
   - *candidates*: FINDING, or harmless and why. None is dropped without a line;
   - *files*: every script, pipeline and template with the areas list below in mind: `line: what is wrong`, or `nothing`. The issues nobody was looking for are found here.

3. **Test, disprove and ground**, issued in the same step as the notes: one program and one `fact-check` request. The program runs the project's own checks (`helm lint` and `helm template` with each environment's values, `terraform validate`, linters, the validators the repo ships, short tests) plus one experiment for each High or Medium finding that rests on how a library, flag, template or runtime behaves: call the function, render the chart, run the snippet. Use only tools the survey lists as installed, and run each check through `kt.sh`, in Python `kt.sh("cmd")` (prints the last lines) or in bash `kt.sh "cmd"` (prints everything), so that one that hangs, on a private package feed or a cluster, is cut and reported instead of taking the whole run with it. A finding you can see in the file needs no test; one you cannot test is tagged `(likely)` with what would confirm it. For each High or Medium the program also searches for what would make it harmless (an earlier check, an override in another file or environment, a caller that never passes the bad value); a finding it disproves is dropped or downgraded in the notes.

4. **Report** in the format below. Every FINDING line of your notes becomes a finding, however many there are: a review with thirty findings is fine, one that drops the small ones is not.

A committed secret is a finding by file, line and kind. Never print a secret value, or a piece of one, to judge it: the masked view says whether each value looks real or like a placeholder, and the survey says which secrets files git tracks. The read and search tools refuse a file that holds secret values; `kt.read` and `kt.grep` show it masked.

Scouts are for folders you did not read; do not spawn helpers to re-check your own findings. `fact-check` gets, in one numbered request, every claim a finding rests on that depends on a version (a removed API, a changed default, a limit, a CVE, an end-of-life date), however sure you are, with the pinned version (no code, paths or internal names: its claims become web searches); add the pinned versions on the exposed path (base images, Kubernetes APIs, providers, charts, runtimes, CI actions): end of life, or a security fix in a later release? At most ten claims. REFUTED removes or corrects a finding; VERIFIED adds its source link. A verdict without a copied quote counts as UNVERIFIED and never overturns what the code or a test showed.

## Output

Reply in rendered markdown. The example below is fenced only to show the raw markdown; your reply is never inside a code block.

````markdown
## Review: 2 high · 2 medium · 1 low

**Fix first:** rotate the committed database password (1), then close SSH (2).

**Covered:** all 41 source files (2,300 lines); `terraform validate` and `helm lint` pass. **Not reviewed:** `data/licenses.json` (4,000 lines of data).

### High

1. **Database password committed** · `deploy/values-prod.yaml:14`, `deploy/values-dev.yaml:14`
   - `dbPassword: [redacted]`: a real-looking password is in the values files, readable by anyone with repo access.
   - **Fix:** reference a Key Vault secret instead and rotate the password.
2. **SSH open to the internet** · `infra/network.tf:42`
   - `source_address_prefix = "0.0.0.0/0"` on port 22.
   - **Fix:** restrict the source to the bastion subnet.

### Medium

3. **Backup job cannot fail** (likely) · `scripts/backup.sh:31-34`
   - `pg_dump "$DB" > "$out" || true`: a failed dump still uploads an empty file, then the prune step removes the last good one.
   - **Fix:** drop `|| true` and check the dump size before uploading and pruning.
4. **Ingress uses a removed API** · `charts/api/templates/ingress.yaml:1`
   - `apiVersion: networking.k8s.io/v1beta1`: removed in Kubernetes 1.22, the clusters run 1.29, so the chart cannot install ([source](https://kubernetes.io/docs/reference/using-api/deprecation-guide/)).
   - **Fix:** `networking.k8s.io/v1`, with `pathType` on each path.

### Low

5. `scripts/deploy.sh:7`: unquoted `$ENV` breaks on values with spaces; quote it.

```diff
- High: database password committed (deploy/values-prod.yaml:14): rotate it
- High: SSH open to the internet (infra/network.tf:42)
```
````

- The first characters of your final message are `## Review`: no sentence before the heading and no working notes. After the last finding comes only the must-see block of the working-style rule (red `-` lines in a `diff` block): one line per High finding, and one for a check that failed or could not run.
- The verdict comes first: counts in the heading, what to fix first, then what you covered (how many files and lines, which checks ran and their result) and what you did not review and why. A file `.kiroignore` hides exists; it is not missing. Say "before merge" only when reviewing a diff or PR.
- High and Medium findings: a bold title of a few words, then the location with line numbers; one sub-bullet that quotes the line in question (one line, secrets masked) and says what is wrong and what it leads to, one with the fix. Two sentences at most per sub-bullet. A finding not plain from its quoted line ends the first sub-bullet with how it was confirmed: `(reproduced: <command>)` or `([source](url))`. Add `(likely)` or `(unsure)` after the title when not certain; sure findings carry no tag.
- Low findings: one line each, with location, problem and fix.
- Severity is what happens, not how wrong the code looks or what it sits next to:
  - **High**: it goes wrong today: a secret is exposed, data or infrastructure can be lost or reached by the wrong party, a production action hits the wrong target or uses the wrong credentials.
  - **Medium**: it goes wrong after one more failure or change, or the damage is limited: a job that runs too often, a check that never runs, a weakness that needs another fault to matter.
  - **Low**: nothing goes wrong today: robustness, style, a misleading message, code that is wrong but gives the intended result by accident (say that it is by accident, even when the line sits next to a delete).
  - When the repo cannot tell you whether something is applied, defined elsewhere or reachable, tag it `(unsure)` and rate it one level lower.
- **Fix first** names exposed secrets first, then what can lose data or act on the wrong target.
- Number findings continuously across sections so the user can say "fix 2 and 5". When one root cause shows up in several files, report it once with every location.
- Keep each line short enough to read without wrapping (about 100 characters); split a long point into a second sub-bullet rather than lengthen it.
- Never print secret values; name the file and line where the secret is instead.

## Areas that often hide real issues

- Logic: an undefined or misspelt variable, a property read from the wrong object, a flag set once and never reset in a loop, output or deletion outside the condition that guards it, unchecked exit codes and HTTP statuses, errors swallowed before a destructive step, dates and numbers parsed without handling bad input, validation run on one folder or environment while others exist, dry-run paths that differ from the real run, a validator or test no pipeline runs
- Contracts between files: the arguments a pipeline passes against the parameters the script declares and how it indexes them (count, order, names); the environment a script reads against what its caller sets; the keys a template reads against the keys the values files set; a variable used in a condition against where it is defined; each cron expression read field by field against its comment
- Access: Azure Owner/Contributor/User Access Administrator at subscription or management-group scope; AWS IAM policies with `"Action": "*"` or `"Resource": "*"` on write actions, `AdministratorAccess`, trust policies open to `*`; Kubernetes `cluster-admin` bindings or `*` verbs/resources, cluster-wide roles where a namespace would do, roles bound to a `default` service account, RBAC rules naming an API group the resource no longer lives in (`extensions`); long-lived client secrets / access keys instead of managed identity, workload identity or IRSA/Pod Identity
- Exposure: NSG/security-group rules from `0.0.0.0/0` on admin ports; public blob access, `allowSharedKeyAccess`, S3 buckets without Block Public Access; public endpoints on Key Vault, SQL, RDS, AKS/EKS API servers without authorized IP ranges or private access
- Secrets: values in code, tfvars, Helm values, pipeline YAML or logs; tokens placed in URLs or command lines; secrets files tracked in git; scanner allowlists that contain the secret itself; Key Vault without soft delete or purge protection
- Destroy risk: changes that force replacement of stateful resources (`ForceNew` attributes such as names, SKUs, locations, CloudFormation *Replacement: True*); missing `prevent_destroy`, Azure resource locks, or CloudFormation `DeletionPolicy: Retain` on databases, storage, Key Vaults; Bicep/ARM Complete mode; `skip_final_snapshot = true`; scheduled jobs that delete with a force flag
- Reliability and hardening: missing resource requests/limits, probes, PodDisruptionBudgets, a single replica or a budget that allows zero, no zone redundancy for production; no `securityContext` (runAsNonRoot, read-only root filesystem, dropped capabilities)
- Supply chain: unpinned providers, modules, images (`:latest` or no tag at all, helper and sidecar images included), Helm charts, template repositories and actions/tasks (`@main`, no `ref`)
- Shell and pipelines: unquoted variables and URLs, missing `set -euo pipefail`, `curl` without `--fail`, unchecked exit codes
