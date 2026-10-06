---
name: troubleshoot
description: Diagnose a failure such as an error, a crash, a failing pipeline or deployment, a pod that keeps restarting, or a slow or flaky system. Evidence first, then hypotheses checked in parallel by the team (fact-check for known issues and changed defaults, scout for where the failing value comes from), then the root cause with proof and a prepared fix. Use when the user asks why something fails, or to debug, troubleshoot, investigate or find a root cause.
---

# Troubleshooting

Symptom, evidence, hypotheses, checks, root cause: in that order. No fix is proposed before the cause is shown, and a guess is labelled as one.

## Method

1. **Capture the symptom: one program.** The error text word for word, when it started, what changed just before (`git log --since`, the last deploy or release), and the exact versions involved. Find which component prints the error: grep the distinctive part of the message in the repo and in the installed dependencies (`site-packages`, `node_modules`, the Go module cache, the chart's templates); that component and its version go into every search. For a cluster: events, `describe`, and logs counted and grouped before they are read (code-mode skill). Commands against a cluster or cloud account need read-only credentials inside a program; without them issue each as a single direct call.
2. **Hypotheses** in your reply: at most four, one line each: the cause, what you would see if it were true, and the check that rules it out. At least one lies outside the code (configuration, environment, infrastructure, credentials); when something was upgraded shortly before it started, one is a known issue of the new version.
3. **One `orchestrate_subagent` call**, in the same step as the hypotheses. Stages without `depends_on` run in parallel:
   ```json
   {"task": "Find out why <symptom>",
    "stages": [
     {"name": "known", "role": "fact-check", "prompt_template": "1. Is \"<distinctive part of the error>\" a known issue of <component that prints it> <version> (used by <product> <version>)? Quote the issue or changelog line, the affected versions and the version that fixes it.\n2. Did <default or behaviour> change between <version A> and <version B>? Quote the changelog line."},
     {"name": "origin", "role": "scout", "prompt_template": "Where is <the failing value, flag or config> set for <environment>, and what changed there in the last <N> commits? Look in <folders>."}]}
   ```
   One `scout` stage per independent area (the chart, the pipeline, the application config). Every stage prompt stands on its own: the helper sees nothing of this conversation, so give it the error text, the versions and the paths. Ask `fact-check` for what the source lists ("which releases mention this error, quote the changelog line"), not for a superlative.
4. **Experiment: one program** that separates the hypotheses still standing: reproduce it locally, render the chart with the environment's values, diff the working and the failing configuration, run the failing command with its verbose flag.
5. **Root cause**, when one hypothesis explains every piece of evidence, including why it started when it did, and the others are ruled out. A `fact-check` line without a copied quote counts as UNVERIFIED, whatever its label, and no helper's verdict overturns what the code or a test showed you: test it again in a program, or keep your finding and list the disagreement as an open risk. When two helpers disagree, keep both claims with the helper that made each and let the experiment decide. A stage that failed or returned nothing leaves its question open (`not checked: …` under the hypotheses it would have tested); re-run that stage alone once if the diagnosis depends on it, never the stages that answered. If the fix changes production, have `skeptic` attack the diagnosis first (one stage: the user's words, the diagnosis, the evidence, the fix).

Stop and say so when the evidence does not decide: name the two remaining causes and the one observation that would decide between them.

## Output

````markdown
## Diagnosis: <root cause in one sentence>

**Evidence**
- `path:line` or `<command>`: what it shows

**Fix** (prepared, not run)
```
<exact command or diff>
```
**Verify:** `<command>` shows `<expected>`

**Ruled out**
- <hypothesis>: why

**Sources:** [<title>](https://...)
````

- The first characters of the final message are `## Diagnosis`, or `## Not yet diagnosed` with the two remaining causes; the must-see block of the working-style rule closes it.
- Evidence is quoted from what you or a helper actually read or ran; open the lines a helper cites before you rely on them.
- A fix on a shared cluster, account or database is the exact command for the user to run, with the target named.
