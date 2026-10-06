---
name: plan
description: Plan a change before making it, such as a migration, an upgrade, a new feature, a refactoring or an infrastructure change. Produces a short step-by-step plan whose assumptions were checked in parallel by the team (fact-check, scout, skeptic), with acceptance checks that define done, a check per step and a rollback. Use when the user asks for a plan, a design, an approach or "how should we", and before any change that touches several files or shared infrastructure.
---

# Planning a change

A plan is worth what its weakest assumption is worth. Find the assumptions, have them checked in parallel, then write the plan.

## Method

1. **Ground it: one program.** `kt.survey()` plus `kt.read([...])` or `kt.grep` for the files the change touches: what exists today, what calls what, which versions are pinned.
2. **Frame, then draft**, in your reply, a few lines. The outcome and the constraints in the user's words (downtime allowed, deadline, compatibility, who else is affected). When there are two real approaches, one line each and the one you pick with the deciding reason. Then the assumptions, three kinds:
   - *world*: versions, flags, API fields, defaults, limits, deprecations, compatibility ("chart 4.x runs on Kubernetes 1.31");
   - *repo*: things about this codebase you have not read yourself ("nothing else imports this module"); one a short program can settle, settle now in a program instead of delegating it;
   - *decision*: what only the user can decide (a maintenance window, the risk they accept); it goes to the user under Open risks, never to a helper.
3. **One `orchestrate_subagent` call**, in the same step as the draft. Stages without `depends_on` run in parallel:
   ```json
   {"task": "Check the assumptions behind the plan to <goal>",
    "stages": [
     {"name": "facts", "role": "fact-check", "prompt_template": "Verify for the versions this repo pins, each with the copied row or sentence and its link:\n1. <world assumption> (<product> <version>, as pinned)\n2. ..."},
     {"name": "usage", "role": "scout", "prompt_template": "<one repo question, with the folders to look in>"},
     {"name": "doubts", "role": "skeptic", "depends_on": ["facts", "usage"],
      "prompt_template": "Request (the user's words): <quote>\nConstraints: <the list>\nApproach: <chosen> over <alternative>: <reason>\nPlan: <the draft, step by step>\nAssumptions: <the list>\nEvidence so far: <path:line facts from step 1>"}]}
   ```
   One `scout` stage per independent repo question; none when step 1 already answered them. No world assumptions means no `facts` stage. Every stage prompt stands on its own, because the helper sees nothing of this conversation: the goal in one line, the facts it needs (paths, pinned versions with `path:line`, error text, the user's constraint), one question, what counts as an answer (a copied row, a `path:line`), and where to stop. Ask `fact-check` for what the source lists, not for a superlative: "which PostgreSQL versions does the provider list as supported, quote each row", not "what is the newest PostgreSQL I can use".
4. **Write the plan** from what came back: change or drop a step whose assumption was REFUTED, carry an UNVERIFIED one as an open risk, and answer each DOUBT (fixed in the plan, or why it stands). A claim without a quote or a `path:line` is dropped; when two helpers disagree, keep both claims with the helper that made each, and settle it with a program or carry it as an open risk. A stage that failed or returned nothing is a gap: list it under Open risks as `not checked: <its question>` instead of guessing its answer, and re-run that stage alone once if a step depends on it, never the stages that answered. Open the lines a helper cites before you build on them. A value a step writes into a file because of an outside fact (a version, a flag, an API field) must appear in the row or sentence `fact-check` quoted; if it does not, ask again with a sharper question before the value goes into the plan. A `fact-check` line without a copied quote counts as UNVERIFIED, whatever its label, and no helper's verdict overturns what the code or a test showed you: test it again in a program, or keep your finding and list the disagreement as an open risk.

A small change (one file, no outside facts, nothing shared) needs no helpers: steps 1 and 4 are enough.

## Output

````markdown
## Plan: <goal in a few words>

**Not in scope:** what stays as it is. **Approach:** <chosen> over <alternative>: <the deciding reason>.

### Acceptance
- **A1** `<command>` shows `<expected>`: what it proves
- **A2** ...

### Steps
1. <action> · `<file>`, `<function or key>` (→ A1)
   - check: `<command>` shows `<expected>`
2. ...

### Rollback
<how to get back, per step that cannot simply be reverted>

### Verified
- <fact the plan rests on> ([source](https://...))

### Open risks
- <unverified claim or standing doubt>: how to settle it
- decision for you: <what only the user can decide>
````

- **Acceptance** lists the checks that define done, each a command, test or probe with its expected result; "it builds" or "verify it works" is not one. Every acceptance item is met by a step (→ A1), and the plan is finished only when each has run and passed.
- Write each step so that a cheaper model (Auto) can carry it out without re-deriving the design: the exact file and function or key, the command, the value, the check. "Update as needed" or "adjust the config" leaves the design to the executor.
- Steps are ordered so that each can be checked before the next starts; the check is a command with its expected result, not "verify it works". The step most likely to change the plan comes first (a dry run, a render, a small spike); reversible steps come before irreversible ones, and each irreversible step has a check right before it that stops the plan when it fails.
- Steps that change a shared cluster, account, database or branch are prepared as exact commands for the user to run; say which ones.
- Three to eight steps. A plan that needs more is two plans: say where to cut.
- The first characters of the final message are `## Plan`; the must-see block of the working-style rule closes it.
