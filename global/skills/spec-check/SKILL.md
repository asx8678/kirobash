---
name: spec-check
description: "Check finished or in-progress work against a spec, requirements, acceptance criteria, a ticket or a user story: every requirement gets evidence (met, missing, contradicted) and changes no requirement asks for are listed, with auditor helpers checking slices in parallel. Use when the user asks whether work meets or covers a spec or ticket, is complete against it, or to verify acceptance criteria, including Kiro specs under .kiro/specs/."
---

# Spec check

A requirement is met when the repository shows it, not when a plan, a commit message or a helper says so. Build the ledger of requirements, have each one checked against what was built, then report what is met, what is missing and what was built that nobody asked for. Judge the outcome, never the approach.

## Method

1. **Ledger: one program.** Find the spec: the file or ticket text the user gives, else `.kiro/specs/<feature>/requirements.md` (with its `tasks.md`). Print it, the changed files and the spec's own validation command if it names one.
   ```bash
   kiro-run <<'EOF'
   # Q: what does the spec require, and what changed?
   import kt
   kt.show(".kiro/specs/checkout/requirements.md")
   rc, base = kt.sh("git merge-base HEAD origin/main", quiet=True)
   kt.sh("git diff --stat %s" % (base.strip() if rc == 0 else "HEAD~1"), tail=60)
   kt.sh("git status --short", tail=40)
   EOF
   ```
   Then write the ledger in your reply: `R1` … `Rn`, one testable statement each in the spec's own words. A sentence with two demands is two requirements; each acceptance criterion (`WHEN … THE SYSTEM SHALL …`) is one.

2. **Audit: one `orchestrate_subagent` call**, in the same step as the ledger. Up to four `auditor` stages in parallel, each with a slice of at most ten requirements:
   ```json
   {"task": "Check the work against <spec>",
    "stages": [
     {"name": "r1-r8", "role": "auditor", "prompt_template": "Requirements:\nR1 <spec's words>\n...\nR8 <spec's words>\nChanged files: <paths from git diff --stat>\nValidation: <the spec's command, or none>\nCheck each requirement against this repository."},
     {"name": "r9-r14", "role": "auditor", "prompt_template": "Requirements:\nR9 ...\nChanged files: <paths>\nValidation: none (stage r1-r8 runs it)\nCheck each requirement against this repository."}]}
   ```
   Every stage prompt stands on its own: the auditor sees nothing of this conversation. Give the validation command to one stage only. A spec of six requirements or fewer over a few files needs no helpers: check it yourself in one program, by the same rules.

3. **Confirm: one program.** Open every MISSING, CONTRADICTED and EXTRA line (`kt.show(path, around=n)`, `kt.grep`) before it goes into the report; a MET line carries its evidence. A stage that failed or returned nothing leaves its requirements UNVERIFIED (`not checked: auditor stage failed`): re-run that stage alone once, never the stages that answered. When an auditor and your own check disagree, the file or the command output decides.

4. **Report** in the format below. Do not fix anything in this pass: the user decides what to do about each gap.

## Output

````markdown
## Spec check: 9 met · 2 missing · 1 contradicted · 1 unverified

**Spec:** `.kiro/specs/checkout/requirements.md`, 13 requirements, against `main...HEAD` (9 files). **Validation:** `npm test -- checkout` passed.

### Not met
1. **R4 missing**: "THE SYSTEM SHALL email a receipt" · no mail call under `src/checkout/` (searched `sendReceipt|mailer`)
2. **R7 contradicted** · `src/checkout/total.ts:41`
   - `return Math.round(total)`: the spec requires two decimal places.
3. **R11 unverified**: retry after a payment timeout; needs the payment sandbox to probe.

### Extra (no requirement asks for it)
- `src/checkout/coupons.ts:1-80`: a coupon API.

### Met
- R1 `src/checkout/cart.ts:18` `export function addItem(`
- R2 ... (one line each, with the evidence)

```diff
- R4 missing: receipt email
- R7 contradicted: totals rounded to whole units
```
````

- The first characters of your final message are `## Spec check`. Counts in the heading, then the spec and what it was checked against, then whether its validation ran and what it showed (or why not).
- **Not met** first, numbered continuously so the user can say "fix 1 and 2"; then **Extra**; then **Met**, one line each with the location or command that shows it.
- UNVERIFIED is not met: say what would settle it. A requirement that needs the user (a decision, credentials, a clarification) says so.
- The must-see block of the working-style rule closes the reply: one red line per missing or contradicted requirement, and one for a validation that failed or could not run.
