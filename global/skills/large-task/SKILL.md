---
name: large-task
description: "Work through material too large for one context, such as a map of a whole repository or monorepo, a survey or inventory across all services, modules or charts, or what a migration touches everywhere: split it by size into folder groups, have scout helpers read one group each in parallel, and combine their findings with the coverage stated. Use when the user asks to map, inventory, survey, document or explain a whole codebase or every service; reviews use the code-review skill."
---

# Large tasks

Split for size, not for difficulty: when the material fits one context, read it yourself in one program. When it does not, every helper gets one slice it can read whole and returns only what it found, and the reply says what was covered.

## Method

1. **Orient: one program.** The survey plus a split into at most four groups that each fit one helper:
   ```bash
   kiro-run <<'EOF'
   # Q: how large is this, and how does it split into groups one helper can read whole?
   import kt
   kt.tree(depth=2)
   kt.partition(max_lines=3000, parts=4)
   EOF
   ```
   `kt.partition` groups folders by line count (a folder that is too large is split into its subfolders), names each group and prints its globs; `targets=["services/a", "services/b"]` limits it to those folders. When it prints `fits one context`, read it yourself (`kt.read`) and skip step 2. What does not fit four groups is listed as `not covered`: that is a second round, after this one.

2. **One `orchestrate_subagent` call**, one `scout` stage per group, in the same step as step 1's summary:
   ```json
   {"task": "Map <what> across the repository",
    "stages": [
     {"name": "services-api", "role": "scout", "prompt_template": "Question: <the one question, the same for every group>\nRead every file of: services/api/** services/auth/** with kt.read([...]) in one kiro-run program, all parts.\nReturn, at most 40 lines: <the shape you want back, e.g. one line per service: name, entry point path:line, what it calls, where its config comes from>."},
     {"name": "libs", "role": "scout", "prompt_template": "Question: <same>\nRead every file of: libs/** Makefile README.md ...\nReturn ..."}]}
   ```
   Every stage asks the same question in the same shape, so the answers line up. Every prompt stands on its own: the helper sees nothing of this conversation.

3. **Combine** what came back. Keep a finding only with its `path:line`; when two helpers disagree, keep both claims with the group each came from, and open the lines (`kt.show`) before you choose. A stage that failed or returned nothing leaves its group uncovered: say so, and re-run that stage alone once, never the stages that answered. Open every line a conclusion rests on before you state it.

4. **Second round**, only when step 1 listed `not covered` groups and the question needs them: `kt.partition(targets=[...])` on those folders, then step 2 again.

## Output

Lead with the answer in the shape the question asked for (a map, a table, an inventory), then one coverage line:

`Covered 4/4 groups (18,400 lines); not covered: data/fixtures/** (6,000 lines of test data).`

- A group nobody read is named in the coverage line with the reason (`scout failed`, `second round not run`); its contents are not guessed.
- The must-see block of the working-style rule closes the reply: a red line for any group that was not covered when the question needed it.
