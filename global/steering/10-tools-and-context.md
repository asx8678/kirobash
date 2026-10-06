# Tools and context

Credits scale with what you pull into context and every turn is a full round trip, so let code do the looking and bring back only the answer.

**Code first.** Treat code as your main instrument, not a fallback. When a question spans more than a couple of files, commands or resources, write a short Python or bash program and run it once with `kiro-run` (code-mode skill): the loops, filters, joins and counts happen in the program and only the result enters context. Be inventive: extraction scripts, experiments that prove or kill a hypothesis, harnesses that print only failures. If no tool does what you need, write one; save one you will reuse under `.kiro/scratch/tools/` (`kiro-run .kiro/scratch/tools/name.py args`). Programs can `import kt` (bash: `kt survey` …): `kt.survey`, `kt.read`, `kt.calls`, `kt.grep`, `kt.outline`, `kt.show`, `kt.sh`.

What runs how (the guard enforces it):

- **A program** — `kiro-run <<'EOF'` … `EOF`, with `--bash` for shell: any line with more than one command (`;`, `&&`, a loop), any inline code (`python3 -c`, a heredoc into an interpreter), every investigation, check, comparison, fan-out, log analysis, bulk mechanical edit and test run, and reading a batch of files (`kt.read`, never `cat` in a loop). The shell tool's own advice to chain commands with `&&` or `;` does not apply here: a chain is a program. One run answers the whole question and prints findings, not raw data. A long result comes in parts: fetch the rest with the `kiro-run --more` calls part 1 names, in one step.
- **A direct call** — one command on its own (`cd dir &&` and a pipe into `head`, `grep` or `jq` are fine); `read`/`grep`/`glob` for the lines you are about to edit or quote, issued together in one step; `write`/edit; `web_search`/`web_fetch`/`fact-check`.
- **Alone, never inside a program** — a step that changes shared state or needs approval (`git push`, apply, deploy, publish, install, `ssh`) and, without read-only credentials, a command against a cluster or cloud account (`kubectl`, `helm list`, `az`, `aws`). When a program is refused for such a step, take the step out, run the rest again, and issue the step as a single direct command. A refusal concerns one step; it is never a reason to leave code mode.

Secrets do not stop work: `kiro-run` masks secret values as `[redacted]` in everything a program prints. The read and search tools and a direct `cat` or `grep` refuse content that holds secret values: use `kt.read` or `kt.grep`. Never try to recover a masked value.

- To understand a repo you haven't seen this session (review, debugging, "how does X work"), start with one program: `kt.survey()`, then `kt.read()` for what it points at.
- Open a file before making claims about it, and don't re-read one that hasn't changed.
- Filter the output of direct commands: `--query … -o tsv`, `| jq`, `| tail -n 60`.
- If an approach fails twice for the same reason, change it or report what blocks you.
- After editing a file, run the cheapest check for its type once (rung 1 of the `infra-checks` skill) before reporting done.
- Delete temporary files you created when done.
