#!/usr/bin/env bash
# UserPromptSubmit hook: routing for prompts the pack has a skill for.
# Kiro appends whatever this prints to the user's prompt; printing nothing costs nothing.
# Payload on STDIN: {"hook_event_name": "UserPromptSubmit", "prompt": "...", "cwd": "...", "session_id": "..."}
#
# A review, a failure to diagnose or a change to plan gets the matching skill itself, not a request to
# load it: that saves the turn the load would take and the method is in front of the agent before its
# first step. Later prompts of the same kind in the same session get one line, since the skill is
# already in the conversation. The hook does not run for the prompts of subagents.
payload="$(cat)"
field() { printf '%s' "$payload" | python3 -c 'import json, sys; print(json.load(sys.stdin).get(sys.argv[1]) or "")' "$1" 2>/dev/null; }
prompt="$(field prompt)" || prompt="$payload"
[ -n "$prompt" ] || prompt="$payload"
p="$(printf '%s' "$prompt" | head -c 2000 | tr '[:upper:]' '[:lower:]')"
has() { printf '%s' "$p" | grep -qE "$1"; }

# a request to review or audit something (not "prepare this for review")
review='(^|[.,;:!?] *|and +|please +|can you +|could you +|to +)(review|audit)([^a-z]|$)|code[ -]?review|(review|audit) +(this|the|my|our|it|these|that|all)([^a-z]|$)|find +(the +)?(bugs|issues|problems|vulnerabilities)'
# something fails and the user wants to know why
trouble='troubleshoot|diagnos|root cause|(help me |please |can you |could you |^)debug |debug (this|the|why|it|that|my|our)|(^|[^a-z])why (is|are|does|do|did|has|have|was|were|can.?t|cannot|won.?t|isn.?t|doesn.?t|aren.?t)[^?.]*(fail|crash|error|broken|not work|stuck|slow|restart|time ?out|timing out|hang|pending|denied|refus|unhealthy|down)|not working|(doesn.?t|does not|won.?t|didn.?t) (work|start|deploy|build|run)|keeps? (failing|crashing|restarting|timing out)|crash ?loop|(is|are|was|keeps) failing|fail(s|ed|ing) with|what.?s wrong|what is wrong|investigate (why|the|this)|find (out )?why|figure out why|(fail(s|ed|ing|ure)?|errors?|crash(es|ed|ing)?|broken|time(s|d)? ?out|stuck)[^.?!]*[ ,;:-]why([^a-z]|$)|(fails?|failed|is failing|crash(es|ed)|broke|stopped working)[^.?!]* (since|after|anymore|suddenly) '
# a change to think through before it is made (not the command `terraform plan`)
plan='(^|[^a-z])(plan|roadmap|proposal)([^a-z]|$)|(^|[^a-z])planning([^a-z]|$)|how (should|would|do|can|could) (we|i) [a-z ]*(migrate|upgrade|implement|introduce|roll ?out|move|split|refactor|restructure|design|set ?up|replace)|design (a|an|the|our) |approach (to|for) |strategy (to|for) '

skill=""
if has "$review" && ! has '(for|after|before|in|under|peer|awaiting) +review'; then
  skill=code-review; kind="a review"; first="starting with the survey-and-read program"
elif has "$trouble"; then
  skill=troubleshoot; kind="a failure to diagnose"; first="starting with the program that captures the symptom"
elif has "$plan" && ! has '(terraform|tofu|terragrunt|tf|pulumi|execution|query|explain|test|free|pricing|subscription|floor|meal|payment) +plan|plan +(file|output|mode)|-out[= ]'; then
  skill=plan; kind="a change to plan"; first="starting with the program that grounds it in what exists"
fi
[ -n "$skill" ] || exit 0

cwd="$(field cwd)"; session="$(field session_id | tr -cd 'A-Za-z0-9_-')"
file="$HOME/.kiro/skills/$skill/SKILL.md"
[ -n "$cwd" ] && [ -f "$cwd/.kiro/skills/$skill/SKILL.md" ] && file="$cwd/.kiro/skills/$skill/SKILL.md"
seen="${TMPDIR:-/tmp}/kiro-skill-router-$(id -u)"; mark="$seen/${session:-none}.$skill"
if [ ! -f "$file" ]; then
  echo "[kiro-pack] This is $kind: load the $skill skill before anything else and follow its method and its output format."
elif [ -n "$session" ] && [ -f "$mark" ]; then
  echo "[kiro-pack] This is $kind: follow the $skill skill given earlier in this session (load it again only if it is no longer in view)."
else
  echo "[kiro-pack] This is $kind. The $skill skill is given below, so do not load it: follow its method and its output format, $first."
  echo
  awk 'started { print } /^---[[:space:]]*$/ { n++; if (n == 2) started = 1 }' "$file"
  if [ -n "$session" ]; then mkdir -p "$seen" 2>/dev/null && : > "$mark" 2>/dev/null; find "$seen" -type f -mtime +2 -delete 2>/dev/null; fi
fi
exit 0
