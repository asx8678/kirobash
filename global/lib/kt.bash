# Sourced by kiro-run for bash programs (BASH_ENV): the kt helpers as commands.
#   kt survey          kt read 'src/**' max_lines=800     kt tree   kt secrets   kt risky   kt calls
#   kt grep 'regex' '**/*.go' ctx=1    kt outline 'internal/**/*.go'    kt show path 120 160
#   kt.sh "helm lint chart"   runs a command with a 60 s limit (KT_SH_TIMEOUT), all of its output, its exit code
# `kt.show path` works too, for programs written the Python way.
kt() { if [ "${1:-}" = sh ]; then shift; kt.sh "$@"; else python3 -m kt "$@"; fi; }
for _kt_fn in review survey tree read secrets risky calls tools files grep outline show hidden; do
  eval "kt.${_kt_fn}() { python3 -m kt ${_kt_fn} \"\$@\"; }"
done
unset _kt_fn
# In bash, output is piped and filtered by the program itself, so kt.sh shows everything (the Python
# kt.sh prints only the last lines) and returns the command's own exit code; only the time limit is added.
kt.sh() {
  local t="${KT_SH_TIMEOUT:-60}" rc
  timeout -k 5 "$t" bash -o pipefail -c "$*"; rc=$?
  [ "$rc" -eq 124 ] && echo "[kt.sh: stopped after ${t}s: $*]" >&2
  return "$rc"
}
