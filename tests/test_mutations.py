#!/usr/bin/env python3
"""Mutation check for kiro-guard: proves that tests/test_guard.py notices every rule in kiro_guard.py.
Run: python3 tests/test_mutations.py [-j N] [--only LINE ...]      (on demand; install.sh does not run it)

Each rule site gets a mutant of the guard that allows instead: a `return Verdict(...)` returns None, a block in
main() returns 0, a block decision in decide() becomes False, a protected-path class or a message that sends a
read to the masked path becomes None. tests/test_guard.py then runs against the mutant in-process: its calls to
kiro-guard.sh and kiro_guard.py are answered by the mutant (calls without python3 on PATH, the bash fallback,
still run the real wrapper). A mutant is killed when a check fails; a survivor is a rule no test notices, and
has to be killed by a new test or explained in ALLOWED_SURVIVORS.
"""
import ast
import contextlib
import io
import multiprocessing
import os
import shutil
import subprocess as real_subprocess
import sys
import tempfile
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD_PY = os.path.abspath(os.path.join(HERE, "..", "global", "hooks", "scripts", "kiro_guard.py"))
LIB = os.path.abspath(os.path.join(HERE, "..", "global", "lib"))

# Sites no test can notice, keyed "function: reason" (line numbers move; this does not), with why.
ALLOWED_SURVIVORS = {
    "analyze_tf: %s apply -destroy":
        "unreachable: `apply` is in TF_D, so every terraform/tofu/terragrunt apply is blocked one line earlier",
    "analyze_kiro: %s %s":
        "equivalent: the next line returns M as well, and its reason also names the subcommand",
    "analyze_env_leak: rm -r on %s":
        "unreachable: dead code after `return None` at the end of analyze_env_leak",
}

DECIDING = {"read_tool_secrets", "command_reads_secrets"}     # a message sends the read to the masked path


# ------------------------------------------------------------------ mutants ---
def find_sites(src):
    """[(line, function, reason, (start, end) byte span to replace, replacement)]"""
    tree = ast.parse(src)
    data = src.encode("utf-8")
    starts = [0]
    for line in data.split(b"\n")[:-1]:
        starts.append(starts[-1] + len(line) + 1)

    def span(node):
        return starts[node.lineno - 1] + node.col_offset, starts[node.end_lineno - 1] + node.end_col_offset

    def text_of(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.BinOp):
            return text_of(node.left)
        if isinstance(node, ast.JoinedStr):
            return "".join(v.value for v in node.values if isinstance(v, ast.Constant))
        if isinstance(node, ast.Call) and node.args:
            return text_of(node.args[0])
        return ""

    out = []

    class V(ast.NodeVisitor):
        stack = []

        def visit_FunctionDef(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        def visit_Return(self, node):
            fn = self.stack[-1] if self.stack else "<module>"
            v = node.value
            line = src.splitlines()[node.lineno - 1].strip()
            if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "Verdict":
                reason = text_of(v.args[1]) if len(v.args) > 1 else line
                out.append((node.lineno, fn, reason or line, span(v), "None"))
            elif fn == "main" and isinstance(v, ast.Constant) and v.value == 2:
                out.append((node.lineno, fn, "block in main(): " + line, span(v), "0"))
            elif fn == "decide" and isinstance(v, ast.Tuple) and v.elts and isinstance(v.elts[0], ast.Constant) \
                    and v.elts[0].value is True:
                out.append((node.lineno, fn, text_of(v.elts[1]) or line, span(v.elts[0]), "False"))
            elif fn == "path_class" and isinstance(v, ast.Constant) and isinstance(v.value, str):
                out.append((node.lineno, fn, "protected path class %r" % v.value, span(v), "None"))
            elif fn in DECIDING and v is not None and not (isinstance(v, ast.Constant) and v.value is None):
                out.append((node.lineno, fn, text_of(v) or line, span(v), "None"))
            self.generic_visit(node)

    V().visit(tree)
    return sorted(out)


def mutant_source(src, site):
    data = src.encode("utf-8")
    (a, b), rep = site[3], site[4]
    return (data[:a] + rep.encode() + data[b:]).decode("utf-8")


def key(site):
    return "%s: %s" % (site[1], " ".join(site[2].split())[:70])


# --------------------------------------------- the guard, answered in-process ---
CODE = None          # the compiled mutant
CACHE = {}           # (guard folder, HOME/TMPDIR/KIRO_* of the env) -> module: settings are read at import


@contextlib.contextmanager
def environ(env, cwd=None):
    saved_env, saved_cwd = dict(os.environ), os.getcwd()
    os.environ.clear()
    os.environ.update(env)
    if cwd:
        os.chdir(cwd)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved_env)
        os.chdir(saved_cwd)


@contextlib.contextmanager
def without_lib():
    """A guard copy without its lib folder (test_guard's log check) must not find kt/kiro_redact either."""
    saved = {m: sys.modules.pop(m) for m in ("kt", "kiro_redact") if m in sys.modules}
    path = list(sys.path)
    sys.path[:] = [p for p in sys.path if os.path.abspath(p) != LIB]
    try:
        yield
    finally:
        sys.path[:] = path
        sys.modules.update(saved)


def guard_module(folder, env):
    k = (folder, tuple(sorted((n, v) for n, v in env.items() if n in ("HOME", "TMPDIR") or n.startswith("KIRO_"))))
    if k not in CACHE:
        mod = types.ModuleType("kiro_guard_mutant")
        mod.__file__ = os.path.join(folder, "kiro_guard.py")
        mod.NOLIB = not os.path.isdir(os.path.join(folder, "..", "..", "lib"))
        with environ(env):
            exec(CODE, mod.__dict__)
        CACHE[k] = mod
    return CACHE[k]


def call_main(mod, argv, stdin_text, env, cwd):
    out, err = io.StringIO(), io.StringIO()
    saved = sys.argv, sys.stdin, sys.stdout, sys.stderr
    sys.argv, sys.stdin, sys.stdout, sys.stderr = argv, io.StringIO(stdin_text or ""), out, err
    try:
        with environ(env, cwd), (without_lib() if mod.NOLIB else contextlib.nullcontext()):
            try:
                rc = mod.main()
            except SystemExit as exc:
                rc = exc.code if isinstance(exc.code, int) else 1
            except Exception as exc:                 # the guard's own __main__ fails closed the same way
                err.write("kiro-guard: internal error (%s); blocking to be safe.\n" % exc.__class__.__name__)
                rc = 2
    finally:
        sys.argv, sys.stdin, sys.stdout, sys.stderr = saved
    return rc, out.getvalue(), err.getvalue()


class Shim:
    """Stands in for the subprocess module inside test_guard."""
    PIPE, STDOUT, DEVNULL = real_subprocess.PIPE, real_subprocess.STDOUT, real_subprocess.DEVNULL
    CompletedProcess = real_subprocess.CompletedProcess

    def run(self, args, input=None, capture_output=False, text=False, env=None, cwd=None, **kw):
        env = dict(os.environ) if env is None else env
        a = [str(x) for x in args]
        if len(a) >= 2 and a[0] == "bash" and a[1].endswith("kiro-guard.sh") \
                and shutil.which("python3", path=env.get("PATH", "")):
            rc, out, err = call_main(guard_module(os.path.dirname(os.path.abspath(a[1])), env), ["kiro_guard.py"],
                                     input, env, cwd)
            if rc not in (0, 2):                    # what the bash wrapper does with any other exit code
                err, rc = "kiro-guard: internal error (rc=%s); blocking to be safe.\n" % rc, 2
            return real_subprocess.CompletedProcess(args, rc, out, err)
        if len(a) >= 2 and a[1].endswith("kiro_guard.py"):
            rc, out, err = call_main(guard_module(os.path.dirname(os.path.abspath(a[1])), env),
                                     ["kiro_guard.py"] + a[2:], input, env, cwd)
            return real_subprocess.CompletedProcess(args, rc, out, err)
        return real_subprocess.run(args, input=input, capture_output=capture_output, text=text, env=env, cwd=cwd, **kw)


class Killed(Exception):
    pass


class FirstFailure(list):
    def append(self, item):
        raise Killed(item)


TG = None
ROOT = None


def worker_init():
    global TG, ROOT
    ROOT = tempfile.mkdtemp(prefix="kiro-mutants-")
    tempfile.tempdir = ROOT                          # test_guard's fixtures land here and are wiped per mutant
    sys.path.insert(0, HERE)
    import test_guard
    test_guard.subprocess = Shim()
    TG = test_guard


def run_suite(source):
    """None when every check passes against this source, else the first failure."""
    global CODE
    CODE = compile(source, GUARD_PY, "exec")
    CACHE.clear()
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            TG.main(FirstFailure())
        return None
    except Killed as exc:
        return str(exc.args[0])[:240]
    except Exception as exc:                         # the suite itself breaking counts as a failure
        return "suite error: %s: %s" % (exc.__class__.__name__, str(exc)[:160])
    finally:
        CACHE.clear()
        for name in os.listdir(ROOT):
            shutil.rmtree(os.path.join(ROOT, name), ignore_errors=True)


def check_site(job):
    src, site = job
    return site, run_suite(mutant_source(src, site))


def main():
    args = sys.argv[1:]
    jobs = os.cpu_count() or 2
    only = set()
    while args:
        a = args.pop(0)
        if a == "-j" and args:
            jobs = int(args.pop(0))
        elif a == "--only" and args:
            only.add(int(args.pop(0)))
        else:
            sys.exit(__doc__)
    src = open(GUARD_PY, encoding="utf-8").read()
    sites = [s for s in find_sites(src) if not only or s[0] in only]
    t0 = time.time()
    worker_init()
    base = run_suite(src)
    if base:
        print("mutations: the unmutated guard already fails test_guard in-process, so nothing can be judged:\n  " + base)
        sys.exit(2)
    with multiprocessing.Pool(jobs, initializer=worker_init) as pool:
        results = pool.map(check_site, [(src, s) for s in sites], chunksize=1)
    killed = [s for s, r in results if r]
    survivors = [s for s, r in results if not r]
    allowed = [s for s in survivors if key(s) in ALLOWED_SURVIVORS]
    unexplained = [s for s in survivors if key(s) not in ALLOWED_SURVIVORS]
    for s in unexplained:
        print("SURVIVOR kiro_guard.py:%d  %s" % (s[0], key(s)))
    stale = set(ALLOWED_SURVIVORS) - {key(s) for s in survivors}
    if not only:
        for k in sorted(stale):
            print("STALE allowed survivor (now killed or gone): %s" % k)
    print("mutations: %d killed, %d allowed survivors, %d unexplained  (%d sites, %.0fs, %d workers)"
          % (len(killed), len(allowed), len(unexplained), len(sites), time.time() - t0, jobs))
    shutil.rmtree(ROOT, ignore_errors=True)
    sys.exit(1 if unexplained else 0)


if __name__ == "__main__":
    main()
