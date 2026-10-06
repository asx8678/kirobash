#!/usr/bin/env python3
"""kiro_hint: one-line hints kiro-run adds to a failed run, for errors whose fix is not in the traceback.

  kiro_hint.py OUT RC SANDBOX     OUT: the masked output of the run; RC: its exit code; SANDBOX: off, deny
                                  or allow (how the run was sandboxed). Prints at most two lines
                                  `[kiro-run hint: ...]`, or nothing.

Only the first and last 8 KB of the output are read: an error is at the end, a usage message at the start.
A hint names the allowed path (the sandbox, the guard and the runner refuse the rest), never a way around.
"""
import difflib
import inspect
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # run with python3 -I: no script dir

EDGE = 8192
EROFS = re.compile(r"Read-only file system|\[Errno 30\]|\bEROFS\b")
NO_NET = re.compile(r"Temporary failure in name resolution|Name or service not known|\[Errno -[23]\]|"
                    r"Could not resolve host|Network is unreachable|getaddrinfo failed|\[Errno 101\]|no such host")
EPERM = re.compile(r"Operation not permitted|\[Errno 1\]|\bEPERM\b")
NET_WORDS = re.compile(r"socket|connect|urlopen|urllib|requests|http|ssl|dial ", re.I)
NO_MODULE = re.compile(r"ModuleNotFoundError: No module named '([\w.]+)'")
KT_ATTR = re.compile(r"module 'kt' has no attribute '(\w+)'")
HELPERS = ("survey", "review", "tree", "read", "secrets", "risky", "calls", "tools", "files", "grep", "outline",
           "show", "sh", "partition", "hidden")          # the helpers the code-mode skill documents
KT_CALL = re.compile(r"\b(\w+)\(\) (?:got an unexpected keyword argument '\w+'|missing \d+ required positional "
                     r"argument|takes \d+ positional arguments? but \d+ (?:were|was) given)")


def edges(path):
    try:
        with open(path, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            if size <= 2 * EDGE:
                return fh.read().decode("utf-8", "replace")
            head = fh.read(EDGE)
            fh.seek(size - EDGE)
            return (head + b"\n" + fh.read()).decode("utf-8", "replace")
    except OSError:
        return ""


def kt_api():
    try:
        import kt
    except Exception:
        return {}
    return {n: f for n, f in vars(kt).items() if callable(f) and not n.startswith("_") and inspect.isfunction(f)
            and getattr(f, "__module__", "") == "kt"}


def hints(text, rc, sandbox):
    out = []
    if rc == 124:
        out.append("the program hit its time limit: split the work into smaller programs, or run it in the "
                   "background (kiro-run --bg, then kiro-run --wait ID)")
    if sandbox != "off" and EROFS.search(text):
        out.append("the sandbox keeps everything outside the project read-only, and .git and .kiro inside it: "
                   "write inside the project or /tmp, or issue that step as a direct command")
    if sandbox == "deny" and (NO_NET.search(text) or (EPERM.search(text) and NET_WORDS.search(text))):
        out.append("the sandbox has no network: issue the step that needs it as a direct command (the user is "
                   "asked)")
    m = NO_MODULE.search(text)
    if m and m.group(1).split(".")[0] != "kt":
        out.append("no module named '%s' here, and installs are refused inside programs: use the standard "
                   "library, or ask the user to install it" % m.group(1))
    m = KT_ATTR.search(text)
    if m:
        api = [h for h in HELPERS if h in kt_api()]
        close = difflib.get_close_matches(m.group(1), api, n=1, cutoff=0.5)
        out.append("kt has no %s%s; its helpers: %s" % (m.group(1), ", did you mean kt.%s?" % close[0] if close else "",
                                                       ", ".join(api)))
    for m in KT_CALL.finditer(text):
        name = m.group(1)
        api = kt_api()
        if name in api and re.search(r"\bkt[ .]%s\b" % re.escape(name), text):
            out.append("kt.%s%s" % (name, inspect.signature(api[name])))
            break
    return out[:2]


def main(argv):
    if len(argv) != 4:
        sys.stderr.write(__doc__)
        return 64
    try:
        rc = int(argv[2])
    except ValueError:
        rc = 1
    for h in hints(edges(argv[1]), rc, argv[3]):
        sys.stdout.write("[kiro-run hint: %s]\n" % h)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
