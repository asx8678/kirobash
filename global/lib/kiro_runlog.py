#!/usr/bin/env python3
"""kiro_runlog: kiro-run's records of what it ran, and what a failed run changed.

  kiro_runlog.py record [ARG...]     append one JSON line to $KR_SCRATCH/runs.jsonl and, when $KR_ACTION
                                     is set, one line to the audit log ($KR_LOG). Fields come from KR_*
                                     variables; the program's arguments (ARG) are masked before they are
                                     written. No output of the program is ever recorded. runs.jsonl keeps
                                     the newest KEEP records (trimmed once it passes TRIM_AT bytes).
  kiro_runlog.py changed SNAP START  print the paths a run changed (at most 10, then +N): SNAP is
                                     `git status --porcelain=v1 -z` from before the run, START its
                                     start (epoch seconds); a path counts when its status changed or it
                                     is dirty now and was written since START
"""
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # run with python3 -I: no script dir


def masked(text):
    try:
        import kiro_redact
        values, lines = kiro_redact.file_secrets(os.getcwd())
        return kiro_redact.redact(text, known=values, lines=lines)[0]
    except Exception:
        return "[not recorded: masking unavailable]" if text else text


def question(prog):
    """The first comment line of the program: by convention the question it answers."""
    try:
        with open(prog, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                s = line.strip()
                if s.startswith("#") and not s.startswith("#!"):
                    return s.lstrip("#").strip()[:200]
                if i > 20:
                    break
    except OSError:
        pass
    return ""


def sha256(path):
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return ""


def git_head():
    try:
        p = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=5)
        return p.stdout.strip() if p.returncode == 0 else ""
    except Exception:
        return ""


KEEP = 5000                     # records kept in runs.jsonl
TRIM_AT = 4 * 1024 * 1024       # bytes: past this, the file is cut back to the newest KEEP records


def append(path, line):
    """Append under a lock; past TRIM_AT bytes keep only the newest KEEP records (rewritten atomically, and
    a writer that waited on the lock appends to the new file, not to the replaced one)."""
    while True:
        with open(path, "a", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                if os.fstat(fh.fileno()).st_ino != os.stat(path).st_ino:
                    continue                            # replaced while we waited: open the new one
            except OSError:
                continue
            fh.write(line)
            fh.flush()
            if os.fstat(fh.fileno()).st_size > TRIM_AT:
                with open(path, encoding="utf-8", errors="replace") as src:
                    keep = src.readlines()[-KEEP:]
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as out:
                    out.writelines(keep)
                os.replace(tmp, path)
            return


def num(name):
    try:
        return int(os.environ.get(name, ""))
    except ValueError:
        return None


def record(args):
    e = os.environ.get
    prog = e("KR_PROG", "")
    cmdline = masked(" ".join(args))
    rec = {"v": 1, "id": e("KR_ID", ""), "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "mode": e("KR_MODE", "run"),
           "cwd": os.getcwd(), "git_head": git_head(), "lang": e("KR_LANG", ""), "prog": prog,
           "sha256": sha256(prog) if prog else "", "question": masked(question(prog)) if prog else "",
           "args": cmdline, "outcome": e("KR_OUTCOME", ""), "rc": num("KR_RC"), "ms": num("KR_MS"),
           "timeout_s": num("KR_TIMEOUT"), "lines_out": num("KR_LINES"), "parts": num("KR_PARTS"),
           "masked": num("KR_MASKED") or 0, "sandbox": e("KR_SANDBOX", "off")}
    if e("KR_REASON"):
        rec["reason"] = e("KR_REASON")
    scratch = e("KR_SCRATCH")
    if scratch and os.path.isdir(scratch):
        append(os.path.join(scratch, "runs.jsonl"), json.dumps(rec, ensure_ascii=False) + "\n")
    action, log = e("KR_ACTION"), e("KR_LOG")
    if action and log:
        what = (prog + (" " + cmdline if cmdline else "")).replace("\t", " ").replace("\n", " ")
        line = "%s\t%s\tkiro-run\trc=%s\t%s" % (rec["ts"], action, e("KR_RC", ""), what)
        if e("KR_REASON"):
            line += "\t" + e("KR_REASON").replace("\t", " ").replace("\n", " ")
        try:
            os.makedirs(os.path.dirname(log), exist_ok=True)
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass
    return 0


def parse(raw):
    out, items, i = {}, raw.decode("utf-8", "replace").split("\0"), 0
    while i < len(items):
        it = items[i]
        i += 1
        if len(it) < 4:
            continue
        out[it[3:]] = it[:2]
        if it[0] in "RC":
            i += 1                                  # the rename's source path follows
    return out


def changed(snap, start):
    try:
        with open(snap, "rb") as fh:
            before = parse(fh.read())
        start = float(start)
        p = subprocess.run(["git", "status", "--porcelain=v1", "-z"], capture_output=True, timeout=20)
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0
    if p.returncode != 0:
        return 0
    after = parse(p.stdout)
    diff = set(p for p in set(before) | set(after) if before.get(p) != after.get(p))
    for path in after:
        try:
            if os.stat(path).st_mtime >= start:
                diff.add(path)
        except OSError:
            pass
    diff = sorted(diff)
    if diff:
        shown = ", ".join(diff[:10]) + (" (+%d)" % (len(diff) - 10) if len(diff) > 10 else "")
        sys.stdout.write(masked(shown) + "\n")
    return 0


def main(argv):
    if len(argv) >= 2 and argv[1] == "record":
        return record(argv[2:])
    if len(argv) == 4 and argv[1] == "changed":
        return changed(argv[2], argv[3])
    sys.stderr.write(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
