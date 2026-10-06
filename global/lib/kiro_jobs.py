#!/usr/bin/env python3
"""kiro_jobs: background programs started with `kiro-run --bg` (state in .kiro/scratch/jobs/).

  kiro_jobs.py register DIR ID PID TIMEOUT LANG PROG [CAP]
                                                        record a job kiro-run has just started (CAP: the
                                                        bytes of output it keeps)
  kiro_jobs.py running DIR                              how many jobs are still running
  kiro_jobs.py wait DIR ID SECONDS CHARS                wait up to SECONDS for the job to end; print its
                                                        status and the output it printed since the last
                                                        wait, masked (exit: the job's code once it ended)
  kiro_jobs.py stop DIR ID                              stop the job and everything it started
  kiro_jobs.py list DIR                                 one line per job
  kiro_jobs.py prune DIR DAYS                           remove the files of jobs that ended more than DAYS
                                                        days ago (a running job is never touched)

A job's raw output is kept (mode 0600) only while it runs: every wait masks what it shows, and once the
job has ended and all of it was shown, the masked output replaces the raw file (ID.out).
"""
import json
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # run with python3 -I: no script dir

TAIL_LINES = 120
CAP = 20 * 1024 * 1024          # a job's output is kept up to this size (kiro-run stops a job that prints more)


def paths(d, jid):
    b = os.path.join(d, jid)
    return {"json": b + ".json", "raw": b + ".raw", "rc": b + ".rc", "out": b + ".out", "cut": b + ".cut"}


def load(d, jid):
    try:
        with open(paths(d, jid)["json"], encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def save(d, jid, job):
    p = paths(d, jid)["json"]
    with open(p + ".tmp", "w", encoding="utf-8") as fh:
        json.dump(job, fh)
    os.replace(p + ".tmp", p)


def start_ticks(pid):
    try:
        with open("/proc/%d/stat" % pid, encoding="utf-8", errors="replace") as fh:
            return fh.read().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError, ValueError):
        return None


def session_of(pid):
    try:
        with open("/proc/%d/stat" % pid, encoding="utf-8", errors="replace") as fh:
            return int(fh.read().rsplit(")", 1)[1].split()[3])
    except (OSError, IndexError, ValueError):
        return None


def alive(job):
    return start_ticks(job["pid"]) == job.get("ticks")


def ended_rc(d, jid):
    try:
        with open(paths(d, jid)["rc"], encoding="utf-8") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def status(d, jid, job):
    rc = ended_rc(d, jid)
    if rc is not None:
        return "stopped" if rc == "stopped" else "done", rc
    if alive(job):
        return "running", None
    return "lost", None             # ended without writing its exit code (killed from outside)


def elapsed(job):
    s = int(time.time() - job["started"])
    return "%dm%02ds" % (s // 60, s % 60) if s >= 60 else "%ds" % s


def register(d, jid, pid, timeout, lang, prog, cap=CAP):
    pid = int(pid)
    job = {"id": jid, "pid": pid, "ticks": start_ticks(pid), "started": time.time(), "timeout_s": int(timeout),
           "deadline": time.time() + int(timeout), "lang": lang, "prog": prog, "cursor": 0, "cwd": os.getcwd(),
           "cap": min(int(cap), CAP)}
    save(d, jid, job)
    return 0


def jobs(d):
    try:
        names = sorted(n[:-5] for n in os.listdir(d) if n.endswith(".json"))
    except OSError:
        return []
    return [(n, j) for n, j in ((n, load(d, n)) for n in names) if j]


def running(d):
    sys.stdout.write("%d\n" % sum(1 for n, j in jobs(d) if status(d, n, j)[0] == "running"))
    return 0


def mask(text):
    import kiro_redact
    values, lines = kiro_redact.file_secrets(os.getcwd())
    return kiro_redact.redact(text, known=values, lines=lines)


def take(raw, cursor, final, cap=CAP):
    """New complete lines since cursor -> (text, new cursor). An unfinished key block is held back so a
    secret is never shown in two halves that the masking cannot recognise."""
    try:
        with open(raw, "rb") as fh:
            fh.seek(cursor)
            data = fh.read(max(0, cap - cursor))       # nothing beyond the cap is shown or kept
    except OSError:
        return "", cursor
    if not final:
        cut = data.rfind(b"\n") + 1
        data = data[:cut]
        begin = data.rfind(b"-----BEGIN")
        if begin >= 0 and data.find(b"-----END", begin) < 0:
            data = data[:data.rfind(b"\n", 0, begin) + 1]
    return data.decode("utf-8", "replace"), cursor + len(data)


def units(text):
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def wait(d, jid, seconds, chars):
    job = load(d, jid)
    if job is None:
        sys.stderr.write("kiro-run: no job %s here (kiro-run --jobs lists them; call it from the folder the job "
                         "was started in)\n" % jid)
        return 66
    end = time.time() + max(0, min(int(seconds), 100))
    while status(d, jid, job)[0] == "running" and time.time() < end:
        time.sleep(0.5)
    state, rc = status(d, jid, job)
    p = paths(d, jid)
    final = state != "running"
    cap = job.get("cap", CAP)
    text, cursor = take(p["raw"], job["cursor"], final, cap)
    text, n = mask(text)
    lines = text.splitlines(True)
    if len(lines) > TAIL_LINES or units(text) > chars:
        keep = lines[-TAIL_LINES:]
        while len(keep) > 1 and units("".join(keep)) > chars:
            keep = keep[1:]
        text = "... [kiro-run: %d earlier lines of new output not shown%s]\n" % (
            len(lines) - len(keep), "; the whole masked output is kept in %s" % p["out"] if final else
            "; the whole masked output is kept when the job ends") + "".join(keep)
    sys.stdout.write(text + ("" if not text or text.endswith("\n") else "\n"))
    if n:
        sys.stdout.write("[kiro-run: %d secret value%s masked as [redacted] in this output]\n" % (n, "" if n == 1 else "s"))
    job["cursor"] = cursor
    if final and os.path.exists(p["raw"]):           # the job is over: keep the masked output, drop the raw
        try:
            with open(p["raw"], encoding="utf-8", errors="replace") as fh:
                whole = mask(fh.read(cap))[0]
            with open(p["out"], "w", encoding="utf-8") as fh:
                fh.write(whole)
            os.remove(p["raw"])
        except OSError:
            pass
    save(d, jid, job)
    if os.path.exists(p["cut"]):
        sys.stdout.write("[kiro-run: output cut at %d MB; the job was stopped: print findings, not raw data]\n"
                         % max(1, cap // (1024 * 1024)))
    if state == "running":
        sys.stdout.write("[kiro-run: job %s still running (%s of at most %ds). Do other work, then: kiro-run --wait %s]\n"
                         % (jid, elapsed(job), job["timeout_s"], jid))
        return 0
    if state == "lost":
        sys.stdout.write("[kiro-run: job %s ended without an exit code (stopped from outside)]\n" % jid)
        return 1
    if state == "stopped":
        sys.stdout.write("[kiro-run: job %s was stopped]\n" % jid)
        return 1
    rcn = int(rc) if rc.isdigit() else 1
    sys.stdout.write("[kiro-run: job %s ended: exit %s%s after %s; full output: %s]\n" % (
        jid, rc, " (killed at its %ds timeout)" % job["timeout_s"] if rcn == 124 else "", elapsed(job), p["out"]))
    return rcn


def holders(raw):
    """Processes that still have the job's output file open (they were started by it)."""
    found = set()
    try:
        target = os.path.realpath(raw)
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                for fd in os.listdir("/proc/%s/fd" % pid):
                    if os.readlink("/proc/%s/fd/%s" % (pid, fd)) == target:
                        found.add(int(pid))
                        break
            except OSError:
                continue
    except OSError:
        pass
    return found


def stop(d, jid):
    job = load(d, jid)
    if job is None:
        sys.stderr.write("kiro-run: no job %s here\n" % jid)
        return 66
    state, _ = status(d, jid, job)
    if state != "running":
        sys.stdout.write("[kiro-run: job %s is not running (%s)]\n" % (jid, state))
        return 0
    sid = session_of(job["pid"])
    victims = holders(paths(d, jid)["raw"])
    if sid == job["pid"]:
        for pid in os.listdir("/proc"):
            if pid.isdigit() and session_of(int(pid)) == sid:
                victims.add(int(pid))
    victims.add(job["pid"])
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid in victims:
            try:
                os.kill(pid, sig)
            except OSError:
                pass
        if sig == signal.SIGTERM:
            time.sleep(1)
    with open(paths(d, jid)["rc"], "w", encoding="utf-8") as fh:
        fh.write("stopped\n")
    sys.stdout.write("[kiro-run: job %s stopped (%d process%s)]\n" % (jid, len(victims), "" if len(victims) == 1 else "es"))
    return 0


def listing(d):
    rows = jobs(d)
    if not rows:
        sys.stdout.write("[kiro-run: no jobs in this folder]\n")
        return 0
    for jid, job in rows:
        state, rc = status(d, jid, job)
        what = "%s %s" % (state, elapsed(job)) if state == "running" else \
            ("done, exit %s" % rc if state == "done" else state)
        q = ""
        try:
            import kiro_runlog
            q = kiro_runlog.masked(kiro_runlog.question(job["prog"]))
        except Exception:
            pass
        sys.stdout.write("%s  %-22s %s\n" % (jid, what, ('"%s"' % q) if q else job["prog"]))
    return 0


def prune(d, days):
    """Jobs that ended more than DAYS days ago (by the newest of their files) lose all their files."""
    limit = time.time() - float(days) * 86400
    try:
        names = os.listdir(d)
    except OSError:
        return 0
    ids = sorted({n.split(".", 1)[0] for n in names if "." in n and n[0].isdigit()})
    for jid in ids:
        files = [os.path.join(d, n) for n in names if n.split(".", 1)[0] == jid]
        try:
            newest = max(os.stat(f).st_mtime for f in files)
        except (OSError, ValueError):
            continue
        job = load(d, jid)
        if newest > limit or (job is not None and status(d, jid, job)[0] == "running"):
            continue
        for f in files:
            try:
                os.remove(f)
            except OSError:
                pass
    return 0


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "register" and len(argv) in (8, 9):
        return register(*argv[2:9])
    if cmd == "running" and len(argv) == 3:
        return running(argv[2])
    if cmd == "wait" and len(argv) == 6:
        return wait(argv[2], argv[3], argv[4], int(argv[5]))
    if cmd == "stop" and len(argv) == 4:
        return stop(argv[2], argv[3])
    if cmd == "list" and len(argv) == 3:
        return listing(argv[2])
    if cmd == "prune" and len(argv) == 4:
        return prune(argv[2], argv[3])
    sys.stderr.write(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
