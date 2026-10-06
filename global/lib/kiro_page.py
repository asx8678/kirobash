#!/usr/bin/env python3
"""kiro_page: keeps what kiro-run returns inside one tool result.

Kiro replaces a tool result of 30,000 characters or more with a 1,000-character preview and the path
of a file; the agent then reads that file back chunk by chunk, one turn and one permission prompt per
chunk. So kiro-run returns at most one part (about 28,000 characters) and keeps the other parts in the
scratch folder. The first part says how to fetch them: `kiro-run --more <id> <part>`, and several of
those calls fit in one step.

  kiro_page.py first <file> <chars> <prefix> <id>    print part 1 and how to get the rest; save the rest
                                                     as <prefix>.part2, <prefix>.part3 ...
  kiro_page.py fail <file> <lines> <chars> <rc> <full> [extra]
                                                     a failed run in one result: its start, its last lines
                                                     (the error) and the exit code; no parts
"""
import sys

LISTED = 8          # with more parts than this, the calls are described instead of listed


def units(text):
    """Length as Kiro counts it: UTF-16 code units."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def split(text, budget):
    """Cut text into parts of at most `budget` units, at line ends; a line longer than a part is cut."""
    if units(text) <= budget:
        return [text]
    parts, cur, size = [], [], 0
    for line in text.splitlines(True):
        while units(line) > budget:                     # one enormous line: cut it by characters
            if cur:
                parts.append("".join(cur))
                cur, size = [], 0
            cut = budget if units(line[:budget]) <= budget else budget // 2      # a character is at most 2 units
            parts.append(line[:cut])
            line = line[cut:]
        n = units(line)
        if cur and size + n > budget:
            parts.append("".join(cur))
            cur, size = [], 0
        cur.append(line)
        size += n
    if cur:
        parts.append("".join(cur))
    return parts


def first_footer(run_id, total, budget):
    rest = total - 1
    head = ("[kiro-run: part 1 of %d. One tool result holds about %s characters, so the rest of this output "
            "waits in %d more part%s.\n Fetch %s now, as separate calls issued together in ONE step:\n"
            % (total, format(budget, ","), rest, "" if rest == 1 else "s", "it" if rest == 1 else "them all"))
    if total <= LISTED:
        calls = "".join("   kiro-run --more %s %d\n" % (run_id, k) for k in range(2, total + 1))
    else:
        calls = "   kiro-run --more %s N     (one call for each N from 2 to %d)\n" % (run_id, total)
    return head + calls + " Read every part before you draw conclusions from this output.]\n"


def footer(k, total):
    return "[kiro-run: part %d of %d%s]\n" % (k, total, " — end of the output" if k == total else "")


def first(path, budget, prefix, run_id):
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    parts = split(text, budget)
    if len(parts) == 1:
        sys.stdout.write(text)
        return 0
    for k, part in enumerate(parts[1:], 2):
        with open("%s.part%d" % (prefix, k), "w", encoding="utf-8") as fh:
            fh.write(part)
            if not part.endswith("\n"):
                fh.write("\n")
            fh.write(footer(k, len(parts)))
    sys.stdout.write(parts[0])
    if not parts[0].endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.write(first_footer(run_id, len(parts), budget))
    return 0


TAIL = 60          # a failed run shows its last lines: that is where the traceback or the error is


def fail(path, max_lines, budget, rc, full, extra):
    """A failed run in one result: the whole output when it fits, otherwise its start, a marker and its
    last TAIL lines, both within the line cap and the character budget. Ends with the exit code."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines(True)
    end = "[kiro-run: exit %s]\n" % rc
    if extra:
        end += extra if extra.endswith("\n") else extra + "\n"
    if len(lines) <= max_lines and units("".join(lines)) + units(end) <= budget:
        text = "".join(lines)
        sys.stdout.write(text + ("" if not text or text.endswith("\n") else "\n") + end)
        return 0
    tail = lines[-TAIL:]
    while len(tail) > 1 and units("".join(tail)) > budget // 2:     # very long lines: fewer of them
        tail = tail[1:]
    tail_text = "".join(tail)
    if units(tail_text) > budget // 2:
        tail_text = tail_text[-(budget // 4):]
    end = ("[kiro-run: exit %s; full output: %s — read it with kt.show or grep instead of running the "
           "program again]\n" % (rc, full)) + (extra if not extra or extra.endswith("\n") else extra + "\n")
    room = budget - units(tail_text) - units(end) - 200
    head, size = [], 0
    for line in lines[:max(0, min(max_lines - len(tail), len(lines) - len(tail)))]:
        n = units(line)
        if size + n > room:
            break
        head.append(line)
        size += n
    skipped = len(lines) - len(head) - len(tail)
    sys.stdout.write("".join(head))
    if head and not head[-1].endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.write("... [kiro-run: %d lines not shown; the last %d lines follow]\n" % (skipped, len(tail)))
    sys.stdout.write(tail_text + ("" if tail_text.endswith("\n") else "\n") + end)
    return 0


def main(argv):
    if len(argv) == 6 and argv[1] == "first":
        return first(argv[2], max(2000, int(argv[3])), argv[4], argv[5])
    if len(argv) in (7, 8) and argv[1] == "fail":
        return fail(argv[2], int(argv[3]), max(2000, int(argv[4])), argv[5], argv[6], argv[7] if len(argv) == 8 else "")
    sys.stderr.write(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
