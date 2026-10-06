#!/usr/bin/env python3
"""kiro_migrate: bring an installed kiro-guard.conf and permissions.yaml up to this version of the pack
without losing what the user set (install.sh runs it on every update).

  kiro_migrate.py conf TEMPLATE CURRENT
      rewrite CURRENT from the shipped TEMPLATE: the template's comments and settings, each setting with
      the user's value where CURRENT sets it (kept as written, even an invalid one: kiro-doctor reports
      it), settings only CURRENT has appended at the end. A new setting arrives with its explanation and
      its safe default. Nothing is written when nothing would change.
  kiro_migrate.py perms CURRENT NEW BASELINE
      three-way merge of permission rules (needs PyYAML). BASELINE holds the pack's rules as the last
      install wrote them: a rule of CURRENT that is in BASELINE but no longer in NEW was dropped or changed
      by the pack and goes; a rule of NEW that is not in BASELINE is new and is added; a rule of NEW that
      is in BASELINE but not in CURRENT was removed by the user and stays out, except a deny rule, which
      always comes back (an update never leaves the pack's protection weaker); every rule the user wrote
      stays. Without BASELINE (an install by an older installer) rules are only added. BASELINE is then
      rewritten from NEW.
"""
import os
import re
import sys
import tempfile

SETTING_RE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
KEPT_HEADER = ("# kept from your previous kiro-guard.conf: settings this version of the pack does not know\n"
               "# (kiro-doctor lists them; delete them when they are not yours)")


def write_atomic(path, text):
    """Replace path with text in one step, keeping its permissions."""
    d = os.path.dirname(os.path.abspath(path))
    mode = None
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(prefix=".kiro-migrate-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ------------------------------------------------------------------------- kiro-guard.conf ---
def settings(text):
    """{KEY: value as written} of a conf file; a later line wins, as in the guard."""
    out = {}
    for line in text.splitlines():
        m = SETTING_RE.match(line.strip())
        if m:
            out[m.group(1)] = m.group(2).rstrip()
    return out


def merge_conf(template, current):
    """(new text, settings added from the template, settings kept that the template does not have)."""
    mine = settings(current)
    known, added, lines = set(), [], []
    for line in template.splitlines():
        m = SETTING_RE.match(line.strip())
        if m and m.group(1) not in known:
            key = m.group(1)
            known.add(key)
            if key in mine:
                line = "%s=%s" % (key, mine[key])
            else:
                added.append(key)
        lines.append(line)
    extra = [k for k in mine if k not in known]
    text = "\n".join(lines).rstrip("\n") + "\n"
    if extra:
        text += "\n" + KEPT_HEADER + "\n" + "".join("%s=%s\n" % (k, mine[k]) for k in extra)
    return text, added, extra


def migrate_conf(template_path, current_path):
    with open(template_path, encoding="utf-8") as fh:
        template = fh.read()
    with open(current_path, encoding="utf-8") as fh:
        current = fh.read()
    text, added, extra = merge_conf(template, current)
    if text == current:
        return "kiro-guard.conf: up to date"
    write_atomic(current_path, text)
    if added:
        msg = "kiro-guard.conf: added %s with their defaults (your values kept)" % ", ".join(added)
    else:
        msg = "kiro-guard.conf: comments brought up to date (your values kept)"
    if extra:
        msg += "; kept settings this version does not know: %s" % ", ".join(extra)
    return msg


# ------------------------------------------------------------------------- permissions.yaml ---
def load_baseline(path):
    """The pack's rules as the last install wrote them, or None."""
    if not os.path.isfile(path):
        return None
    import yaml
    with open(path, encoding="utf-8") as fh:
        rules = (yaml.safe_load(fh) or {}).get("rules")
    return rules if isinstance(rules, list) else None


def merge_rules(current, new, baseline=None):
    """(merged rules, added, removed). Rules compare as whole values (capability, match list, effect)."""
    removed = [r for r in current if baseline is not None and r in baseline and r not in new]
    merged = [r for r in current if r not in removed]
    added = []
    for r in new:
        if r in merged:
            continue
        if baseline is not None and r in baseline and not (isinstance(r, dict) and r.get("effect") == "deny"):
            continue                    # the pack shipped it before and the user took it out (a deny comes back)
        merged.append(r)
        added.append(r)
    return merged, added, removed


def describe(rule):
    if not isinstance(rule, dict):
        return repr(rule)[:80]
    match = rule.get("match")
    first = match[0] if isinstance(match, list) and match else match
    more = " +%d" % (len(match) - 1) if isinstance(match, list) and len(match) > 1 else ""
    return "%s %s %s%s" % (rule.get("effect", "?"), rule.get("capability", "?"), first, more)


def migrate_perms(current_path, new_path, baseline_path):
    import yaml
    with open(new_path, encoding="utf-8") as fh:
        new_text = fh.read()
    with open(current_path, encoding="utf-8") as fh:
        cur = yaml.safe_load(fh) or {}
    new = yaml.safe_load(new_text) or {}
    # Only the baseline this installer wrote decides what goes: a rule list left by another installer (such as
    # permissions.kiro-pack.json) may come from a different pack, and removing its rules could weaken yours.
    baseline, msgs = load_baseline(baseline_path), []
    if baseline is None:
        msgs.append("permissions: no record of the rules the last install wrote yet, so rules are only added this "
                    "time (kiro-doctor lists rules that look like older copies of the pack's)")
    rules, added, removed = merge_rules(cur.get("rules") or [], new.get("rules") or [], baseline)
    if added or removed:
        others = {k: v for k, v in cur.items() if k != "rules"}
        if not others and rules == (new.get("rules") or []):
            text = new_text             # nothing of the user's left to keep: the pack's file, comments included
        else:
            cur["rules"] = rules
            text = ("# kiro-pack rules merged with yours by install.sh (the previous file is in ~/.kiro/backup-*)\n"
                    + yaml.safe_dump(cur, sort_keys=False, default_flow_style=False))
        write_atomic(current_path, text)
        msgs += ["permissions: added %s" % describe(r) for r in added]
        msgs += ["permissions: removed %s (dropped or changed by the pack)" % describe(r) for r in removed]
    elif not msgs:
        msgs.append("permissions: up to date")
    write_atomic(baseline_path, new_text)
    return "\n".join(msgs)


def main(argv):
    if len(argv) == 4 and argv[1] == "conf":
        print(migrate_conf(argv[2], argv[3]))
        return 0
    if len(argv) == 5 and argv[1] == "perms":
        print(migrate_perms(argv[2], argv[3], argv[4]))
        return 0
    sys.stderr.write(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
