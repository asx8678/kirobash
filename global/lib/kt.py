"""kt: helpers for kiro-run programs (`import kt`; in a bash program: `kt tree`, `kt read 'src/**'` ...).

Read-only repo inspection that keeps output small and keeps secrets out of it.

  kt.review()                             step one of a code review: kt.survey(), kt.read() and what to work out next
  kt.survey()                             the first look, in one call: tree, secrets, risky, calls and the tools installed
  kt.tree(depth=2)                        layout: folders, files, lines by type, and what is hidden
  kt.read("**/*")                         whole files, numbered, one after another: read a batch in one run
  kt.secrets()                            committed secrets: file, line and kind, never the value
  kt.risky()                              lines worth a look for the stack (tokens in URLs, RBAC, TLS off ...)
  kt.calls()                              scripts run from other files: what each declares, what each caller passes
  kt.files("**/*.go")                     matching files (list)
  kt.grep(r"pattern", "**/*.py", ctx=1)   matches as path:line: text
  kt.outline("internal/**/*.go")          functions/types with line numbers
  kt.show("path", 120, 160)               numbered lines of a range (or around=140)
  kt.sh("go vet ./...", tail=40)          run a command; prints the exit code and the last lines

Each function prints its findings and returns the data, so call it bare (`kt.tree()`), or pass
quiet=True to get only the data. Listings and searches skip what .gitignore and .kiroignore hide.
A secrets file (.env, secrets/, keys ...) can still be looked at: kt.show() and kt.read() print its
structure with every value replaced by [redacted] and a note on whether the value looks real.
"""
import fnmatch
import os
import re
import subprocess
import sys

MARK = "[redacted]"
_HOME = os.path.expanduser("~")
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".terraform", ".kiro", "vendor",
              "dist", "build", "target", ".cache", ".idea", ".vscode"}
_MAX_BYTES = 1_000_000
_ignore_cache = {}
_rule_cache = {}
# Secret files, known as such even where no .kiroignore exists; a .kiroignore can re-include with `!pattern`.
_SECRET_PATTERNS = [".env", ".env.*", "!.env.example", "!.env.sample", "!.env.template", "*.env", "!example.env",
                    "!sample.env", "!template.env", ".envrc", "*.pem", "*.key", "*.p12",
                    "*.pfx", "*kubeconfig*", "secrets/", "*.tfstate", "*.tfstate.*", ".ssh/", ".aws/", ".azure/",
                    "id_rsa*", "id_ed25519*", ".netrc", ".npmrc", ".git-credentials", "local.settings.json"]
# In a .kiroignore, the patterns under a comment that mentions one of these words are secrets;
# the rest (dependencies, build output, logs, archives) are hidden only to save tokens.
_SECRET_SECTION = re.compile(r"secret|credential|sensitive|password|token", re.I)
_CODE_EXT = (".sh", ".bash", ".zsh", ".ps1", ".psm1", ".py", ".rb", ".go", ".js", ".ts", ".java", ".cs", ".md", ".rst",
             ".tf", ".tpl", ".cmd", ".bat")


class _Rows(list):
    """Result of a helper that already printed its findings: printing it again adds nothing."""

    def __repr__(self):
        return ""

    __str__ = __repr__


class _Info(dict):
    def __repr__(self):
        return ""

    __str__ = __repr__


class _Run(tuple):
    def __repr__(self):
        return ""

    __str__ = __repr__


# ------------------------------------------------------------- ignore rules ---
def _patterns(root):
    """[(pattern, is_secret)] from the built-in list, ~/.kiro/settings/kiroignore and <root>/.kiroignore."""
    key = os.path.abspath(root)
    if key not in _ignore_cache:
        pats = [(p, True) for p in _SECRET_PATTERNS]
        for p in (os.path.join(_HOME, ".kiro", "settings", "kiroignore"), os.path.join(key, ".kiroignore")):
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    is_secret = False
                    for ln in fh:
                        ln = ln.strip()
                        if ln.startswith("#"):
                            is_secret = bool(_SECRET_SECTION.search(ln))
                        elif ln:
                            pats.append((ln, is_secret))
            except OSError:
                pass
        _ignore_cache[key] = pats
    return _ignore_cache[key]


def _compiled(root):
    """Rules as regexes, plus one combined regex that tells quickly whether any rule can match a name."""
    key = os.path.abspath(root)
    if key not in _rule_cache:
        rules, names, has_path_rule = [], [], False
        for pat, is_secret in _patterns(root):
            neg = pat.startswith("!")
            p = pat[1:] if neg else pat
            dir_only = p.endswith("/")
            p = p.strip("/")
            if not p:
                continue
            rules.append((neg, dir_only, "/" in p, p, re.compile(fnmatch.translate(p)), is_secret))
            if not neg:
                if "/" in p:
                    has_path_rule = True
                else:
                    names.append(fnmatch.translate(p))
        _rule_cache[key] = (rules, re.compile("|".join(names)) if names else None, has_path_rule)
    return _rule_cache[key]


def _kind_rel(rel, root=".", is_dir=False):
    """Classify a path given relative to root: None (visible), "secret" or "bulk".
    The last matching rule wins, as in .gitignore."""
    parts = rel.split("/")
    rules, quick, has_path_rule = _compiled(root)
    if not has_path_rule and (quick is None or not any(quick.match(c) for c in parts)):
        return None
    kind = None
    for neg, dir_only, has_slash, p, rx, is_secret in rules:
        if has_slash:
            m = rx.match(rel) or rel.startswith(p + "/")
        elif dir_only:
            m = any(rx.match(c) for c in parts[:-1]) or (is_dir and rx.match(parts[-1]))
        else:
            m = any(rx.match(c) for c in parts)
        if m:
            kind = None if neg else ("secret" if is_secret else "bulk")
            if kind == "secret" and "*" in p and not has_slash and not dir_only and rel.lower().endswith(_CODE_EXT):
                kind = "bulk"          # make-kubeconfig.sh, secret-rotation.md: hidden, but code or text, not values
    return kind


def _kind(path, root="."):
    rel = os.path.relpath(os.path.abspath(path), os.path.abspath(root)).replace(os.sep, "/")
    return _kind_rel(rel, root, os.path.isdir(path))


def ignored(path, root="."):
    """True when .kiroignore (built-in, global or the project's) hides this path."""
    return _kind(path, root) is not None


def secret(path, root="."):
    """True when the path is a secrets file (.env, secrets/, keys, state ...)."""
    return _kind(path, root) == "secret"


# ------------------------------------------------------------------ files ---
def _glob_re(glob):
    if "/" not in glob:
        glob = "**/" + glob
    out, i = "", 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif glob.startswith("**", i):
            out, i = out + ".*", i + 2
        elif glob[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif glob[i] == "?":
            out, i = out + "[^/]", i + 1
        elif glob[i] == "{" and "}" in glob[i:]:
            j = glob.index("}", i)
            out, i = out + "(?:" + "|".join(re.escape(x) for x in glob[i + 1:j].split(",")) + ")", j + 1
        else:
            out, i = out + re.escape(glob[i]), i + 1
    return re.compile("^" + out + "$")


def _all_files(root):
    """Every file git would track or add (or, outside git, every file below root), relative to root."""
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-co", "--exclude-standard"],
                             capture_output=True, text=True, timeout=30)
        if out.returncode == 0:
            return sorted({n for n in out.stdout.splitlines() if n and os.path.isfile(os.path.join(root, n))})
    except (OSError, subprocess.SubprocessError):
        pass
    names = []
    for d, dirs, fs in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in _SKIP_DIRS)
        names += [os.path.relpath(os.path.join(d, f), root).replace(os.sep, "/") for f in fs]
        if len(names) > 20000:                           # not a project (a home folder?): stop here
            break
    return sorted(names)


def _as_glob(target, root="."):
    """A folder given where a glob is expected means everything below it."""
    if isinstance(target, str) and not any(c in target for c in "*?{") and os.path.isdir(os.path.join(root, target)):
        return target.rstrip("/") + "/**"
    return target


def files(glob="**/*", root=".", limit=5000):
    """Files under root matching the glob (`**` crosses folders; a glob without `/` matches at any depth;
    a folder name means everything below it), sorted, without anything .gitignore or .kiroignore hides."""
    rx = _glob_re(_as_glob(glob, root))
    return [n for n in _all_files(root) if rx.match(n) and _kind_rel(n, root) is None][:limit]


def hidden(root="."):
    """Files .kiroignore hides: [(path, "secret" | "bulk")]. Names only; see kt.show for a masked view."""
    return [(n, k) for n, k in ((n, _kind_rel(n, root)) for n in _all_files(root)) if k]


def _clip(line, width=600):
    """A line as printed: whole up to `width` characters, else cut with a note of how much is missing."""
    line = line.rstrip()
    return line if len(line) <= width else "%s …[+%d chars]" % (line[:width], len(line) - width)


def _read(path):
    """Lines of a text file, or None for binary, huge or unreadable files."""
    try:
        if os.path.getsize(path) > _MAX_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\0" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace").splitlines()


# ---------------------------------------------------------------- secrets ---
_KEEP_ATTRS = ("key", "name", "id", "type", "version", "encoding")
# what a secrets file holds besides secrets: plain URLs, host names, paths, numbers and sizes
_PLAIN_VALUE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://[^\s@?#]+|[\w-]+(?:\.[\w-]+)+(?::\d+)?|[~.]{0,2}/?(?:[\w.-]+/)+[\w.-]*|"
                          r"\d+(?:\.\d+)*\s?[A-Za-z%]{0,5})$")
_XML_TEXT = re.compile(r">([^<>]*[^<>\s][^<>]*)<")
_ATTR = re.compile(r"""([\w:.-]+)(\s*=\s*)(["'])(.*?)\3""")
_KV = re.compile(r"""^(\s*(?:-\s+)?(?:export\s+)?["']?[A-Za-z_@][\w.\-/ \[\]"']*?["']?\s*[:=]\s*)(.*?)([,;]?\s*)$""")
_SCOPED_KEY = re.compile(r"^(\s*//[^\s=]+=\s*)(\S.*)$")          # .npmrc: //registry.host/path/:_authToken=value
_STRUCT_LINE = re.compile(r"^\s*(?:<[^<>]*>|\[redacted\]|[{}\[\],]|\s)*\s*$")
_PEM = re.compile(r"-----BEGIN [^-\n]+-----[\s\S]*?(?:-----END [^-\n]+-----|\Z)")
_BLOCK_OPENERS = ("", "{", "[", "|", ">", "|-", ">-", "|+", ">+", "{}", "[]")


def _keeps(attr):
    name = attr.lower()
    return name.startswith("xmlns") or name.split(":")[-1] in _KEEP_ATTRS


def mask(text):
    """The structure of a secrets file with every value replaced by [redacted]: keys, tags and plain
    comments stay, values go. Anything that is not clearly structure is masked as a whole line."""
    out = []
    for line in _PEM.sub(MARK, text).splitlines():
        s = line.rstrip("\r")
        body = s.strip()
        indent = s[:len(s) - len(s.lstrip())]
        if not body:
            out.append(s)
            continue
        m = _SCOPED_KEY.match(s)
        if m:                                            # a key that starts with //: keep it, mask the value
            out.append(m.group(1) + MARK)
            continue
        if re.match(r"(#|//|;|--|<!--)", body):          # a comment: kept unless it carries a value
            out.append(indent + MARK if re.search(r"[:=]\s*\S", body.lstrip("#/;-<! ")) else s)
            continue
        s = _XML_TEXT.sub(">" + MARK + "<", s)
        s = _ATTR.sub(lambda m: m.group(0) if _keeps(m.group(1)) else m.group(1) + m.group(2) + m.group(3) + MARK + m.group(3), s)
        if _STRUCT_LINE.match(s):
            out.append(s)
            continue
        m = _KV.match(s)
        if m:
            out.append(s if m.group(2).strip() in _BLOCK_OPENERS else m.group(1) + MARK + m.group(3))
            continue
        out.append(indent + MARK)
    return "\n".join(out)


def _masked_lines(lines):
    """The lines of a secrets file with their values masked, each followed by what the value looks like."""
    masked = mask("\n".join(lines)).splitlines()
    if len(masked) != len(lines):                # a multi-line key was folded into one mark
        return masked
    return [m + (_line_hint(raw) if m.strip() != raw.strip() else "") for raw, m in zip(lines, masked)]


def _wordy(v):
    """True for a short lower-case value made of words and numbers joined by - _ or . (eu-west-1,
    api-service-01, us_east_2): a region, a name or a tag, not a key. Capitals (Summer-2024) or four and
    more parts in 20+ characters (a passphrase) do not count."""
    parts = [x for x in re.split(r"[-_.]+", v) if x]
    return len(parts) >= 2 and (len(parts) <= 3 or len(v) < 20) and all(re.fullmatch(r"[a-z]+\d{0,3}|\d{1,4}", x) for x in parts)


def _secretish(v):
    if not 6 <= len(v) <= 4000:
        return False
    if re.match(r"(\$\{|\$\(|\{\{|<|%\(|%\{)", v) or v.lower() in ("changeme", "placeholder", "example", "localhost"):
        return False
    if _PLAIN_VALUE.match(v) or _wordy(v):
        return False
    return len(v) >= 20 or bool(re.search(r"\d", v)) or bool(re.search(r"[^\w\s.-]", v))


def _raw_values(text):
    """Every value found in a secrets file: element text, attribute values, key=value and list items,
    values left in comments, and the parts of connection strings."""
    vals = set(m.group(1).strip() for m in _XML_TEXT.finditer(text))
    vals |= set(m.group(4) for m in _ATTR.finditer(text) if not _keeps(m.group(1)))
    for line in text.splitlines():
        body = line.strip()
        m = _SCOPED_KEY.match(line)
        if m:
            vals.add(m.group(2).strip().strip("\"',"))
            continue
        if body.startswith(("#", "//", ";", "<!--")):          # a value left in a comment: "# old: pw=..."
            m = re.search(r"[:=]\s*([^\s:=]+)\s*(?:-->)?$", body)
            if m:
                vals.add(m.group(1).strip("\"',"))
            continue
        if not body or body.startswith("<"):
            continue
        m = _KV.match(line)
        vals.add((m.group(2) if m else body.lstrip("- ")).strip().strip("\"',"))
    for v in list(vals):
        for part in re.split(r"[;&\s]+", v):
            if "=" in part:
                vals.add(part.split("=", 1)[1].strip("\"'"))
    return {v for v in vals if v}


def _values(text):
    """The values of a secrets file that are worth hiding wherever they are printed."""
    return {v for v in _raw_values(text) if _secretish(v)}


_PLACEHOLDER = re.compile(r"(?i)^(secret|password|passwd|change[-_ ]?me|example|sample|placeholder|dummy|test|todo|x{3,}|"
                          r"your[-_ ]|my[-_ ]|none|null|admin|user|root|guest|default|true|false)|^<.*>$|^\$\{.*\}$|"
                          r"localhost|127\.0\.0\.1|UseDevelopmentStorage|devstoreaccount1|example\.(com|org)")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$")          # SECRET_API_KEY: the name of a variable, not a value


_SECRET_KEY = re.compile(r"(?i)pass(word|wd)?|pwd|secret|token|api[-_]?key|private|credential")
_CARRIES_CREDENTIAL = re.compile(r"(?i)(password|pwd|accountkey|sharedaccesskey|secret|token|sig)\s*=\s*[^;&\s]{6,}|://[^/\s:@]+:[^@\s]{6,}@")


def _shape(v):
    """How a secret value looks, without showing it: "placeholder-looking", "plain setting" (a URL, a host,
    a path, a number, a list of words), "real-looking" or "unclear"."""
    v = v.strip().strip("\"'")
    if not v or _PLACEHOLDER.search(v) or _ENV_NAME.match(v):
        return "placeholder-looking"
    if _CARRIES_CREDENTIAL.search(v):
        return "real-looking"                              # a connection string or URL with a credential in it
    pieces = [x for x in re.split(r"[,;|\s]+", v) if x]
    if _PLAIN_VALUE.match(v) or _wordy(v) or (len(pieces) >= 2 and all(re.fullmatch(r"[A-Za-z]+\d{0,3}|\d+", x) or _wordy(x) for x in pieces)):
        return "plain setting"
    classes = sum(bool(re.search(rx, v)) for rx in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]"))
    one_token = re.fullmatch(r"[A-Za-z0-9+/=_.~-]+", v)
    if (len(v) >= 8 and classes >= 3 and " " not in v) or (one_token and len(v) >= 20 and classes >= 2 and re.search(r"\d", v)):
        return "real-looking"
    return "unclear"


def _line_hint(line):
    """' <- real-looking, 44 chars' for a line of a secrets file that carries a value, else ''."""
    vals = [v for v in _raw_values(line) if len(v) >= 3]
    if not vals:
        return ""
    whole = max(vals, key=len)
    shape = _shape(whole)
    if shape != "placeholder-looking" and any(_shape(v) == "real-looking" for v in vals):
        shape = "real-looking"
    if shape == "plain setting" and _SECRET_KEY.search(line.split("=")[0].split(":")[0]):
        shape = "unclear"                        # under a key called password or token, words are not just a setting
    return "   <- %s, %d chars" % (shape, len(whole))


def _harmless(shape):
    return shape in ("placeholder-looking", "plain setting")


_material_cache = {}


def _secret_material(root, max_files=200, max_bytes=262144):
    """(values, lines) of the secrets files below root. `lines` maps each line that carries a value to
    its masked form, so a file printed verbatim is masked line by line whatever the values look like."""
    key = os.path.abspath(root)
    if key not in _material_cache:
        vals, lines = set(), {}
        names = [n for n in _all_files(root) if _kind_rel(n, root) == "secret"]
        for n in names[:max_files]:
            full = os.path.join(root, n)
            try:
                if os.path.getsize(full) > max_bytes:
                    continue
            except OSError:
                continue
            content = _read(full)
            if content is None:
                continue
            text = "\n".join(content)
            vals |= _values(text)
            for raw, masked in zip(text.splitlines(), mask(text).splitlines()):
                raw, masked = raw.strip(), masked.strip()
                if len(raw) >= 4 and raw != masked:
                    lines[raw] = masked
            if len(vals) > 5000 or len(lines) > 20000:
                break
        _material_cache[key] = (vals, lines)
    return _material_cache[key]


def secret_values(root="."):
    """Values of the secrets files below root, for the output filter of kiro-run: whatever a program
    prints, these strings are replaced by [redacted]."""
    return _secret_material(root)[0]


def secret_lines(root="."):
    """{line of a secrets file: the same line with its value masked}, for the output filter."""
    return _secret_material(root)[1]


# ------------------------------------------------------------------- grep ---
def grep(pattern, glob="**/*", ctx=0, max_hits=60, ignore_case=False, root=".", quiet=False, path=None):
    """Regex search. Prints `path:line: text` (with ctx lines around each hit) and returns
    [(path, line number, text)]. Output stops after max_hits; the return value has every hit.
    The glob may be a folder or a file (`path=` is accepted as another name for it)."""
    glob = path or glob
    rx = re.compile(pattern, re.I if ignore_case else 0)
    hits = []
    for n in files(glob, root):
        lines = _read(os.path.join(root, n))
        if lines is None:
            continue
        for i, line in enumerate(lines):
            if not rx.search(line):
                continue
            hits.append((n, i + 1, line.rstrip()))
            if quiet or len(hits) > max_hits:
                continue
            for j in range(max(0, i - ctx), min(len(lines), i + ctx + 1)):
                print("%s:%d%s %s" % (n, j + 1, ":" if j == i else "-", _clip(lines[j], 300)))
            if ctx:
                print("--")
    if quiet:
        return hits
    if len(hits) > max_hits:
        print("... %d more matches not shown (%d in total)" % (len(hits) - max_hits, len(hits)))
    elif not hits:
        print("no matches for %r in %s" % (pattern, glob))
    return _Rows(hits)


# ---------------------------------------------------------------- outline ---
def _rules(*pairs):
    return [re.compile(p) for p in pairs]


_OUTLINE = {
    ".go": _rules(r"^func\s", r"^type\s+\w+\s+(struct|interface)\b"),
    ".py": _rules(r"^\s*(async\s+)?def\s+\w+", r"^\s*class\s+\w+"),
    ".js": _rules(r"^\s*(export\s+)?(default\s+)?(async\s+)?function\b", r"^\s*(export\s+)?(default\s+)?class\s+\w+",
                  r"^\s*(export\s+)?(const|let|var)\s+\w+\s*=\s*(async\s*)?(\([^)]*\)|\w+)\s*=>"),
    ".rs": _rules(r"^\s*(pub(\([^)]*\))?\s+)?(async\s+)?(unsafe\s+)?fn\s+\w+",
                  r"^\s*(pub(\([^)]*\))?\s+)?(struct|enum|trait|impl|mod)\b"),
    ".java": _rules(r"^\s*(public|protected|private)?\s*(static\s+)?(final\s+)?(abstract\s+)?(class|interface|enum|record)\s+\w+",
                    r"^\s*(public|protected|private)\s+[\w<>\[\], ]+\s+\w+\s*\([^;]*$"),
    ".sh": _rules(r"^\s*(function\s+)?[A-Za-z_][\w-]*\s*\(\)\s*\{?", r"^\s*function\s+[A-Za-z_][\w-]*"),
    ".tf": _rules(r'^(resource|data|module|variable|output|provider|locals|terraform)\b'),
    ".bicep": _rules(r"^(resource|module|param|var|output|targetScope)\b"),
    ".sql": _rules(r"(?i)^\s*(create|alter)\s+(or\s+replace\s+)?(table|view|function|procedure|index|trigger)\b"),
    ".yaml": _rules(r"^(kind|name|stages|jobs|steps|services|resources|on|trigger):", r"^- (stage|job|name|template):"),
    ".ps1": _rules(r"(?i)^\s*function\s+[\w-]+"),
    ".rb": _rules(r"^\s*(def|class|module)\s+\w+"),
    ".php": _rules(r"^\s*((public|protected|private|static|final|abstract)\s+)*function\s+\w+", r"^\s*(abstract\s+|final\s+)?(class|interface|trait)\s+\w+"),
}
for _ext, _same in ((".ts", ".js"), (".tsx", ".js"), (".jsx", ".js"), (".mjs", ".js"), (".cjs", ".js"), (".kt", ".java"),
                    (".cs", ".java"), (".bash", ".sh"), (".yml", ".yaml"), (".tfvars", ".tf")):
    _OUTLINE[_ext] = _OUTLINE[_same]
_OUTLINE[".ts"] = _OUTLINE[".js"] + _rules(r"^\s*(export\s+)?(declare\s+)?(interface|type|enum|namespace)\s+\w+")
_OUTLINE[".tsx"] = _OUTLINE[".ts"]


def outline(target="**/*", root=".", max_lines=300, quiet=False):
    """Definitions (functions, types, resources ...) with their line numbers, per file.
    target is a path or a glob. Returns [(path, line number, signature)]."""
    names = [target] if os.path.isfile(os.path.join(root, target)) else files(target, root)
    rows, shown = [], 0
    for n in names:
        rules = _OUTLINE.get(os.path.splitext(n)[1].lower())
        lines = _read(os.path.join(root, n)) if rules and not secret(os.path.join(root, n), root) else None
        if lines is None:
            continue
        found = [(i + 1, ln.strip()[:140]) for i, ln in enumerate(lines) if any(r.search(ln) for r in rules)]
        rows += [(n, i, sig) for i, sig in found]
        if quiet:
            continue
        if shown < max_lines:
            print("%s (%d lines)" % (n, len(lines)))
        for i, sig in found:
            shown += 1
            if shown <= max_lines:
                print("%6d  %s" % (i, sig))
    if quiet:
        return rows
    if shown > max_lines:
        print("... %d more definitions not shown; narrow the glob" % (shown - max_lines))
    return _Rows(rows)


# ------------------------------------------------------------------- show ---
def show(path, start=1, end=None, around=None, span=20, root="."):
    """Print lines start..end of a file with line numbers (or `span` lines either side of `around`).
    Without a range the whole file is printed, up to 400 lines. A secrets file is printed with its
    values masked."""
    full = os.path.join(root, path)
    lines = _read(full)
    if lines is None:
        print("%s: missing, binary or larger than 1 MB" % path)
        return _Rows()
    note = ""
    if secret(full, root):
        lines = _masked_lines(lines)
        note = " — secrets file: values are masked"
    if around:
        start, end = max(1, around - span), around + span
    start = max(1, start)
    end = min(len(lines), end or start + 399)
    print("%s:%d-%d (of %d lines)%s" % (path, start, end, len(lines), note))
    for i in range(start - 1, end):
        print("%6d  %s" % (i + 1, _clip(lines[i])))
    return _Rows(lines[start - 1:end])


# ------------------------------------------------------------------- read ---
_DATA_EXT = {".json", ".csv", ".tsv", ".xml", ".whitelist", ".lock", ".svg", ".map", ".ndjson", ".jsonl", ".txt", ".sum"}
_SKIP_NAMES = {".gitignore", ".gitattributes", ".editorconfig", ".dockerignore", ".helmignore", ".npmignore", "LICENSE"}
# dot-folders that hold source (pipelines, build config); any other dot-folder is some tool's own state
_SOURCE_DOT_DIRS = {".github", ".azure-pipelines", ".gitlab", ".circleci", ".devcontainer", ".husky", ".pipelines", ".ci",
                    ".config", ".buildkite", ".tekton", ".chglog", ".semgrep"}


def _raise_cap(printed):
    """Tell kiro-run that this much output is wanted, so a deliberate read is not cut at the default cap."""
    path = os.environ.get("KIRO_RUN_CAPFILE")
    if not path:
        return
    try:
        old = 0
        if os.path.exists(path):
            with open(path) as fh:
                old = int(fh.read().strip() or 0)
        with open(path, "w") as fh:
            fh.write(str(old + printed))
    except (OSError, ValueError):
        pass


def _name_some(rows, limit=12):
    """'a (3 lines), b (9 lines)' for a short list; for a long one the first few, then totals by folder."""
    if len(rows) <= limit:
        return ", ".join("%s (%d lines)" % r for r in rows)
    folders = {}
    for n, c in rows:
        top = n.split("/")[0] + "/" if "/" in n else "(top level)"
        f = folders.setdefault(top, [0, 0])
        f[0] += 1
        f[1] += c
    by_size = sorted(folders.items(), key=lambda kv: -kv[1][1])
    return "%d files, %d lines. By folder: %s%s" % (
        len(rows), sum(c for _, c in rows), "; ".join("%s %d files %d lines" % (d, f, c) for d, (f, c) in by_size[:15]),
        "; ... %d more folders" % (len(by_size) - 15) if len(by_size) > 15 else "")


def read(target="**/*", max_lines=2500, root=".", data_lines=200, first=()):
    """Print whole files, numbered, one after another: the way to read a batch of source in ONE run
    instead of one file per turn. target is a glob, a path, or a list of them. Long data files
    (JSON, XML, CSV ... over data_lines lines) and housekeeping files are named, not printed; a secrets
    file comes with its values masked. Stops at max_lines and says what is left; when not everything
    fits, the files named in `first` are printed before the others.
    Returns [(path, lines printed)]."""
    targets = target if isinstance(target, (list, tuple)) else [target]
    names = []
    for t in targets:
        hit = [t] if os.path.isfile(os.path.join(root, t)) else files(t, root)
        if not hit and any(c in t for c in "*?{"):
            hit = [n for n, _ in hidden(root) if _glob_re(t).match(n)]       # asked for by name: show it masked
        names += [n for n in hit if n not in names]
    wanted, skipped, unreadable = [], [], []
    for n in names:
        lines = _read(os.path.join(root, n))
        if lines is None:
            unreadable.append(n)
            continue
        tool_state = any(d.startswith(".") and d not in _SOURCE_DOT_DIRS for d in n.split("/")[:-1])
        if n not in targets and (os.path.basename(n) in _SKIP_NAMES or tool_state or
                                 (os.path.splitext(n)[1].lower() in _DATA_EXT and len(lines) > data_lines)):
            skipped.append((n, len(lines)))
            continue
        wanted.append((n, lines))
    if first and sum(len(lines) + 1 for _, lines in wanted) > max_lines:     # not everything fits: what matters first
        rank = {n: k for k, n in enumerate(first)}
        wanted.sort(key=lambda w: rank.get(w[0], len(rank)))
    done, left, used = [], [], 0
    for n, lines in wanted:
        if used and used + len(lines) > max_lines:
            left.append((n, len(lines)))
            continue
        note = ""
        if secret(os.path.join(root, n), root):
            lines, note = _masked_lines(lines), " — secrets file: values are masked"
        print("=== %s (%d lines)%s ===" % (n, len(lines), note))
        width = len(str(len(lines)))                 # a narrow number column: more source fits in one result
        for i, ln in enumerate(lines):
            print("%*d  %s" % (width, i + 1, _clip(ln)))
        used += len(lines) + 1
        done.append((n, len(lines)))
    print("--- read %d file%s, %d lines" % (len(done), "" if len(done) == 1 else "s", sum(c for _, c in done)))
    if skipped or unreadable:
        print("not printed (data, housekeeping or a tool's own folder; kt.show or kt.grep them if they matter): "
              + _name_some(skipped) + ("; binary or over 1 MB: %d files" % len(unreadable) if unreadable else ""))
    if left:
        print("NOT READ YET (over the %d-line budget of this call): %s" % (max_lines, _name_some(left)))
        print("  -> kt.read([\"path\", \"folder/**\"]) for what the task needs; kt.outline(\"folder/**\") shows what is in a folder first")
    _raise_cap(used + 6)
    return _Rows(done)


# ---------------------------------------------------------------- secrets ---
def secrets(glob="**/*", root=".", max_lines=60, quiet=False):
    """Committed secrets, reported safely: for every secret-looking value in the visible files the file,
    the line and the kind of secret, never the value; and for the secrets files that git tracks, how many
    of their values look real. Returns [(path, line number, kind)]."""
    try:
        import kiro_redact
    except ImportError:
        print("kt.secrets: the masking filter is not installed next to kt")
        return _Rows()
    found = []
    for n in files(glob, root):
        lines = _read(os.path.join(root, n))
        if lines is None:
            continue
        for i, ln in enumerate(lines):
            for kind in kiro_redact.kinds(ln):
                found.append((n, i + 1, kind))
    try:
        out = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True, timeout=30)
        tracked = set(out.stdout.splitlines()) if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        tracked = None
    files_report = []
    for n, kind in hidden(root):
        if kind != "secret":
            continue
        lines = _read(os.path.join(root, n))
        vals = [v for ln in (lines or []) for v in [max(_raw_values(ln), key=len, default="")] if len(v) >= 3] if lines else []
        shapes = [_shape(v) for v in vals]
        files_report.append((n, tracked is None or n in tracked, len(vals), shapes.count("real-looking"),
                             sum(1 for x in shapes if _harmless(x))))
    if quiet:
        return found
    if found:
        groups = {}
        for n, i, kind in found:
            groups.setdefault((n, kind), []).append(i)
        print("secret-looking values committed in ordinary files (%d lines in %d files) — each is a finding to confirm:"
              % (len(found), len({n for n, _, _ in found})))
        for k, ((n, kind), nums) in enumerate(sorted(groups.items())):
            if k >= max_lines:
                print("  ... %d more groups" % (len(groups) - max_lines))
                break
            where = "line %d" % nums[0] if len(nums) == 1 else "lines %s" % _ranges(nums)
            print("  %s: %s — %s%s" % (n, where, kind, " x%d" % len(nums) if len(nums) > 1 else ""))
    else:
        print("no secret-looking values in the visible files")
    for n, is_tracked, total, real, placeholder in files_report:
        print("secrets file %s: %s, %d value%s — %d real-looking, %d placeholders or plain settings, %d unclear"
              % (n, "TRACKED IN GIT" if is_tracked else "not tracked", total, "" if total == 1 else "s",
                 real, placeholder, total - real - placeholder))
    return _Rows(found)


def _ranges(nums):
    """[3, 4, 5, 9] -> '3-5, 9'"""
    out, start, prev = [], None, None
    for n in sorted(set(nums)):
        if start is None:
            start = prev = n
        elif n == prev + 1:
            prev = n
        else:
            out.append("%d" % start if start == prev else "%d-%d" % (start, prev))
            start = prev = n
    if start is not None:
        out.append("%d" % start if start == prev else "%d-%d" % (start, prev))
    return ", ".join(out)


# ------------------------------------------------------------------ risky ---
def _untagged_image(line):
    """True for `image: repo/name` with no tag and no digest (templating removed first)."""
    m = re.match(r"\s*-?\s*image:\s*(.+?)\s*$", line)
    if not m:
        return False
    val = re.sub(r"\{\{.*?\}\}", "", m.group(1)).strip("\"' ")
    return bool(val) and "@" not in val and ":" not in val.split("/")[-1] and re.search(r"[A-Za-z0-9]$", val) is not None



# Candidates, not findings: constructs that are often a problem in a given kind of file. (label, regex)
_PIPELINE_GLOBS = ("azure-pipelines*.yml", "azure-pipelines*.yaml", ".azure-pipelines/**", ".github/workflows/**",
                   ".gitlab-ci.yml", "**/*pipeline*.yml", "**/*pipeline*.yaml", "Jenkinsfile", ".circleci/**")
_PIPELINE_KEYS = re.compile(r"(?m)^\s*-?\s*(?:steps|jobs|stages|runs-on|pool)\s*:|^\s*-\s*(?:task|script|bash|pwsh|powershell|checkout|"
                            r"template|uses|run)\s*:")
_RISKY = [
    ("pipeline", _PIPELINE_GLOBS, [
        ("token or password placed in a URL", r"://[^\s/\"':@]+:[^\s\"'@/]+@"),
        ("pipeline access token in use (check where it is sent)", r"System\.AccessToken|SYSTEM_ACCESSTOKEN|secrets\.GITHUB_TOKEN"),
        ("curl without --fail (an HTTP error passes as success)", r"\bcurl\b(?![^\n]*(--fail|\s-f\b|-sf|-fs))"),
        ("failure ignored", r"continueOnError:\s*true|continue-on-error:\s*true|\|\|\s*true\b"),
        ("unpinned template, action or image", r"@(main|master|latest)\b|:latest\b"),
        ("script piped into a shell", r"\|\s*(sudo\s+)?(ba)?sh\b"),
        ("unquoted URL with & (the shell splits it)", r"(?<![\"'=])https?://[^\s\"']*&[^\s\"']*(?![\"'])"),
    ]),
    ("powershell", ("**/*.ps1", "**/*.psm1"), [
        ("Invoke-Expression", r"\bInvoke-Expression\b|\biex\s"),
        ("TLS or certificate check disabled", r"SkipCertificateCheck|ServerCertificateValidationCallback"),
        ("plain-text secret", r"ConvertTo-SecureString\b.*-AsPlainText"),
        ("errors silenced", r"-ErrorAction\s+(SilentlyContinue|Ignore)|\$ErrorActionPreference\s*=\s*['\"]?(SilentlyContinue|Ignore)"),
    ]),
    ("shell", ("**/*.sh", "**/*.bash"), [
        ("eval", r"\beval\s"),
        ("download piped into a shell", r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba)?sh\b"),
        ("chmod 777", r"chmod\s+(-R\s+)?777"),
        ("rm -rf on a variable", r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+[\"']?\$"),
        ("TLS verification disabled", r"curl\b[^\n]*\s(-k|--insecure)\b|wget\b[^\n]*--no-check-certificate"),
    ]),
    ("kubernetes / helm", ("**/*.yaml", "**/*.yml", "**/*.tpl"), [
        ("privileged or host access", r"privileged:\s*true|hostNetwork:\s*true|hostPID:\s*true|hostPath:|allowPrivilegeEscalation:\s*true"),
        ("runs as root", r"runAsUser:\s*0\b|runAsNonRoot:\s*false"),
        ("cluster-wide RBAC (does it need the whole cluster?)", r"kind:\s*ClusterRole(Binding)?\b|cluster-admin"),
        ("wildcard RBAC", r"(verbs|resources|apiGroups):\s*\[?\s*[\"']\*[\"']"),
        ("single replica", r"\b(replicaCount|replicas):\s*1\b"),
        ("disruption budget allows zero", r"minAvailable:\s*[\"']?0"),
        ("unpinned image", r"image:\s*[\"']?[^\s\"']+:latest\b|tag:\s*[\"']?latest\b"),
        ("image without a tag or digest", _untagged_image),
        ("cron runs every minute of the hour (minute field is *) - compare with its comment", r"schedule:\s*[\"']?\*\s+\d"),
        ("RBAC rule in the removed extensions API group (ingresses: networking.k8s.io, deployments: apps)", r"apiGroups:.*[\"']extensions[\"']"),
        ("TLS verification disabled", r"insecureSkipVerify:\s*true|insecure-skip-tls-verify"),
        ("open to any address", r"0\.0\.0\.0/0"),
    ]),
    ("terraform", ("**/*.tf", "**/*.tfvars"), [
        ("open to any address", r"0\.0\.0\.0/0|\"\*\"\s*#?.*source"),
        ("wildcard permission", r"\"(Action|actions|Resource|resources)\"?\s*[=:]\s*\[?\s*\"\*\""),
        ("protection off", r"skip_final_snapshot\s*=\s*true|prevent_destroy\s*=\s*false|deletion_protection\s*=\s*false|purge_protection_enabled\s*=\s*false"),
        ("public access", r"public_network_access_enabled\s*=\s*true|allow_blob_public_access\s*=\s*true|publicly_accessible\s*=\s*true"),
    ]),
    ("docker", ("**/Dockerfile*", "**/docker-compose*.yml", "**/docker-compose*.yaml", "**/compose*.yml"), [
        ("unpinned base image", r"^\s*FROM\s+\S+:latest\b|^\s*FROM\s+[^\s:@]+\s*$|image:\s*[^\s:]+\s*$|image:\s*\S+:latest\b"),
        ("runs as root", r"^\s*USER\s+root\b"),
        ("privileged container", r"privileged:\s*true|--privileged"),
        ("password in plain text", r"(?i)(PASSWORD|SECRET|TOKEN)\w*\s*[:=]\s*[\"']?[^\s\"'${][^\s\"']+"),
        ("port published on every interface", r"^\s*-\s*[\"']?\d+:\d+"),
    ]),
    ("scripts and pipelines", ("**/*.ps1", "**/*.psm1", "**/*.sh", "**/*.bash", "**/*.py") + _PIPELINE_GLOBS, [
        ("deletes or destroys - trace what selects the items, and what is left of that selection when an earlier call fails or returns nothing",
         r"(?i)-Method\s+Delete|\bRemove-(Item|Az\w+)\b|-X\s*DELETE|--request[= ]DELETE|\brm\s+-\w*r|\bkubectl\s+delete|"
         r"\bhelm\s+(uninstall|delete)\b|\bterraform\s+destroy|\baz\s[^\n|;#]*\sdelete\b|\baws\s[^\n|;#]*\s(delete|terminate)-|"
         r"requests\.delete\(|shutil\.rmtree|\bDROP\s+(TABLE|DATABASE)|\bDELETE\s+FROM|\bTRUNCATE\s+TABLE"),
        ("force flag - what does it skip, and who passes it (a schedule?)", r"(?<![\w-])--?force\b(?![\w-])"),
    ]),
    ("any file", ("**/*",), [
        ("TLS verification disabled", r"verify\s*=\s*False|InsecureSkipVerify:\s*true|rejectUnauthorized:\s*false|NODE_TLS_REJECT_UNAUTHORIZED"),
        ("left to do", r"\b(TODO|FIXME|HACK|XXX)\b"),
    ]),
]


def risky(glob="**/*", root=".", per_label=6, quiet=False):
    """Lines that are often a problem in the kinds of file this project has: tokens in URLs, cluster-wide
    or wildcard RBAC, single replicas, TLS checks turned off, unpinned images, silenced errors ...
    Candidates to confirm in the code, not findings. Returns [(stack, label, path, line number, text)]."""
    names = files(glob, root)
    hits, cache = [], {}

    def lines_of(n):
        if n not in cache:
            cache[n] = _read(os.path.join(root, n))
        return cache[n]
    # a pipeline is known by its name or folder, or by what a yaml file contains (steps, jobs, tasks)
    pipe_rx = [_glob_re(g) for g in _PIPELINE_GLOBS]
    pipes = set()
    for n in names:
        if any(r.match(n) for r in pipe_rx):
            pipes.add(n)
        elif n.lower().endswith((".yml", ".yaml")):
            text = "\n".join((lines_of(n) or [])[:400])
            if len(_PIPELINE_KEYS.findall(text)) >= 2:
                pipes.add(n)
    for stack, globs, rules in _RISKY:
        rxs = [_glob_re(g) for g in globs]
        mine = [n for n in names if any(r.match(n) for r in rxs)]
        if stack == "pipeline":
            mine = [n for n in names if n in pipes]
        elif stack == "kubernetes / helm":                 # pipelines are yaml too: they have their own rules
            mine = [n for n in mine if n not in pipes]
        elif stack == "scripts and pipelines":
            mine = [n for n in names if n in pipes or n in mine]
        compiled = [(label, rx if callable(rx) else re.compile(rx, re.M).search) for label, rx in rules]
        workloads, has_context = [], False
        for n in mine:
            lines = lines_of(n)
            if lines is None or len(lines) > 5000:
                continue
            if stack == "kubernetes / helm":
                text = "\n".join(lines)
                has_context = has_context or "securityContext" in text
                for m in re.finditer(r"^kind:\s*(Deployment|StatefulSet|DaemonSet|CronJob|Job)\b", text, re.M):
                    workloads.append((n, text.count("\n", 0, m.start()) + 1, m.group(0)))
                for m in re.finditer(r"kind:\s*ServiceAccount\s*\n\s*name:\s*default\b", text):
                    hits.append((stack, "role bound to the default service account", n, text.count("\n", 0, m.start()) + 2, "name: default"))
            if stack == "powershell":
                for i, name, close in _ps_unassigned(lines):
                    hits.append((stack, "variable read but never assigned in the file (a typo?)", n, i,
                                 "$%s%s" % (name, " - did you mean $%s?" % close if close else "")))
                text = "\n".join(_ps_code(lines))
                first = re.search(r"(?im)^.*\b(Invoke-RestMethod|Invoke-WebRequest|Remove-Item|az |kubectl |git )", text)
                if first and not re.search(r"(?i)\$ErrorActionPreference\s*=\s*[\"']?Stop", text):
                    hits.append((stack, "no $ErrorActionPreference = 'Stop': a failed call does not stop the script, the next line runs with what is left",
                                 n, text.count("\n", 0, first.start()) + 1, first.group(0).strip()[:120]))
            if stack == "shell" and len(lines) > 3:
                text = "\n".join(lines)
                if not re.search(r"(?m)^\s*set\s+-[a-zA-Z]*e|^\s*set\s+-o\s+errexit|^#!.*\s-[a-zA-Z]*e", text):
                    hits.append((stack, "no set -e: a failed command does not stop the script, the next line runs anyway", n, 1,
                                 lines[0].strip()[:120]))
            for i, ln in enumerate(lines):
                for label, match in compiled:
                    if match(ln):
                        text = ln.strip()[:160]
                        if label.startswith("password in plain text"):
                            text = re.sub(r"([:=]\s*[\"']?)[^\s\"']+", r"\1" + MARK, text, count=1)
                        hits.append((stack, label, n, i + 1, text))
        if workloads and not has_context:
            for n, i, text in workloads:
                hits.append((stack, "no securityContext on any workload (runAsNonRoot, readOnlyRootFilesystem, dropped capabilities)", n, i, text))
    if quiet:
        return hits
    if not hits:
        print("no risky constructs matched")
        return _Rows(hits)
    groups = {}
    for stack, label, n, i, text in hits:
        groups.setdefault((stack, label), []).append((n, i, text))
    print("candidates to confirm in the code (%d lines):" % len(hits))
    for (stack, label), rows in groups.items():
        print("[%s] %s — %d" % (stack, label, len(rows)))
        for n, i, text in rows[:per_label]:
            print("    %s:%d: %s" % (n, i, text))
        if len(rows) > per_label:
            print("    ... %d more" % (len(rows) - per_label))
    return _Rows(hits)


# ------------------------------------------------------------- powershell ---
_PS_AUTO = set("""_ args true false null psitem psscriptroot pscommandpath psboundparameters pscmdlet psversiontable
myinvocation lastexitcode error erroractionpreference host home pwd pid profile input this matches ofs foreach switch
event sender stacktrace executioncontext progresspreference verbosepreference warningpreference debugpreference
informationpreference confirmpreference whatifpreference psdefaultparametervalues psculture psuiculture psedition
iswindows islinux ismacos iscoreclr nestedpromptlevel shellid psstyle outputencoding formatenumerationlimit env using
script global local private function variable alias psnativecommanduseerroractionpreference pssessionoption
psnativecommandargumentpassing psemailserver maximumhistorycount consolefilename""".split())


def _ps_code(lines):
    """PowerShell lines without comments and single-quoted strings (variables in those are not read)."""
    text = re.sub(r"<#[\s\S]*?#>", lambda m: "\n" * m.group(0).count("\n"), "\n".join(lines))
    out = []
    for ln in text.split("\n"):
        ln = re.sub(r"'[^'\n]*'", "''", ln).replace("`$", "")           # '...' and `$ are literal text
        out.append(re.sub(r"(^|\s)#.*$", r"\1", ln))
    return out


def _ps_param_blocks(code):
    """[(first index, last index, [names])] for every param(...) block of a PowerShell file."""
    blocks = []
    for i, ln in enumerate(code):
        if not re.match(r"(?i)^\s*param\s*(\(|$)", ln):          # `param (` or `param` with the ( on the next line
            continue
        depth, j, opened = 0, i, False
        for j in range(i, min(len(code), i + 80)):
            if not opened and j > i and code[j].strip() and not code[j].lstrip().startswith("("):
                break
            opened = opened or "(" in code[j]
            depth += code[j].count("(") - code[j].count(")")
            if opened and depth <= 0:
                break
        if not opened:
            continue
        body = re.sub(r"\[\w+\([^\]]*\)\]", "", "\n".join(code[i:j + 1]))        # [Parameter(...)], [ValidateSet(...)]
        names = []
        for piece in body.split(","):
            found = re.findall(r"\$(\w+)", piece.split("=", 1)[0])
            if found and found[-1].lower() not in ("true", "false", "null") and found[-1] not in names:
                names.append(found[-1])
        blocks.append((i, j, names))
    return blocks


def _ps_unassigned(lines, limit=5):
    """[(line number, name, closest assigned name or None)]: variables a PowerShell file reads and never
    assigns. Nothing is reported for a file that takes definitions from elsewhere (dot-sourcing, modules)."""
    code = _ps_code(lines)
    text = "\n".join(code)
    if re.search(r"(?im)^\s*\.\s+\S|\bImport-Module\b|\bInvoke-Expression\b|\busing\s+module\b", text):
        return []
    assigned = set()
    for _, _, names in _ps_param_blocks(code):
        assigned.update(n.lower() for n in names)
    for rx in (r"\$(?:(?:script|global|local|private):)?(\w+)\s*(?:[-+*/%]|\?\?)?=(?!=)", r"\$(\w+)\s*(?:\+\+|--)",
               r"(?i)\bforeach\s*\(\s*\$(\w+)\s+in\b", r"(?i)\[ref\]\s*\$(\w+)",
               r"(?i)-(?:OutVariable|ErrorVariable|WarningVariable|InformationVariable|PipelineVariable|ov|ev|wv|iv|pv)\s+[\"']?(\w+)",
               r"(?i)\b(?:Set|New)-Variable\s+(?:-Name\s+)?[\"']?(\w+)"):
        assigned.update(m.group(1).lower() for m in re.finditer(rx, text))
    for m in re.finditer(r"(\$\w+(?:\s*,\s*\$\w+)+)\s*=(?!=)", text):                      # $a, $b = ...
        assigned.update(n.lower() for n in re.findall(r"\$(\w+)", m.group(1)))
    for m in re.finditer(r"(?i)\bfunction\s+[\w-]+\s*\(([^)]*)\)", text):
        assigned.update(n.lower() for n in re.findall(r"\$(\w+)", m.group(1)))
    found, seen = [], set()
    for i, ln in enumerate(code):
        for m in re.finditer(r"\$(?:\{(\w+)\}|(\w+))(?!\w*:\w)", ln):
            name = m.group(1) or m.group(2)
            low = name.lower()
            if low in assigned or low in _PS_AUTO or low in seen or name.isdigit():
                continue
            seen.add(low)
            close = [a for a in assigned if abs(len(a) - len(low)) <= 2 and (a.startswith(low) or low.startswith(a))]
            found.append((i + 1, name, next((n for n in re.findall(r"\$(\w+)", text) if n.lower() in close), None)))
    return found[:limit]


# ------------------------------------------------------------------ calls ---
_SCRIPT_EXT = (".ps1", ".psm1", ".sh", ".bash", ".zsh", ".py", ".rb", ".pl", ".js", ".mjs", ".cjs", ".ts", ".cmd", ".bat")
_NOT_A_CALLER = (".md", ".rst", ".txt", ".adoc", ".lock", ".svg", ".map", ".sum")
_READS_ARGS = {
    ".sh": r"\$[1-9@*#](?![\w{])|\$\{[1-9@*][^}]*\}|\bgetopts\b|\$\{[A-Za-z_]\w*:\?",
    ".py": r"add_argument\(|sys\.argv|click\.(option|argument)\(|os\.environ\[|os\.getenv\(|environ\.get\(",
    ".js": r"process\.argv|process\.env\.\w+",
    ".rb": r"\bARGV\b|\bENV\[",
    ".pl": r"@ARGV|\$ARGV|\$ENV\{",
    ".cmd": r"%[1-9*]|%~[a-z]*[1-9]",
}
for _ext, _same in ((".bash", ".sh"), (".zsh", ".sh"), (".mjs", ".js"), (".cjs", ".js"), (".ts", ".js"), (".bat", ".cmd")):
    _READS_ARGS[_ext] = _READS_ARGS[_same]


_COMMON_ENV = set("""HOME PATH PWD OLDPWD USER SHELL TERM LANG TMPDIR TMP TEMP HOSTNAME IFS RANDOM SECONDS LINENO UID EUID
BASH_SOURCE BASH_VERSION BASH_REMATCH BASHPID FUNCNAME PIPESTATUS OSTYPE OPTARG OPTIND REPLY EDITOR DISPLAY LOGNAME
PPID SHLVL COLUMNS LINES""".split())


def _env_reads(ext, lines):
    """'environment it reads: A, B' for a shell or PowerShell script (names it uses and never sets)."""
    text = "\n".join(lines)
    if ext in (".ps1", ".psm1"):
        names = sorted(set(re.findall(r"(?i)\$env:(\w+)", "\n".join(_ps_code(lines)))) - {"PATH", "TEMP", "TMP", "USERPROFILE"})
    else:
        setting = (r"(?m)^\s*(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)?)?([A-Z][A-Z0-9_]{2,})\+?=",
                   r"\bread\s+(?:-\w+\s+)*([A-Z][A-Z0-9_]{2,})", r"\bfor\s+([A-Z][A-Z0-9_]{2,})\s+in\b")
        own = {m.group(1) for rx in setting for m in re.finditer(rx, text)}
        code = "\n".join(ln for ln in lines if not ln.lstrip().startswith("#"))
        names = sorted(set(re.findall(r"\$\{?([A-Z][A-Z0-9_]{2,})\b", code)) - own - _COMMON_ENV)
    return "environment it reads: %s%s" % (", ".join(names[:15]), " ..." if len(names) > 15 else "") if names else ""


def _interface(name, lines):
    """What a script declares or reads from its caller: (title, [line indexes], note)."""
    ext = os.path.splitext(name)[1].lower()
    env = _env_reads(ext, lines) if ext in (".ps1", ".psm1", ".sh", ".bash", ".zsh") else ""
    if ext in (".ps1", ".psm1"):
        code = _ps_code(lines)
        blocks = _ps_param_blocks(code)
        if not blocks:
            return "declares no param block", [], env
        first, last, names = blocks[0]
        uses = []
        for nm in names:
            rx = re.compile(r"(?i)\$(?:script:|global:)?\{?%s\b" % re.escape(nm))
            at = [i + 1 for i, ln in enumerate(code) if not first <= i <= last and rx.search(ln)]
            uses.append("$%s %s%s" % (nm, _ranges(at[:8]) if at else "NEVER USED", " ..." if len(at) > 8 else ""))
        return "declares", list(range(first, min(last, first + 29) + 1)), \
            "used at lines: " + " · ".join(uses) + ("\n        " + env if env else "")
    rx = _READS_ARGS.get(ext)
    if not rx:
        return "", [], ""
    rx = re.compile(rx)
    inside, local = None, set()                      # $1 inside a shell function is that function's argument
    if ext in (".sh", ".bash", ".zsh"):
        for i, ln in enumerate(lines):
            if inside is None:
                m = re.match(r"^(\s*)(?:function\s+[\w-]+\s*(?:\(\))?|[\w-]+\s*\(\))\s*\{?\s*$", ln)
                if m:
                    inside = len(m.group(1))
            else:
                local.add(i)
                if re.match(r"^\s{%d}\}\s*$" % inside, ln):
                    inside = None
    at = [i for i, ln in enumerate(lines) if i not in local and rx.search(ln) and not ln.lstrip().startswith(("#", "//"))]
    more = "+%d more lines" % (len(at) - 12) if len(at) > 12 else ""
    note = "\n        ".join(x for x in (more, env) if x)
    return ("reads its arguments at", at[:12], note) if at else ("reads no arguments", [], note)


def _call_block(lines, i, needle):
    """Line indexes of one call: the line that names the script plus the lines that carry its arguments."""
    def indent_of(k):
        return len(lines[k]) - len(lines[k].lstrip())
    ln = lines[i]
    indent = indent_of(i)
    out = [i]
    if re.match(r"^\s*-?\s*[\w.-]+\s*:\s*[\"']?[^\s\"']*" + re.escape(needle) + r"[\"']?\s*$", ln):
        # `filePath: scripts/x.ps1`: arguments, environment and condition are other keys of the same step,
        # so show the whole list item the line belongs to
        start = i if ln.lstrip().startswith("- ") else None
        k = i - 1
        while start is None and k >= 0 and i - k <= 10:
            if lines[k].lstrip().startswith("- ") and indent_of(k) < indent:
                start = k
            k -= 1
        if start is None:
            start = i
        depth = indent_of(start)
        out, j = [start], start + 1
        while j < len(lines) and len(out) < 16 and (not lines[j].strip() or indent_of(j) > depth):
            if lines[j].strip():
                out.append(j)
            j += 1
    else:
        j = i
        while lines[j].rstrip().endswith(("\\", "`", "^")) and j + 1 < len(lines) and j - i < 8:
            j += 1
            out.append(j)
        m = re.match(r"^\s*(?:local\s+|export\s+|readonly\s+)?\$?(\w+)\s*=", ln)
        if m:                                            # the path is kept in a variable: show where it is run
            rx = re.compile(r"\$\{?%s\b" % re.escape(m.group(1)))
            later = [k for k in range(j + 1, min(len(lines), j + 60)) if rx.search(lines[k])]
            out += later[:3]
    return out


_LIST_ITEM = r"(?:\"[^\"]*\"|'[^']*'|\$\([^)]*\)|\$\{[^}]*\}|[^\s,\"']+)"
_LIST_ARG = re.compile(r"(?<![\w-])(--?[A-Za-z][\w-]*)[ =]+(%s(?:,%s)+)(?=\s|$)" % (_LIST_ITEM, _LIST_ITEM))


def _list_args(text):
    """{flag: number of values} for the arguments of a call that carry a comma-separated list."""
    return {m.group(1): len(re.findall(_LIST_ITEM, m.group(2))) for m in _LIST_ARG.finditer(text)}


def calls(glob="**/*", root=".", max_scripts=12, quiet=False):
    """Scripts that other files run, with both sides of every call: what the script declares or reads
    (param block, positional arguments, argument parser, environment) and the lines of each caller that
    name it and pass its arguments. A count, an order or a name that differs between the two sides is a
    bug that reading either file alone does not show. Returns [(script, caller, line number)]."""
    names = files("**/*", root)
    rx_glob = _glob_re(glob)
    scripts = [n for n in names if os.path.splitext(n)[1].lower() in _SCRIPT_EXT and rx_glob.match(n)]
    if not scripts:
        if not quiet:
            print("no scripts here that another file could call")
        return [] if quiet else _Rows()
    bases = [os.path.basename(n) for n in scripts]
    needle = {n: (os.path.basename(n) if bases.count(os.path.basename(n)) == 1 else "/".join(n.split("/")[-2:])) for n in scripts}
    by_needle = {v: k for k, v in needle.items()}
    rx_any = re.compile(r"(?<![\w-])(%s)(?![\w-])" % "|".join(re.escape(v) for v in sorted(by_needle, key=len, reverse=True)))
    cache, callers = {}, {}
    for n in names:
        if os.path.splitext(n)[1].lower() in _NOT_A_CALLER or os.path.basename(n) in _SKIP_NAMES:
            continue
        lines = _read(os.path.join(root, n))
        if lines is None or len(lines) > 5000:
            continue
        cache[n] = lines
        code = _ps_code(lines) if n.lower().endswith((".ps1", ".psm1")) else lines       # no <# comment blocks #>
        for i, ln in enumerate(code):
            if ln.lstrip().startswith(("#", "//", "REM ", "::")) or re.match(r"^\s*-?\s*[\"']?[\w./\\-]+[\"']?,?\s*$", ln) \
                    or re.search(r"^\s*(COPY|ADD)\s|\b(chmod|chown|dos2unix)\s|\bgit\s+add\s", ln):
                continue          # a comment, a bare path in a list (a trigger filter, an ignore file), a copy
            for m in rx_any.finditer(ln):
                token = re.search(r"\S*$", ln[:m.start()]).group(0)
                script = by_needle[m.group(1)]
                if script != n and "://" not in token and (n, i) not in callers.get(script, []):
                    callers.setdefault(script, []).append((n, i))
    rows = [(s, n, i + 1) for s in scripts for n, i in callers.get(s, [])]
    if quiet:
        return rows
    called = [s for s in scripts if s in callers]
    if not called:
        print("no script is called from another file here (%d scripts: %s%s)"
              % (len(scripts), ", ".join(scripts[:8]), " ..." if len(scripts) > 8 else ""))
        return _Rows(rows)
    print("%d script%s run from other files. Compare what each caller passes (count, order, names) with what "
          "the script declares and how it indexes and uses it:" % (len(called), "" if len(called) == 1 else "s"))
    for s in called[:max_scripts]:
        lines = cache.get(s) or _read(os.path.join(root, s)) or []
        title, at, note = _interface(s, lines)
        print("%s (%d lines)%s" % (s, len(lines), " " + title + ":" if at else (" " + title if title else "")))
        for i in at:
            print("%8d  %s" % (i + 1, lines[i].rstrip()[:200]))
        if note:
            print("        %s" % note)
        for n, i in callers[s][:6]:
            print("  called from %s:%d" % (n, i + 1))
            block = _call_block(cache[n], i, needle[s])
            for j in block:
                print("%8d  %s" % (j + 1, cache[n][j].strip()[:200]))
            lists = _list_args(" ".join(cache[n][j].strip() for j in block))
            if len(set(lists.values())) > 1:
                print("        note: list arguments of different lengths (%s): how does the script pair them?"
                      % ", ".join("%s has %d" % kv for kv in lists.items()))
        if len(callers[s]) > 6:
            print("  ... %d more callers" % (len(callers[s]) - 6))
    if len(called) > max_scripts:
        print("... %d more called scripts: kt.calls(%r)" % (len(called) - max_scripts, "path/**"))
    idle = [s for s in scripts if s not in callers and s.lower().endswith((".ps1", ".sh", ".bash", ".zsh", ".cmd", ".bat"))]
    if idle:
        print("not called from any file here (run by hand, or from outside the repo): %s%s"
              % (", ".join(idle[:10]), " +%d more" % (len(idle) - 10) if len(idle) > 10 else ""))
    return _Rows(rows)


# ----------------------------------------------------------------- survey ---
# checkers and interpreters worth knowing about, by what the project contains
_TOOLS = [((".ps1", ".psm1"), ("pwsh",)), ((".sh", ".bash"), ("bash", "shellcheck")), ((".tf",), ("terraform", "tflint")),
          ((".bicep",), ("az",)), ((".py",), ("python3", "ruff")), ((".go",), ("go",)), ((".js", ".ts"), ("node",)),
          (("Chart.yaml",), ("helm", "kubeconform")), (("Dockerfile",), ("docker", "hadolint")),
          ((".github/workflows/",), ("actionlint",)), ((".yaml", ".yml"), ("yamllint",))]


def tools(root=".", quiet=False):
    """Which of the interpreters and checkers this project's files call for are installed here, so a
    program does not spend a run finding out. Returns {"installed": [...], "missing": [...]}."""
    import shutil
    names = files("**/*", root)
    have, missing = [], []
    for marks, cmds in _TOOLS:
        if any(n.endswith(m) or (m.endswith("/") and m in n) for n in names for m in marks):
            for c in cmds:
                (have if shutil.which(c) else missing).append(c)
    info = {"installed": sorted(set(have)), "missing": sorted(set(missing))}
    if quiet:
        return info
    print("installed: %s" % (", ".join(info["installed"]) or "none of the tools this stack uses"))
    if info["missing"]:
        print("not installed (do not try them; say so under Covered): %s" % ", ".join(info["missing"]))
    return _Info(info)


class _Counted:
    """stdout that counts the lines written through it."""

    def __init__(self, out):
        self.out, self.lines = out, 0

    def write(self, text):
        self.lines += text.count("\n")
        return self.out.write(text)

    def flush(self):
        self.out.flush()


def survey(root=".", glob="**/*"):
    """The first look at a project, in one call: its layout (kt.tree), committed secrets (kt.secrets),
    constructs that are often a problem (kt.risky), how its scripts are called (kt.calls) and which of
    the stack's tools are installed (kt.tools). With a glob ("charts/**") the secrets, the risky
    constructs and the calls are those of that part only. What it prints are candidates to confirm in
    the code, not findings."""
    out = sys.stdout
    sys.stdout = counted = _Counted(out)
    try:
        print("##### layout")
        tree(root=root)
        for title, fn in (("committed secrets", secrets), ("risky constructs", risky), ("script calls", calls)):
            print("##### %s%s" % (title, "" if glob == "**/*" else " in " + glob))
            fn(glob, root=root)
        print("##### tools for this stack")
        tools(root=root)
    finally:
        sys.stdout = out
    _raise_cap(counted.lines)                  # a deliberate look: shown whole, like kt.read
    return _Rows()


_NOT_LOGIC = (".md", ".rst", ".txt", ".json", ".xml", ".xsd", ".toml", ".ini", ".cfg", ".lock", ".csv", ".svg")
_BRANCHING = re.compile(r"\b(?:if|elif|else|for|foreach|while|until|switch|case|try|catch|except|finally|range|with)\b|&&|\|\||\$\(")


def _review_form(root, printed, glob="**/*"):
    """The working notes of a review as a form to fill in, built from this project: its script calls,
    its destructive steps, the candidate groups of the survey and the files that hold logic."""
    out = ["##### working notes: fill this in, in your reply, before any test (one line each; the review comes later)"]
    by_script = {}
    for script, caller, line in calls(glob, root=root, quiet=True):
        by_script.setdefault(script, []).append("%s:%d" % (caller, line))
    if by_script:
        out.append("calls: the values the caller passes per argument (count them) against the lines where the script indexes or reads them -> OK or MISMATCH")
        out += ["  %s <- %s :" % (script, ", ".join(where[:4])) for script, where in list(by_script.items())[:12]]
    hits = risky(glob, root=root, quiet=True)
    deletes = [(n, i) for _, label, n, i, _ in hits if label.startswith("deletes or destroys")]
    if deletes:
        out.append("deletes: what selects the items / what that selection is when an earlier call fails or returns nothing / what is printed against what is done")
        out += ["  %s:%d :" % (n, i) for n, i in deletes[:12]]
    groups = {}
    for n, _, kind in secrets(glob, root=root, quiet=True):
        groups[("secrets", kind)] = groups.get(("secrets", kind), 0) + 1
    for stack, label, n, i, _ in hits:
        if not label.startswith("deletes or destroys"):
            key = (stack, re.split(r" - | \(|: ", label)[0][:70])
            groups[key] = groups.get(key, 0) + 1
    if groups:
        out.append("candidates: FINDING, or harmless and why")
        out += ["  [%s] %s (%d) :" % (stack, label, count) for (stack, label), count in list(groups.items())[:40]]
    logic = []                                    # the files with the most branching: where unlooked-for bugs live
    for n, _ in printed:
        if n.lower().endswith(_NOT_LOGIC) or os.path.basename(n).startswith("."):
            continue
        score = len(_BRANCHING.findall("\n".join(_read(os.path.join(root, n)) or [])))
        if score >= 3:
            logic.append((score, n))
    keep = {n for _, n in sorted(logic, reverse=True)[:14]}
    if keep:
        out.append("files: go through each of these again, top to bottom, for what no rule above covers -> `line: what is wrong`, or `nothing`")
        out += ["  %s :" % n for n, _ in printed if n in keep]
    out.append("Then one test program for what needs testing. Then the review: every FINDING above is in it, however many there are, and that "
               "last message starts with `## Review`, with no narration before it (no \"confirmed\", no \"writing the review\").")
    return out


def review(target="**/*", max_lines=2500, root="."):
    """Step one of a code review, in one call: the survey, the source (kt.read: every file, numbered,
    secrets masked) and, last, the working notes to fill in before testing anything. With a glob
    ("charts/**") it is the review of that part of the project."""
    scope = target if isinstance(target, str) and not os.path.isfile(os.path.join(root, target)) else "**/*"
    survey(root=root, glob=scope)
    print("##### source")
    weight = {}                                   # what the survey points at is read first when not everything fits
    for _, _, n, _, _ in risky(scope, root=root, quiet=True):
        weight[n] = weight.get(n, 0) + 1
    for n, _, _ in secrets(scope, root=root, quiet=True):
        weight[n] = weight.get(n, 0) + 1
    for script, caller, _ in calls(scope, root=root, quiet=True):
        weight[script] = weight.get(script, 0) + 5
        weight[caller] = weight.get(caller, 0) + 3
    rows = read(target, max_lines=max_lines, root=root, first=sorted(weight, key=lambda n: (-weight[n], n)))
    form = _review_form(root, rows, scope)
    print("\n".join(form))
    _raise_cap(len(form) + 2)
    return rows


# ------------------------------------------------------------------- tree ---
def tree(depth=2, root=".", quiet=False):
    """Layout of the project: folders (to `depth`) with file and line counts, the file names when the
    project is small, lines by file type, and the files .kiroignore hides (names only).
    Returns {"files": n, "lines": n, "dirs": {dir: [files, lines]}, "types": {ext: [files, lines]}, "hidden": [...]}."""
    dirs, types, members, total = {}, {}, {}, 0
    classified = [(n, _kind_rel(n, root)) for n in _all_files(root)]
    names = [n for n, k in classified if k is None]
    for k, n in enumerate(names):
        parts = n.split("/")
        d = "/".join(parts[:depth]) if len(parts) > depth else ("/".join(parts[:-1]) or ".")
        ext = os.path.splitext(n)[1].lower() or parts[-1]
        lines = _read(os.path.join(root, n)) if k < 4000 else None
        loc = len(lines) if lines is not None else 0
        total += loc
        members.setdefault(d, []).append(n[len(d) + 1:] if d != "." else n)
        for table, key in ((dirs, d), (types, ext)):
            row = table.setdefault(key, [0, 0])
            row[0] += 1
            row[1] += loc
    hid = [(n, k) for n, k in classified if k]
    info = {"files": len(names), "lines": total, "dirs": dirs, "types": types, "hidden": hid}
    if quiet:
        return info
    print("%d files, %d lines" % (len(names), total))
    for d in sorted(dirs):
        line = "  %-44s %5d files %8d lines" % (d + "/", dirs[d][0], dirs[d][1])
        if len(names) <= 150:
            shown = members[d][:30]
            line += "  " + " ".join(shown) + (" +%d more" % (len(members[d]) - 30) if len(members[d]) > 30 else "")
        print(line)
    top = sorted(types.items(), key=lambda kv: -kv[1][1])[:10]
    print("by type: " + "; ".join("%s %d files %d lines" % (e, c, l) for e, (c, l) in top))
    if hid:
        shown = ["%s%s" % (n, " (secrets)" if k == "secret" else "") for n, k in hid[:20]]
        print("hidden by .kiroignore, %d file%s: %s%s" % (len(hid), "" if len(hid) == 1 else "s", ", ".join(shown),
                                                         " +%d more" % (len(hid) - 20) if len(hid) > 20 else ""))
        print("  (they exist; kt.show(path) prints a secrets file with its values masked)")
    return _Info(info)


# --------------------------------------------------------------------- sh ---
def sh(cmd, tail=40, timeout=60, cwd=None, quiet=False):
    """Run a command (a string runs in bash with pipefail, a list is an argv). Prints `$ cmd -> exit N`
    and the last `tail` lines of its combined output; returns (exit code, full output). A command that
    is still running after `timeout` seconds is stopped and reported, so one check that hangs (a private
    package feed, a cluster that is not there) does not take the others with it."""
    shown = cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd)
    argv = ["bash", "-o", "pipefail", "-c", cmd] if isinstance(cmd, str) else [str(c) for c in cmd]
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace",
                           timeout=timeout, cwd=cwd)
        rc, text = p.returncode, p.stdout or ""
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        rc, text = 124, (out if isinstance(out, str) else out.decode("utf-8", "replace")) + "\n[timed out after %ss]" % timeout
    except OSError as exc:
        rc, text = 127, str(exc)
    if quiet:
        return rc, text
    lines = text.rstrip("\n").splitlines()
    more = " (last %d of %d lines)" % (tail, len(lines)) if len(lines) > tail else ""
    print("$ %s -> exit %d%s" % (shown, rc, more))
    for ln in lines[-tail:] if tail else []:
        print("  " + _clip(ln))
    return _Run((rc, text))


def _main(argv):
    """python3 -m kt <function> [args...]: positional args are passed as strings, or as ints when numeric."""
    fns = {"tree": tree, "files": files, "grep": grep, "outline": outline, "show": show, "sh": sh, "hidden": hidden,
           "read": read, "secrets": secrets, "risky": risky, "calls": calls, "survey": survey, "review": review, "tools": tools}
    if len(argv) < 2 or argv[1] not in fns:
        print(__doc__.strip())
        return 2

    def value(a):
        return int(a) if re.fullmatch(r"-?\d+", a) else {"true": True, "false": False}.get(a.lower(), a)
    args, kwargs = [], {}
    for a in argv[2:]:
        m = re.fullmatch(r"([a-z_]+)=(.*)", a)
        if m:
            kwargs[m.group(1)] = value(m.group(2))
        else:
            args.append(value(a))
    if argv[1] == "read" and len(args) > 1:            # kt read a b c -> one call for all of them
        args = [args]
    result = fns[argv[1]](*args, **kwargs)
    if argv[1] == "files":
        print("\n".join(result))
    elif argv[1] == "hidden":
        print("\n".join("%s (%s)" % (n, k) for n, k in result))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
