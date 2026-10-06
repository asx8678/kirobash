#!/usr/bin/env python3
"""kiro_redact: filter for kiro-run output. Reads stdin, writes stdout with secret values replaced by
[redacted], so a program can look at anything without the secrets reaching the agent's context or the
saved .out file. Layers, most specific first:

  1. every value-carrying line of the project's secrets files (.env, secrets/, keys ... as kt classifies
     them), so a file printed verbatim is masked whatever its values look like;
  2. the values of secret-looking environment variables and the values found in those secrets files,
     wherever they are printed, including a piece of one (the first or last characters);
  3. known formats: cloud keys, tokens, private keys, signed URLs, credentials in URLs, and the value
     assigned to a key that names a secret (password, token, secret, credential, api key);
  4. long random-looking tokens.

A safety net, not a guarantee: a value that was encoded, hashed or scrambled is not recognised.
"""
import os
import re
import sys

MARK = "[redacted]"
SECRET_NAME = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|_PWD$|^PWD_|_KEY$|APIKEY|API_KEY|CREDENTIAL|PRIVATE|"
                         r"CONN(ECTION)?_?STR|_SAS$|SIGNATURE|WEBHOOK)", re.I)

# (what it is, pattern, replacement) — the replacement keeps whatever names the secret and drops the value.
FIXED = [
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)"), MARK + " private key"),
    ("AWS access key id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), MARK),
    ("GitHub token", re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|gh[osur]_[A-Za-z0-9]{36})\b"), MARK),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}"), MARK),
    ("API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), MARK),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}"), MARK),
    ("storage account key or SAS", re.compile(r"\b(AccountKey|SharedAccessKey|SharedAccessSignature)=[A-Za-z0-9+/=%&;:_.-]{20,}", re.I), r"\1=" + MARK),
    ("signed URL (sig=)", re.compile(r"([?&;]sig=)[A-Za-z0-9%+/=_-]{16,}", re.I), r"\1" + MARK),
    ("kubeconfig key or token", re.compile(r"\b((?:client-key-data|client-certificate-data|certificate-authority-data|id-token|refresh-token)"
                                           r"\s*:\s*)[A-Za-z0-9+/=_.-]{40,}", re.I), r"\1" + MARK),
    ("AWS secret key", re.compile(r"\b((?:aws_secret_access_key|aws_session_token)\s*[=:]\s*)\S+", re.I), r"\1" + MARK),
    ("Teams webhook URL", re.compile(r"https://[\w.-]*webhook\.office\.com/\S+"), "https://…webhook.office.com/" + MARK),
    ("Slack webhook URL", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{8,}"), "https://hooks.slack.com/services/" + MARK),
    ("Discord webhook URL", re.compile(r"https://discord(?:app)?\.com/api/webhooks/[A-Za-z0-9/_-]{8,}"), "https://discord.com/api/webhooks/" + MARK),
    ("credentials in a URL", re.compile(r"(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s/]{6,})(@)"), None),      # see _url_credentials
    ("bearer token", re.compile(r"\b(Bearer\s+)[A-Za-z0-9._~+/=-]{20,}"), r"\1" + MARK),
]
GENERIC = re.compile(r"((?:client[_-]?secret|api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|pwd)"
                     r"\w*[\"']?\s*[=:]\s*[\"']?)([A-Za-z0-9~._+/=-]{16,})", re.I)
# Any key that names a secret, with a value of 6+ characters of any kind: API_TOKEN=..., "secret": "...",
# dbPassword: Summer2024!. Wider than GENERIC in both the keys and the values, so _keyed_secret decides by
# what the value looks like: generated or chosen is masked, a word, a name or a piece of code is not.
KEYED = re.compile(r"((?:pass(?:word|wd|phrase)|pwd|secret|token|credential|private[_-]?key|api[_-]?key)\w{0,14}[\"']?\s*[=:]\s*[\"']?)"
                   r"([^\s\"'`,;<>]{6,})", re.I)
# values that are references or placeholders rather than secrets
NOT_A_SECRET = re.compile(r"^(\$\{|\$\(|\$[A-Za-z_]|\{\{|<|%\(|%\{|var\.|data\.|local\.|ref\(|lookup\(|random_)|"
                          r"secretKeyRef|valueFrom|keyvault|secretsmanager|example|placeholder|changeme|dummy|"
                          r"xxxx|\*\*\*|REDACTED|redacted", re.I)
# the key names something about the secret (where it is, what it is called), not the secret itself
NAMES_NOT_VALUES = re.compile(r"(name|ref|path|file|dir|id|url|uri|endpoint|header|length|len|size|type|policy|expiry|expires|"
                              r"ttl|timeout|enabled|required|prompt|label|field|hint|regex|pattern|format|version|count|"
                              r"min|max)s?[\"']?\s*[=:]\s*[\"']?$", re.I)
# code and configuration that only looks like a value: settings.Password, ENV_VAR_NAME, /a/path/to/it
CODE_NOT_VALUE = re.compile(r"^(_?[A-Za-z][A-Za-z_]*\d{0,2}(\.[A-Za-z_][A-Za-z_]*\d{0,2})+|[A-Z][A-Z0-9]*(_[A-Z0-9]+)+|"
                            r"[~.]{0,2}/(?:[\w.-]+/)+[\w.-]*)$")
# a long token with upper case, lower case and digits and no separators: a key, not a word, path or hash
RANDOM_TOKEN = re.compile(r"(?<![A-Za-z0-9_+=-])(?=[A-Za-z0-9_+=-]*[a-z])(?=[A-Za-z0-9_+=-]*[A-Z])(?=[A-Za-z0-9_+=-]*[0-9])"
                          r"[A-Za-z0-9_+=-]{40,}(?![A-Za-z0-9_+=-])")
# what a pipeline substitutes at run time is a reference, not a committed secret
RUNTIME_REF = re.compile(r"\$\(|\$\{|\$[A-Za-z_]|\{\{|%[A-Za-z_]+%")


def _url_credentials(m):
    """user:password@ in a URL is masked, unless the password is a reference a pipeline fills in at run
    time ($(System.AccessToken), ${TOKEN}): that is worth seeing, and it is not a secret."""
    return m.group(0) if RUNTIME_REF.match(m.group(2)) else m.group(1) + MARK + m.group(3)


def _assigned_secret(m):
    """True when a `password = value` match carries a value, not a name, a reference or a piece of code."""
    key, value = m.group(1), m.group(2)
    if NOT_A_SECRET.search(value) or CODE_NOT_VALUE.match(value) or NAMES_NOT_VALUES.search(key):
        return False
    if re.match(r"(?:OLD)?PWD\b", key):                         # the shell's working directory
        return False
    return m.string[m.end():m.end() + 1] != "("                 # a function call


def _word(seg):
    """True for one piece of a name: a number, or letters with a short number, written as a word
    (prod, Token, API, v2, tokenFromRequest2) and not as a run of random letters (QxZvLmKp, aB3)."""
    if re.fullmatch(r"\d{1,4}", seg):
        return True
    if not re.fullmatch(r"[A-Za-z]+\d{0,4}", seg):
        return False
    if re.fullmatch(r"(?:[a-z]+|[A-Z][a-z]*|[A-Z]+)\d*", seg):
        return True
    return sum(len(run) for run in re.findall(r"[a-z]{3,}", seg)) * 2 >= len(seg)


# a variable inside a value (repoV2/$projectId, db-${ENV}-secret) makes it a template; Pa$$w0rd is not one
_TEMPLATE = re.compile(r"\$\(|\$\{|\{\{|%[A-Za-z_]+%|(?<![\w$])\$[A-Za-z_]")


def _name(value):
    """True when a value is the name of something rather than a secret: pieces that are words, with at
    most short abbreviations among them (prod-db-01, my-k8s-store-secret, tokenFromRequest2)."""
    segs = [x for x in re.split(r"[-_+=.~/:@]+", value) if x]
    if not all(_word(x) or (len(x) <= 4 and x.isalnum()) for x in segs):
        return False
    words = [x for x in segs if _word(x) and len(re.sub(r"\d", "", x)) >= 3]
    return sum(len(x) for x in words) * 2 >= sum(len(x) for x in segs)


def _keyed_secret(m):
    """True when the value after a secret-named key is a secret. Never one: a reference, a placeholder, a
    template with a variable in it, a URL, a path, an expression or call, and the name of something
    (token_url, secretName, arn:aws:secretsmanager:...). After a password key, anything with a digit or
    with three kinds of character counts (hunter2, Summer2024!). After the other keys the value must look
    generated: a digit among letters, or 16+ characters, and not a name made of words."""
    key, value = m.group(1), m.group(2).rstrip(")]}.")
    if len(value) < 6 or MARK in value or re.search(r"[()\[\]{}]", value) or re.match(r"[a-z][a-z0-9+.-]*://", value, re.I):
        return False
    if NOT_A_SECRET.search(value) or _TEMPLATE.search(value) or CODE_NOT_VALUE.match(value):
        return False
    if NAMES_NOT_VALUES.search(key) or re.match(r"(?:OLD)?PWD\b", key) or re.match(r"secretsmanager|keyvault", key, re.I):
        return False                                             # a name, the shell's working directory, an ARN
    digit = bool(re.search(r"\d", value))
    if re.match(r"pass|pwd", key, re.I):
        classes = sum(bool(re.search(rx, value)) for rx in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
        return digit or (len(value) >= 8 and classes >= 3)
    if not (re.search(r"[A-Za-z]", value) and (digit or len(value) >= 16)):
        return False
    return not _name(value)


_WORD = re.compile(r"[A-Za-z]+\d{0,3}|\d{1,4}|[0-9a-f]{8,}")
_CHECKSUM = re.compile(r"(?:h1:|zh:|sha\d+[-:]|md5[-:])")
_PUBLIC_KEY = re.compile(r"(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+)\s+$")


def _random_token(m):
    """True when a long mixed-case run is a key rather than a name or a checksum: identifiers are made
    of words (Connection__Strings__0__Name, AllowScopedInstanceAccess), keys are not."""
    tok = m.group(0)
    text = m.string
    start = m.start()
    while start > 0 and text[start - 1] not in " \t\n\"'=,;()[]{}<>":      # back to the start of the word
        start -= 1
    if _CHECKSUM.match(text, start) or _PUBLIC_KEY.search(text[max(0, start - 40):start]) \
            or re.match(r"[\w-]*verification=", tok):
        return False                    # go.sum and lock-file checksums, public keys, DNS verification records
    segs = [x for x in re.split(r"[-_+=]+", tok) if x]
    if len(segs) >= 2 and all(_WORD.fullmatch(x) for x in segs):
        return False
    wordy = sum(len(run) for run in re.findall(r"[a-z]{3,}", tok))
    return wordy * 2 < len(tok)


def kinds(line):
    """What secret-looking things a line of a file contains, by name and never by value: the committed
    -secrets scan of kt.secrets() is built on this."""
    found = []
    if "devstoreaccount1" in line or "UseDevelopmentStorage" in line:        # the public Azurite emulator account
        return found
    for label, rx, _ in FIXED:
        m = rx.search(line)
        if m and not (label == "credentials in a URL" and RUNTIME_REF.match(m.group(2))):
            found.append(label)
    if not found and any(_assigned_secret(m) for m in GENERIC.finditer(line)):
        found.append("password or key assignment")
    if not found and any(_keyed_secret(m) for m in KEYED.finditer(line)):
        found.append("possible password or token")              # the wider tier: weaker evidence than the above
    if not found and any(_random_token(m) for m in RANDOM_TOKEN.finditer(line)):
        found.append("long random token")
    return found


def scan(lines, environ=None, known=(), secret_lines=None):
    """[(index, [kinds])] for the lines that hold a secret value, by kind and never by value: the lines
    redact() would change. kiro-guard uses it to tell whether a read would show a secret."""
    values = sorted((v for v in set(known) | env_secrets(os.environ if environ is None else environ) if len(v) >= 8),
                    key=len, reverse=True)[:3000]
    literal = re.compile("|".join(re.escape(v) for v in values)) if values else None
    found = []
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        ks = kinds(line)
        if literal is not None and literal.search(line):
            ks.append("value kept in a secrets file or a secret variable")
        elif secret_lines and not ks and line.strip() in secret_lines:
            ks.append("line of a secrets file")
        if ks:
            found.append((i, ks))
    return found


def env_secrets(environ):
    """Values of secret-looking environment variables."""
    return {value for name, value in environ.items()
            if SECRET_NAME.search(name) and len(value) >= 8 and not os.path.exists(value)}


def file_secrets(root):
    """(values, lines) from the project's secrets files; empty when the kt helpers are not available."""
    try:
        import kt
        return kt.secret_values(root), kt.secret_lines(root)
    except Exception:       # the filter must never stop a program's output from coming through
        return set(), {}


def _mask_pieces(text, values):
    """A piece of a secret is still a secret: mask a run that matches the start or the end of a known
    value for 12 characters or more (8 when that is at least half of the value)."""
    count = 0
    for v in values:
        if len(v) < 10:
            continue
        for head in (True, False):
            probe = v[:8] if head else v[-8:]
            i = text.find(probe)
            while i >= 0:
                if head:
                    a, b = i, i + 8
                    while b - a < len(v) and b < len(text) and text[b] == v[b - a]:
                        b += 1
                else:
                    a, b = i, i + 8
                    while b - a < len(v) and a > 0 and text[a - 1] == v[len(v) - (b - a) - 1]:
                        a -= 1
                n = b - a
                if n >= 12 or n * 2 >= len(v):
                    text, count = text[:a] + MARK + text[b:], count + 1
                    i = text.find(probe, a + len(MARK))
                else:
                    i = text.find(probe, i + 1)
    return text, count


def redact(text, environ=None, known=(), lines=None):
    """-> (redacted text, number of values replaced). `known` are literal secret values; `lines` maps a
    line of a secrets file to its masked form (a file printed verbatim is masked line by line)."""
    count = 0
    if lines:
        out = []
        for ln in text.split("\n"):
            body = ln.strip()
            if body in lines:
                ln = ln[:len(ln) - len(ln.lstrip())] + lines[body]
                count += 1
            out.append(ln)
        text = "\n".join(out)
    literals = sorted(env_secrets(os.environ if environ is None else environ) | set(known), key=len, reverse=True)
    for value in literals:
        n = text.count(value)
        if n:
            text, count = text.replace(value, MARK), count + n
    text, n = _mask_pieces(text, literals)
    count += n
    for _, rx, repl in FIXED:
        if repl is None:
            new = rx.sub(_url_credentials, text)
            count += sum(1 for m in rx.finditer(text) if not RUNTIME_REF.match(m.group(2)))
            text = new
        else:
            text, n = rx.subn(repl, text)
            count += n

    def generic(m):
        nonlocal count
        if MARK in m.group(0) or not _assigned_secret(m):
            return m.group(0)
        count += 1
        return m.group(1) + MARK

    def token(m):
        nonlocal count
        if not _random_token(m):
            return m.group(0)
        count += 1
        return MARK
    def keyed(m):
        nonlocal count
        if not _keyed_secret(m):
            return m.group(0)
        count += 1
        kept = len(m.group(2).rstrip(")]}."))                   # a closing bracket after the value stays
        return m.group(1) + MARK + m.group(2)[kept:]
    text = KEYED.sub(keyed, GENERIC.sub(generic, text))
    return RANDOM_TOKEN.sub(token, text), count


def main():
    data = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    values, lines = file_secrets(os.getcwd())
    out, n = redact(data, known=values, lines=lines)
    sys.stdout.write(out)
    if n:
        if out and not out.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.write("[kiro-run: %d secret value%s masked as %s in this output]\n" % (n, "" if n == 1 else "s", MARK))
    return 0


if __name__ == "__main__":
    sys.exit(main())
