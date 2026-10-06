#!/usr/bin/env python3
"""Tests for global/lib: kt (repo helpers for kiro-run programs) and kiro_redact (output filter).
Run: python3 tests/test_lib.py
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "global", "lib"))

FILES = {
    "main.go": "package main\n\nfunc main() {\n\trun()\n}\n\ntype Server struct{}\n\nfunc (s *Server) http(c int) {\n}\n",
    "pkg/util.py": "import os\n\nclass Loader:\n    def load(self, path):\n        return open(path).read()\n\nasync def fetch(url):\n    pass\n",
    "web/app.ts": "export interface Props { a: string }\nexport const handler = async (e) => {\n}\nexport function render() {}\n",
    "infra/main.tf": 'resource "azurerm_resource_group" "rg" {\n  name = "x"\n}\nvariable "env" {}\n',
    "scripts/deploy.sh": "#!/bin/bash\ncleanup() {\n  rm -rf build\n}\n",
    "docs/notes.md": "# notes\nreturn of the notes\n",
    ".env": "API_TOKEN=abc123\n",
    ".env.example": "API_TOKEN=\n",
    "config/secrets/app.xml": "<secret>hunter2</secret>\n",
    "config/secrets/db.yaml": "# database\nhost: db.internal\npassword: S3cr3t-Pw\nport: 5432\nusers:\n  - alice\noptions: {}\n# old: pw=Old-Pass1\n",
    "config/secrets/conn.json": "{\n  \"connectionString\": \"Server=sql.internal;Password=Json-Pw-77;\",\n  \"nested\": {\n    \"apiKey\": \"k-123456\"\n  }\n}\n",
    "prod.vault": "unlock = Vault-Key-99\n",
    "config/app/teams.json": "{\n  \"zuse\": \"https://flow.example.net/workflows/abc/invoke?api-version=1&sig=AbCdEfGhIjKlMnOpQrStUv\"\n}\n",
    "pipelines/azure-pipelines.yml": "steps:\n- bash: |\n    curl --silent --url https://anyone:$(System.AccessToken)@dev.azure.com/x?a=1&b=2\n",
    "chart/templates/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  replicas: 1\n  template:\n    spec:\n      containers:\n      - image: \"{{ .Values.registry }}/pau/curl\"\n",
    "chart/templates/role.yaml": "kind: ClusterRole\nrules:\n- apiGroups: [\"\", \"extensions\"]\n  resources: [\"ingresses\"]\n---\nkind: ClusterRoleBinding\nsubjects:\n- kind: ServiceAccount\n  name: default\n  namespace: default\n",
    "chart/values-prod.yaml": "jobs:\n- schedule: \"* 13 * * 0-4\" # once a day\n- schedule: \"0 13 * * 1-5\"\n",
    "data/licenses.json": "[\n" + "  1,\n" * 300 + "  2\n]\n",
    "docker-compose.yml": "services:\n  db:\n    image: postgres:14\n    environment:\n      POSTGRES_PASSWORD: devpassword\n      Conn: AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==\n",
    "certs/tls.key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
    "infra/terraform.tfstate": "{}\n",
    "ignored-by-git.txt": "x\n",
    "data/big.sql": "select 1;\n",
    "bin/blob.bin": "\0\0\0binary",
}


def capture(fn, *a, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        res = fn(*a, **kw)
    return res, buf.getvalue()


def main():
    fails, n = [], [0]

    def check(label, want, got):
        n[0] += 1
        if want != got:
            fails.append("%s: expected %r, got %r" % (label, want, got))

    tmp = tempfile.mkdtemp()
    home = os.path.join(tmp, "home")
    proj = os.path.join(tmp, "proj")
    os.makedirs(os.path.join(home, ".kiro", "settings"))
    with open(os.path.join(home, ".kiro", "settings", "kiroignore"), "w") as fh:
        fh.write("# global\n*.sql\nnode_modules/\n\n# Secrets of this team\n*.vault\n")
    for rel, body in FILES.items():
        p = os.path.join(proj, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(body)
    with open(os.path.join(proj, ".gitignore"), "w") as fh:
        fh.write("ignored-by-git.txt\n")
    with open(os.path.join(proj, ".kiroignore"), "w") as fh:
        fh.write("docs/\n")
    subprocess.run(["git", "init", "-q", proj], check=True)
    os.environ["HOME"] = home
    os.chdir(proj)
    import kt
    kt._HOME = home

    # ---- files / ignore rules
    visible = kt.files()
    check("files: code is listed", True, all(f in visible for f in ("main.go", "pkg/util.py", "web/app.ts", "infra/main.tf", "scripts/deploy.sh")))
    for hidden, why in ((".env", "built-in secret rule"), ("config/secrets/app.xml", "secrets/ folder"), ("certs/tls.key", "*.key"),
                        ("infra/terraform.tfstate", "*.tfstate"), ("data/big.sql", "global kiroignore"),
                        ("docs/notes.md", "project .kiroignore"), ("ignored-by-git.txt", ".gitignore"),
                        ("prod.vault", "secret section of the global kiroignore")):
        check("files: %s hidden (%s)" % (hidden, why), False, hidden in visible)
    for path, want in ((".env", "secret"), ("config/secrets/db.yaml", "secret"), ("prod.vault", "secret"), ("certs/tls.key", "secret"),
                       ("data/big.sql", "bulk"), ("docs/notes.md", "bulk"), ("main.go", None), (".env.example", None)):
        check("kind of %s" % path, want, kt._kind(path))
    check("secret()", (True, False, False), (kt.secret(".env"), kt.secret("data/big.sql"), kt.secret("main.go")))
    hid = dict(kt.hidden())
    check("hidden(): names what is hidden and why", ("secret", "bulk", False, False),
          (hid.get("config/secrets/app.xml"), hid.get("data/big.sql"), "main.go" in hid, "ignored-by-git.txt" in hid))
    check("files: .env.example stays visible", True, ".env.example" in visible)
    check("files: glob without a slash matches at any depth", ["pkg/util.py"], kt.files("*.py"))
    check("files: ** glob", ["infra/main.tf"], kt.files("infra/**/*.tf"))
    check("files: brace glob", ["main.go", "pkg/util.py"], kt.files("**/*.{go,py}"))
    check("ignored()", (True, False), (kt.ignored(".env"), kt.ignored("main.go")))

    # ---- a folder or path= where a glob is expected (helpers guess the call shape)
    check("files/grep: a folder name means everything below it, and path= names the glob", (["pkg/util.py"], 1, 1, 1),
          (kt.files("pkg"), len(kt.grep("return", "pkg", quiet=True)), len(kt.grep("return", path="pkg", quiet=True)), len(kt.grep("func main", "main.go", quiet=True))))

    # ---- long lines keep their end: an error message is often longer than 240 characters
    with open("long.log.txt", "w") as fh:
        fh.write("Error: " + "x" * 300 + ' no matches for kind "PodDisruptionBudget" in version "policy/v1beta1"\n' + "y" * 900 + "\n")
    _, out = capture(kt.read, "long.log.txt")
    check("read: a 380-character line is shown whole; a longer one is cut with a note of how much is missing", (True, True),
          ('version "policy/v1beta1"' in out, "…[+300 chars]" in out))
    os.remove("long.log.txt")

    # ---- grep
    hits, out = capture(kt.grep, r"return", "**/*")
    check("grep: finds code, not hidden docs", [("pkg/util.py", 5, "        return open(path).read()")], hits)
    check("grep: output format", "pkg/util.py:5:         return open(path).read()\n", out)
    hits, out = capture(kt.grep, r"hunter2|abc123|BEGIN PRIVATE|S3cr3t|Vault-Key")
    check("grep: secrets files are never searched", ([], True), (list(hits), out.startswith("no matches")))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print(kt.grep(r"func main", "*.go"))
    check("print(kt.grep(...)) adds nothing to what grep printed", "main.go:3: func main() {\n\n", buf.getvalue())
    check("quiet=True returns plain data", "[('main.go', 3, 'func main() {')]", repr(kt.grep(r"func main", "*.go", quiet=True)))
    hits, out = capture(kt.grep, r"func", "*.go", ctx=1, max_hits=1)
    check("grep: max_hits caps output, not the result", (2, True), (len(hits), "1 more matches not shown (2 in total)" in out))
    hits, out = capture(kt.grep, r"func", "*.go", quiet=True)
    check("grep: quiet", (2, ""), (len(hits), out))

    # ---- outline
    rows, out = capture(kt.outline, "**/*")
    names = [(p, i) for p, i, _ in rows]
    for want in (("main.go", 3), ("main.go", 7), ("main.go", 9), ("pkg/util.py", 3), ("pkg/util.py", 4), ("pkg/util.py", 7),
                 ("web/app.ts", 1), ("web/app.ts", 2), ("web/app.ts", 4), ("infra/main.tf", 1), ("infra/main.tf", 4),
                 ("scripts/deploy.sh", 2)):
        check("outline: %s:%d" % want, True, want in names)
    check("outline: prints file headers", True, "main.go (10 lines)" in out and "     9  func (s *Server) http(c int) {" in out)
    rows, out = capture(kt.outline, "main.go")
    check("outline: a single path", 3, len(rows))

    # ---- show
    _, out = capture(kt.show, "main.go", 3, 5)
    check("show: range", "main.go:3-5 (of 10 lines)\n     3  func main() {\n     4  \trun()\n     5  }\n", out)
    _, out = capture(kt.show, "main.go", around=9, span=1)
    check("show: around", True, out.startswith("main.go:8-10 (of 10 lines)"))
    _, out = capture(kt.show, "certs/tls.key")
    check("show: a key file is masked", "certs/tls.key:1-1 (of 1 lines) — secrets file: values are masked\n     1  [redacted]\n", out)
    _, out = capture(kt.show, "config/secrets/db.yaml")
    check("show: yaml secrets keep keys and plain comments, lose every value, and say what each value looks like", [
        "config/secrets/db.yaml:1-8 (of 8 lines) — secrets file: values are masked",
        "     1  # database", "     2  host: [redacted]   <- plain setting, 11 chars", "     3  password: [redacted]   <- real-looking, 9 chars",
        "     4  port: [redacted]   <- plain setting, 4 chars", "     5  users:", "     6    [redacted]   <- unclear, 5 chars",
        "     7  options: {}", "     8  [redacted]   <- real-looking, 9 chars"], out.splitlines())
    _, out = capture(kt.show, "config/secrets/conn.json")
    check("show: json secrets", [
        "config/secrets/conn.json:1-6 (of 6 lines) — secrets file: values are masked",
        "     1  {", '     2    "connectionString": [redacted],   <- real-looking, 40 chars', '     3    "nested": {',
        '     4      "apiKey": [redacted]   <- real-looking, 8 chars', "     5    }", "     6  }"], out.splitlines())
    for value, want in (("SECRET_API_KEY", "placeholder-looking"), ("Host=localhost;Username=postgres;Password=postgres", "placeholder-looking"),
                        ("changeme", "placeholder-looking"), ("Zx9-Qp4_Lm2k", "real-looking"), ("bob", "unclear"),
                        ("AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcq", "placeholder-looking"),
                        ("https://repo.acme-corp.net/artifactory/api/npm/npm-all/", "plain setting"), ("linux,x64", "plain setting"),
                        ("db1.internal.acme-corp.net:5432", "plain setting"), ("8080", "plain setting"), ("true", "placeholder-looking"),
                        ("NpmTok_4f9a2c7d1e8b3f6a5c0d9e2b7a4f1c8d", "real-looking"), ("0123456789abcdef0123456789abcdef", "real-looking"),
                        ("https://deploy:Sup3rS3cret@host.acme-corp.net/x", "real-looking"), ("https://deploy:Sup3rS3cret@host.example.com/x", "placeholder-looking"), ("Server=sql;Password=Json-Pw-77;", "real-looking"),
                        ("a sentence that somebody left in the file", "plain setting"), ("Tok_4f9a2c7d1e8b3f6a5c0d9e2b7a4f", "real-looking"),
                        ("eu-west-1", "plain setting"), ("api-service-01", "plain setting"), ("us_east_2,eu-west-1", "plain setting"),
                        ("correct-horse-battery-staple", "unclear"), ("hunter2", "unclear"), ("Summer-2024", "real-looking")):
        check("shape of a %d-char value" % len(value), want, kt._shape(value))
    _, out = capture(kt.show, "data/big.sql")
    check("show: a file hidden only to save tokens can be shown on request", "data/big.sql:1-1 (of 1 lines)\n     1  select 1;\n", out)
    check("mask: xml text and attributes", '<a key="K" value="[redacted]"/>\n<b>[redacted]</b>\n<c />',
          kt.mask('<a key="K" value="v1"/>\n<b>text</b>\n<c />'))
    check("mask: env file", "A=[redacted]\nexport B=[redacted]\n# note\n[redacted]", kt.mask("A=1\nexport B=\"x y\"\n# note\nfree text line"))
    vals = kt.secret_values()
    check("secret_values: learned from every secrets file", True,
          all(v in vals for v in ("hunter2", "abc123", "S3cr3t-Pw", "Json-Pw-77", "k-123456", "Vault-Key-99", "Old-Pass1")))
    check("secret_values: ordinary words and short values are not learned", False, any(v in vals for v in ("alice", "5432", "database")))
    lines = kt.secret_lines()
    check("secret_lines: each value-carrying line maps to its masked form", ("password: [redacted]", "[redacted]", None),
          (lines.get("password: S3cr3t-Pw"), lines.get("- alice"), lines.get("users:")))
    _, out = capture(kt.show, "bin/blob.bin")
    check("show: binary", True, "binary" in out)

    # ---- tree
    info, out = capture(kt.tree)
    check("tree: counts only visible files", True, info["files"] == len(visible) and ".tf" in info["types"] and ".sql" not in info["types"])
    check("tree: prints a summary", True, out.splitlines()[0].startswith("%d files," % len(visible)) and "by type:" in out)
    check("tree: names the files of a small project", True, "main.go" in out and "util.py" in out)
    check("tree: names what is hidden, secrets marked", True,
          "hidden by .kiroignore, 9 files:" in out and "config/secrets/app.xml (secrets)" in out and "data/big.sql" in out)

    # ---- partition: folder groups for helpers, no overlap, nothing lost
    info, out = capture(kt.partition, max_lines=100000)
    check("partition: a small project fits one context", (1, [], info["lines"], True),
          (len(info["parts"]), info["rest"], kt.tree(quiet=True)["lines"], "fits one context" in out))

    def owners(info):
        globs = [g for b in info["parts"] + info["rest"] for g in b["globs"]]
        return {f: [g for g in globs if f in kt.files(g)] for f in visible}
    info, out = capture(kt.partition, max_lines=10, parts=3)
    own = owners(info)
    check("partition: every visible file is in exactly one group or in the rest", [], [f for f, gs in own.items() if len(gs) != 1])
    check("partition: at most `parts` groups, the rest named for a second round", (3, True, True),
          (len(info["parts"]), bool(info["rest"]), "not covered (a second round)" in out))
    check("partition: a group stays within max_lines unless one file alone is larger", [],
          [b["name"] for b in info["parts"] if b["lines"] > 10 and len(b["globs"]) > 1])
    check("partition: group names are unique", True, len({b["name"] for b in info["parts"]}) == len(info["parts"]))
    check("partition: hidden files are never part of a group", [], [f for f in (".env", "config/secrets/db.yaml") if f in own])
    info, out = capture(kt.partition, max_lines=1000, targets=["../up", "~/x", "/etc", "nope", "chart", "chart/templates"])
    check("partition: targets outside the project or without files are rejected, a target inside another is dropped",
          (["../up", "~/x", "/etc", "nope"], True),
          ([t for t, _ in info["rejected"]], all(g.startswith("chart/") for b in info["parts"] for g in b["globs"])))
    check("partition: rejected targets are printed with the reason", True,
          "rejected target ../up: contains .." in out and "rejected target /etc: absolute path" in out)
    p = subprocess.run([sys.executable, "-m", "kt", "partition", "max_lines=100000"], capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "global", "lib")))
    check("partition: python3 -m kt partition (the bash form)", True, "fits one context" in p.stdout)

    # ---- read: a batch of files in one go
    rows, out = capture(kt.read, "**/*.{go,py,ts}")
    check("read: prints every matching file whole, numbered", (["main.go", "pkg/util.py", "web/app.ts"], True),
          ([n for n, _ in rows], "=== main.go (10 lines) ===\n 1  package main\n 2  \n 3  func main() {" in out and out.rstrip().endswith("--- read 3 files, 22 lines")))
    rows, out = capture(kt.read)
    check("read: long data files are named, not printed", (True, False), ("data/licenses.json (303 lines)" in out.split("not printed")[1], "=== data/licenses.json" in out))
    check("read: hidden files are not part of a glob read", False, "config/secrets" in out or ".env (" in out.replace(".env.example", ""))
    rows, out = capture(kt.read, ["config/secrets/db.yaml", "data/big.sql"])
    check("read: a secrets file asked for by name comes masked", True, "=== config/secrets/db.yaml (8 lines) — secrets file: values are masked ===" in out
          and "S3cr3t-Pw" not in out and "=== data/big.sql (1 lines) ===" in out)
    os.makedirs(".toolstate/cache")
    with open(".toolstate/cache/state.json", "w") as fh:
        fh.write("{}\n")
    rows, out = capture(kt.read)
    check("read: another tool's dot-folder is named, not printed; a pipeline folder is source", (True, False, True),
          (".toolstate/cache/state.json (1 lines)" in out.split("not printed")[1], "=== .toolstate" in out, "=== pipelines/azure-pipelines.yml" in out))
    shutil.rmtree(".toolstate")
    rows, out = capture(kt.read, "**/*", max_lines=30)
    check("read: stops at the budget and names what is left", True, "NOT READ YET (over the 30-line budget of this call):" in out and 'kt.read(["path", "folder/**"])' in out)
    os.makedirs("many/a")
    os.makedirs("many/b")
    for k in range(30):
        with open("many/%s/f%02d.py" % ("a" if k % 3 else "b", k), "w") as fh:
            fh.write("x = %d\n" % k * 4)
    rows, out = capture(kt.read, "many/**", max_lines=20, first=["many/b/f27.py", "many/a/f01.py"])
    check("read: when not everything fits, the files named first are read first", ["many/b/f27.py", "many/a/f01.py"], [n for n, _ in rows[:2]])
    check("read: a long list of what is left is summed up by folder, not spelled out", (True, False),
          ("NOT READ YET (over the 20-line budget of this call): 26 files, 104 lines. By folder: many/ 26 files 104 lines" in out, "f29.py (4 lines)" in out))
    rows, out = capture(kt.read, "many/**", max_lines=500, first=["many/b/f27.py"])
    check("read: when everything fits the order is by path", "many/a/f01.py", rows[0][0])
    shutil.rmtree("many")
    capfile = os.path.join(tmp, "cap")
    os.environ["KIRO_RUN_CAPFILE"] = capfile
    capture(kt.read, "main.go")
    capture(kt.read, "pkg/util.py")
    with open(capfile) as fh:
        wanted = int(fh.read())
    del os.environ["KIRO_RUN_CAPFILE"]
    check("read: tells kiro-run how many lines it deliberately printed", (10 + 1 + 6) + (8 + 1 + 6), wanted)

    # ---- a settings file that merely could hold a secret (.npmrc) is not reported as holding one
    with open(".npmrc", "w") as fh:
        fh.write('registry=https://repo.acme-corp.net/artifactory/api/npm/npm-all/\nalways-auth=true\n'
                 'supported-architectures["os"]=linux,x64\nsupported-architectures["cpu"]=x64\n')
    _, out = capture(kt.show, ".npmrc")
    check("show: every line of a settings file keeps its key, and no setting is called real-looking", [
        ".npmrc:1-4 (of 4 lines) — secrets file: values are masked",
        "     1  registry=[redacted]   <- plain setting, 55 chars", "     2  always-auth=[redacted]   <- placeholder-looking, 4 chars",
        '     3  supported-architectures["os"]=[redacted]   <- plain setting, 9 chars',
        '     4  supported-architectures["cpu"]=[redacted]   <- unclear, 3 chars'], out.splitlines())
    with open(".npmrc", "a") as fh:
        fh.write("//repo.acme-corp.net/artifactory/api/npm/:_authToken=NpmTok_4f9a2c7d1e8b3f6a5c0d9e2b7a4f1c8d\n")
    kt._material_cache.clear()
    _, out = capture(kt.show, ".npmrc")
    check("show: a token on a //scoped key is the one line called real-looking, its key kept",
          "     5  //repo.acme-corp.net/artifactory/api/npm/:_authToken=[redacted]   <- real-looking, 39 chars", out.splitlines()[-1])
    check("secret values: the token of a //scoped key is learned, so it is masked wherever it is printed", True,
          "NpmTok_4f9a2c7d1e8b3f6a5c0d9e2b7a4f1c8d" in kt.secret_values())
    os.remove(".npmrc")
    kt._material_cache.clear()

    # ---- secrets: committed secrets by place and kind, never by value
    found, out = capture(kt.secrets)
    check("secrets: finds the signed URL and names file, line and kind", True, ("config/app/teams.json", 2, "signed URL (sig=)") in found)
    check("secrets: a token a pipeline fills in at run time is not a committed secret", False, any(n == "pipelines/azure-pipelines.yml" for n, _, _ in found))
    check("secrets: the public Azurite account is not a secret", False, any(n == "docker-compose.yml" for n, _, _ in found))
    check("secrets: never prints a value", False, any(v in out for v in ("AbCdEfGhIjKlMnOpQrStUv", "S3cr3t-Pw", "hunter2", "Vault-Key-99")))
    check("secrets: reports the secrets files and what their values look like", True,
          "secrets file config/secrets/db.yaml: not tracked, 5 values — 2 real-looking, 2 placeholders or plain settings, 1 unclear" in out)
    subprocess.run(["git", "add", "-f", "config/secrets/app.xml"], check=True, capture_output=True)
    _, out = capture(kt.secrets)
    check("secrets: says when git tracks a secrets file", True, "secrets file config/secrets/app.xml: TRACKED IN GIT" in out)

    # ---- risky: candidates per stack
    hits, out = capture(kt.risky)
    labels = {(n, label.split(" (")[0].split(" - ")[0]) for _, label, n, _, _ in hits}
    for want in (("pipelines/azure-pipelines.yml", "token or password placed in a URL"),
                 ("pipelines/azure-pipelines.yml", "curl without --fail"),
                 ("pipelines/azure-pipelines.yml", "unquoted URL with &"),
                 ("chart/templates/deployment.yaml", "image without a tag or digest"),
                 ("chart/templates/deployment.yaml", "no securityContext on any workload"),
                 ("chart/templates/deployment.yaml", "single replica"),
                 ("chart/templates/role.yaml", "RBAC rule in the removed extensions API group"),
                 ("chart/templates/role.yaml", "role bound to the default service account"),
                 ("chart/templates/role.yaml", "cluster-wide RBAC"),
                 ("chart/values-prod.yaml", "cron runs every minute of the hour"),
                 ("docker-compose.yml", "password in plain text")):
        check("risky: %s in %s" % (want[1], want[0]), True, want in labels)
    check("risky: a cron with a fixed minute is fine", 1, sum(1 for _, label, n, _, _ in hits if label.startswith("cron runs") and n == "chart/values-prod.yaml"))
    check("risky: never prints a plain-text password", False, "devpassword" in out)
    check("risky: a tagged image is fine", False, ("docker-compose.yml", "image without a tag or digest") in labels)
    check("tree: never prints a secret value", False, any(v in out for v in ("hunter2", "abc123", "S3cr3t-Pw", "Vault-Key-99")))

    # ---- sh
    (rc, text), out = capture(kt.sh, "echo a; echo b; echo c; exit 2", tail=2)
    check("sh: exit code, full text, capped print", (2, "a\nb\nc\n", "$ echo a; echo b; echo c; exit 2 -> exit 2 (last 2 of 3 lines)\n  b\n  c\n"), (rc, text, out))
    (rc, text), out = capture(kt.sh, ["printf", "x"], quiet=True)
    check("sh: argv form, quiet", (0, "x", ""), (rc, text, out))
    (rc, text), _ = capture(kt.sh, "sleep 3", timeout=1)
    check("sh: timeout", 124, rc)
    (rc, _), _ = capture(kt.sh, ["definitely-not-a-command-xyz"])
    check("sh: missing command", 127, rc)

    # ---- command-line form
    p = subprocess.run([sys.executable, "-m", "kt", "files", "*.go"], capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "global", "lib")))
    check("python3 -m kt files", "main.go\n", p.stdout)
    p = subprocess.run([sys.executable, "-m", "kt", "grep", "func", "*.go", "ctx=0", "max_hits=1", "quiet=false"], capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "global", "lib")))
    check("python3 -m kt grep with name=value arguments", "main.go:3: func main() {\n... 1 more matches not shown (2 in total)\n", p.stdout)
    p = subprocess.run([sys.executable, "-m", "kt", "read", "main.go", "pkg/util.py", "max_lines=100"], capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "global", "lib")))
    check("python3 -m kt read a b: several paths in one call", True, "=== main.go (10 lines) ===" in p.stdout and "--- read 2 files, 18 lines" in p.stdout)

    # ---- skill-router hook: a review prompt gets the code-review skill, others get nothing
    router = os.path.join(HERE, "..", "global", "hooks", "scripts", "skill-router.sh")
    for prompt, want in (("review this repo", True), ("have a look at the code and review it", True), ("Can you audit the helm chart?", True),
                         ("do a code review of the pipeline", True), ("find the bugs in this script", True),
                         ("fix the typo in README", False), ("prepare this branch for review", False), ("what does the nightly pipeline do?", False),
                         ("add a preview environment", False)):
        p = subprocess.run(["bash", router], input=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": prompt}), capture_output=True, text=True)
        check("skill-router: %r" % prompt, (0, want), (p.returncode, "code-review skill" in p.stdout))
    # with the skill installed the prompt gets the skill itself, once per session
    rhome = os.path.join(tmp, "router-home")
    os.makedirs(os.path.join(rhome, ".kiro", "skills", "code-review"))
    shutil.copy(os.path.join(HERE, "..", "global", "skills", "code-review", "SKILL.md"), os.path.join(rhome, ".kiro", "skills", "code-review"))
    renv = dict(os.environ, HOME=rhome, TMPDIR=rhome)

    def route(prompt, session):
        payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "cwd": proj, "session_id": session}
        return subprocess.run(["bash", router], input=json.dumps(payload), capture_output=True, text=True, env=renv).stdout
    first, again, other = route("review this repo", "sess_a"), route("now review the fix", "sess_a"), route("review this repo", "sess_b")
    check("skill-router: the first review prompt of a session gets the skill itself, without its front matter",
          (True, True, True, False), ("do not load it" in first, "## Method" in first, "## Output" in first, "name: code-review" in first))
    check("skill-router: a later review prompt in the same session gets one line", (1, True), (len(again.strip().splitlines()), "earlier in this session" in again))
    check("skill-router: another session gets the skill again", True, "## Method" in other)
    check("skill-router: what it injects fits comfortably in a prompt", True, len(first) < 13000)
    for name in ("plan", "troubleshoot"):
        os.makedirs(os.path.join(rhome, ".kiro", "skills", name))
        shutil.copy(os.path.join(HERE, "..", "global", "skills", name, "SKILL.md"), os.path.join(rhome, ".kiro", "skills", name))
    for k, (prompt, want) in enumerate([
            ("why is the deployment failing?", "troubleshoot"), ("the pod keeps restarting, find out why", "troubleshoot"),
            ("debug this pipeline error", "troubleshoot"), ("CI fails with exit code 1 on the lint job", "troubleshoot"),
            ("find the root cause of the 502s", "troubleshoot"), ("what's wrong with my chart", "troubleshoot"),
            ("the deploy pipeline fails on dev since the cluster was upgraded, see logs/deploy.log - why?", "troubleshoot"),
            ("helm upgrade failed after the node pool change", "troubleshoot"), ("terraform apply errors out, why", "troubleshoot"),
            ("make the test fail if the value is null", None), ("the linter fails on line 3, fix the indentation", None),
            ("make a plan to migrate the ingress to gateway api", "plan"), ("how should we split this chart into two?", "plan"),
            ("what is the best approach to rotate the secrets", "plan"), ("plan how to fix the failing deployment", "plan"),
            ("review the plan in docs/migration.md", "code-review"),
            ("run terraform plan for the dev stack", None), ("explain plan for this slow query", None),
            ("add debug logging to the worker", None), ("why do we use helm here?", None), ("upgrade the chart version to 2.3.1", None)]):
        out = route(prompt, "route-%d" % k)
        got = next((n for n in ("code-review", "troubleshoot", "plan") if "The %s skill is given below" % n in out), None)
        check("skill-router: %r -> %s" % (prompt, want), want, got)
    out = route("why is the build failing since yesterday?", "sess_t")
    check("skill-router: a failure gets the troubleshooting method and its pipeline example", (True, True, True, False),
          ("## Method" in out, '"role": "fact-check"' in out, "## Diagnosis" in out, "name: troubleshoot" in out))
    out = route("plan the upgrade to kubernetes 1.31", "sess_p")
    check("skill-router: a change to plan gets the planning method with all three helpers", (True, True, True),
          ('"role": "skeptic"' in out, '"role": "scout"' in out, "## Plan" in out))
    check("skill-router: other prompts still get nothing", "", route("fix the typo in README", "sess_a"))
    for name in ("spec-check", "large-task"):
        os.makedirs(os.path.join(rhome, ".kiro", "skills", name))
        shutil.copy(os.path.join(HERE, "..", "global", "skills", name, "SKILL.md"), os.path.join(rhome, ".kiro", "skills", name))
    for k, (prompt, want) in enumerate([
            ("check this against the spec", "spec-check"), ("does the implementation meet the requirements in docs/req.md?", "spec-check"),
            ("verify the acceptance criteria for the checkout feature", "spec-check"), ("is everything in the ticket done?", "spec-check"),
            ("check the work against .kiro/specs/checkout/requirements.md", "spec-check"), ("are the acceptance criteria met?", "spec-check"),
            ("does the PR satisfy all the requirements of JIRA-123", "spec-check"), ("review this PR against the ticket", "spec-check"),
            ("did we implement everything in the spec?", "spec-check"),
            ("write a spec for the login page", None), ("update requirements.txt with pytest", None), ("review the spec", "code-review"),
            ("plan how to meet the requirements of the new API", "plan"), ("implement the spec in .kiro/specs/checkout", None),
            ("make the build meet the requirements of SOC2", None), ("check the values against the schema", None),
            ("the requirements are unclear, what do you think", None),
            ("map the whole repo", "large-task"), ("explain how the whole system works", "large-task"),
            ("give me an architecture overview of this repo", "large-task"), ("document every service's endpoints", "large-task"),
            ("survey all the helm charts for missing limits", "large-task"), ("inventory everything the migration touches", "large-task"),
            ("review the whole repo", "code-review"), ("make a plan to migrate all services", "plan"),
            ("find all services that use redis", None), ("explain this function", None), ("describe each step of the pipeline", None)]):
        out = route(prompt, "route2-%d" % k)
        got = next((n for n in ("spec-check", "code-review", "troubleshoot", "plan", "large-task") if "The %s skill is given below" % n in out), None)
        check("skill-router: %r -> %s" % (prompt, want), want, got)
    out = route("is everything in the ticket implemented?", "sess_s")
    check("skill-router: a spec check gets its method with the auditor stages", (True, True, True, False),
          ("## Method" in out, '"role": "auditor"' in out, "## Spec check" in out, "name: spec-check" in out))
    out = route("map the whole repo for me", "sess_l")
    check("skill-router: work too large for one context gets the split-by-size method", (True, True, True),
          ("kt.partition" in out, '"role": "scout"' in out, "Covered" in out))

    # ---- redaction
    import kiro_redact
    env = {"GITHUB_TOKEN": "tok_0123456789abcdef", "HOME": "/home/x", "DB_PASSWORD": "short", "PATH": "/usr/bin"}
    cases = [
        ("env value", "token is tok_0123456789abcdef here", "token is [redacted] here"),
        ("short env values are left alone", "the word short stays", "the word short stays"),
        ("aws key id", "key AKIAABCDEFGHIJKLMNOP ok", "key [redacted] ok"),
        ("github token", "ghp_" + "a" * 36, "[redacted]"),
        ("jwt", "eyJ" + "a" * 24 + ".eyJ" + "b" * 24 + "." + "c" * 12, "[redacted]"),
        ("private key block", "x\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\ny", "x\n[redacted] private key\ny"),
        ("storage connection string", "DefaultEndpointsProtocol=https;AccountName=a;AccountKey=" + "Zm9v" * 22 + "==;EndpointSuffix=x",
         "DefaultEndpointsProtocol=https;AccountName=a;AccountKey=[redacted]"),
        ("sas signature", "https://a.blob.core.windows.net/c?sv=2022-11-02&sig=abcdEFGH1234%2Bxyz7890abcd&se=1", "https://a.blob.core.windows.net/c?sv=2022-11-02&sig=[redacted]&se=1"),
        ("teams webhook", "url https://contoso.webhook.office.com/webhookb2/abc/IncomingWebhook/def/ghi end", "url https://…webhook.office.com/[redacted] end"),
        ("url credentials", "postgres://app:Sup3rS3cretPw@db.internal:5432/x", "postgres://app:[redacted]@db.internal:5432/x"),
        ("bearer header", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345", "Authorization: Bearer [redacted]"),
        ("generic password assignment", 'password = "hunter2hunter2hunter2"', 'password = "[redacted]"'),
        ("camelCase client secret", "clientSecret: abcDEF123456ghiJKL789", "clientSecret: [redacted]"),
        ("client_secret key", "client_secret: abcDEF123456ghiJKL789", "client_secret: [redacted]"),
        ("references are not secrets", "password: ${DB_PASSWORD_FROM_VAULT}", "password: ${DB_PASSWORD_FROM_VAULT}"),
        ("placeholders are not secrets", "api_key = changeme-changeme-changeme", "api_key = changeme-changeme-changeme"),
        ("ordinary output is untouched", "charts/web/values.yaml: no resources.limits\n42 files, 10891 lines", "charts/web/values.yaml: no resources.limits\n42 files, 10891 lines"),
        ("kubeconfig client key", "client-key-data: " + "QUJD" * 20, "client-key-data: [redacted]"),
    ]
    cases += [
        ("long random token", "token AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh end", "token [redacted] end"),
        ("a git sha is not a token", "commit 3f9c2b7a1d4e5f60718293a4b5c6d7e8f9012345", "commit 3f9c2b7a1d4e5f60718293a4b5c6d7e8f9012345"),
        ("a long path is not a token", "src/Very/Long/Path/To/Some/Deeply/Nested/Module/File2.go:12", "src/Very/Long/Path/To/Some/Deeply/Nested/Module/File2.go:12"),
    ]
    cases += [
        ("a pipeline token reference in a URL stays readable", "curl https://anyone:$(System.AccessToken)@dev.azure.com/x", "curl https://anyone:$(System.AccessToken)@dev.azure.com/x"),
    ]
    for label, text, want in cases:
        got, _ = kiro_redact.redact(text, env)
        check("redact: " + label, want, got)
    got, _ = kiro_redact.redact("preview='Zx9-Qp4_Lm2k-Wq' and tail='7Hs-end-of-key'", {}, known=["Zx9-Qp4_Lm2k-Wq8Rt5-Yu1Io3-7Hs-end-of-key"])
    check("redact: the first or last characters of a known secret are masked too", "preview='[redacted]' and tail='[redacted]'", got)
    got, _ = kiro_redact.redact("https://example.net/a and https://other.org/b", {}, known=["https://secret.example.com/hook/Zx9Qp4Lm2kWq8Rt5"])
    check("redact: a short common start of a secret is not a piece of it", "https://example.net/a and https://other.org/b", got)
    check("kinds: names what a line holds", (["signed URL (sig=)"], ["long random token"], [], []),
          (kiro_redact.kinds('"u": "https://x/y?a=1&sig=AbCdEfGhIjKlMnOpQrStUv"'), kiro_redact.kinds('  "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh"'),
           kiro_redact.kinds("--url https://anyone:$(System.AccessToken)@dev.azure.com"), kiro_redact.kinds("AccountName=devstoreaccount1;AccountKey=" + "Zm9v" * 22)))
    got, masked = kiro_redact.redact("pw is S3cr3t-Pw\n  password: S3cr3t-Pw\nusers:\n  - alice\n", {}, known=kt.secret_values(), lines=kt.secret_lines())
    check("redact: values and whole lines learned from the secrets files", ("pw is [redacted]\n  password: [redacted]\nusers:\n  [redacted]\n", 3), (got, masked))
    _, count = kiro_redact.redact("a AKIAABCDEFGHIJKLMNOP b tok_0123456789abcdef", env)
    check("redact: count", 2, count)
    p = subprocess.run([sys.executable, os.path.join(HERE, "..", "global", "lib", "kiro_redact.py")], input="x AKIAABCDEFGHIJKLMNOP",
                       capture_output=True, text=True)
    check("redact: filter appends a note", "x [redacted]\n[kiro-run: 1 secret value masked as [redacted] in this output]\n", p.stdout)
    with open("config/secrets/db.yaml") as fh:
        p = subprocess.run([sys.executable, os.path.join(HERE, "..", "global", "lib", "kiro_redact.py")], input=fh.read(),
                           capture_output=True, text=True)
    check("redact: the filter learns from the project it runs in", False, "S3cr3t-Pw" in p.stdout or "db.internal" not in p.stdout.replace("[redacted]", "db.internal"))
    p = subprocess.run([sys.executable, os.path.join(HERE, "..", "global", "lib", "kiro_redact.py")], input="plain\n", capture_output=True, text=True)
    check("redact: clean output passes through unchanged", "plain\n", p.stdout)

    # ---- detectors: names and checksums are not secrets, secrets still are
    for label, text, want in [
        ("a config key made of words", "- name: ConnectionStrings__Redis__ConnectionString__0__ApiKeyName", None),
        ("a long CamelCase identifier", 'sid = "AllowScopedEC2InstanceAccessActionsForTheNodeRole"', None),
        ("a policy name with numbers", "sslPolicy: ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09-Extended", None),
        ("a role name with a hex suffix", "arn:aws:iam::1:role/AWSReservedSSO_AdministratorAccess_0123abcd4567ef89", None),
        ("a go.sum checksum", "github.com/a/b v1.2.3 h1:Zm9vQmFyQmF6/UXV4Rm9vQmFyQmF6UXV4Rm9vQmFyQmF6UXV4Rm9vQmE0=", None),
        ("a lock-file checksum", '    "h1:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKl=",', None),
        ("a public ssh key", "ssh.dev.azure.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7Hr1oTWqNqOlzGJOfGJ4NakVyIzf1rXYd4d7wo6jBlkLvCA4o", None),
        ("a DNS verification record", 'txt = "google-site-verification=AbCdEfG1HIjK-lMnOp-QR2S3tU4vwXYz5ABCde6"', None),
        ("a property read", "Password = settings.Database.Password;", None),
        ("a function call", "password = credentialProvider.getPasswordFor(user)", None),
        ("the name of a secret", 'clientSecretSecretRefName: "PLATFORM_CLIENT_APP_SECRET"', None),
        ("where the password file is", "passwordFile: /run/secrets/database/password", None),
        ("the shell's working directory", '"PWD": "/home/dev/src/project/internal"', None),
        ("a real password assignment", 'password = "Xk9-Qp4_Lm2k-Wq8Rt5"', "password or key assignment"),
        ("a real random token", "token AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh", "long random token"),
        ("a real base64url token", "key: q9Xk2LmP0aZ7_bT4cW8dV1eY6fU3gR5hS-iN0jK2lM4nO6", "long random token"),
        ("a real Slack webhook", "hook https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnop", "Slack webhook URL"),
        ("the pattern of a webhook is not one", 're.compile(r"https://hooks\\.slack\\.com/services/"), "https://hooks.slack.com/services/" + MARK', None),
    ]:
        got = kiro_redact.kinds(text)
        check("kinds: " + label, [want] if want else [], got)
        masked, count = kiro_redact.redact(text, {})
        check("redact agrees: " + label, bool(want), count > 0 and masked != text)
    # ---- the wider tier: the value under any key that names a secret (token, secret, short passwords)
    for label, text, want in [
        ("a token under a TOKEN key", "API_TOKEN=Zx9Qp4Lm2kV7Rt3Ws8Nb", "API_TOKEN=[redacted]"),
        ("a quoted token in YAML", '  token: "Zx9Qp4Lm2kV7Rt3Ws8Nb"', '  token: "[redacted]"'),
        ("a hex secret in JSON", '"secret": "9f8e7d6c5b4a39281706f5e4d3c2b1a0"', '"secret": "[redacted]"'),
        ("a prefixed webhook secret", "webhook_secret: whsec_Xk29LmPq83ZtRv7Yb1Nc", "webhook_secret: [redacted]"),
        ("random letters without a digit", "secret: QxZvLmKpRtWsNbYcDfGh", "secret: [redacted]"),
        ("a short password with a symbol", "dbPassword: Summer2024!", "dbPassword: [redacted]"),
        ("a weak password with a digit", "password = hunter2", "password = [redacted]"),
        ("a password with @ in it", "DB_PASSWORD=P@ssw0rd123", "DB_PASSWORD=[redacted]"),
        ("a password with $ in it", "password: Pa$$w0rd!", "password: [redacted]"),
        ("a numeric password", "password: 12345678", "password: [redacted]"),
        ("a password inside a connection string", "Server=db;User=app;Password=Sup3rS3cret;Database=x", "Server=db;User=app;Password=[redacted];Database=x"),
        ("the bracket that closes a call stays", "connect(host, password=Sup3rS3cret)", "connect(host, password=[redacted])"),
    ]:
        check("keyed: " + label, (want, 1), kiro_redact.redact(text, {}))
        check("keyed: its own kind, weaker evidence than a 16+ character assignment: " + label, ["possible password or token"], kiro_redact.kinds(text))
    for label, text in [
        ("a variable", "token = authorizationHeader"),
        ("an expression", 'access_token = response.json()["access_token"]'),
        ("a call", "csrf_token = generate_csrf_token()"),
        ("a class with a digit in its name", 'tokenizer = GPT2Tokenizer.from_pretrained("gpt2")'),
        ("an environment lookup", 'api_key = os.environ["OPENAI_API_KEY"]'),
        ("a URL", "tokenUrl: https://login.example.net/oauth2/token"),
        ("a URL under a secret key", "secret: https://vault.example.com/v1/secret/data/app2"),
        ("a Helm template", "password: {{ .Values.db.password }}"),
        ("a pipeline expression", "token: ${{ secrets.X }}"),
        ("a shell variable", "TOKEN=${GITHUB_TOKEN}"),
        ("a template with a variable in it", '$securityToken = "repoV2/$projectId/$repositoryId"'),
        ("a secret name with a variable", "--set postgres.secret=app-db-$DATABASE-admin-secret"),
        ("the name of a secret", "secretName: my-app-secret"),
        ("a secret name with a version", "existingSecret: my-app-secret-v2"),
        ("a secret name with an abbreviation", "secret: test-my-k8s-store-secret"),
        ("a resource name with a number", "secret: prod-db-01"),
        ("a token type", "token_type: Bearer"),
        ("a boolean", "secret: true"),
        ("a number", "max_tokens: 4096"),
        ("a setting about passwords", "password_min_length = 12"),
        ("a date", "token_created: 2024-06-01"),
        ("an expiry", "TokenExpiry: 2024-06-01T00:00:00Z"),
        ("a path", "passwordFile: /run/secrets/db"),
        ("a JSON schema", '"password": {"type": "string"}'),
        ("a type hint", "password: Optional[str] = None"),
        ("a pipeline logging command", 'echo "##vso[task.setvariable variable=access_token;issecret=true]$TOKEN_VALUE1"'),
        ("an ARN", '"resource_ref": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:app-AbCdEf"'),
        ("an exception name", "Microsoft.IdentityModel.Tokens.SecurityTokenInvalidIssuerException: 'IDX10205: Issuer validation failed"),
        ("a word after the key", "auth: token abcdef"),
    ]:
        check("keyed: not a secret: " + label, (text, 0, []), kiro_redact.redact(text, {}) + (kiro_redact.kinds(text),))
    check("files: *.env and .envrc are secrets files, example.env is not",
          ("secret", "secret", "secret", None, None), tuple(kt._kind_rel(x) for x in ("app.env", "deploy/prod.env", ".envrc", "example.env", ".env.example")))
    found = kiro_redact.scan(["plain line", "  url: https://x.example/y?a=1&sig=AbCdEfGhIjKlMnOpQrSt", "", "pw is S3cr3t-Pw!9"], {}, known=["S3cr3t-Pw!9"])
    check("scan: the lines a read would have to mask, by index and kind",
          [(1, ["signed URL (sig=)"]), (3, ["value kept in a secrets file or a secret variable"])], found)

    # ---- paging: what kiro-run returns fits one tool result
    import kiro_page
    text = "".join("line %04d %s\n" % (i, "x" * 60) for i in range(1500))
    parts = kiro_page.split(text, 28000)
    check("page: parts fit the budget, break at line ends and lose nothing",
          (True, True, True), (all(kiro_page.units(x) <= 28000 for x in parts), all(x.endswith("\n") for x in parts), "".join(parts) == text))
    check("page: short output is one part", ["short\n"], kiro_page.split("short\n", 28000))
    parts = kiro_page.split("y" * 70000 + "\nend\n", 28000)
    check("page: a line longer than a part is cut", (True, True), (all(kiro_page.units(x) <= 28000 for x in parts), "".join(parts) == "y" * 70000 + "\nend\n"))
    check("page: length is counted the way Kiro counts it (UTF-16 units)", (2, True), (kiro_page.units("\U0001F600"), all(
        kiro_page.units(x) <= 28000 for x in kiro_page.split("\U0001F600" * 20000 + "\n", 28000))))
    check("page: part 1 names every call that fetches the rest", (True, True, True), tuple(
        w in kiro_page.first_footer("20260101-000000-1", 4, 28000) for w in ("kiro-run --more 20260101-000000-1 2", "kiro-run --more 20260101-000000-1 4", "ONE step")))

    # ---- calls / survey / PowerShell checks, in a project of their own
    proj2 = os.path.join(tmp, "proj2")
    files2 = {
        "scripts/cleanup.ps1": "param (\n  [string[]] $apiKeys = @('a', 'b'),\n  [string[]] $envs = @('dev', 'prod'),\n  [switch] $force=$False\n)\n"
                               "$idx = 0\nforeach ($env in $envs) {\n  $h = @{ 'X-Api-Key' = $apiKeys[$idx] }\n  $idx += 1\n}\n"
                               "$last = $apiKeys[$apiKey.Length-1]\nif ($force) { Invoke-RestMethod -Method Delete -Uri \"$url/x\" }\n"
                               "$body = \"{ \"\"`$skip\"\": 0 }\"\n",
        "pipelines/nightly.yml": "steps:\n  - task: PowerShell@2\n    inputs:\n      targetType: filePath\n      filePath: scripts/cleanup.ps1\n"
                                 "      arguments: >\n        -apiKeys $(dev_key),$(staging_key),$(prod_key)\n        -envs \"staging\",\"prod\"\n        -force\n"
                                 "    displayName: Cleanup\n    condition: eq(variables['should_remove'], 'true')\n  - script: echo done\n"
                                 "trigger:\n  paths:\n    include:\n    - scripts/cleanup.ps1\n",
        "scripts/deploy.sh": "#!/bin/bash\nset -euo pipefail\nlog() {\n  echo \"$1\"\n}\nENVIRONMENT=\"$1\"\nTAG=\"${2:-latest}\"\n"
                             "log \"deploying $TAG to $ENVIRONMENT with $REGISTRY_TOKEN\"\n",
        "Makefile": "deploy:\n\t./scripts/deploy.sh staging\n",
        "Dockerfile": "FROM alpine:3.20\nCOPY scripts/deploy.sh /app/deploy.sh\nRUN chmod +x /app/deploy.sh\nENTRYPOINT [\"/app/deploy.sh\", \"prod\", \"v1\"]\n",
        "tools/report.py": "import argparse, os\np = argparse.ArgumentParser()\np.add_argument('--since')\nprint(os.environ['REPORT_TOKEN'])\n",
        ".github/workflows/ci.yml": "jobs:\n  a:\n    steps:\n      - run: python tools/report.py --since 7d --until now\n",
        "tools/runner.ps1": "$script = Join-Path $PSScriptRoot \"helper.ps1\"\nif (Test-Path $script) {\n  & $script -Name x -Count 2\n}\n",
        "tools/helper.ps1": "param\n(\n  [Parameter(Mandatory)]\n  [string]$Name\n)\nWrite-Host $Name\n",
        "tools/lonely.sh": "#!/bin/bash\necho hi\n",
        "docs/install.md": "Run ./scripts/deploy.sh staging to deploy.\n",
        "setup.sh": "#!/bin/bash\ncurl -fsSL https://example.com/deploy.sh | bash\n",
        "tools/shared.ps1": ". ./common.ps1\nWrite-Host $fromCommon\n",
        "ops/make-kubeconfig.sh": "#!/bin/bash\nout=x\ncount=0\n",
        "ops/prod.kubeconfig.yaml": "users:\n- name: admin\n  user:\n    token: abc\n",
    }
    for rel, body in files2.items():
        path = os.path.join(proj2, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(body)
    subprocess.run(["git", "init", "-q", proj2], check=True)
    os.chdir(proj2)
    rows, out = capture(kt.calls)
    check("calls: every real call site, and nothing else",
          [("scripts/cleanup.ps1", "pipelines/nightly.yml", 5), ("scripts/deploy.sh", "Dockerfile", 4), ("scripts/deploy.sh", "Makefile", 2),
           ("tools/helper.ps1", "tools/runner.ps1", 1), ("tools/report.py", ".github/workflows/ci.yml", 4)], sorted(rows))
    for label, piece in [
        ("the param block is shown with line numbers", "       2    [string[]] $apiKeys = @('a', 'b'),"),
        ("where each parameter is used", "used at lines: $apiKeys 8, 11 · $envs 7 · $force 12"),
        ("the whole pipeline step: arguments ...", "       7  -apiKeys $(dev_key),$(staging_key),$(prod_key)"),
        ("... and its condition", "      11  condition: eq(variables['should_remove'], 'true')"),
        ("a shell script's own arguments, not those of its functions", "scripts/deploy.sh (8 lines) reads its arguments at:\n       6  ENVIRONMENT=\"$1\"\n       7  TAG=\"${2:-latest}\"\n"),
        ("the environment a shell script reads", "environment it reads: REGISTRY_TOKEN"),
        ("a python script's parser and environment", "       3  p.add_argument('--since')\n       4  print(os.environ['REPORT_TOKEN'])"),
        ("a caller with inline arguments", "       4  - run: python tools/report.py --since 7d --until now"),
        ("a path kept in a variable: where it is run", "       3  & $script -Name x -Count 2"),
        ("a param block whose ( is on the next line", "tools/helper.ps1 (6 lines) declares:\n       1  param\n       2  (\n"),
        ("scripts nothing calls are named", "not called from any file here (run by hand, or from outside the repo): setup.sh, tools/lonely.sh, tools/runner.ps1, tools/shared.ps1"),
    ]:
        check("calls: " + label, True, piece in out)
    check("calls: a download URL, a COPY, a trigger path and a doc are not calls", (False, False, False, False),
          ("example.com" in out, "COPY" in out, "      16  " in out, "install.md" in out))
    check("calls: list arguments of different lengths are pointed out", True,
          "note: list arguments of different lengths (-apiKeys has 3, -envs has 2): how does the script pair them?" in out)
    check("calls: what counts as a list argument", ({"-keys": 3, "--envs": 2}, {}, {"-I": 2}),
          (kt._list_args('-keys $(a),$(b),"c d" --envs=x,y -force'), kt._list_args("--name app --tag v1,"), kt._list_args("gcc -I a,b -o out x.c")))
    _, out = capture(kt.survey)
    check("survey: layout, secrets, risky constructs, calls and tools in one call", [True] * 5,
          [("##### " + t) in out for t in ("layout", "committed secrets", "risky constructs", "script calls", "tools for this stack")])
    info = kt.tools(quiet=True)
    check("tools: only what the project's files call for, split into installed and missing", (True, True, False),
          ("bash" in info["installed"], set(info["installed"] + info["missing"]) >= {"pwsh", "bash", "shellcheck", "python3", "docker", "actionlint"},
           "terraform" in info["installed"] + info["missing"]))
    capfile = os.path.join(tmp, "cap2")
    os.environ["KIRO_RUN_CAPFILE"] = capfile
    rows, out = capture(kt.review)
    with open(capfile) as fh:
        wanted = int(fh.read())
    del os.environ["KIRO_RUN_CAPFILE"]
    check("review: the survey, the source, then the working notes to fill in, last", (True, True, True),
          (out.index("##### layout") < out.index("##### source") < out.index("=== scripts/cleanup.ps1") < out.index("##### working notes: fill this in"),
           "starts with `## Review`, with no narration before it" in out.rstrip().splitlines()[-1], ("scripts/cleanup.ps1", 13) in rows))
    form = out[out.index("##### working notes"):]
    check("review: the notes form is built from this project: its calls, deletes, candidate groups and logic files", [True] * 6,
          [piece in form for piece in ("  scripts/cleanup.ps1 <- pipelines/nightly.yml:5 :", "  scripts/cleanup.ps1:12 :",
                                       "  [powershell] variable read but never assigned in the file (2) :", "  [scripts and pipelines] force flag (1) :",
                                       "files: go through each of these again", "  scripts/cleanup.ps1 :")])
    check("review: only files with branching are on the list to go through again", False, "  docs/install.md :" in form or "  tools/report.py :" in form)
    rows, out = capture(kt.review, "tools/**")
    check("review of one folder: its files only, and the survey's secrets, risky constructs and calls are those of that folder",
          (True, True, False, False, True),
          ("##### risky constructs in tools/**" in out, "=== tools/runner.ps1" in out, "=== scripts/cleanup.ps1" in out,
           "scripts/cleanup.ps1 <-" in out[out.index("##### working notes"):], "  tools/helper.ps1 <- tools/runner.ps1:1 :" in out))
    check("review: everything it prints is asked for, so kiro-run does not cut it at the line cap", True, wanted >= out.count("\n"))
    hits = kt.risky(quiet=True)
    check("risky: a variable that is read and never assigned, with the name it resembles",
          [("scripts/cleanup.ps1", 11, "$apiKey - did you mean $apiKeys?"), ("scripts/cleanup.ps1", 12, "$url")],
          [(n2, i, t) for st, label, n2, i, t in hits if label.startswith("variable read")])
    check("risky: a file that takes definitions from another one is not judged", [], [h for h in hits if h[2] == "tools/shared.ps1"])
    with open("tools/sync.sh", "w") as fh:
        fh.write("#!/bin/bash\ncd /data\nrm -rf old\ncp -r new old\n")
    hits = kt.risky(quiet=True)
    check("risky: scripts that carry on after a failed call are candidates (PowerShell without Stop, shell without set -e)",
          [("scripts/cleanup.ps1", 12), ("tools/sync.sh", 1)],
          sorted((n2, i) for st, label, n2, i, t in hits if label.startswith(("no $ErrorActionPreference", "no set -e"))))
    os.remove("tools/sync.sh")
    hits = kt.risky(quiet=True)
    check("risky: destructive steps and force flags are candidates to trace", [("pipelines/nightly.yml", 9), ("scripts/cleanup.ps1", 12)],
          sorted((n2, i) for st, label, n2, i, t in hits if label.startswith(("deletes or destroys", "force flag"))))
    check("risky: a pipeline is recognised by its content, whatever its folder is called", True,
          any(st == "scripts and pipelines" and n2 == "pipelines/nightly.yml" for st, label, n2, i, t in hits))
    check("kind: a script that only has kubeconfig in its name is hidden but holds no secrets", ("bulk", "secret"),
          (kt._kind("ops/make-kubeconfig.sh"), kt._kind("ops/prod.kubeconfig.yaml")))
    check("secret values: URLs, hosts, paths, numbers, regions and names of a secrets file are not spread as secrets",
          [False, False, False, False, False, False, True, True, True, True],
          [kt._secretish(v) for v in ("https://api.example.com/v1/items", "db1.internal.example.com:5432", "/var/lib/app/data1", "1024 MB",
                                      "eu-west-1", "api-service-01", "S3cr3t-Pw!9", "https://user:pw@host/x?sig=abc",
                                      "correct-horse-battery-staple", "Summer-2024")])
    check("hint: words under a key called password are not called a plain setting", ("   <- unclear, 11 chars", "   <- plain setting, 9 chars"),
          (kt._line_hint("db_password: summer-2024"), kt._line_hint("AWS_REGION=eu-west-1")))

    # ---- kiro_migrate: an installed kiro-guard.conf and permissions.yaml brought up to this version ----
    import kiro_migrate as mig
    tmpl = "# head\nA=1\n# about B\nB=two\n# new in this version\nC=x\n"
    text, added, extra = mig.merge_conf(tmpl, "A=9\n# my own note\nZ=keep me\nB=Not Valid\n")
    check("conf: the user's values stay as written, a new setting comes with its comment and default, unknown ones are kept at the end",
          ("# head\nA=9\n# about B\nB=Not Valid\n# new in this version\nC=x\n\n" + mig.KEPT_HEADER + "\nZ=keep me\n", ["C"], ["Z"]),
          (text, added, extra))
    check("conf: migrating twice changes nothing", text, mig.merge_conf(tmpl, text)[0])
    check("conf: a later line wins and commented settings are not settings", {"A": "2"}, mig.settings("A=1\n#B=3\n  # C=4\nA=2\n"))
    r1, r2, r2b, r3 = ({"capability": "shell", "match": [m], "effect": "deny"} for m in ("a *", "b *", "b2 *", "c *"))
    mine = {"capability": "shell", "match": ["my-tool *"], "effect": "allow"}
    check("rules: a rule the pack dropped or changed goes, new pack rules arrive, the user's own rule stays",
          ([r1, mine, r2b, r3], [r2b, r3], [r2]), mig.merge_rules([r1, r2, mine], [r1, r2b, r3], [r1, r2]))
    a1 = {"capability": "shell", "match": ["kubectl get *"], "effect": "allow"}
    check("rules: an allow or ask rule of the pack the user removed stays out", ([r2, mine], [], []),
          mig.merge_rules([r2, mine], [a1, r2], [a1, r2]))
    check("rules: a deny rule of the pack the user removed comes back", ([r2, mine, r1], [r1], []),
          mig.merge_rules([r2, mine], [r1, r2], [r1, r2]))
    check("rules: without a record of the last install's rules, nothing is removed", ([r2, mine, r1], [r1], []),
          mig.merge_rules([r2, mine], [r1], None))
    try:
        import yaml
    except ImportError:
        yaml = None
    if yaml:
        # end to end: install over an old-style install, then again, then once more
        inst = os.path.join(tmp, "inst")
        os.makedirs(os.path.join(inst, ".kiro", "hooks", "scripts"))
        conf = os.path.join(inst, ".kiro", "hooks", "scripts", "kiro-guard.conf")
        with open(conf, "w") as fh:
            fh.write("# my old settings\nGUARD_MODE=readonly\nCODE_MODE=inline\nMY_NOTE=1\n")
        env = dict(os.environ, HOME=inst)
        install = lambda: subprocess.run(["bash", os.path.join(HERE, "..", "install.sh"), "--no-test"], env=env,
                                         capture_output=True, text=True)
        p1 = install()
        with open(conf) as fh:
            c1 = fh.read()
        s1 = mig.settings(c1)
        check("install over an old kiro-guard.conf: values kept, new settings added with their defaults, unknown kept",
              (0, "readonly", "inline", "off", "deny", "0", "1", True),
              (p1.returncode, s1.get("GUARD_MODE"), s1.get("CODE_MODE"), s1.get("RUN_SANDBOX"), s1.get("RUN_SANDBOX_NET"),
               s1.get("RUN_ALLOW_ADMIN"), s1.get("MY_NOTE"),
               all(k in "".join(l for l in p1.stdout.splitlines() if l.startswith("kiro-guard.conf: added"))
                   for k in ("RUN_ALLOW_ADMIN", "RUN_SANDBOX", "RUN_SANDBOX_NET"))))
        perm = os.path.join(inst, ".kiro", "settings", "permissions.yaml")
        base = os.path.join(inst, ".kiro", "settings", ".kiro-pack-rules.yaml")
        with open(perm) as fh:
            pack_rules = yaml.safe_load(fh)["rules"]
        check("fresh permissions: the pack's file and a record of its rules", (True, pack_rules),
              (os.path.isfile(base), yaml.safe_load(open(base))["rules"]))
        # as if the previous pack had shipped one more rule, the user added one and removed the subagent allow
        old_rule = {"capability": "shell", "match": ["retired-tool *"], "effect": "ask"}
        sub = next(r for r in pack_rules if r.get("capability") == "subagent")
        with open(perm, "w") as fh:
            yaml.safe_dump({"rules": [r for r in pack_rules if r != sub] + [old_rule, mine]}, fh, sort_keys=False)
        with open(base, "w") as fh:
            yaml.safe_dump({"rules": pack_rules + [old_rule]}, fh, sort_keys=False)
        p2 = install()
        rules2 = yaml.safe_load(open(perm))["rules"]
        check("upgrade: the rule the pack retired goes, the user's rule stays, a pack rule the user removed stays out, the rest is there",
              (0, False, True, False, True, True),
              (p2.returncode, old_rule in rules2, mine in rules2, sub in rules2,
               all(r in rules2 for r in pack_rules if r != sub), "removed ask shell retired-tool *" in p2.stdout))
        with open(conf) as fh:
            c2 = fh.read()
        with open(perm) as fh:
            perm2 = fh.read()
        p3 = install()
        check("installing again changes neither file and says so", (c2, perm2, True, True),
              (open(conf).read(), open(perm).read(), "kiro-guard.conf: up to date" in p3.stdout, "permissions: up to date" in p3.stdout))

    os.chdir(HERE)
    shutil.rmtree(tmp, ignore_errors=True)
    if fails:
        print("\n".join(fails))
        print("\nlib: %d of %d FAILED" % (len(fails), n[0]))
        return 1
    print("lib: all %d checks passed" % n[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
