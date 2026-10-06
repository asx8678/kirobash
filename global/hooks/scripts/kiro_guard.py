#!/usr/bin/env python3
"""kiro-guard: Kiro CLI v3 PreToolUse hook that blocks destructive Kubernetes,
Helm, Azure and IaC commands.

Contract (Kiro hooks): JSON payload on STDIN. Exit 0 = allow, exit 2 = block
(stderr is shown to the agent). Any other exit code is treated by the wrapper
script as "block" (fail closed).

Classes:
  D  destructive / irreversible  -> always blocked (k8s tools: allowed on local
                                    dev contexts such as kind-*, minikube)
  M  mutating but recoverable    -> allowed here (permissions.yaml asks you);
                                    blocked when GUARD_MODE=readonly (except
                                    on local dev contexts)
  R  redirect (code mode)        -> blocked with instructions to re-issue the
                                    work as a kiro-run program
  A  needs approval              -> an M step found inside a kiro-run program.
                                    kiro-run is allowed without a prompt, so
                                    nothing would ask the user: blocked, to be
                                    issued alone as a direct command
  (nothing)                      -> read-only, allowed
"""
import json
import os
import re
import shlex
import subprocess
import sys
import time

HOME = os.path.expanduser("~")
CONF_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kiro-guard.conf")


# ----------------------------------------------------------------- config ---
def load_conf():
    conf = {
        "GUARD_MODE": "destructive",  # destructive | readonly | off
        "CODE_MODE": "enforce",       # enforce (inline code and multi-command lines go through kiro-run) | inline | prefer | off
        "SECRET_READS": "mask",       # mask (a read that would show a secret value goes through kiro-run, which masks it) | off
        "LOCAL_CONTEXTS": r"kind-.*|minikube|docker-desktop|docker-for-desktop|rancher-desktop|orbstack|k3d-.*|colima.*|microk8s",
        "LOG_FILE": os.path.join(HOME, ".kiro", "kiro-guard.log"),
    }
    try:
        with open(CONF_PATH, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                conf[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    # The person launching Kiro may override via environment (the agent cannot
    # change the environment of the Kiro process that runs this hook).
    for k in ("GUARD_MODE", "CODE_MODE", "SECRET_READS", "LOCAL_CONTEXTS", "LOG_FILE"):
        env = os.environ.get("KIRO_" + k)
        if env:
            conf[k] = env
    conf["LOG_FILE"] = os.path.expanduser(conf["LOG_FILE"])
    return conf


CONF = load_conf()
LOCAL_RE = re.compile(r"^(?:%s)$" % CONF["LOCAL_CONTEXTS"])


class Verdict:
    def __init__(self, cls, reason, k8s=None):
        self.cls = cls          # "D", "M", "R" or "A" (see the module docstring)
        self.reason = reason    # short human text
        self.k8s = k8s          # dict(context=..., kubeconfig=..., server=...) for kube tools


# ------------------------------------------------------------- constants ---
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
PYTHONS = {"python", "python3", "python2"}
PWSH = {"pwsh", "powershell", "pwsh.exe", "powershell.exe"}
WRAPPERS_NOARG = {"command", "builtin", "exec", "nohup", "time", "caffeinate", "unbuffer",
                  "if", "then", "else", "elif", "do", "while", "until", "!", "{", "}"}
WRAPPERS_FLAGVALUE = {
    "sudo": {"-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t", "-D", "-R"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p", "-t"},
    "stdbuf": {"-i", "-o", "-e"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "gtimeout": {"-s", "--signal", "-k", "--kill-after"},
    "watch": {"-n", "--interval", "-d", "--differences", "-x"},
    "xargs": {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "--max-args", "--max-procs", "--delimiter", "--arg-file"},
    "parallel": {"-j", "--jobs", "-S", "--sshlogin", "--delay"},
    "chronic": set(),
    "strace": {"-o", "-e", "-p"},
}
KUBE_TOOLS = {"kubectl", "oc", "k", "kubecolor", "kubectl.exe"}
KUBECTL_VALUE_FLAGS = {
    "-n", "--namespace", "--context", "--cluster", "--user", "--kubeconfig", "-s", "--server",
    "--token", "--as", "--as-group", "--as-uid", "--request-timeout", "--cache-dir",
    "--certificate-authority", "--client-certificate", "--client-key", "--tls-server-name",
    "-v", "--v", "--vmodule", "--profile", "--profile-output", "--password", "--username",
}
HELM_VALUE_FLAGS = {
    "-n", "--namespace", "--kube-context", "--kubeconfig", "--kube-apiserver", "--kube-token",
    "--kube-as-user", "--kube-as-group", "--kube-ca-file", "--kube-tls-server-name",
    "--registry-config", "--repository-cache", "--repository-config", "--burst-limit", "--qps",
}
KUBECTL_D = {"delete", "drain", "replace", "edit"}
KUBECTL_M = {
    "apply", "create", "patch", "scale", "label", "annotate", "set", "cordon", "uncordon",
    "taint", "exec", "cp", "run", "expose", "autoscale", "attach", "debug", "certificate",
}
KUBECTL_CONFIG_D = {"delete-context", "delete-cluster", "delete-user", "unset"}
KUBECTL_CONFIG_M = {"use-context", "use", "set-context", "set-cluster", "set-credentials", "set", "rename-context"}
KUBECTL_ROLLOUT_M = {"restart", "undo", "pause", "resume"}

AZ_LOCAL_GROUPS = {"extension", "config", "cache", "bicep", "interactive", "find", "version",
                   "feedback", "self-test", "init", "survey", "upgrade"}
AZ_GLOBAL_VALUE = {"--subscription", "-o", "--output", "--query"}
AZ_D = {"delete", "delete-batch", "purge", "remove", "deallocate", "stop", "power-off", "reimage",
        "redeploy", "reset", "reset-password", "regenerate", "regenerate-key", "regenerate-keys",
        "revoke", "detach", "failover", "swap", "untag", "force-delete", "wipe", "rollback",
        "uninstall", "unregister", "disable-local-accounts", "delete-all"}
AZ_M = {"create", "update", "set", "add", "start", "restart", "upgrade", "scale", "assign",
        "import", "deploy", "invoke", "enable", "disable", "apply", "attach", "login", "logout",
        "rotate", "renew", "publish", "up", "tag", "move", "resize", "run", "sync", "upload",
        "copy", "restore", "approve", "reject", "patch", "put", "grant", "register", "install",
        "enable-addons", "disable-addons", "rotate-certs", "update-credentials", "reconcile",
        "execute", "trigger", "queue", "cancel", "abort", "acquire", "renew-lease", "break-lease",
        "set-policy", "delete-policy", "generate-sas", "get-credentials"}
AZ_D_PREFIX = ("delete", "purge", "remove", "deallocate", "regenerate", "revoke", "reset", "force-delete",
               "wipe", "uninstall")
AZ_M_PREFIX = ("create", "update", "set-", "add-", "start", "restart", "assign", "import", "deploy",
               "enable", "disable", "attach", "rotate", "renew", "upgrade", "scale", "grant", "register",
               "install", "run-", "invoke", "move", "resize", "swap", "promote", "failback")
TF_TOOLS = {"terraform", "tofu", "terragrunt"}
AWS_VALUE_FLAGS = {"--profile", "--region", "--output", "--query", "--endpoint-url", "--cli-read-timeout",
                   "--cli-connect-timeout", "--ca-bundle", "--color", "--cli-binary-format", "--page-size",
                   "--max-items", "--starting-token"}
AWS_D_PREFIX = ("delete", "terminate", "deregister", "purge", "reboot", "stop", "deactivate", "release",
                "batch-delete", "schedule-key-deletion", "revoke", "remove", "disable", "failover", "empty")
AWS_D_EXACT = {"rm", "rb", "send-command", "nuke"}
AWS_M_PREFIX = ("create", "update", "put", "modify", "start", "run", "attach", "associate", "disassociate",
                "enable", "tag", "untag", "register", "invoke", "copy", "restore", "import", "add", "set",
                "authorize", "replace", "reset", "rotate", "apply", "execute", "promote", "cancel", "detach",
                "retire", "assume", "accept", "reject", "upload", "complete", "abort", "initiate", "resume",
                "suspend", "swap", "scale", "move", "transfer", "wipe", "cp", "mv", "sync", "login", "logout",
                "update-kubeconfig", "start-session", "retry", "redeploy", "reencrypt", "re-encrypt")
AWS_READ_PREFIX = ("describe", "list", "get", "head", "wait", "lookup", "search", "query", "scan", "check",
                   "estimate", "preview", "test", "validate", "simulate", "generate", "ls", "presign", "tail",
                   "filter", "select", "view", "batch-get", "count", "verify", "decode", "export", "download",
                   "help", "lookup-events", "receive")
AWS_M_EXACT = {"remove-tags", "untag-resource", "remove-role-from-instance-profile", "remove-user-from-group",
               "remove-permission", "remove-tags-from-resource", "disable-alarm-actions", "disable-metrics-collection"}
KNOWN_TOOLS = KUBE_TOOLS | TF_TOOLS | {"helm", "az", "azd", "pulumi", "flux", "argocd", "velero", "kubectx",
                                       "kubens", "k9s", "istioctl", "linkerd", "kubeadm", "azcopy", "func", "aws", "eksctl", "cdk", "sam",
                                       "serverless", "sls", "copilot", "kops", "aws-nuke",
                                       "curl", "wget", "http", "https", "xh", "rm"}
TF_D = {"destroy", "apply", "force-unlock", "test", "destroy-all", "apply-all"}
TF_M = {"import", "taint", "untaint", "refresh"}

METADATA_RE = re.compile(r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200|"
                         r"fd00:ec2::254|169\.254\.170\.2|\[fd00:ec2::254\]", re.I)
CLOUD_API_RE = re.compile(
    r"(management\.azure\.com|graph\.microsoft\.com|vault\.azure\.net|\.azmk8s\.io|amazonaws\.com|"
    r"/api/v1/|/apis/|:6443\b|:8001\b|kubernetes\.default)", re.I)

# Broad patterns used for script files, inline code, here-docs, things piped
# into an interpreter, and commands that could not be tokenised.
RAW_D_PATTERNS = [
    (r"\baws\b[^\n;|&]*\s(delete|terminate|deregister|purge|reboot|stop|batch-delete|schedule-key-deletion)[\w-]*\b", "destructive aws command"),
    (r"\baws\s+s3\s+(rm|rb)\b", "aws s3 rm/rb"),
    (r"\baws\s+s3\s+sync\b[^\n;|&]*--delete\b", "aws s3 sync --delete"),
    (r"\baws\s+ssm\s+send-command\b", "aws ssm send-command (remote code)"),
    (r"\beksctl\s+delete\b", "eksctl delete"),
    (r"\b(cdk\s+(destroy|deploy)|sam\s+(delete|deploy|sync)|serverless\s+(remove|deploy)|sls\s+(remove|deploy)|kops\s+delete|aws-nuke)\b", "IaC deploy/destroy"),
    (r"\b(delete_\w+|terminate_instances|deregister_\w+|purge_queue|stop_instances|reboot_instances|"
     r"delete_db_instance|schedule_key_deletion|batch_delete_\w+)\b", "SDK (boto3) delete/terminate call"),
    (r"\b(boto3|botocore|azure\.|kubernetes|google\.cloud)[\s\S]{0,400}\.(delete|terminate|destroy|purge|delete_all)\s*\(",
     "cloud SDK object .delete()/.terminate() call"),
    (r"\b(kubectl|oc|kubecolor)\b[^\n;|&]*\s(delete|drain|replace|edit)\b", "kubectl delete/drain/replace/edit"),
    (r"\bhelm\b[^\n;|&]*\s(uninstall|delete)\b", "helm uninstall"),
    (r"\baz\b[^\n;|&]*\s(delete|delete-batch|purge|deallocate|stop|reimage|redeploy|regenerate[\w-]*|revoke|failover|untag)\b", "destructive az command"),
    (r"--mode[=\s]+['\"]?complete\b", "Complete-mode deployment (deletes unlisted resources)"),
    (r"\bazd\s+down\b", "azd down"),
    (r"\b(terraform|tofu|terragrunt)\b[^\n;|&]*\s(destroy|apply|force-unlock)\b", "terraform apply/destroy"),
    (r"\bpulumi\b[^\n;|&]*\s(destroy|up|update)\b", "pulumi up/destroy"),
    (r"\b(Remove|Stop|Reset|Clear|Revoke|Suspend|Disable)-Az\w+", "destructive Az PowerShell cmdlet"),
    (r"\b(delete_namespaced_\w+|delete_collection_\w+|delete_cluster_custom_object|begin_delete\w*|"
     r"begin_deallocate|begin_power_off|begin_stop|begin_restart|purge_deleted_\w+)\b", "SDK delete/stop call"),
    (r"(-X\s*|--request[=\s]+)['\"]?DELETE\b", "HTTP DELETE request"),
    (r"\bkubeadm\s+reset\b", "kubeadm reset"),
    (r"\bflux\b[^\n;|&]*\s(delete|uninstall)\b", "flux delete/uninstall"),
    (r"\bargocd\b[^\n;|&]*\s(delete|rm)\b", "argocd delete"),
    (r"\bvelero\b[^\n;|&]*\sdelete\b", "velero delete"),
    (r"\bistioctl\b[^\n;|&]*\suninstall\b", "istioctl uninstall"),
    (r"\bazcopy\s+(remove|rm)\b", "azcopy remove"),
    (r"--delete-destination[=\s]+['\"]?true", "sync with --delete-destination"),
    # list-form process calls: subprocess.run(["kubectl", "delete", ...]), spawn('az', ['group', 'delete'])
    (r"['\"](kubectl|oc|helm|az|azd|terraform|tofu|terragrunt|pulumi)['\"]\s*,\s*\[?\s*(['\"][^'\"]*['\"]\s*,\s*){0,4}"
     r"['\"](delete|drain|replace|uninstall|purge|deallocate|destroy|apply|down|stop|delete-batch)['\"]",
     "destructive command started from code"),
    (r"X-HTTP-Method(-Override)?['\"]?\s*[:=,]\s*['\"]?DELETE", "HTTP DELETE via method-override header"),
    (r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|169\.254\.170\.2|fd00:ec2::254",
     "access to a cloud instance-metadata endpoint (credential theft)"),
]
RAW_D = [(re.compile(p, re.I if "Az" not in p else 0), why) for p, why in RAW_D_PATTERNS]

# Tool ids the Kiro v3 engine passes to PreToolUse hooks as tool_name.
BUILTIN_TOOLS = {"read_file", "list_directory", "file_search", "grep_search", "read_code", "get_diagnostics",
                 "fs_write", "fs_append", "str_replace", "delete_file", "edit_code", "semantic_rename",
                 "smart_relocate", "execute_bash", "execute_pwsh", "control_bash_process", "control_pwsh_process",
                 "list_processes", "get_process_output", "web_fetch", "remote_web_search", "invoke_sub_agent",
                 "orchestrate_subagent", "disclose_context", "kiro_powers", "knowledge", "introspect", "code",
                 "tool_search", "todo"}
WRITE_TOOLS = {"fs_write", "fs_append", "str_replace", "delete_file", "edit_code", "smart_relocate"}
MCP_D_NAME = re.compile(r"(delete|destroy|purge|uninstall|drain|deallocate|remove|wipe|terminate)", re.I)
MCP_INFRA_NAME = re.compile(r"(k8s|kube|pod|namespace|node|helm|deploy|aks|azure|azmcp|^az_|resource|aws|eks|ec2|"
                            r"s3|rds|iam|lambda|cloudformation|cfn|dynamo|ecs|ecr|sqs|sns|kms|secret|"
                            r"cluster|vm|storage|keyvault|vault|sql|cosmos|terraform|subscription|group|"
                            r"container|registry|acr|network|nsg|dns|role|identity|app_?service|webapp|function)", re.I)


# ------------------------------------------------------------- helpers ---
def basename(tok):
    return os.path.basename(tok.rstrip("/")).lower()


def flag_value(args, names):
    """Value of a flag given as '--x v', '--x=v' or '-xv' (short)."""
    for i, a in enumerate(args):
        for n in names:
            if a == n and i + 1 < len(args):
                return args[i + 1]
            if a.startswith(n + "="):
                return a.split("=", 1)[1]
    return None


def has_flag(args, *names):
    for a in args:
        for n in names:
            if a == n or a.startswith(n + "="):
                return True
    return False


def positional(args, value_flags):
    """Positional words, skipping flags and the values of known value-flags."""
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a == "--":
            break
        if a.startswith("-"):
            if a in value_flags:
                skip = True
            continue
        out.append(a)
    return out


def tokenize(cmd):
    """Return list of segments (each a list of words) or None if unparsable."""
    lex = shlex.shlex(cmd.replace("\r", " ").replace("\n", " ; "), posix=True, punctuation_chars=";&|()<>")
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        toks = list(lex)
    except ValueError:
        return None
    segs, cur = [], []
    for t in toks:
        if t and set(t) <= set(";&|()"):
            if cur:
                segs.append(cur)
            cur = []
            continue
        cur.append(t)
    if cur:
        segs.append(cur)
    return segs




def read_script(path, cwd):
    p = os.path.expanduser(path)
    if not os.path.isabs(p):
        p = os.path.join(cwd, p)
    try:
        if os.path.isfile(p) and os.path.getsize(p) <= 1_000_000:
            with open(p, encoding="utf-8", errors="replace") as fh:
                return fh.read()
    except OSError:
        pass
    return None


def raw_scan(text):
    for rx, why in RAW_D:
        if rx.search(text):
            return Verdict("D", why + " (found inside a script, inline code or unparsed command)")
    return None


CODE_CRED_RE = re.compile(r"(~|\$HOME|\$\{HOME\}|\$env:USERPROFILE|\$env:HOME|expanduser\(\s*['\"]~|"
                          r"homedir\(\)[^\n]{0,40}?|Path\.home\(\)[^\n]{0,40}?|" + re.escape(HOME) +
                          r")[/\\'\", +)]*\.(kube|azure|aws)\b")
# Kiro's own guard, settings, steering and runner files, as a path ('.kiro/hooks') or as path parts
# ('.kiro', 'hooks'): a program has no business reading or changing the files that govern the agent.
CODE_KIRO_RE = re.compile(r"\.kiro['\"/\\, +)]*\s*['\"]?/?(hooks|settings|workspace-roots|lib|steering|skills|agents)\b|"
                          r"kiro[-_]guard|\.local/bin/kiro-|\.kiroignore\b|kiroignore['\"]")


def code_scan(text):
    """raw_scan plus access to credential files and to Kiro's own files, for interpreter / PowerShell code."""
    v = raw_scan(text)
    if v:
        return v
    if CODE_CRED_RE.search(text):
        return Verdict("D", "code that reads cloud credential files (~/.kube, ~/.azure, ~/.aws)")
    if CODE_KIRO_RE.search(text):
        return Verdict("D", "code that touches Kiro's guard, settings, steering or runner files")
    return None


# -------------------------------------------------------- tool analyzers ---
def analyze_kube(tool, args, env):
    if has_flag(args, "--dry-run") and flag_value(args, ["--dry-run"]) not in ("none",):
        return None
    pos = positional(args, KUBECTL_VALUE_FLAGS)
    if not pos:
        return None
    verb = pos[0]
    sub = pos[1] if len(pos) > 1 else ""
    if verb.startswith("$") or PLACEHOLDER in verb:
        return Verdict("D", "%s with a verb built at runtime (cannot be checked)" % tool, None)
    k8s = {
        "context": flag_value(args, ["--context"]),
        "kubeconfig": flag_value(args, ["--kubeconfig"]) or env.get("KUBECONFIG"),
        "server": flag_value(args, ["-s", "--server"]),
    }
    label = "%s %s" % (tool, verb)
    if verb in KUBECTL_D:
        return Verdict("D", label, k8s)
    if verb == "config":
        if sub in KUBECTL_CONFIG_D:
            return Verdict("D", "%s config %s" % (tool, sub), None)
        if sub == "view" and has_flag(args, "--raw"):
            return Verdict("D", "%s config view --raw (prints credentials)" % tool, None)
        if sub in KUBECTL_CONFIG_M:
            return Verdict("M", "%s config %s" % (tool, sub), None)
        return None
    if verb == "rollout" and sub in KUBECTL_ROLLOUT_M:
        return Verdict("M", "%s rollout %s" % (tool, sub), k8s)
    if verb == "scale":
        reps = flag_value(args, ["--replicas"])
        if reps is not None and reps.strip() == "0":
            return Verdict("D", "%s scale --replicas=0" % tool, k8s)
    if verb == "apply" and (has_flag(args, "--prune") or has_flag(args, "--force")):
        return Verdict("D", "%s apply --prune/--force" % tool, k8s)
    if verb == "taint" and any("NoExecute" in a for a in args):
        return Verdict("D", "%s taint NoExecute (evicts pods)" % tool, k8s)
    if verb == "auth" and sub == "reconcile":
        return Verdict("M", "%s auth reconcile" % tool, k8s)
    if verb in ("exec", "debug") and "--" in args:
        inner = shlex.join(args[args.index("--") + 1:])
        iv = analyze_command(inner, os.getcwd(), env, 1, force_remote=True)
        if iv and iv.cls == "D":
            return Verdict("D", "%s %s: %s" % (tool, verb, iv.reason), k8s)
        return Verdict("M", label, k8s)
    if verb in KUBECTL_M:
        return Verdict("M", label, k8s)
    return None


def analyze_helm(args, env):
    if has_flag(args, "--dry-run"):
        return None
    pos = positional(args, HELM_VALUE_FLAGS | {"-f", "--values", "--set", "--set-string", "--set-file",
                                               "--version", "--timeout", "--repo", "--post-renderer"})
    if not pos:
        return None
    verb = pos[0]
    k8s = {"context": flag_value(args, ["--kube-context"]),
           "kubeconfig": flag_value(args, ["--kubeconfig"]) or env.get("KUBECONFIG"),
           "server": flag_value(args, ["--kube-apiserver"])}
    if verb in ("uninstall", "delete", "del", "un"):
        return Verdict("D", "helm uninstall", k8s)
    if verb in ("push", "registry") or (verb == "repo" and len(pos) > 1 and pos[1] in ("add", "update")):
        return Verdict("M", "helm " + verb, None) if verb != "repo" else None
    if verb in ("install", "upgrade", "rollback", "test"):
        if has_flag(args, "--force") or has_flag(args, "--force-replace"):
            return Verdict("D", "helm %s --force" % verb, k8s)
        return Verdict("M", "helm " + verb, k8s)
    return None


def analyze_az(args, env, cwd, depth):
    if not args:
        return None
    # The command path is the positional words before the first argument flag. Global flags
    # (-o json, --subscription X, --only-show-errors, --debug) may come first: skip them.
    path, i = [], 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            if path:
                break
            i += 2 if (a in AZ_GLOBAL_VALUE and "=" not in a) else 1
            continue
        path.append(a.lower())
        i += 1
    if not path or path[0] in AZ_LOCAL_GROUPS:
        return None
    joined = "az " + " ".join(path)
    if any(w.startswith("$") or PLACEHOLDER in w for w in path):
        return Verdict("D", joined + " (command built at runtime; cannot be checked)")
    # Commands that run code remotely: inspect what they run.
    if path[:3] == ["aks", "command", "invoke"]:
        inner = flag_value(args, ["--command", "-c"])
        if inner:
            v = analyze_command(inner, cwd, env, depth + 1, force_remote=True)
            if v:
                return Verdict(v.cls, "az aks command invoke → " + v.reason)
        return Verdict("M", joined)
    if len(path) >= 2 and path[0] in ("vm", "vmss") and path[1] == "run-command" and \
            (len(path) < 3 or path[2] in ("invoke", "create", "update")):
        return Verdict("D", joined + " (arbitrary code on remote machines)")
    if path[0] == "rest":
        method = (flag_value(args, ["--method", "-m"]) or "get").lower()
        if method == "delete":
            return Verdict("D", "az rest --method delete")
        if method in ("put", "patch", "post"):
            return Verdict("M", "az rest --method " + method)
        return None
    if "deployment" in path or path[0] in ("stack",):
        mode = (flag_value(args, ["--mode"]) or "").lower()
        if mode == "complete":
            return Verdict("D", joined + " --mode Complete (deletes resources not in the template)")
        if "--action-on-unmanage" in args or any(a.startswith("--action-on-unmanage") for a in args):
            val = (flag_value(args, ["--action-on-unmanage", "--aou"]) or "").lower()
            if "delete" in val:
                return Verdict("D", joined + " --action-on-unmanage delete")
    if has_flag(args, "--delete-destination"):
        val = (flag_value(args, ["--delete-destination"]) or "true").lower()
        if val != "false":
            return Verdict("D", joined + " --delete-destination")
    words = path[1:] or path
    if any(w in ("keys", "key", "credential", "credentials", "secret") for w in words) and \
            any(w in ("renew", "regenerate", "rotate", "reset", "roll") for w in words):
        return Verdict("D", joined + " (invalidates existing keys/credentials)")
    if any(w in AZ_D or w.startswith(AZ_D_PREFIX) for w in words):
        return Verdict("D", joined)
    if any(w in AZ_M or w.startswith(AZ_M_PREFIX) for w in words) or path[0] in ("login", "logout") \
            or path[:2] == ["account", "set"]:
        return Verdict("M", joined)
    return None


def analyze_tf(tool, args):
    pos = [a for a in args if not a.startswith("-")]
    if tool == "terragrunt":
        pos = [a for a in pos if a not in ("run-all", "run", "stack")]
    if not pos:
        return None
    verb = pos[0]
    if verb in TF_D:
        return Verdict("D", "%s %s" % (tool, verb))
    if any(a == "-destroy" for a in args) and verb in ("apply",):
        return Verdict("D", "%s apply -destroy" % tool)
    if verb == "state" and len(pos) > 1:
        if pos[1] in ("rm", "push", "replace-provider"):
            return Verdict("D", "%s state %s" % (tool, pos[1]))
        if pos[1] == "mv":
            return Verdict("M", "%s state mv" % tool)
    if verb == "workspace" and len(pos) > 1 and pos[1] == "delete":
        return Verdict("D", "%s workspace delete" % tool)
    if verb in TF_M:
        return Verdict("M", "%s %s" % (tool, verb))
    return None


def classify_aws_op(service, op, args_text=""):
    """Classify an AWS CLI/API operation name (kebab-case) -> Verdict or None."""
    op = re.sub(r"(?<!^)(?=[A-Z])", "-", op).lower().strip() if op else ""
    label = "aws %s %s" % (service, op)
    if not op or op.startswith("$") or PLACEHOLDER in op or PLACEHOLDER in service:
        return Verdict("D", label + " (operation built at runtime; cannot be checked)") if op else None
    if service == "s3" and op == "sync" and re.search(r"(^|\s|\")--?delete\b", args_text):
        return Verdict("D", "aws s3 sync --delete")
    if service == "configure":
        return Verdict("M", "aws configure " + op) if op in ("set", "import", "sso", "sso-session") else None
    if service == "sso":
        return Verdict("M", "aws sso " + op)
    if op in AWS_M_EXACT or op in ("untag-resource",):
        return Verdict("M", label)
    if op in AWS_D_EXACT or op.startswith(AWS_D_PREFIX) or "deletion" in op:
        return Verdict("D", label)
    if service == "ssm" and op == "start-session":
        return Verdict("M", label + " (interactive shell on an instance)")
    if op.startswith(AWS_READ_PREFIX) or op in ("sts", "get-caller-identity"):
        if op in ("get-secret-value", "get-parameter", "get-parameters", "get-parameters-by-path") and \
                ("decrypt" in args_text or op == "get-secret-value"):
            return Verdict("M", label + " (prints a secret)")
        return None
    if op.startswith(AWS_M_PREFIX) or service in ("s3",):
        return Verdict("M", label)
    return Verdict("M", label + " (unknown operation, treated as a change)")


def analyze_aws(args):
    pos = positional(args, AWS_VALUE_FLAGS)
    if not pos:
        return None
    service = pos[0].lower()
    op = pos[1] if len(pos) > 1 else ""
    if service in ("help", "--version"):
        return None
    return classify_aws_op(service, op, " ".join(args))


def analyze_simple(tool, args):
    pos = [a for a in args if not a.startswith("-")]
    verb = pos[0] if pos else ""
    sub = pos[1] if len(pos) > 1 else ""
    if tool == "azd":
        if verb == "down":
            return Verdict("D", "azd down")
        if verb in ("up", "provision", "deploy", "hooks"):
            return Verdict("M", "azd " + verb)
    elif tool == "pulumi":
        if verb in ("destroy", "up", "update") or (verb == "stack" and sub in ("rm", "remove")) or \
                (verb == "state" and sub == "delete"):
            return Verdict("D", "pulumi %s %s" % (verb, sub if verb in ("stack", "state") else ""))
        if verb in ("refresh", "import", "cancel"):
            return Verdict("M", "pulumi " + verb)
    elif tool == "flux":
        if verb in ("delete", "uninstall"):
            return Verdict("D", "flux " + verb)
        if verb in ("suspend", "resume", "reconcile", "create", "bootstrap"):
            return Verdict("M", "flux " + verb)
    elif tool == "argocd":
        if sub in ("delete", "rm", "remove", "terminate-op") or verb in ("delete",):
            return Verdict("D", "argocd %s %s" % (verb, sub))
        if verb == "app" and sub == "sync":
            if has_flag(args, "--prune"):
                return Verdict("D", "argocd app sync --prune")
            return Verdict("M", "argocd app sync")
        if sub in ("create", "set", "rollback", "patch", "add"):
            return Verdict("M", "argocd %s %s" % (verb, sub))
    elif tool == "velero":
        if "delete" in pos:
            return Verdict("D", "velero delete")
        if "create" in pos:
            return Verdict("M", "velero %s create" % verb)
    elif tool == "kubectx":
        if "-d" in args:
            return Verdict("D", "kubectx -d")
        if pos:
            return Verdict("M", "kubectx (switches cluster)")
    elif tool == "kubens":
        if pos:
            return Verdict("M", "kubens (switches namespace)")
    elif tool == "k9s":
        return Verdict("D", "k9s (interactive UI that can delete resources)")
    elif tool == "istioctl":
        if "uninstall" in pos:
            return Verdict("D", "istioctl uninstall")
        if verb in ("install", "upgrade") or (verb == "manifest" and sub == "apply"):
            return Verdict("M", "istioctl " + verb)
    elif tool == "linkerd":
        if verb in ("install", "upgrade", "uninstall"):
            return Verdict("M", "linkerd " + verb)
    elif tool == "kubeadm":
        if verb == "reset":
            return Verdict("D", "kubeadm reset")
    elif tool == "azcopy":
        if verb in ("remove", "rm"):
            return Verdict("D", "azcopy remove")
        if verb == "sync" and has_flag(args, "--delete-destination"):
            if (flag_value(args, ["--delete-destination"]) or "true").lower() != "false":
                return Verdict("D", "azcopy sync --delete-destination")
        if verb in ("copy", "cp", "sync"):
            return Verdict("M", "azcopy " + verb)
    elif tool == "func":
        if verb == "azure":
            return Verdict("M", "func azure " + " ".join(pos[1:3]))
    elif tool == "eksctl":
        if verb == "delete":
            return Verdict("D", "eksctl delete " + sub)
        if verb in ("create", "upgrade", "scale", "set", "unset", "enable", "disable", "deregister",
                    "register", "associate", "disassociate", "update") or (verb == "utils" and sub != "describe-stacks"):
            return Verdict("D" if verb == "deregister" else "M", "eksctl %s %s" % (verb, sub))
    elif tool == "cdk":
        if verb in ("destroy", "deploy", "watch"):
            return Verdict("D", "cdk " + verb)
        if verb in ("bootstrap", "import", "rollback", "gc"):
            return Verdict("M", "cdk " + verb)
    elif tool == "sam":
        if verb in ("delete", "deploy", "sync"):
            return Verdict("D", "sam " + verb)
    elif tool in ("serverless", "sls"):
        if verb in ("remove", "deploy"):
            return Verdict("D", "serverless " + verb)
    elif tool == "copilot":
        if sub in ("delete", "deploy") or verb in ("delete", "deploy"):
            return Verdict("D", "copilot %s %s" % (verb, sub))
        if verb in ("init", "env", "svc", "job", "pipeline", "app", "secret"):
            return Verdict("M", "copilot %s %s" % (verb, sub))
    elif tool == "kops":
        if verb == "delete" or (verb in ("update", "rolling-update") and has_flag(args, "--yes", "-y")):
            return Verdict("D", "kops %s" % verb)
        if verb in ("create", "edit", "update", "rolling-update", "upgrade", "set"):
            return Verdict("M", "kops " + verb)
    elif tool == "aws-nuke":
        return Verdict("D", "aws-nuke")
    return None


def analyze_http(tool, args):
    if any(METADATA_RE.search(a) for a in args):
        return Verdict("D", "%s to a cloud instance-metadata endpoint (credential theft)" % tool)
    method = None
    for i, a in enumerate(args):
        if a in ("-X", "--request", "--method") and i + 1 < len(args):
            method = args[i + 1]
        elif a.startswith("-X") and len(a) > 2:
            method = a[2:]
        elif a.startswith(("--request=", "--method=")):
            method = a.split("=", 1)[1]
        if re.search(r"x-http-method(-override)?\s*:\s*['\"]?delete", a, re.I):
            return Verdict("D", "%s with a DELETE method-override header" % tool)
    if tool in ("http", "https", "xh") and args:
        pos = [a for a in args if not a.startswith("-")]
        if pos and pos[0].upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            method = pos[0]
    url_hit = any(CLOUD_API_RE.search(a) for a in args)
    if not method and url_hit and any(
            a in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form", "--json",
                  "-T", "--upload-file") or a.startswith(("--data", "--json", "--post-data", "--post-file"))
            for a in args):
        method = "POST"
    if not method:
        return None
    method = method.upper()
    if method == "DELETE":
        return Verdict("D", "%s DELETE request" % tool)
    if method in ("PUT", "PATCH", "POST") and url_hit:
        return Verdict("M", "%s %s to a cloud/cluster API" % (tool, method))
    return None


SAFE_RM_ROOTS = ["/tmp", "/var/tmp", "/dev/null", os.path.join(HOME, ".cache"), os.path.join(HOME, "Library/Caches"),
                 os.path.join(HOME, ".npm/_cacache"), os.path.join(HOME, ".cargo/registry")]
if os.environ.get("TMPDIR"):
    SAFE_RM_ROOTS.append(os.path.normpath(os.environ["TMPDIR"]))
SYSTEM_D = {"shutdown", "reboot", "halt", "poweroff", "mkfs", "fdisk", "sfdisk", "parted", "wipefs", "mkswap",
            "swapoff", "crontab", "userdel", "groupdel", "chpasswd", "passwd", "nft", "iptables", "ip6tables",
            "ufw", "firewall-cmd"}
NODE_UNITS = ("kubelet", "containerd", "docker", "etcd", "kube-", "crio", "k3s", "rke2", "sshd")
DB_TOOLS = {"psql", "pgcli", "mysql", "mariadb", "mycli", "sqlcmd", "sqlite3", "clickhouse-client", "cockroach",
            "redis-cli", "mongosh", "mongo", "cqlsh", "usql", "litecli", "pg_restore", "mysqladmin", "dropdb",
            "dropuser", "mongorestore", "mysqlsh", "bq", "snowsql"}
SQL_D_RE = re.compile(r"\b(DROP\s+(TABLE|DATABASE|SCHEMA|INDEX|USER|ROLE|VIEW|COLLECTION|KEYSPACE|TABLESPACE)|TRUNCATE|"
                      r"DELETE\s+FROM|ALTER\s+TABLE[^;]*\bDROP\b|FLUSHALL|FLUSHDB|dropDatabase|\.drop\(|deleteMany\(|"
                      r"remove\(\{\}\)|PURGE\s+BINARY|RESET\s+MASTER|DELETE\s+(?!FROM)\w)", re.I)
SQL_M_RE = re.compile(r"\b(INSERT|UPDATE|ALTER|CREATE|GRANT|REVOKE|MERGE|REPLACE|UPSERT|SET\s+GLOBAL|FLUSH|KILL|"
                      r"insertOne|insertMany|updateOne|updateMany|createIndex|createCollection|set\s+\w+\s+\w+|"
                      r"CONFIG\s+SET|DEBUG)\b", re.I)
PUBLISH_CMDS = {("npm", "publish"), ("yarn", "publish"), ("pnpm", "publish"), ("twine", "upload"), ("cargo", "publish"),
                ("gem", "push"), ("helm", "push"), ("oras", "push"), ("docker", "push"), ("podman", "push"),
                ("nerdctl", "push"), ("crane", "push"), ("cosign", "sign"), ("flyctl", "deploy"), ("fly", "deploy"),
                ("vercel", "deploy"), ("netlify", "deploy"), ("wrangler", "publish"), ("wrangler", "deploy")}
PKG_MANAGERS = {"apt", "apt-get", "yum", "dnf", "apk", "zypper", "pacman", "brew", "snap", "choco", "winget", "port"}
SECRET_VAR_RE = re.compile(r"\$\{?\w*(SECRET|TOKEN|PASSWORD|PASSWD|_KEY\b|APIKEY|API_KEY|CREDENTIAL|PRIVATE|CONN(ECTION)?_?STR)\w*\}?", re.I)
PROTECTED_BRANCH_RE = re.compile(r"^(main|master|trunk|develop|development|prod(uction)?|release(/.*)?|stable|live)$", re.I)
SSH_VALUE_OPTS = {"-p", "-l", "-i", "-o", "-J", "-F", "-L", "-R", "-D", "-W", "-E", "-b", "-c", "-e", "-m", "-O", "-Q",
                  "-S", "-w", "-B", "-I", "-P"}


def rm_target_class(t, cwd):
    """-> 'D' (outside the project / repo metadata / parents), 'M' (the whole project), or None (fine)."""
    raw = t.strip("'\"")
    if raw in ("/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "$HOME/*", "${HOME}", "${HOME}/", "..", "../", "../*"):
        return "D"
    if raw.startswith("$") and raw not in ("$TMPDIR", "$TMPDIR/", "${TMPDIR}"):
        return "D"  # unknown variable: could expand to anything
    p = resolve(raw.rstrip("*"), cwd)
    cwd_n = os.path.normpath(cwd)
    home_roots = [r for r in SAFE_RM_ROOTS if r.startswith(HOME + "/")]
    if raw.startswith(("..", "~", "$HOME", "${HOME}")) or raw.startswith(HOME):
        for root in home_roots:
            if p == root or p.startswith(root + "/"):
                return None
        return "D"
    if p in ("/", HOME) or p == os.path.dirname(cwd_n) or (cwd_n.startswith(p + "/") and p != cwd_n):
        return "D"
    if os.path.basename(p) == ".git" or "/.git/" in p + "/":
        return "D"
    if p == cwd_n or raw in ("*", "./*", ".", "./"):
        return "M"
    if p.startswith(cwd_n + "/"):
        return None
    for root in SAFE_RM_ROOTS:
        if p == root or p.startswith(root + "/"):
            return None
    return "D"


def analyze_rm(args, cwd):
    flags = "".join(a.lstrip("-") for a in args if a.startswith("-") and not a.startswith("--"))
    recursive = "r" in flags.lower() or "--recursive" in args
    targets = [a for a in args if not a.startswith("-") or a == "-"]
    worst_c = None
    for t in targets:
        c = rm_target_class(t, cwd)
        if c == "D":
            return Verdict("D", "rm on %s (outside the project, a parent directory, or repo metadata)" % t)
        if c == "M":
            worst_c = "M"
    if worst_c == "M" and recursive:
        return Verdict("M", "rm -r of the whole project directory")
    return None


def analyze_system(tool, args, cwd):
    pos = [a for a in args if not a.startswith("-")]
    verb = pos[0] if pos else ""
    if tool in ("shutdown", "reboot", "halt", "poweroff") or (tool == "init" and verb in ("0", "6")):
        return Verdict("D", tool + " (power state of this machine)")
    if tool.startswith("mkfs") or tool in ("fdisk", "sfdisk", "parted", "wipefs", "mkswap"):
        return Verdict("D", tool + " (disk/partition destruction)")
    if tool == "dd" and any(a.startswith("of=/dev/") for a in args):
        return Verdict("D", "dd onto a block device")
    if tool in ("iptables", "ip6tables", "nft", "ufw", "firewall-cmd"):
        if any(a in ("-F", "--flush", "flush", "reset", "--reload") for a in args) or verb in ("flush", "reset", "disable"):
            return Verdict("D", tool + " flush/reset (drops firewall rules)")
        return Verdict("M", tool)
    if tool == "crontab":
        if "-r" in args:
            return Verdict("D", "crontab -r (deletes all cron jobs)")
        if "-l" in args:
            return None
        return Verdict("M", "crontab edit")
    if tool in ("userdel", "groupdel", "chpasswd", "passwd"):
        return Verdict("D", tool)
    if tool in ("systemctl", "service", "rc-service", "launchctl"):
        action = verb
        unit = pos[1] if len(pos) > 1 else (pos[0] if tool == "service" and len(pos) > 1 else "")
        if tool == "service" and len(pos) > 1:
            unit, action = pos[0], pos[1]
        if action in ("stop", "disable", "mask", "kill", "restart", "reload", "unload", "bootout") or \
                (tool == "launchctl" and action in ("unload", "bootout", "remove", "kill")):
            if any(unit.startswith(u) for u in NODE_UNITS):
                return Verdict("D", "%s %s %s (cluster node component)" % (tool, action, unit))
            return Verdict("M", "%s %s %s" % (tool, action, unit))
        if action in ("start", "enable", "daemon-reload", "edit", "set-property", "isolate"):
            return Verdict("M", "%s %s %s" % (tool, action, unit))
        return None
    if tool in ("kill", "pkill", "killall"):
        if any(a in ("-1",) for a in args) or ("-9" in args and "-1" in args) or (tool == "killall" and not pos):
            return Verdict("D", tool + " all processes")
        return None
    if tool in ("chmod", "chown", "chgrp"):
        recursive = any(a in ("-R", "--recursive") or (a.startswith("-") and not a.startswith("--") and "R" in a) for a in args)
        targets = [a for a in pos[1:]]
        for t in targets:
            c = rm_target_class(t, cwd)
            if c == "D" and recursive:
                return Verdict("D", "%s -R outside the project" % tool)
        if tool == "chmod" and any(a in ("777", "a+rwx", "-R777") or a.endswith("777") for a in pos):
            return Verdict("M", "chmod 777")
        return None
    return None


def analyze_db(tool, args, body=""):
    text = " ".join(args) + " " + body
    if tool in ("dropdb", "dropuser"):
        return Verdict("D", tool)
    if tool in ("pg_restore", "mongorestore") and (has_flag(args, "--clean", "-c", "--drop")):
        return Verdict("D", "%s with --clean/--drop (drops objects before restore)" % tool)
    if tool == "mysqladmin" and "drop" in [a.lower() for a in args]:
        return Verdict("D", "mysqladmin drop")
    if SQL_D_RE.search(text):
        return Verdict("D", "%s: destructive SQL/command (DROP/TRUNCATE/DELETE/FLUSH)" % tool)
    if tool in ("pg_restore", "mongorestore"):
        return Verdict("M", tool + " (writes into a database)")
    if SQL_M_RE.search(text):
        return Verdict("M", "%s: statement that changes data or schema" % tool)
    if tool == "redis-cli" and any(a.upper() in ("SET", "DEL", "FLUSH", "CONFIG", "SHUTDOWN", "DEBUG", "SAVE") for a in args):
        return Verdict("D" if any(a.upper() in ("SHUTDOWN", "DEBUG") for a in args) else "M", "redis-cli write command")
    return None


def analyze_git(args, cwd, env, depth, force_remote):
    pos = [a for a in args if not a.startswith("-")]
    opts = [a for a in args if a.startswith("-")]
    verb = pos[0] if pos else ""
    if verb == "push":
        forced = any(o in ("-f", "--force", "--force-with-lease", "--force-if-includes") or o.startswith("--force") for o in opts)
        deleting = "--delete" in opts or "-d" in opts or any(p.startswith(":") for p in pos[1:])
        refs = [p for p in pos[2:]] or []
        targets = [r.split(":")[-1].lstrip("+") for r in refs if r]
        plus_force = any(r.startswith("+") for r in refs)
        if (forced or deleting or plus_force) and (any(PROTECTED_BRANCH_RE.match(t) for t in targets) or not targets):
            return Verdict("D", "git push --force/--delete to a protected or unspecified branch")
        if forced or deleting or plus_force:
            return Verdict("M", "git push --force/--delete")
        return Verdict("M", "git push (visible to others)")
    if verb in ("filter-branch", "filter-repo", "replace") or (verb == "update-ref" and "-d" in opts) or \
            (verb == "reflog" and "expire" in pos) or (verb == "gc" and any(o.startswith("--prune") for o in opts)):
        return Verdict("D", "git %s (rewrites or destroys history)" % verb)
    if verb == "reset" and any(o in ("--hard", "--merge") for o in opts):
        return Verdict("M", "git reset --hard (discards uncommitted work)")
    if verb == "clean" and any("f" in o.lstrip("-") for o in opts if not o.startswith("--")) or (verb == "clean" and "--force" in opts):
        return Verdict("M", "git clean -f (deletes untracked files)")
    if verb == "branch" and any(o in ("-D", "-d", "--delete") or (o.startswith("-") and "D" in o) for o in opts):
        return Verdict("M", "git branch -D")
    if verb == "stash" and len(pos) > 1 and pos[1] in ("drop", "clear"):
        return Verdict("M", "git stash %s" % pos[1])
    if verb in ("checkout", "restore", "switch") and ("." in pos or "--" in args and args[-1] in (".", "*")):
        return Verdict("M", "git %s . (discards working-tree changes)" % verb)
    if verb in ("rebase", "commit") and any(o in ("--amend", "-i", "--interactive") for o in opts) or verb == "rebase":
        return Verdict("M", "git %s (rewrites local history)" % verb)
    if verb in ("remote",) and len(pos) > 1 and pos[1] in ("remove", "rm", "set-url"):
        return Verdict("M", "git remote %s" % pos[1])
    if verb == "tag" and ("-d" in opts or "--delete" in opts):
        return Verdict("M", "git tag -d")
    if verb in ("commit", "merge", "cherry-pick", "revert", "am", "apply", "mv", "rm", "add", "pull", "fetch",
                "stash", "tag", "init", "clone", "worktree", "submodule", "checkout", "switch", "restore", "config"):
        return None
    return None


def analyze_gh(args):
    pos = [a for a in args if not a.startswith("-")]
    verb = pos[0] if pos else ""
    sub = pos[1] if len(pos) > 1 else ""
    if verb == "api":
        method = (flag_value(args, ["-X", "--method"]) or "GET").upper()
        if method == "DELETE":
            return Verdict("D", "gh api DELETE")
        if method in ("POST", "PUT", "PATCH") or has_flag(args, "-f", "-F", "--field", "--raw-field", "--input"):
            return Verdict("M", "gh api %s" % method)
        return None
    if (verb in ("repo", "release", "gist", "codespace", "secret", "variable", "label", "ruleset", "cache") and sub == "delete") \
            or (verb == "repo" and sub in ("archive",)):
        return Verdict("D", "gh %s %s" % (verb, sub))
    if sub in ("merge", "close", "create", "edit", "comment", "review", "set", "run", "rerun", "cancel", "enable",
               "disable", "sync", "fork", "rename", "transfer", "approve", "ready", "lock", "unlock", "reopen",
               "checkout", "upload", "dispatch", "deploy-key") or verb in ("auth",) and sub in ("login", "logout", "refresh", "setup-git"):
        return Verdict("M", "gh %s %s" % (verb, sub))
    return None


def analyze_docker(tool, args):
    pos = [a for a in args if not a.startswith("-")]
    verb = pos[0] if pos else ""
    sub = pos[1] if len(pos) > 1 else ""
    if verb == "compose" or tool in ("docker-compose", "podman-compose"):
        cverb = sub if verb == "compose" else verb
        if cverb == "down" and (has_flag(args, "-v", "--volumes") or has_flag(args, "--rmi")):
            return Verdict("M", "%s compose down -v (deletes volumes)" % tool)
        if cverb in ("down", "up", "restart", "rm", "kill", "stop", "run", "exec", "build", "push", "pull"):
            return Verdict("M", "%s compose %s" % (tool, cverb)) if cverb in ("down", "rm", "kill", "push", "run", "exec") else None
        return None
    if sub == "prune" or (verb == "system" and sub == "prune"):
        return Verdict("M", "%s %s prune" % (tool, verb))
    if verb in ("volume",) and sub in ("rm", "remove"):
        return Verdict("M", "%s volume rm" % tool)
    if verb in ("rm", "rmi", "kill", "stop", "restart", "push", "login", "logout", "context", "swarm", "service",
                "stack", "node", "secret", "config", "plugin", "run", "exec", "cp", "commit", "tag", "load", "save"):
        if verb in ("run", "exec") and has_flag(args, "--privileged"):
            return Verdict("M", "%s %s --privileged" % (tool, verb))
        if verb in ("rm", "rmi", "kill", "stop", "push", "login", "context", "swarm", "stack", "service", "node",
                    "secret", "plugin") or (verb == "run" and any(a.startswith(("-v", "--volume", "--mount")) and
                                                                  ("/:" in a or ":/host" in a) for a in args)):
            return Verdict("M", "%s %s" % (tool, verb))
    return None


def analyze_ssh(tool, args, cwd, env, depth, force_remote):
    if tool in ("scp", "sftp"):
        return Verdict("M", tool + " (copies files to/from a remote host)") if any(":" in a for a in args) else None
    if tool == "rsync":
        if any(a.startswith("--delete") for a in args) or "--remove-source-files" in args:
            return Verdict("D", "rsync --delete")
        if any(":" in a and not a.startswith("-") for a in args):
            return Verdict("M", "rsync to/from a remote host")
        return None
    # ssh [opts] [user@]host [command...]
    i, host = 0, None
    while i < len(args):
        a = args[i]
        if a in ("-G", "-V"):
            return None
        if a.startswith("-"):
            if a in SSH_VALUE_OPTS and len(a) == 2:
                i += 2
            else:
                i += 1
            continue
        host = a
        i += 1
        break
    if host is None:
        return None
    remote = args[i:]
    if remote:
        inner = shlex.join(remote) if len(remote) > 1 and any(" " in w for w in remote) else " ".join(remote)
        v = analyze_command(inner, cwd, env, depth + 1, force_remote=True)
        if v and v.cls == "D":
            return Verdict("D", "ssh %s: %s" % (host, v.reason))
        if v and v.cls == "M":
            return Verdict("M", "ssh %s: %s" % (host, v.reason))
        read_only = all(norm_tool(w) in {"uptime", "hostname", "cat", "ls", "df", "free", "ps", "top", "id", "whoami",
                                         "journalctl", "tail", "head", "grep", "systemctl", "ip", "ss", "netstat",
                                         "dmesg", "uname", "date", "echo", "true", "kubectl", "crictl", "nvidia-smi"}
                        for w in [remote[0]])
        if read_only and not any(w in ("status",) or w.startswith("-") for w in []) and \
                not (norm_tool(remote[0]) in ("systemctl", "kubectl", "crictl") and
                     any(x in remote for x in ("stop", "restart", "delete", "rm", "rmp", "stopp", "disable"))):
            return Verdict("M", "ssh %s (runs a command on a remote host)" % host)
        return Verdict("M", "ssh %s (runs a command on a remote host)" % host)
    return Verdict("M", "ssh %s (interactive remote shell)" % host)


def analyze_gcloud(tool, args):
    pos = [a.lower() for a in args if not a.startswith("-")]
    if tool == "gsutil":
        verb = pos[0] if pos else ""
        if verb in ("rm", "rb") or (verb == "rsync" and "-d" in args):
            return Verdict("D", "gsutil " + verb)
        if verb in ("cp", "mv", "rsync", "mb", "setmeta", "acl", "iam", "defacl", "lifecycle", "versioning", "web"):
            return Verdict("M", "gsutil " + verb)
        return None
    if not pos:
        return None
    joined = "gcloud " + " ".join(pos)
    if any(w in ("delete", "destroy", "purge", "stop", "suspend", "reset", "remove-iam-policy-binding", "undelete") for w in pos) \
            or any(w.startswith(("delete", "remove")) for w in pos):
        return Verdict("D" if not any(w.startswith("remove-iam") for w in pos) else "M", joined)
    if any(w in ("create", "update", "set", "add", "deploy", "apply", "enable", "disable", "start", "resize", "scale",
                 "upgrade", "rollback", "import", "attach", "detach", "login", "activate-service-account",
                 "add-iam-policy-binding", "set-iam-policy", "run", "submit", "ssh", "scp", "patch", "move", "copy",
                 "restore", "rotate", "promote", "failover") for w in pos) or any(w.startswith(("add-", "set-", "create")) for w in pos):
        return Verdict("M", joined)
    return None


def analyze_ansible(tool, args, cwd, env, depth):
    if has_flag(args, "--check", "-C"):
        return None
    if tool in ("ansible-lint", "ansible-doc", "ansible-inventory", "ansible-config", "ansible-galaxy"):
        return None
    inner = flag_value(args, ["-a", "--args"])
    if inner:
        v = analyze_command(inner, cwd, env, depth + 1, force_remote=True)
        if v and v.cls == "D":
            return Verdict("D", "ansible ad-hoc: " + v.reason)
    mod = flag_value(args, ["-m", "--module-name"]) or ""
    if mod in ("shell", "command", "raw", "script") and inner and re.search(r"\b(rm -rf|mkfs|dd |reboot|shutdown|kubeadm reset)", inner):
        return Verdict("D", "ansible %s with a destructive command" % mod)
    return Verdict("M", "%s (changes managed hosts; use --check --diff first)" % tool)


def analyze_pkg(tool, args, as_root):
    pos = [a for a in args if not a.startswith("-")]
    verb = pos[0] if pos else ""
    if tool in PKG_MANAGERS:
        if verb in ("install", "add", "upgrade", "update", "dist-upgrade", "full-upgrade", "remove", "purge", "uninstall",
                    "autoremove", "reinstall", "-S", "-Syu", "-R", "cask") or any(a in ("-S", "-Syu", "-R", "-Rns") for a in args):
            if verb in ("remove", "purge", "uninstall", "autoremove", "-R") or any(a in ("-R", "-Rns") for a in args):
                return Verdict("D" if as_root and tool != "brew" else "M", "%s %s (removes system packages)" % (tool, verb))
            return Verdict("M", "%s %s (installs system packages)" % (tool, verb))
        return None
    if tool in ("pip", "pip3", "npm", "yarn", "pnpm", "gem", "cargo", "go", "pipx", "uv"):
        glob_ = has_flag(args, "-g", "--global", "--system", "--break-system-packages") or as_root or \
            (tool == "pipx" and verb == "install") or (tool in ("uv",) and verb == "tool" and "install" in pos)
        if verb in ("install", "i", "add", "uninstall", "remove", "rm", "un") and glob_:
            return Verdict("M", "%s %s outside the project (global/system)" % (tool, verb))
    return None


def analyze_env_leak(words):
    if not words:
        return None
    tool = norm_tool(words[0])
    args = words[1:]
    if tool in ("env", "printenv") and not args:
        return Verdict("M", "%s prints every environment variable (may include secrets)" % tool)
    if tool == "set" and not args:
        return Verdict("M", "set prints the whole environment")
    if tool in ("export", "declare", "typeset") and args and args[0] in ("-p", "-x") and len(args) == 1:
        return Verdict("M", "%s -p prints exported variables" % tool)
    if tool == "printenv" and any(SECRET_VAR_RE.search("$" + a) for a in args):
        return Verdict("M", "printenv of a secret-looking variable")
    if tool in ("echo", "printf") and any(SECRET_VAR_RE.search(a) for a in args):
        return Verdict("M", "prints a secret-looking variable")
    if tool == "cat" and any(a.endswith("/environ") for a in args):
        return Verdict("M", "reads a process environment (may include secrets)")
    return None
    targets = [a for a in args if not a.startswith("-")]
    bad = {"/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "$HOME/*", "${HOME}", "${HOME}/", HOME, HOME + "/"}
    for t in targets:
        if t in bad:
            return Verdict("D", "rm -r on %s" % t)
    return None


# ------------------------------------------------------------ dispatcher ---
KIRO_PROTECTED = [os.path.join(HOME, p) for p in (".kiro/hooks", ".kiro/settings", ".kiro/workspace-roots", ".kiro/lib",
                                                  ".local/bin/kiro-safe", ".local/bin/kiro-run", ".local/bin/kiro-doctor")]
CRED_DIRS = [os.path.join(HOME, p) for p in (".kube", ".azure", ".azure-kiro", ".aws", ".aws-kiro")]
KIRO_READ_OK = {"cat", "less", "more", "head", "tail", "grep", "rg", "ls", "stat", "jq", "yq", "diff", "wc",
                "file", "bat", "sha256sum", "shasum", "md5sum", "readlink", "realpath", "test", "[", "echo",
                "printf", "tree", "du"}
CRED_OK = {"ls", "stat", "test", "[", "echo", "printf", "export", "kubectl", "oc", "k", "kubecolor", "helm",
           "az", "azd", "kubelogin", "kubectx", "kubens", "flux", "argocd", "kustomize", "terraform", "tofu",
           "aws", "eksctl", "cdk", "sam", "copilot", "aws-vault", "granted", "assume", "saml2aws", "aws-sso-util",
           "terragrunt", "file", "du", "tree"}
GIT_SAFE = {"add", "status", "diff", "log", "show", "commit", "blame"}
DESTRUCTIVE_WORDS = {"delete", "drain", "destroy", "purge", "uninstall", "deallocate", "remove", "wipe",
                     "down", "replace", "reset", "revoke", "stop", "rm"}
REDIRECT_RE = re.compile(r"^\d*(<<<|<<|>>|>\||&>>|&>|>&|<&|>|<)$")
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
DECODE_RE = re.compile(r"base64\s+(-d|--decode|-D)|xxd\s+-r|openssl\s+(enc|base64)|gunzip|zcat|uudecode")
INTERPRETERS = PYTHONS | {"node", "ruby", "perl", "deno", "bun"}
PLACEHOLDER = "__KIRO_SUBST__"


def norm_tool(tok):
    b = os.path.basename(tok.rstrip("/")).lower()
    if b.endswith(".exe"):
        b = b[:-4]
    b2 = re.sub(r"[._-]?v?\d+(?:\.\d+)*$", "", b)
    return b2 or b


def subst(word, shell_vars, env):
    def rep(m):
        name = m.group(1) or m.group(2)
        if SECRET_VAR_RE.search("$" + name):
            return m.group(0)  # never pull secret values into the analysis or the log
        if name in shell_vars:
            return shell_vars[name]
        if name in env:
            return env[name]
        return m.group(0)
    return re.sub(r"\$\{(\w+)\}|\$(\w+)", rep, word)


def resolve(tok, cwd, base=None):
    t = tok
    if t.startswith("-") and "=" in t:
        t = t.split("=", 1)[1]
    if t.startswith("~"):
        t = HOME + t[1:]
    t = t.replace("${HOME}", HOME).replace("$HOME", HOME)
    if not t.startswith("/"):
        t = os.path.join(base or cwd, t)
    t = os.path.normpath(t)
    try:
        if os.path.lexists(t):
            t = os.path.realpath(t)
    except OSError:
        pass
    return t


def path_class(p):
    for d in KIRO_PROTECTED:
        if p == d or p.startswith(d + "/"):
            return "kiro"
    if "/.kiro/hooks/" in p + "/":
        return "kiro"
    for d in CRED_DIRS:
        if p == d or p.startswith(d + "/"):
            return "cred"
    return None


def split_redirects(words):
    """-> (plain words, redirect targets [(op, target)], here-string content or None)"""
    plain, redirs, herestr = [], [], None
    i = 0
    while i < len(words):
        w = words[i]
        if REDIRECT_RE.match(w):
            tgt = words[i + 1] if i + 1 < len(words) else ""
            if w.endswith("<<<"):
                herestr = tgt
            else:
                redirs.append((w, tgt))
            i += 2
            continue
        plain.append(w)
        i += 1
    return plain, redirs, herestr


def protected_access(tool, args, redirs, cwd):
    base = None
    if tool == "tar":
        d = flag_value(args, ["-C", "--directory"])
        base = resolve(d, cwd) if d else None
    classes = set()
    for a in args:
        c = path_class(resolve(a, cwd, base))
        if c:
            classes.add(c)
        if base and a.split("/")[0] in (".kube", ".azure", ".azure-kiro", ".kiro"):
            c = path_class(resolve(a, cwd, base))
            if c:
                classes.add(c)
    for op, tgt in redirs:
        if ">" in op and path_class(resolve(tgt, cwd)):
            return Verdict("D", "writing to Kiro guard, Kiro settings or cloud credential files")
    if "kiro" in classes:
        ok = tool in KIRO_READ_OK or (tool == "git" and args and args[0] in GIT_SAFE) or \
            (tool == "find" and not any(a in ("-delete", "-exec", "-execdir", "-ok") for a in args))
        if not ok:
            return Verdict("D", "changing Kiro guard or Kiro settings files")
    if "cred" in classes and tool not in CRED_OK:
        return Verdict("D", "reading or copying cloud credential files (~/.kube, ~/.azure)")
    return None


def created_here(path, raw):
    """True if this same command line also writes the file it later runs."""
    name = re.escape(os.path.basename(path))
    return bool(re.search(r"(>>?|tee\s+(-a\s+)?|-o\s*|--output[=\s]+|cp\s+\S+\s+|mv\s+\S+\s+)\s*['\"]?\S*" + name, raw))


def run_script(path, cwd, env, depth, force_remote, raw, kind):
    text = read_script(path, cwd)
    # written by this same command line: what is on disk now is not what will run
    here = raw_scan(raw) if created_here(path, raw) else None
    if text is None:
        return here
    if kind == "shell" and depth < 3:
        return worst([analyze_text(text, cwd, env, depth, force_remote), here])
    return worst([code_scan(text), here])


def analyze_segment(seg, cwd, env, depth, force_remote, raw, shell_vars=None):
    shell_vars = {} if shell_vars is None else shell_vars
    env = dict(env)
    leak = analyze_env_leak(list(seg))
    if leak:
        return leak
    words = [subst(w, shell_vars, env) for w in seg]
    # assignment-only segment (C=kubectl) or export/declare: remember for later segments
    if words and all(ASSIGN_RE.match(w) for w in words):
        for w in words:
            k, v = w.split("=", 1)
            shell_vars[k] = v
        return None
    if words and words[0] in ("export", "declare", "typeset", "local", "readonly"):
        for w in words[1:]:
            if ASSIGN_RE.match(w):
                k, v = w.split("=", 1)
                shell_vars[k] = v
        return None
    # strip leading VAR=value assignments (and remember KUBECONFIG etc.)
    while words and ASSIGN_RE.match(words[0]):
        k, v = words.pop(0).split("=", 1)
        env[k] = v
    # strip wrappers
    changed = True
    as_root = False
    while words and changed:
        changed = False
        w = norm_tool(words[0])
        if w in ("sudo", "doas"):
            as_root = True
        if w in WRAPPERS_NOARG:
            words.pop(0)
            changed = True
        elif w == "env" and any(a == "-S" or a.startswith(("-S", "--split-string")) for a in words[1:]):
            for i, a in enumerate(words[1:], 1):
                if a in ("-S", "--split-string") and i + 1 < len(words):
                    return analyze_command(" ".join(words[i + 1:]), cwd, env, depth + 1, force_remote)
                if a.startswith("--split-string="):
                    return analyze_command(a.split("=", 1)[1] + " " + " ".join(words[i + 1:]), cwd, env,
                                           depth + 1, force_remote)
                if a.startswith("-S"):
                    return analyze_command(a[2:] + " " + " ".join(words[i + 1:]), cwd, env, depth + 1,
                                           force_remote)
        elif w in WRAPPERS_FLAGVALUE:
            vf = WRAPPERS_FLAGVALUE[w]
            words.pop(0)
            while words and (words[0].startswith("-") or ASSIGN_RE.match(words[0])
                             or (w in ("timeout", "gtimeout") and re.match(r"^\d+[smhd]?$", words[0]))):
                f = words.pop(0)
                if "=" in f and not f.startswith("-"):
                    k, v = f.split("=", 1)
                    env[k] = v
                elif f in vf and words:
                    words.pop(0)
            changed = True
    if not words:
        return None
    words, redirs, herestr = split_redirects(words)
    if not words:
        return None
    tool = norm_tool(words[0])
    args = words[1:]

    pv = protected_access(tool, args, redirs, cwd)
    if pv:
        return pv

    # command name built at runtime: $(...), `...`, unresolved $VAR
    if words[0].startswith(("$", "`")) or PLACEHOLDER in words[0]:
        if any(a.lower().strip("'\"") in DESTRUCTIVE_WORDS for a in args):
            return Verdict("D", "command name built at runtime together with a destructive verb")
        return None
    stdin_file = next((t for op, t in redirs if op.endswith("<") and not op.endswith("<<")), None)

    if tool in SHELLS:
        for i, a in enumerate(args):
            if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", a) and i + 1 < len(args):
                return redirect("%s -c (inline shell program)" % tool,
                                analyze_command(args[i + 1], cwd, env, depth + 1, force_remote), depth)
        script = next((a for a in args if not a.startswith("-")), None)
        if script and PLACEHOLDER not in script:
            return run_script(script, cwd, env, depth, force_remote, raw, "shell")
        if herestr is not None:
            return redirect("%s with a here-string program" % tool,
                            analyze_command(herestr, cwd, env, depth + 1, force_remote) or raw_scan(herestr), depth)
        if stdin_file:
            return run_script(stdin_file, cwd, env, depth, force_remote, raw, "shell")
        # reading commands from a heredoc / pipe / process substitution: inspect everything we can see
        v = raw_scan(raw)
        if v:
            return v
        if DECODE_RE.search(raw):
            return Verdict("D", "decoded or decompressed content piped into a shell (cannot be inspected)")
        if PIPE_TO_SHELL_RE.search(raw):
            return None  # download piped into a shell: already classified M (ask) by analyze_command
        return redirect("%s reading a program from stdin" % tool, None, depth)
    if tool == "kiro-run":
        opts, rest, i = [], [], 0
        while i < len(args):                      # options come before the program file; the rest are its args
            a = args[i]
            if a == "--more":                     # prints a saved part of an earlier run's output: nothing runs
                return None
            if a in ("--timeout", "--lines") and i + 1 < len(args):
                i += 2
                continue
            if a == "--":
                rest = args[i + 1:]
                break
            if not a.startswith("-"):
                rest = args[i:]
                break
            opts.append(a)
            i += 1
        script = rest[0] if rest else None
        kind = "shell" if "--bash" in opts or (script or "").endswith((".sh", ".bash")) else "code"

        def from_file(path):
            text = read_script(path, cwd)
            here = raw_scan(raw) if created_here(path, raw) else None
            if text is None:
                return here
            return worst([program_scan(text, kind, cwd, env, depth, force_remote), here])
        if script:
            # a saved tool may run whatever its arguments say, so they are analysed as a command too
            tail = analyze_command(" ".join(shlex.quote(a) for a in rest[1:]), cwd, env, depth + 1, force_remote) \
                if len(rest) > 1 else None
            return worst([from_file(script), in_program(tail)])
        if herestr is not None:
            return program_scan(herestr, kind, cwd, env, depth, force_remote)
        if stdin_file:
            return from_file(stdin_file)
        v = raw_scan(raw)
        if v:
            return v
        if DECODE_RE.search(raw):
            return Verdict("D", "decoded content piped into kiro-run (cannot be inspected)")
        return None
    if tool in ("source", ".") and args:
        return run_script(args[0], cwd, env, depth, force_remote, raw, "shell")
    if tool == "eval":
        return analyze_command(" ".join(args), cwd, env, depth + 1, force_remote)
    if tool in INTERPRETERS:
        for flag in ("-c", "-e", "--eval", "-p", "--print"):
            if flag in args:
                i = args.index(flag)
                if i + 1 < len(args):
                    return redirect("%s %s (inline program)" % (tool, flag), code_scan(args[i + 1]), depth)
        script = next((a for a in args if not a.startswith("-")), None)
        if "-m" in args:
            script = None
        if script:
            return run_script(script, cwd, env, depth, force_remote, raw, "code")
        if herestr is not None:
            return redirect("%s with a here-string program" % tool, code_scan(herestr), depth)
        if stdin_file:
            return run_script(stdin_file, cwd, env, depth, force_remote, raw, "code")
        if "-m" in args:
            return None
        return redirect("%s reading a program from stdin" % tool, raw_scan(raw), depth)
    if tool in PWSH:
        for i, a in enumerate(args):
            la = a.lower()
            if la in ("-encodedcommand", "-enc", "-e", "-ec"):
                return Verdict("D", "PowerShell -EncodedCommand (cannot be inspected)")
            if la in ("-c", "-command") and i + 1 < len(args):
                return code_scan(" ".join(args[i + 1:]))
            if la in ("-f", "-file") and i + 1 < len(args):
                return run_script(args[i + 1], cwd, env, depth, force_remote, raw, "code")
        return None
    if tool in ("xargs", "watch", "parallel"):
        return analyze_segment(args, cwd, env, depth + 1, force_remote, raw, shell_vars) if args else None
    if tool == "find":
        for i, a in enumerate(args):
            if a in ("-exec", "-execdir", "-ok", "-okdir"):
                inner = []
                for b in args[i + 1:]:
                    if b in (";", "+", "\\;"):
                        break
                    inner.append(b)
                if inner:
                    return analyze_segment(inner, cwd, env, depth + 1, force_remote, raw, shell_vars)
        return None
    if tool not in KNOWN_TOOLS and (tool.endswith((".sh", ".bash")) or words[0].startswith(("./", "../", "~/"))):
        v = run_script(words[0], cwd, env, depth, force_remote, raw, "shell")
        if v:
            return v
    if tool in DB_TOOLS and stdin_file:
        text = read_script(stdin_file, cwd) or ""
        dv = analyze_db(tool, args, text)
        if dv:
            return dv
        return Verdict("M", "%s < file (runs SQL from a file)" % tool)
    if (tool, (args[0] if args else "")) in PUBLISH_CMDS or (tool in ("fly", "flyctl", "vercel", "netlify", "wrangler") and args):
        v = Verdict("M", "%s %s (publishes to a registry or service)" % (tool, args[0] if args else ""))
    elif tool in KUBE_TOOLS:
        v = analyze_kube(tool, args, env)
    elif tool == "helm":
        v = analyze_helm(args, env)
    elif tool == "az":
        v = analyze_az(args, env, cwd, depth)
    elif tool == "aws":
        v = analyze_aws(args)
    elif tool in TF_TOOLS:
        v = analyze_tf(tool, args)
    elif tool in ("curl", "wget", "http", "https", "xh"):
        v = analyze_http(tool, args)
    elif tool == "rm":
        v = analyze_rm(args, cwd)
    elif tool in DB_TOOLS:
        v = analyze_db(tool, args)
    elif tool == "git":
        v = analyze_git(args, cwd, env, depth, force_remote)
    elif tool == "gh":
        v = analyze_gh(args)
    elif tool in ("docker", "podman", "nerdctl", "docker-compose", "podman-compose"):
        v = analyze_docker(tool, args)
    elif tool in ("ssh", "scp", "sftp", "rsync"):
        v = analyze_ssh(tool, args, cwd, env, depth, force_remote)
    elif tool in ("gcloud", "gsutil"):
        v = analyze_gcloud(tool, args)
    elif tool.startswith("ansible"):
        v = analyze_ansible(tool, args, cwd, env, depth)
    elif tool in SYSTEM_D or tool in ("systemctl", "service", "rc-service", "launchctl", "dd", "init", "kill", "pkill",
                                      "killall", "chmod", "chown", "chgrp") or tool.startswith("mkfs"):
        v = analyze_system(tool, args, cwd)
    elif tool in PKG_MANAGERS or tool in ("pip", "pip3", "npm", "yarn", "pnpm", "gem", "cargo", "go", "pipx", "uv"):
        v = analyze_pkg(tool, args, as_root)
    elif tool in ("vagrant", "multipass", "limactl", "colima", "minikube", "kind", "k3d") and args and \
            args[0] in ("destroy", "delete", "down", "rm", "stop", "halt"):
        v = Verdict("M", "%s %s (local VM/cluster)" % (tool, args[0]))
    else:
        v = analyze_simple(tool, args)
    if v is None and as_root and tool not in KIRO_READ_OK:
        v = Verdict("M", "runs as root: " + tool)
    if v and force_remote and v.k8s is not None:
        v.k8s = dict(v.k8s, server="remote (inside az aks command invoke)")
    return v


# ------------------------------------------------- kiro-run programs ---
# kiro-run is allowed without a prompt (permissions.yaml), so the permission layer never sees what a
# program does. Everything it would have asked about has to be caught here instead. Secrets are not a
# reason to stop a program: kiro-run masks their values in everything a program prints.
STR_LIT = r"""(?:[rRbBuU]|[fF][rR]?|[rR][fF])?("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')"""
STR_LIT_RE = re.compile(STR_LIT)
EXEC_CALL_RE = re.compile(r"(?<![\w])(?:[\w.]*\.)?(?:system|popen|run|call|check_output|check_call|Popen|getoutput|"
                          r"getstatusoutput|execSync|exec|spawnSync|spawn|execFileSync|execFile|sh|shell)\s*\(\s*" + STR_LIT)
LIST_START_RE = re.compile(r"\[\s*" + STR_LIT)
CODE_CMD_TOOLS = KNOWN_TOOLS | DB_TOOLS | PKG_MANAGERS | SHELLS | {
    "git", "gh", "docker", "podman", "nerdctl", "docker-compose", "ssh", "scp", "sftp", "rsync", "sudo", "doas",
    "npm", "yarn", "pnpm", "pip", "pip3", "pipx", "twine", "cargo", "gem", "systemctl", "service", "crontab",
    "gcloud", "gsutil", "ansible", "ansible-playbook", "env", "printenv", "chmod", "chown", "kill", "pkill",
    "killall", "dd", "iptables", "fly", "flyctl", "vercel", "netlify", "wrangler", "vagrant", "minikube", "kind", "k3d"}
TRIVIAL_CMDS = {"cd", "pushd", "popd", "echo", "printf", "true", ":", "set", "export", "unset", "sleep", "wait",
                "source", ".", "umask", "shopt", "alias", "local", "declare", "readonly", "typeset", "exit",
                "return", "test", "["}
LOOP_WORDS = {"for", "while", "until", "if", "case", "select", "function"}


def _literal(tok):
    """Value of a string-literal token ('...' or "...", any prefix); f-string fields become placeholders."""
    m = STR_LIT_RE.fullmatch(tok.strip())
    if not m:
        return None
    val = m.group(1)[1:-1].replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
    if tok.strip()[:2].lower().strip("rb").startswith("f"):
        val = re.sub(r"\{[^{}]*\}", PLACEHOLDER, val)
    return val


def _list_items(text, start):
    """Items of the list literal that opens at text[start] ('['): literal values, PLACEHOLDER for the rest."""
    items, cur, depth, quote, i = [], "", 0, "", start + 1
    end = min(len(text), start + 1500)
    while i < end:
        c = text[i]
        if quote:
            cur += c
            if c == "\\" and i + 1 < end:
                cur += text[i + 1]
                i += 1
            elif c == quote:
                quote = ""
        elif c in "'\"":
            quote, cur = c, cur + c
        elif c in "([{":
            depth, cur = depth + 1, cur + c
        elif c in ")}" or (c == "]" and depth):
            depth, cur = depth - 1, cur + c
        elif c == "]":
            break
        elif c == "," and depth == 0:
            items.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    if cur.strip():
        items.append(cur)
    out = []
    for it in items:
        val = _literal(it)
        if val is None:                     # an expression: keep its literal parts ('-chdir=' + d -> -chdir=<subst>)
            parts = [_literal(m.group(0)) or "" for m in STR_LIT_RE.finditer(it)]
            val = "".join(parts) + PLACEHOLDER if any(parts) else PLACEHOLDER
        out.append(val)
    return out


def _argv_verdict(words, cwd, env, depth, force_remote):
    """Analyse an argv twice: as written, and without the parts only known at run time."""
    known = [w for w in words if w != PLACEHOLDER]
    return worst([analyze_command(" ".join(shlex.quote(w) for w in ws), cwd, env, depth + 1, force_remote)
                  for ws in (words, known) if len(ws) >= 2])


def code_cmd_scan(text, cwd, env, depth, force_remote):
    """Commands a Python/JS program starts: argv lists (["git", "push"]) and strings handed to an
    exec-style call (os.system("..."), subprocess.run("..."), kt.sh("...")). Each one goes through
    the same analysis as a command typed in the shell."""
    verdicts = []
    for m in LIST_START_RE.finditer(text):
        first = _literal(m.group(0)[1:])
        if not first or " " in first.strip() or norm_tool(first) not in CODE_CMD_TOOLS:
            continue
        verdicts.append(_argv_verdict(_list_items(text, m.start()), cwd, env, depth, force_remote))
    for m in EXEC_CALL_RE.finditer(text):
        cmd = _literal(m.group(0)[m.group(0).index("(") + 1:])
        if not cmd:
            continue
        rest = text[m.end():m.end() + 1500]
        if " " not in cmd.strip() and norm_tool(cmd) in CODE_CMD_TOOLS and re.match(r"\s*,\s*\[", rest):
            words = [cmd] + _list_items(rest, rest.index("["))      # spawn("kubectl", ["delete", ...])
            verdicts.append(_argv_verdict(words, cwd, env, depth, force_remote))
        else:
            verdicts.append(analyze_command(cmd, cwd, env, depth + 1, force_remote))
    return worst(verdicts)


def in_program(v):
    """Nothing inside a kiro-run program can ask the user, so a mutating step (M) is refused there."""
    if v is not None and v.cls == "M":
        return Verdict("A", v.reason, v.k8s)
    return v


def program_scan(text, kind, cwd, env, depth, force_remote):
    """Verdict for the body of a kiro-run program (kind 'shell' or 'code')."""
    if kind == "shell":
        v = analyze_text(text, cwd, env, depth, force_remote)
    else:
        v = worst([code_scan(text), code_cmd_scan(text, cwd, env, depth, force_remote)])
    return in_program(v)


# ---- which clouds does a program use? (kiro-run asks this before it runs one) ----
CLOUD_TOOLS = {
    "k8s": KUBE_TOOLS | {"helm", "kubectx", "kubens", "k9s", "flux", "argocd", "velero", "istioctl", "linkerd",
                         "kubeadm", "stern", "kubelogin", "kustomize"},
    "azure": {"az", "azd", "azcopy"},
    "aws": {"aws", "eksctl", "cdk", "sam", "copilot", "kops", "aws-nuke", "aws-vault"},
}
# Subcommands that only work on local files and never contact a cluster or an account.
LOCAL_ONLY = {
    "helm": {"lint", "template", "package", "show", "create", "version", "env", "completion", "dependency", "dep",
             "help", "plugin", "repo", "search"},
    "kubectl": {"kustomize", "completion", "help"},
    "kustomize": {"build", "version", "help"},
    "az": {"bicep", "version", "help"},
    "aws": {"help"},
}
SDK_USE = (
    ("k8s", re.compile(r"^\s*(?:import|from)\s+kubernetes\b|load_kube_config|load_incluster_config|kubernetes\.client|"
                       r"@kubernetes/client-node|\.azmk8s\.io|kubernetes\.default\.svc", re.M)),
    ("azure", re.compile(r"^\s*(?:import|from)\s+(?:azure|msrestazure)\b|DefaultAzureCredential|AzureCliCredential|"
                         r"ClientSecretCredential|require\(['\"]@azure/|management\.azure\.com|vault\.azure\.net|"
                         r"graph\.microsoft\.com", re.M)),
    ("aws", re.compile(r"^\s*(?:import|from)\s+(?:boto3|botocore|aiobotocore)\b|\bboto3\.|@aws-sdk/|\.amazonaws\.com", re.M)),
)
SPAWNS_RE = re.compile(r"\b(subprocess|os\.system|os\.popen|os\.exec\w*|os\.spawn\w*|Popen|check_output|check_call|"
                       r"getoutput|pty\.spawn|child_process|execSync|spawnSync)\b|\bkt\.sh\b|\bsh\(")
CLOUD_ENV = {"k8s": ("KUBECONFIG", "kiro-readonly"), "azure": ("AZURE_CONFIG_DIR", "kiro"), "aws": ("AWS_CONFIG_FILE", "kiro")}


def _command_word(seg):
    """The words of a segment from its command name on: assignments and wrappers (sudo, env, xargs,
    timeout, `do`, `then` ...) stripped. Also returns the values assigned on the way (K=kubectl)."""
    words, assigned = list(seg), []
    changed = True
    while words and changed:
        changed = False
        if ASSIGN_RE.match(words[0]):
            assigned.append(words.pop(0).split("=", 1)[1])
            changed = True
            continue
        w = norm_tool(words[0])
        if w in WRAPPERS_NOARG:
            words.pop(0)
            changed = True
        elif w in WRAPPERS_FLAGVALUE:
            vf = WRAPPERS_FLAGVALUE[w]
            words.pop(0)
            while words and (words[0].startswith("-") or ASSIGN_RE.match(words[0])
                             or (w in ("timeout", "gtimeout") and re.match(r"^\d+[smhd]?$", words[0]))):
                f = words.pop(0)
                if f in vf and words:
                    words.pop(0)
            changed = True
    return words, assigned


def _cloud_of(words):
    """{cloud: evidence} for one command (its words from the command name on)."""
    if not words or words[0].endswith("/"):
        return {}
    tool = norm_tool(words[0])
    args = [a for a in words[1:] if not REDIRECT_RE.match(a)]
    pos = [a for a in args if not a.startswith("-")]
    for cloud, tools in CLOUD_TOOLS.items():
        if tool in tools:
            local = LOCAL_ONLY.get(tool, ())
            if (pos and pos[0] in local or not pos and any(a in ("--version", "--help", "-h", "version") for a in args)) \
                    and not any(a.startswith(("--validate", "--kube-", "--dry-run=server")) for a in args):
                return {}
            return {cloud: " ".join(words[:6])}
    return {}


def cloud_use(text, kind="shell", cwd=".", depth=0):
    """Clouds whose CLI or SDK a program really uses -> {"k8s" | "azure" | "aws": the command or call seen}.
    A word such as `helm` in a path, a comment or a search pattern is not use."""
    used = {}
    if depth > 4:
        return used
    if kind == "code":
        for cloud, rx in SDK_USE:
            m = rx.search(text)
            if m:
                used.setdefault(cloud, m.group(0).strip()[:60])
        if SPAWNS_RE.search(text):                      # only a program that starts processes can run a CLI
            for m in STR_LIT_RE.finditer(text):
                val = _literal(m.group(0))
                if val and len(val) < 4000:
                    for cloud, ev in cloud_use(val, "shell", cwd, depth + 1).items():
                        used.setdefault(cloud, ev)
        return used
    stripped, docs = split_heredocs(text)
    for header, body in docs:
        hsegs = tokenize(replace_subshells(header)[0]) or []
        target = next((sg for sg in hsegs if any(t.startswith("<<") for t in sg)), hsegs[0] if hsegs else [])
        words, _ = _command_word(target)
        t = norm_tool(words[0]) if words else ""
        if t in SHELLS or t in ("source", ".", "eval") or (t == "kiro-run" and "--bash" in target):
            inner = cloud_use(body, "shell", cwd, depth + 1)
        elif t in INTERPRETERS or t == "kiro-run":
            inner = cloud_use(body, "code", cwd, depth + 1)
        else:
            inner = {}
        for cloud, ev in inner.items():
            used.setdefault(cloud, ev)
    flat, inners = replace_subshells(stripped)
    for _, inner in inners:
        for cloud, ev in cloud_use(inner, "shell", cwd, depth + 1).items():
            used.setdefault(cloud, ev)
    for seg in tokenize(flat.replace("\\;", " ")) or []:
        words, assigned = _command_word(seg)
        for val in assigned:                            # K=kubectl; $K get pods
            for cloud, ev in _cloud_of([val]).items():
                used.setdefault(cloud, ev)
        if not words:
            continue
        for cloud, ev in _cloud_of(words).items():
            used.setdefault(cloud, ev)
        tool, args = norm_tool(words[0]), words[1:]
        nested = None
        if tool in SHELLS or tool in INTERPRETERS:
            for flag in ("-c", "-e", "--eval"):
                if flag in args and args.index(flag) + 1 < len(args):
                    nested = (args[args.index(flag) + 1], "shell" if tool in SHELLS else "code")
            script = next((a for a in args if not a.startswith("-")), None)
            if nested is None and script and "-m" not in args:
                body = read_script(script, cwd)
                if body is not None:
                    nested = (body, "shell" if tool in SHELLS or script.endswith((".sh", ".bash")) else "code")
        elif tool in ("find",):
            for i, a in enumerate(args):
                if a in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(args):
                    for cloud, ev in _cloud_of(args[i + 1:]).items():
                        used.setdefault(cloud, ev)
        elif tool == "eval":
            nested = (" ".join(args), "shell")
        elif tool.endswith((".sh", ".bash")) or words[0].startswith(("./", "../", "~/")):
            body = read_script(words[0], cwd)
            if body is not None:
                nested = (body, "shell")
        if nested:
            for cloud, ev in cloud_use(nested[0], nested[1], cwd, depth + 1).items():
                used.setdefault(cloud, ev)
    return used


def kiro_run_would_refuse(text, env, cwd="."):
    """True when kiro-run would refuse a program made of this text: it really uses a cloud CLI/SDK and
    the read-only credentials for that cloud are not active."""
    if env.get("KIRO_RUN_ALLOW_ADMIN") == "1":
        return False
    return any(CLOUD_ENV[c][1] not in env.get(CLOUD_ENV[c][0], "") for c in cloud_use(text, "shell", cwd))


def compound(cmd):
    """Short description when a command line is a multi-command shell program (two or more real
    commands, or a loop/conditional/group), else None. Pipes don't count; neither do `cd`, `echo`
    separators, assignments, `export`, or a trailing `|| true`."""
    stripped, _ = split_heredocs(cmd)
    flat, _ = replace_subshells(stripped)
    flat = flat.replace("\\;", " __KIRO_SEMI__ ").replace("\r", " ").replace("\n", " ; ")
    lex = shlex.shlex(flat, posix=True, punctuation_chars=";&|()<>")
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        toks = list(lex)
    except ValueError:
        return None
    statements, cur = [], []
    for t in toks:
        if t in (";", "&&", "||", "&", ";;"):
            statements.append(cur)
            cur = []
        else:
            cur.append(t)
    statements.append(cur)
    real = 0
    for st in statements:
        words = list(st)
        while words and ASSIGN_RE.match(words[0]):
            words.pop(0)
        if not words:
            real += 1 if any(PLACEHOLDER in w for w in st) else 0      # VAR=$(command)
            continue
        if words[0] in LOOP_WORDS or words[0] in ("(", "{", "[["):
            return "a shell loop, conditional or group"
        if words[0].startswith("#") or norm_tool(words[0]) in TRIVIAL_CMDS:
            continue
        real += 1
    return "a line of %d commands" % real if real >= 2 else None


def redirect(what, inner_v, depth):
    """Code-mode enforcement: inline programs at the top level must go through kiro-run."""
    if inner_v is not None and inner_v.cls in ("D", "R", "A"):
        return inner_v
    if CONF["CODE_MODE"] in ("enforce", "inline") and depth == 0:
        return Verdict("R", what)
    return inner_v


def analyze_text(text, cwd, env, depth, force_remote):
    if depth >= 3:
        return raw_scan(text)
    v = analyze_command(text, cwd, env, depth + 1, force_remote)
    return v or raw_scan(text)


RANK = {"D": 0, "A": 1, "R": 2, "M": 3}


def worst(verdicts):
    vs = [v for v in verdicts if v]
    if not vs:
        return None
    return sorted(vs, key=lambda v: RANK.get(v.cls, 3))[0]


PIPE_TO_SHELL_RE = re.compile(r"\b(curl|wget|iwr|Invoke-WebRequest|fetch)\b[^|;&\n]*\|\s*(sudo\s+(-\S+\s+)*)?"
                              r"(bash|sh|zsh|dash|ksh|python3?|node|pwsh|powershell|perl|ruby)\b")
FORK_BOMB_RE = re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")
HEREDOC_RE = re.compile(r"(?<!<)<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")


def split_heredocs(cmd):
    """Remove here-document bodies. -> (command without bodies, [(header line, body)])"""
    lines = cmd.split("\n")
    out, docs, i = [], [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        for m in HEREDOC_RE.finditer(line):
            strip_tabs, delim = m.group(1) == "-", m.group(3)
            body = []
            while i < len(lines):
                cur = lines[i].lstrip("\t") if strip_tabs else lines[i]
                i += 1
                if cur.strip() == delim:
                    break
                body.append(lines[i - 1])
            docs.append((line, "\n".join(body)))
    return "\n".join(out), docs


def replace_subshells(cmd):
    """Replace $(...), `...`, <(...), >(...) with a placeholder.
    -> (new command, [(kind, inner)]) where kind is 'cmd' (output used as text) or 'proc'"""
    out, inners, i, n = [], [], 0, len(cmd)
    in_single = False
    while i < n:
        c = cmd[i]
        if c == "'" and not in_single:
            j = cmd.find("'", i + 1)
            if j < 0:
                out.append(cmd[i:])
                break
            out.append(cmd[i:j + 1])
            i = j + 1
            continue
        if c == "`":
            j = cmd.find("`", i + 1)
            if j < 0:
                out.append(cmd[i:])
                break
            inners.append(("cmd", cmd[i + 1:j]))
            out.append(PLACEHOLDER)
            i = j + 1
            continue
        if c in "$<>" and i + 1 < n and cmd[i + 1] == "(" and not (c == "$" and i + 2 < n and cmd[i + 2] == "("):
            depth, j = 1, i + 2
            while j < n and depth:
                if cmd[j] == "(":
                    depth += 1
                elif cmd[j] == ")":
                    depth -= 1
                j += 1
            inners.append(("cmd" if c == "$" else "proc", cmd[i + 2:j - 1]))
            out.append(PLACEHOLDER)
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out), inners


def analyze_command(cmd, cwd, env, depth=0, force_remote=False):
    if depth > 4:
        return raw_scan(cmd)
    verdicts = []
    stripped, docs = split_heredocs(cmd)
    for header, body in docs:
        hsegs = tokenize(replace_subshells(header)[0]) or []
        target = next((s for s in hsegs if any(t.startswith("<<") for t in s)), hsegs[0] if hsegs else [])
        first = next((w for w in target if not ASSIGN_RE.match(w) and norm_tool(w) not in
                      (WRAPPERS_NOARG | set(WRAPPERS_FLAGVALUE))), "")
        t = norm_tool(first) if first else ""
        if t == "kiro-run":
            verdicts.append(program_scan(body, "shell" if "--bash" in target else "code", cwd, env, depth, force_remote))
        elif t in SHELLS or t in ("source", ".", "ssh", "eval") or t in KUBE_TOOLS and "exec" in target:
            verdicts.append(analyze_text(body, cwd, env, depth, force_remote))
        elif t in INTERPRETERS or t in PWSH:
            verdicts.append(code_scan(body))
        elif t in DB_TOOLS:
            verdicts.append(analyze_db(t, [], body))
        # anything else (cat > file, tee, kubectl apply -f -) receives the body as data
    if PIPE_TO_SHELL_RE.search(stripped):
        verdicts.append(Verdict("M", "runs code downloaded from the internet (download piped into a shell)"))
    if FORK_BOMB_RE.search(stripped):
        verdicts.append(Verdict("D", "fork bomb"))
    flat, inners = replace_subshells(stripped)
    for kind, inner in inners:
        verdicts.append(analyze_command(inner, cwd, env, depth + 1, force_remote))
        if kind == "proc":
            verdicts.append(raw_scan(inner))
    segs = tokenize(flat)
    if segs is None:
        verdicts.append(raw_scan(stripped))
        return worst(verdicts)
    shell_vars = {}
    for seg in segs:
        verdicts.append(analyze_segment(seg, cwd, env, depth, force_remote, cmd, shell_vars))
    v = worst(verdicts)
    # code mode: a multi-command line typed straight into the shell tool is a program. Lines kiro-run
    # would refuse (cloud CLI without read-only credentials) stay direct, where the permission prompt covers them.
    if depth == 0 and CONF["CODE_MODE"] == "enforce" and (v is None or v.cls == "M"):
        what = compound(cmd)
        if what and not kiro_run_would_refuse(cmd, env, cwd):
            return Verdict("R", "compound:" + what)
    return v


# ------------------------------------------------------ secrets in reads ---
# kiro-run masks secret values in everything a program prints. The built-in read and search tools, and
# a direct `cat` or `grep`, would hand the same values to the model as they are. Such a call is sent
# through kiro-run instead (kt.show / kt.read / kt.grep, or the same command), where the masking
# applies: the read still happens, the value never reaches the conversation.
READ_TOOLS = {"read_file", "read_code", "fs_read", "read_multiple_files"}
SEARCH_TOOLS = {"grep_search"}
READER_CMDS = {"cat", "head", "tail", "less", "more", "bat", "batcat", "nl", "tac", "sed", "awk", "gawk", "cut", "sort",
               "uniq", "jq", "yq", "xmllint", "strings", "base64", "xxd", "od", "hexdump", "diff", "paste", "column",
               "fold", "rev", "expand", "pr"}
SEARCH_CMDS = {"grep", "egrep", "fgrep", "rg", "ag", "ack"}
GREP_VALUE_FLAGS = {"-e", "--regexp", "-f", "--file", "-m", "--max-count", "-A", "-B", "-C", "--context", "--include",
                    "--exclude", "--exclude-dir", "-g", "--glob", "-t", "--type", "-T", "--type-not", "-d", "-D",
                    "--color", "--colour", "-j", "--threads", "--max-depth"}
_LIBS = []


def secret_libs():
    """(kt, kiro_redact) from the pack's lib folder (~/.kiro/lib once installed), or None: without
    them reads are not checked."""
    if not _LIBS:
        lib = os.environ.get("KIRO_LIB") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "lib")
        try:
            if lib not in sys.path:
                sys.path.insert(0, lib)
            import kiro_redact
            import kt
            _LIBS.append((kt, kiro_redact))
        except Exception:
            _LIBS.append(None)
    return _LIBS[0]


def secrets_in_lines(lines, cwd):
    """[(index, [kinds])] for the lines kiro-run would mask."""
    kt, red = secret_libs()
    return red.scan(lines, known=kt.secret_values(cwd), secret_lines=kt.secret_lines(cwd))


def secrets_in_file(path, cwd, first=None, count=None):
    """(kinds, line numbers) of the secret values a read of this file (or of `count` lines from line
    index `first`) would show; ([], []) when there are none or the file cannot be checked."""
    if not secret_libs():
        return [], []
    kt = secret_libs()[0]
    full = resolve(path, cwd)
    try:
        if not os.path.isfile(full) or os.path.getsize(full) > 1_000_000:
            return [], []
    except OSError:
        return [], []
    lines = kt._read(full)
    if lines is None:
        return [], []
    if kt.secret(full, cwd):
        return ["a secrets file"], []
    lo, hi = 0, len(lines)
    if first or count:                                    # a line or two of margin on either side
        lo = max(0, int(first or 0) - 1)
        hi = min(len(lines), int(first or 0) + int(count or len(lines)) + 1)
    hits = [(i + lo, ks) for i, ks in secrets_in_lines(lines[lo:hi], cwd)]
    kinds = []
    for _, ks in hits:
        kinds += [k for k in ks if k not in kinds]
    return kinds, [i + 1 for i, _ in hits]


def _line_ranges(nums):
    out, start, prev = [], None, None
    for n in sorted(set(nums)) + [None]:
        if start is None:
            start = prev = n
        elif n is not None and n == prev + 1:
            prev = n
        else:
            out.append("%d" % start if start == prev else "%d-%d" % (start, prev))
            start = prev = n
    return ", ".join(out[:6]) + (" ..." if len(out) > 6 else "")


def _search_regex(query, ignore_case=False, fixed=False, basic=False):
    if fixed:
        query = re.escape(query)
    elif basic:                                          # grep without -E: \| \( \+ are operators, | ( + are text
        out, i = [], 0
        while i < len(query):
            c = query[i]
            if c == "\\" and i + 1 < len(query):
                out.append(query[i + 1] if query[i + 1] in "|(){}+?" else query[i:i + 2])
                i += 2
            else:
                out.append("\\" + c if c in "|(){}+?" else c)
                i += 1
        query = "".join(out)
    try:
        return re.compile(query, re.I if ignore_case else 0)
    except re.error:
        return re.compile(re.escape(query), re.I if ignore_case else 0)


def search_hits_secret(rx, names, cwd, context=2, budget_s=4.0):
    """(path, line number, kinds) of the first match whose line or context holds a secret value."""
    kt = secret_libs()[0]
    deadline = time.time() + budget_s
    for n in names:
        if time.time() > deadline:
            return None                                  # a huge tree: checked as far as the time allows
        lines = kt._read(os.path.join(cwd, n))
        if lines is None:
            continue
        for i, ln in enumerate(lines):
            if not rx.search(ln):
                continue
            lo = max(0, i - context)
            hits = secrets_in_lines(lines[lo:i + context + 1], cwd)
            if hits:
                kinds = []
                for _, ks in hits:
                    kinds += [k for k in ks if k not in kinds]
                return n, hits[0][0] + lo + 1, kinds
    return None


def read_tool_secrets(tool, ti, cwd):
    """Message when a built-in read or search would return secret values, else None."""
    if CONF["SECRET_READS"] != "mask" or not secret_libs():
        return None
    kt = secret_libs()[0]
    if tool in READ_TOOLS:
        for p in collect_paths(ti) + [ti[k] for k in ("filePath", "file_path", "relativePath") if isinstance(ti.get(k), str)]:
            first, count = ti.get("offset"), ti.get("limit")
            first = first if isinstance(first, int) else None
            count = count if isinstance(count, int) and count > 0 else None
            kinds, nums = secrets_in_file(p, cwd, first, count)
            if not kinds:
                continue
            where = " on line%s %s" % ("" if len(nums) == 1 else "s", _line_ranges(nums)) if nums else ""
            if first or count:
                call = "kt.show(%r, %d, %d)" % (p, (first or 0) + 1, (first or 0) + (count or 400))
            else:
                call = "kt.read(%r)" % p
            return ("kiro-guard: %s holds secret values%s (%s), and the read tool would put them into the "
                    "conversation. Read it masked instead: the same lines and line numbers, values replaced by "
                    "[redacted].\nkiro-run <<'EOF'\nimport kt\n%s\nEOF\nNothing was read. Only this file is "
                    "affected: files without secrets are read as usual." % (p, where, ", ".join(kinds[:3]), call))
    if tool in SEARCH_TOOLS and isinstance(ti.get("query"), str) and ti["query"]:
        rx = _search_regex(ti["query"], ignore_case=ti.get("caseSensitive") is not True)
        include, exclude = ti.get("includePattern") or "**/*", ti.get("excludePattern")
        names = kt.files(include, cwd)
        if exclude:
            ex = kt._glob_re(exclude)
            names = [n for n in names if not ex.match(n)]
        hit = search_hits_secret(rx, names, cwd)
        if hit:
            extra = ", ignore_case=True" if ti.get("caseSensitive") is not True else ""
            return ("kiro-guard: this search would return lines that hold secret values (%s:%d: %s). Run it masked "
                    "instead: the same matches, values replaced by [redacted].\nkiro-run <<'EOF'\nimport kt\n"
                    "kt.grep(%r, %r, ctx=2%s)\nEOF\nNothing was searched. Searches that touch no secret run as usual."
                    % (hit[0], hit[1], ", ".join(hit[2][:3]), ti["query"], include, extra))
    return None


def command_reads_secrets(cmd, cwd):
    """Message when a direct shell command (cat, head, grep ...) would print secret values, else None."""
    if CONF["SECRET_READS"] != "mask" or not secret_libs():
        return None
    kt = secret_libs()[0]
    stripped, _ = split_heredocs(cmd)
    flat, _ = replace_subshells(stripped)
    found = None
    for seg in tokenize(flat) or []:
        words, _, _ = split_redirects(seg)
        while words and (ASSIGN_RE.match(words[0]) or norm_tool(words[0]) in WRAPPERS_NOARG or words[0] == "sudo"):
            words.pop(0)
        if not words:
            continue
        tool, args = norm_tool(words[0]), words[1:]
        if tool == "kiro-run":
            return None                                  # its output is masked
        if tool in READER_CMDS:
            for a in args:
                if a.startswith("-"):
                    continue
                kinds, nums = secrets_in_file(a, cwd)
                if kinds:
                    found = found or (a, kinds)
        elif tool in SEARCH_CMDS:
            flags = [a for a in args if a.startswith("-") and not a.startswith("--")]
            letters = "".join(f[1:] for f in flags)
            pattern = flag_value(args, ["-e", "--regexp"])
            pos = positional(args, GREP_VALUE_FLAGS)
            if pattern is None and pos:
                pattern, pos = pos[0], pos[1:]
            if not pattern:
                continue
            names = []
            for a in pos:
                full = resolve(a, cwd)
                if os.path.isfile(full):
                    names.append(os.path.relpath(full, cwd))
                elif os.path.isdir(full):
                    rel = os.path.relpath(full, cwd)
                    names += kt.files("**/*" if rel == "." else rel.rstrip("/") + "/**", cwd)
            if not pos and (tool in ("rg", "ag", "ack") or "r" in letters or "R" in letters or has_flag(args, "--recursive")):
                names = kt.files("**/*", cwd)
            rx = _search_regex(pattern, ignore_case="i" in letters or has_flag(args, "--ignore-case"),
                               fixed=tool == "fgrep" or "F" in letters or has_flag(args, "--fixed-strings"),
                               basic=tool == "grep" and not ("E" in letters or "P" in letters))
            ctx = 0
            for name in ("-C", "--context", "-A", "-B"):
                value = flag_value(args, [name])
                if value and value.isdigit():
                    ctx = max(ctx, min(int(value), 10))
            hit = search_hits_secret(rx, names, cwd, context=ctx)
            if hit:
                found = found or ("%s:%d" % (hit[0], hit[1]), hit[2])
    if not found:
        return None
    return ("kiro-guard: this command would print secret values (%s: %s) into the conversation. Run the same "
            "command through kiro-run, which masks them:\nkiro-run --bash <<'EOF'\n%s\nEOF\nNothing was executed."
            % (found[0], ", ".join(found[1][:3]), cmd.strip()))


# ---------------------------------------------------- context resolution ---
def kube_is_local(k8s):
    if not k8s:
        return False
    if k8s.get("server"):
        return False
    ctx = k8s.get("context")
    if not ctx:
        env = dict(os.environ)
        if k8s.get("kubeconfig"):
            env["KUBECONFIG"] = os.path.expanduser(k8s["kubeconfig"])
        try:
            out = subprocess.run(["kubectl", "config", "current-context"], capture_output=True,
                                 text=True, timeout=3, env=env)
            ctx = out.stdout.strip() if out.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            ctx = ""
    k8s["resolved_context"] = ctx or "unknown"
    return bool(ctx) and bool(LOCAL_RE.match(ctx))


def must_see(what):
    """Kiro shows the user nothing of a hook's message (the tool call reads "Tool execution failed"), so a
    real block has the agent report it. A `-` line in a diff block is the only red text a reply can show."""
    return ("\nThe user cannot see this message. End your reply with this block (it shows red):\n"
            "```diff\n- BLOCKED by kiro-guard: %s (not run)\n```" % what)


def decide(v):
    """Return (block: bool, message)."""
    if v is None:
        return False, ""
    if v.k8s is not None and kube_is_local(v.k8s):
        return False, "local context " + v.k8s.get("resolved_context", "")
    target = ""
    if v.k8s is not None:
        target = " on context '%s'" % v.k8s.get("resolved_context", v.k8s.get("context") or "unknown")
    if v.cls == "R" and v.reason.startswith("compound:"):
        return True, ("kiro-guard: %s is a program, and programs go through kiro-run: no approval prompt, capped "
                      "output, logged. Re-issue it as:\nkiro-run --bash <<'EOF'\n<the same commands, one per line>\n"
                      "EOF\nLeave out any step that changes shared state or needs approval (push, apply, deploy, "
                      "install, ssh) and issue that one alone as a direct command. Nothing was executed."
                      % v.reason[len("compound:"):])
    if v.cls == "R":
        return True, ("kiro-guard: %s is not run directly — inline programs go through kiro-run so they are "
                      "saved, output-capped, logged and credential-checked. Re-issue the same program as:\n"
                      "kiro-run <<'EOF'\n<program>\nEOF\n(add --bash for a shell program; run files with "
                      "`kiro-run file.py`). Nothing was executed." % v.reason)
    if v.cls == "A":
        return True, ("kiro-guard: this kiro-run program contains a step that needs the user's approval: %s%s. "
                      "A program cannot ask for it. Take that step out and issue it alone as a direct command "
                      "(the user is then prompted); keep the read-only work in kiro-run. Nothing was executed."
                      % (v.reason, target))
    if v.cls == "D":
        return True, ("BLOCKED by kiro-guard: %s%s. This is a deliberate stop: do not retry, rephrase, script "
                      "or call the API another way. Show the user the exact command and what it will change so "
                      "they can run it themselves." % (v.reason, target)) + must_see(v.reason + target)
    if v.cls == "M" and CONF["GUARD_MODE"] == "readonly":
        return True, ("BLOCKED by kiro-guard (read-only mode): %s%s changes infrastructure. Do not work around "
                      "this. Give the user the exact command to run themselves." % (v.reason, target)
                      ) + must_see("%s%s, read-only mode" % (v.reason, target))
    return False, ""


def log(decision, tool, cmd, why):
    try:
        os.makedirs(os.path.dirname(CONF["LOG_FILE"]), exist_ok=True)
        with open(CONF["LOG_FILE"], "a", encoding="utf-8") as fh:
            fh.write("%s\t%s\t%s\t%s\t%s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), decision, tool,
                                                why, cmd.replace("\n", "\\n")[:400]))
    except OSError:
        pass


# ------------------------------------------------------------------ main ---
def collect_paths(ti):
    paths = []
    for k in ("path", "targetFile", "sourcePath", "destinationPath"):
        if isinstance(ti.get(k), str):
            paths.append(ti[k])
    for op in ti.get("operations") or []:
        if isinstance(op, dict) and isinstance(op.get("path"), str):
            paths.append(op["path"])
    return paths


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--cloud-use":
        # kiro-run asks which clouds a program uses: one line per cloud, "<cloud>\t<command or call seen>"
        kind = sys.argv[2] if len(sys.argv) > 2 else "shell"
        for cloud, ev in sorted(cloud_use(sys.stdin.read(), kind, os.getcwd()).items()):
            sys.stdout.write("%s\t%s\n" % (cloud, ev.replace("\n", " ")))
        return 0
    raw = sys.stdin.read()
    if CONF["GUARD_MODE"] == "off":
        return 0
    try:
        data = json.loads(raw) if raw.strip() else {}
    except ValueError:
        sys.stderr.write("kiro-guard: unreadable hook payload; blocking to be safe.\n")
        return 2
    tool = str(data.get("tool_name") or data.get("toolName") or "")
    ti = data.get("tool_input") or data.get("toolInput") or {}
    if isinstance(ti, str):
        try:
            ti = json.loads(ti)
        except ValueError:
            ti = {"command": ti}
    if not isinstance(ti, dict):
        ti = {}
    cwd = ti.get("cwd") or data.get("cwd") or os.getcwd()
    tl = tool.lower()

    # 1. writes to guard / settings / credential files
    if tl in WRITE_TOOLS:
        for p in collect_paths(ti):
            if path_class(resolve(p, cwd)):
                msg = ("BLOCKED by kiro-guard: writing %s is not allowed (Kiro guard, settings or cloud "
                       "credentials). Ask the user to make this change." % p) + must_see("writing %s" % p)
                log("BLOCK", tool, p, "protected path")
                sys.stderr.write(msg + "\n")
                return 2

    # 1b. built-in reads and searches that would show a secret value: sent to the masked path
    if tl in READ_TOOLS or tl in SEARCH_TOOLS:
        try:
            msg = read_tool_secrets(tl, ti, cwd)
        except Exception:
            msg = None                  # this check is a safety net; it never stops a read by failing
        if msg:
            log("REDIRECT", tool, json.dumps(ti)[:400], "would show secret values")
            sys.stderr.write(msg + "\n")
            return 2
        return 0

    # 2. shell commands (any tool that carries a command string)
    cmd = ti.get("command") or ti.get("cmd") or ti.get("script")
    if isinstance(cmd, list):
        cmd = " ".join(shlex.quote(str(c)) for c in cmd)
    if isinstance(cmd, str) and cmd.strip():
        v = analyze_command(cmd, cwd, dict(os.environ))
        block, msg = decide(v)
        if v is not None:
            log("REDIRECT" if v.cls == "R" else ("BLOCK" if block else "allow"), tool, cmd, v.reason)
        if block:
            sys.stderr.write(msg + "\n")
            return 2
        try:
            msg = command_reads_secrets(cmd, cwd)
        except Exception:
            msg = None
        if msg:
            log("REDIRECT", tool, cmd, "would print secret values")
            sys.stderr.write(msg + "\n")
            return 2
        return 0

    # 3. MCP / third-party tools with destructive names (e.g. resources_delete, aks_cluster_delete)
    if tl and tl not in BUILTIN_TOOLS and MCP_D_NAME.search(tool) and MCP_INFRA_NAME.search(tool):
        msg = ("BLOCKED by kiro-guard: tool '%s' looks destructive. Do not work around this; tell the user "
               "what you wanted to do so they can do it themselves." % tool) + must_see("tool '%s'" % tool)
        log("BLOCK", tool, json.dumps(ti)[:400], "destructive MCP tool name")
        sys.stderr.write(msg + "\n")
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # fail closed
        sys.stderr.write("kiro-guard: internal error (%s); blocking to be safe.\n" % exc.__class__.__name__)
        sys.exit(2)
