#!/usr/bin/env python3
"""kiro_sandbox: the bubblewrap arguments and the seccomp filter kiro-run uses for RUN_SANDBOX.

  kiro_sandbox.py bpf                       write the seccomp filter (cBPF) to stdout; exit 2 on an
                                            architecture it does not know (the sandbox is then unusable)
  kiro_sandbox.py args ROOT SCRATCH NET PROG LIB [CRED...]
                                            print the bubblewrap arguments, NUL-separated, for a program
                                            run from the current folder. NET is deny or allow; CRED are
                                            the read-only credential paths to keep visible (only when
                                            the program's cloud commands passed kiro-run's check).

What a program sees: the system and $HOME read-only; the project (ROOT) and its .kiro/scratch writable;
ROOT/.git and ROOT/.kiro read-only; toolchain caches writable; credential folders and files empty (also
where a symlink points, and in the Windows profiles on WSL); a
private /tmp; its own pid, ipc and uts namespaces; with NET=deny no network namespace of the host and no
socket() or connect() at all, so host Unix sockets (docker.sock, ssh-agent) are out of reach too (a
read-only root and a new network namespace alone still leave pathname sockets reachable).
"""
import glob
import os
import platform
import struct
import sys

# seccomp: socket(), connect() and io_uring_setup() fail with EPERM; a foreign architecture or an x32
# syscall kills the process. socketpair() stays (asyncio and multiprocessing use it).
ARCH = {  # machine: (AUDIT_ARCH_*, socket, connect, io_uring_setup, x32 bit)
    "x86_64": (0xC000003E, 41, 42, 425, 0x40000000),
    "amd64": (0xC000003E, 41, 42, 425, 0x40000000),
    "aarch64": (0xC00000B7, 198, 203, 425, None),
    "arm64": (0xC00000B7, 198, 203, 425, None),
}
LD_ABS_W, JEQ, JGE, RET = 0x20, 0x15, 0x35, 0x06
KILL, ERRNO_EPERM, ALLOW = 0x80000000, 0x00050000 | 1, 0x7FFF0000

HIDE_DIRS = (".ssh", ".aws", ".azure", ".kube", ".docker", ".gnupg", ".config/gcloud", ".config/gh",
             ".aws-kiro", ".azure-kiro", ".password-store", ".config/op", ".oci")
HIDE_FILES = (".netrc", ".git-credentials", ".npmrc", ".pypirc", ".vault-token", ".pgpass", ".my.cnf",
              ".terraform.d/credentials.tfrc.json", ".config/hub")
CACHES = (".cache", "go", ".cargo", ".npm", ".m2", ".gradle", ".terraform.d/plugin-cache")


def bpf():
    arch = ARCH.get(platform.machine().lower())
    if not arch:
        return None
    audit, sock, conn, uring, x32 = arch
    prog = [(LD_ABS_W, 0, 0, 4),               # A = arch
            (JEQ, 1, 0, audit),
            (RET, 0, 0, KILL),
            (LD_ABS_W, 0, 0, 0)]               # A = syscall number
    if x32 is not None:
        prog += [(JGE, 0, 1, x32), (RET, 0, 0, KILL)]
    prog += [(JEQ, 3, 0, sock),
             (JEQ, 2, 0, conn),
             (JEQ, 1, 0, uring),
             (RET, 0, 0, ALLOW),
             (RET, 0, 0, ERRNO_EPERM)]
    return b"".join(struct.pack("<HBBI", *ins) for ins in prog)


def under(path, top):
    return path == top or path.startswith(top.rstrip("/") + "/")


def profiles(home):
    """$HOME, and on WSL the Windows user profiles: /mnt/c/Users/<name> holds its own .ssh, .aws, .azure and
    .kube, readable from Linux like any other folder."""
    out = [home]
    for users in sorted(glob.glob("/mnt/?/Users")):
        try:
            names = sorted(os.listdir(users))
        except OSError:
            continue
        out += [os.path.join(users, n) for n in names
                if n not in ("Public", "Default", "Default User", "All Users") and os.path.isdir(os.path.join(users, n))]
    return out


def args(root, scratch, net, prog, lib, creds):
    home = os.path.realpath(os.path.expanduser("~"))
    root, scratch, cwd = os.path.realpath(root), os.path.realpath(scratch), os.path.realpath(os.getcwd())
    out = ["--ro-bind", "/", "/", "--tmpfs", "/tmp"]          # /tmp first: a project may live under it
    if root not in (home, "/"):                               # never make all of $HOME writable
        out += ["--bind", root, root]
    for d in dict.fromkeys((root, cwd)):
        if os.path.exists(os.path.join(d, ".git")):
            out += ["--ro-bind", os.path.join(d, ".git"), os.path.join(d, ".git")]
        if os.path.isdir(os.path.join(d, ".kiro")):
            out += ["--ro-bind", os.path.join(d, ".kiro"), os.path.join(d, ".kiro")]
    out += ["--bind", scratch, scratch]
    for c in CACHES:
        p = os.path.join(home, c)
        if os.path.isdir(p) and not os.path.islink(p):
            out += ["--bind", p, p]
    # credentials are covered where they really are: a dotfile is often a symlink (into a dotfiles repo, or
    # on WSL into the Windows profile), and bubblewrap cannot mount over the link itself
    hidden = set()
    for base in profiles(home):
        for d in HIDE_DIRS:
            p = os.path.realpath(os.path.join(base, d))
            if os.path.isdir(p) and p not in hidden:
                hidden.add(p)
                out += ["--tmpfs", p]
        for f in HIDE_FILES:
            p = os.path.realpath(os.path.join(base, f))
            if os.path.isfile(p) and p not in hidden:
                hidden.add(p)
                out += ["--ro-bind", "/dev/null", p]
    run_user = "/run/user/%d" % os.getuid()                   # ssh-agent, gpg-agent, dbus, podman sockets
    if os.path.isdir(run_user):
        out += ["--tmpfs", run_user]
    for sock in ("/run/docker.sock", "/run/podman/podman.sock"):
        if os.path.exists(sock) and os.path.realpath(sock) == sock:
            out += ["--ro-bind", "/dev/null", sock]
    for c in creds:                                           # the active read-only credentials
        if not c or not os.path.exists(c):
            continue
        c = os.path.realpath(c)
        out += ["--bind" if os.path.isdir(c) else "--ro-bind", c, c]
    for p in (lib, prog):                                     # visible even when they sit under /tmp
        p = os.path.realpath(p)
        if os.path.exists(p) and not under(p, scratch) and not (root not in (home, "/") and under(p, root)):
            out += ["--ro-bind", p, p]
    out += ["--dev", "/dev", "--proc", "/proc", "--unshare-all"]
    if net == "allow":
        out += ["--share-net"]
    out += ["--die-with-parent", "--new-session", "--unsetenv", "SSH_AUTH_SOCK", "--unsetenv", "DOCKER_HOST",
            "--unsetenv", "GPG_AGENT_INFO", "--chdir", cwd]
    return out


def main(argv):
    if len(argv) == 2 and argv[1] == "bpf":
        code = bpf()
        if code is None:
            sys.stderr.write("kiro_sandbox: no seccomp filter for %s\n" % platform.machine())
            return 2
        sys.stdout.buffer.write(code)
        return 0
    if len(argv) >= 7 and argv[1] == "args":
        root, scratch, net, prog, lib = argv[2:7]
        sys.stdout.write("\0".join(args(root, scratch, net, prog, lib, argv[7:])) + "\0")
        return 0
    sys.stderr.write(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
