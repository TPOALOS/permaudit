#!/usr/bin/env python3
"""permaudit - audit file permissions for risky settings.

Read-only. Reports world-writable files and directories, SUID/SGID files,
private keys and .env files that other users can read, and loose ~/.ssh dirs.
Standard library only. Exit code 0 = clean, 1 = findings, 2 = error.
"""
import argparse
import os
import stat
import sys

__version__ = "1.0.0"

PRIVATE_KEY_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
SKIP_DIRS = {".git", "node_modules", "__pycache__"}


def is_private_key(name):
    return name.startswith(PRIVATE_KEY_NAMES) and not name.endswith(".pub") \
        or name.endswith((".pem", ".key")) and not name.endswith(".pub")


def is_env_file(name):
    return name == ".env" or name.startswith(".env.") and not name.endswith(
        (".example", ".sample", ".template"))


def check_entry(path, st):
    """Return a list of (severity, rule, message) for one filesystem entry."""
    mode = stat.S_IMODE(st.st_mode)
    name = os.path.basename(path)
    out = []
    if stat.S_ISDIR(st.st_mode):
        if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
            out.append(("HIGH", "world-writable-dir",
                        "directory is world-writable without sticky bit (%04o)" % mode))
        if name == ".ssh" and mode & 0o077:
            out.append(("HIGH", "loose-ssh-dir",
                        ".ssh directory accessible by others (%04o), want 0700" % mode))
        return out
    if not stat.S_ISREG(st.st_mode):
        return out
    if mode & stat.S_IWOTH:
        out.append(("HIGH", "world-writable-file", "file is world-writable (%04o)" % mode))
    if mode & stat.S_ISUID:
        out.append(("MEDIUM", "suid", "SUID bit set (%04o)" % mode))
    if mode & stat.S_ISGID:
        out.append(("MEDIUM", "sgid", "SGID bit set (%04o)" % mode))
    if is_private_key(name) and mode & 0o077:
        out.append(("HIGH", "loose-private-key",
                    "private key readable/writable by others (%04o), want 0600" % mode))
    if is_env_file(name) and mode & 0o044:
        out.append(("MEDIUM", "readable-env-file",
                    ".env file readable by group/others (%04o), want 0600" % mode))
    return out


def audit(root):
    """Yield (path, severity, rule, message) for everything under root."""
    entries = [root]
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        entries += [os.path.join(dirpath, n) for n in dirs + sorted(files)]
    for path in entries:
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            continue
        for sev, rule, msg in check_entry(path, st):
            yield path, sev, rule, msg


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit file permissions (read-only).")
    ap.add_argument("paths", nargs="*", default=["."], help="directories to audit")
    ap.add_argument("--min-severity", choices=("MEDIUM", "HIGH"), default="MEDIUM")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    bad = [p for p in args.paths if not os.path.isdir(p)]
    if bad:
        print("permaudit: not a directory: %s" % bad[0], file=sys.stderr)
        return 2
    count = 0
    for root in args.paths:
        for path, sev, rule, msg in audit(root):
            if args.min_severity == "HIGH" and sev != "HIGH":
                continue
            count += 1
            print("%-6s %-20s %s: %s" % (sev, rule, path, msg))
    print("permaudit: %d finding(s)" % count, file=sys.stderr)
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
