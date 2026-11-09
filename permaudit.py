#!/usr/bin/env python3
"""permaudit - audit file permissions for risky settings.

Read-only. Reports world-writable files and directories, SUID/SGID files,
private keys and .env files that other users can read, and loose ~/.ssh dirs.
Standard library only. Exit code 0 = clean, 1 = findings, 2 = error.
"""
import argparse
import fnmatch
import json
import os
import shlex
import stat
import sys

__version__ = "1.1.1"

PRIVATE_KEY_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
SKIP_DIRS = {".git", "node_modules", "__pycache__"}
SECRET_FILE_NAMES = {".netrc", ".pgpass", ".git-credentials", ".htpasswd", ".npmrc", ".pypirc", ".my.cnf",
                     "credentials.json", "service-account.json"}
# rule -> (chmod argument, explanation). Suggestions only: permaudit never changes a mode itself.
FIXES = {
    "world-writable-file": ("o-w", "remove write access for others"),
    "world-writable-dir": ("o-w", "remove write access for others (or add the sticky bit with +t for shared dirs)"),
    "loose-private-key": ("600", "owner-only"),
    "loose-ssh-dir": ("700", "owner-only"),
    "readable-env-file": ("600", "owner-only"),
    "loose-secret-file": ("600", "owner-only"),
    "suid": ("u-s", "drop the setuid bit after confirming the file does not need it"),
    "sgid": ("g-s", "drop the setgid bit after confirming the file does not need it"),
}


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
    if name in SECRET_FILE_NAMES and mode & 0o077:
        out.append(("MEDIUM", "loose-secret-file",
                    "credentials file readable/writable by others (%04o), want 0600" % mode))
    if is_env_file(name) and mode & 0o044:
        out.append(("MEDIUM", "readable-env-file",
                    ".env file readable by group/others (%04o), want 0600" % mode))
    return out


def excluded(path, patterns):
    norm = path.replace(os.sep, "/")
    return any(fnmatch.fnmatch(norm, p) or fnmatch.fnmatch(os.path.basename(norm), p) for p in patterns)


def audit(root, exclude=()):
    """Yield (path, severity, rule, message) for everything under root."""
    entries = [root]
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not excluded(os.path.join(dirpath, d), exclude))
        entries += [os.path.join(dirpath, n) for n in dirs + sorted(files)]
    for path in entries:
        if path != root and excluded(path, exclude):
            continue
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            continue
        for sev, rule, msg in check_entry(path, st):
            yield path, sev, rule, msg


def safe_quote(path):
    """Shell-quote ``path``. A name with a newline or other control character could split a pasted command into two,
    so such names get a harmless placeholder instead."""
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        return "'FILE-NAME-HAS-CONTROL-CHARACTERS'"
    return shlex.quote(path)


def fix_command(path, rule):
    """Shell-quoted chmod suggestion for a finding, or None."""
    if rule not in FIXES:
        return None
    return "chmod %s %s" % (FIXES[rule][0], safe_quote(path))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit file permissions (read-only).")
    ap.add_argument("paths", nargs="*", default=["."], help="directories to audit")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="skip paths matching this glob or base name (repeatable)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--show-fix", action="store_true",
                    help="print the chmod command that would fix each finding (never runs it)")
    ap.add_argument("--min-severity", choices=("MEDIUM", "HIGH"), default="MEDIUM")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    bad = [p for p in args.paths if not os.path.isdir(p)]
    if bad:
        print("permaudit: not a directory: %s" % bad[0], file=sys.stderr)
        return 2
    results = []
    for root in args.paths:
        for path, sev, rule, msg in audit(root, args.exclude):
            if args.min_severity == "HIGH" and sev != "HIGH":
                continue
            results.append({"severity": sev, "rule": rule, "path": path, "message": msg,
                            "fix": fix_command(path, rule)})
    count = len(results)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print("%-6s %-20s %s: %s" % (r["severity"], r["rule"], r["path"], r["message"]))
            if args.show_fix and r["fix"]:
                print("         fix: %s" % r["fix"])
    print("permaudit: %d finding(s)" % count, file=sys.stderr)
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
