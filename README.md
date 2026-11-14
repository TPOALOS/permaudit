# permaudit

Read-only file permission auditor. Walks directories and flags risky settings.
Standard library only; it never changes any permissions (it only suggests the target mode).

## Checks

| Rule | Severity | Meaning |
|------|----------|---------|
| `world-writable-file` | HIGH | any user can modify the file |
| `world-writable-dir` | HIGH | world-writable directory without the sticky bit |
| `loose-private-key` | HIGH | `id_*`, `*.pem`, `*.key` accessible by group/others (want `0600`) |
| `loose-ssh-dir` | HIGH | `.ssh` directory accessible by group/others (want `0700`) |
| `readable-env-file` | MEDIUM | `.env` readable by group/others (want `0600`) |
| `loose-secret-file` | MEDIUM | `.netrc`, `.pgpass`, `.git-credentials`, `.htpasswd`, `.npmrc`, `.pypirc`, `.my.cnf`, `credentials.json` accessible by group/others (want `0600`) |
| `suid` / `sgid` | MEDIUM | setuid/setgid bit set |

`.env.example`, `.env.sample` and `*.pub` files are ignored. Symlinks are not followed.

## Usage

```bash
python3 permaudit.py ~/projects ~/.ssh
python3 permaudit.py --min-severity HIGH /srv/app
python3 permaudit.py ~/projects --exclude vendor --exclude '*.generated'
python3 permaudit.py ~/.ssh --show-fix        # prints chmod commands, never runs them
python3 permaudit.py /srv/app --json
# or: pip install git+https://github.com/TPOALOS/permaudit && permaudit ~/projects
```

Example with `--show-fix`:

```
HIGH   loose-private-key    /home/me/.ssh/id_ed25519: private key readable/writable by others (0644), want 0600
         fix: chmod 600 /home/me/.ssh/id_ed25519
```

Suggested commands are shell-quoted, so paths with spaces or `$(...)` stay inert if you paste them.

Exit codes: `0` clean, `1` findings, `2` bad path.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS

---

**More tools by [TPOALOS](https://github.com/TPOALOS):** [headercheck](https://github.com/TPOALOS/headercheck) · [jwtlint](https://github.com/TPOALOS/jwtlint) · [mailtriage](https://github.com/TPOALOS/mailtriage) · [all 51 tools](https://tpoalos.github.io)
