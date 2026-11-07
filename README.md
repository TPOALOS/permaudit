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
| `suid` / `sgid` | MEDIUM | setuid/setgid bit set |

`.env.example`, `.env.sample` and `*.pub` files are ignored. Symlinks are not followed.

## Usage

```bash
python3 permaudit.py ~/projects ~/.ssh
python3 permaudit.py --min-severity HIGH /srv/app
```

Exit codes: `0` clean, `1` findings, `2` bad path.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
