# Changelog

## 1.1.1

- Suggested `chmod` commands no longer contain file names with newlines or other control characters (such a name could
  split a pasted command into two); a harmless placeholder is shown instead

## 1.1.0

- New rule `loose-secret-file` (.netrc, .pgpass, .git-credentials, .htpasswd, .npmrc, .pypirc, ...)
- `--show-fix` prints shell-quoted chmod suggestions (never runs them)
- `--exclude GLOB` (repeatable) and `--json` output
- Installable with pip (`permaudit` command), CI on Linux and macOS

## 1.0.0

Initial release.
