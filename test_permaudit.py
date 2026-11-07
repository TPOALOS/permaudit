import contextlib
import io
import json
import os
import stat
import tempfile
import unittest

import permaudit


def touch(root, rel, mode):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write("x")
    os.chmod(p, mode)
    return p


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def rules(self):
        return {(os.path.relpath(p, self.root), r) for p, _, r, _ in permaudit.audit(self.root)}

    def test_clean(self):
        touch(self.root, "ok.txt", 0o644)
        self.assertEqual(self.rules(), set())

    def test_world_writable_file(self):
        touch(self.root, "w.txt", 0o666)
        self.assertIn(("w.txt", "world-writable-file"), self.rules())

    def test_world_writable_dir_sticky_ok(self):
        d = os.path.join(self.root, "tmpdir")
        os.mkdir(d)
        os.chmod(d, 0o1777)
        self.assertNotIn(("tmpdir", "world-writable-dir"), self.rules())
        os.chmod(d, 0o777)
        self.assertIn(("tmpdir", "world-writable-dir"), self.rules())

    def test_suid(self):
        touch(self.root, "s", 0o4755)
        self.assertIn(("s", "suid"), self.rules())

    def test_private_key(self):
        touch(self.root, "id_ed25519", 0o644)
        touch(self.root, "id_ed25519.pub", 0o644)
        r = self.rules()
        self.assertIn(("id_ed25519", "loose-private-key"), r)
        self.assertNotIn(("id_ed25519.pub", "loose-private-key"), r)
        os.chmod(os.path.join(self.root, "id_ed25519"), 0o600)
        self.assertNotIn(("id_ed25519", "loose-private-key"), self.rules())

    def test_env_file(self):
        touch(self.root, ".env", 0o644)
        touch(self.root, ".env.example", 0o644)
        r = self.rules()
        self.assertIn((".env", "readable-env-file"), r)
        self.assertNotIn((".env.example", "readable-env-file"), r)

    def test_ssh_dir(self):
        d = os.path.join(self.root, ".ssh")
        os.mkdir(d)
        os.chmod(d, 0o755)
        self.assertIn((".ssh", "loose-ssh-dir"), self.rules())
        os.chmod(d, 0o700)
        self.assertNotIn((".ssh", "loose-ssh-dir"), self.rules())

    def test_symlink_ignored(self):
        t = touch(self.root, "t.txt", 0o666)
        os.symlink(t, os.path.join(self.root, "ln"))
        self.assertNotIn(("ln", "world-writable-file"), self.rules())

    def test_exit_codes(self):
        touch(self.root, "ok.txt", 0o644)
        self.assertEqual(permaudit.main([self.root]), 0)
        touch(self.root, "w.txt", 0o666)
        self.assertEqual(permaudit.main([self.root]), 1)
        self.assertEqual(permaudit.main(["/nonexistent-dir-xyz"]), 2)


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = permaudit.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class NewFeatureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def rules(self, **kw):
        return {(os.path.relpath(p, self.root), r) for p, _, r, _ in permaudit.audit(self.root, **kw)}

    def test_secret_files(self):
        for name in (".netrc", ".pgpass", ".git-credentials", ".pypirc"):
            touch(self.root, name, 0o644)
        self.assertEqual({r for _, r in self.rules()}, {"loose-secret-file"})
        self.assertEqual(len(self.rules()), 4)

    def test_secret_file_ok_when_private(self):
        touch(self.root, ".netrc", 0o600)
        self.assertEqual(self.rules(), set())

    def test_group_readable_secret_file_flagged(self):
        touch(self.root, ".pgpass", 0o640)
        self.assertEqual(self.rules(), {(".pgpass", "loose-secret-file")})

    def test_exclude_glob_and_basename(self):
        touch(self.root, "vendor/.netrc", 0o644)
        touch(self.root, "app/.env", 0o644)
        self.assertEqual(self.rules(exclude=["vendor"]), {("app/.env", "readable-env-file")})
        self.assertEqual(self.rules(exclude=[".env"]), {("vendor/.netrc", "loose-secret-file")})
        self.assertEqual(self.rules(exclude=["*/.*"]), set())

    def test_exclude_does_not_hide_the_root_itself(self):
        os.chmod(self.root, 0o777)
        self.assertIn((".", "world-writable-dir"), self.rules(exclude=["*"]))

    def test_fix_commands_are_quoted(self):
        self.assertEqual(permaudit.fix_command("/tmp/a b/.env", "readable-env-file"), "chmod 600 '/tmp/a b/.env'")
        self.assertEqual(permaudit.fix_command("/x/$(rm -rf ~)", "loose-private-key"),
                         "chmod 600 '/x/$(rm -rf ~)'")
        self.assertEqual(permaudit.fix_command("/x", "world-writable-file"), "chmod o-w /x")
        self.assertIsNone(permaudit.fix_command("/x", "unknown-rule"))

    def test_every_rule_has_a_fix(self):
        for rule in ("world-writable-file", "world-writable-dir", "loose-private-key", "loose-ssh-dir",
                     "readable-env-file", "loose-secret-file", "suid", "sgid"):
            self.assertIn(rule, permaudit.FIXES)

    def test_show_fix_output_and_json(self):
        touch(self.root, "id_rsa", 0o644)
        code, out, _ = run_main(self.root, "--show-fix")
        self.assertEqual(code, 1)
        self.assertIn("fix: chmod 600", out)
        code, out, _ = run_main(self.root, "--json")
        data = json.loads(out)
        self.assertEqual(data[0]["rule"], "loose-private-key")
        self.assertTrue(data[0]["fix"].startswith("chmod 600 "))
        self.assertEqual(set(data[0]), {"severity", "rule", "path", "message", "fix"})

    def test_fixes_are_never_applied(self):
        p = touch(self.root, "id_rsa", 0o644)
        run_main(self.root, "--show-fix")
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o644)

    def test_json_clean_and_min_severity(self):
        touch(self.root, ".env", 0o644)
        self.assertEqual(json.loads(run_main(self.root, "--json", "--min-severity", "HIGH")[1]), [])
        self.assertEqual(run_main(self.root, "--json", "--min-severity", "HIGH")[0], 0)

    def test_json_path_with_shell_metacharacters_is_data_not_command(self):
        touch(self.root, "weird $(x)/.env", 0o644)
        data = json.loads(run_main(self.root, "--json")[1])
        self.assertIn("'", data[0]["fix"])


if __name__ == "__main__":
    unittest.main()
