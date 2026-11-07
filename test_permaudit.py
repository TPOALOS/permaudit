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


if __name__ == "__main__":
    unittest.main()
