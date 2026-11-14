import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app  # noqa: E402


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = app.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.store = str(self.root / "store")
        (self.data / "a.log").write_text("hello\n")
        (self.data / "b.log").write_text("world\n")


class HashTests(Base):
    def test_known_digest(self):
        code, out, _ = run("hash", str(self.data / "a.log"))
        self.assertEqual(code, 0)
        self.assertEqual(out.split()[0], hashlib.sha256(b"hello\n").hexdigest())

    def test_multiple_and_json(self):
        code, out, _ = run("hash", "--json", str(self.data / "a.log"), str(self.data / "b.log"))
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)["results"]), 2)

    def test_missing_file_exit_2_but_others_hashed(self):
        code, out, err = run("hash", str(self.data / "nope"), str(self.data / "a.log"))
        self.assertEqual(code, 2)
        self.assertIn(hashlib.sha256(b"hello\n").hexdigest(), out)
        self.assertIn("Not a regular file", err)

    def test_stdin(self):
        old = sys.stdin
        sys.stdin = io.TextIOWrapper(io.BytesIO(b"hello\n"))
        try:
            code, out, _ = run("hash", "-")
        finally:
            sys.stdin = old
        self.assertEqual(code, 0)
        self.assertEqual(out.split()[0], hashlib.sha256(b"hello\n").hexdigest())


class VerifyTests(Base):
    def make_list(self, a=None):
        digest = a or hashlib.sha256(b"hello\n").hexdigest()
        lst = self.data / "sums.txt"
        world = hashlib.sha256(b"world\n").hexdigest()
        lst.write_text(f"{digest}  a.log\n{world}  b.log\n")
        return str(lst)

    def test_ok(self):
        code, out, _ = run("verify", self.make_list())
        self.assertEqual(code, 0)
        self.assertIn("2 OK", out)

    def test_mismatch(self):
        code, out, _ = run("verify", self.make_list("0" * 64))
        self.assertEqual(code, 1)
        self.assertIn("a.log: FAILED", out)

    def test_missing_file(self):
        lst = self.make_list()
        (self.data / "b.log").unlink()
        code, out, _ = run("verify", lst)
        self.assertEqual(code, 1)
        self.assertIn("b.log: MISSING", out)

    def test_garbage_list(self):
        lst = self.data / "bad.txt"
        lst.write_text("not a checksum\n")
        code, _, _ = run("verify", str(lst))
        self.assertEqual(code, 2)


class BaselineTests(Base):
    def test_auto_init_then_clean_check(self):
        code, out, _ = run("--store", self.store, str(self.data))
        self.assertEqual(code, 0)
        self.assertIn("Baseline created", out)
        code, out, _ = run("--store", self.store, str(self.data))
        self.assertEqual((code, "Unmodified" in out), (0, True))

    def test_detects_modified_missing_new(self):
        run("--store", self.store, "init", str(self.data))
        (self.data / "a.log").write_text("changed")
        (self.data / "b.log").unlink()
        (self.data / "c.log").write_text("new")
        code, out, _ = run("--store", self.store, "check", str(self.data), "--json")
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertEqual((report["modified"], report["missing"], report["new"]), (1, 1, 1))

    def test_store_flag_before_subcommand(self):
        # regression: the --store value was mistaken for a bare path
        code, _, err = run("--store", self.store, "init", str(self.data))
        self.assertEqual(code, 0, err)

    def test_init_refuses_overwrite_but_reinit_works(self):
        run("--store", self.store, "init", str(self.data))
        self.assertEqual(run("--store", self.store, "init", str(self.data))[0], 2)
        self.assertEqual(run("--store", self.store, "reinit", str(self.data))[0], 0)

    def test_update_accepts_changes(self):
        run("--store", self.store, "init", str(self.data))
        (self.data / "a.log").write_text("changed")
        run("--store", self.store, "update", str(self.data))
        self.assertEqual(run("--store", self.store, "check", str(self.data))[0], 0)

    def test_nonexistent_path(self):
        self.assertEqual(run("--store", self.store, str(self.root / "zzz"))[0], 2)


if __name__ == "__main__":
    unittest.main()
