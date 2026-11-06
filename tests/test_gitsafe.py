import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = str(Path(__file__).resolve().parents[1])
sys.path.insert(0, ROOT)

from gitsafe.llm import _extract_json  # noqa: E402
from gitsafe.normalize import normalize  # noqa: E402
from gitsafe.scanner import collect_files, make_chunks, select_files  # noqa: E402


class TestNormalize(unittest.TestCase):
    def test_github_variants_collapse_to_one_key(self):
        cases = [
            "evanw/esbuild",
            "https://github.com/evanw/esbuild",
            "https://github.com/evanw/esbuild.git",
            "git@github.com:evanw/esbuild.git",
            "https://github.com/EVANW/EsBuild/tree/main/src",
            "http://github.com/evanw/esbuild/",
        ]
        for c in cases:
            with self.subTest(c=c):
                r = normalize(c)
                self.assertEqual(r["canonical"], "github.com/evanw/esbuild")
                self.assertEqual(r["clone_url"], "https://github.com/evanw/esbuild.git")

    def test_non_github_keeps_case_for_clone(self):
        r = normalize("https://gitlab.com/SomeOrg/SomeRepo")
        self.assertEqual(r["canonical"], "gitlab.com/someorg/somerepo")
        self.assertEqual(r["clone_url"], "https://gitlab.com/SomeOrg/SomeRepo.git")

    def test_rejects_garbage(self):
        for bad in ["", "justone", "https://github.com/onlyone", "not a url at all"]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    normalize(bad)


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="gitsafe-fix-")
        os.makedirs(f"{self.root}/node_modules/x")
        os.makedirs(f"{self.root}/src/auth")
        open(f"{self.root}/node_modules/x/i.js", "w").write("x")
        open(f"{self.root}/src/auth/login.py", "w").write("password = 'hunter2hunter2'\n")
        open(f"{self.root}/img.png", "wb").write(b"\0\0\1" + b"a" * 10)
        open(f"{self.root}/README.md", "w").write("# hi\n")
        open(f"{self.root}/main.py", "w").write("print('hi')\n")

    def test_collect_skips_junk_and_binary(self):
        paths = [f["path"] for f in collect_files(self.root)]
        self.assertNotIn("node_modules/x/i.js", paths)
        self.assertNotIn("img.png", paths)
        self.assertIn("src/auth/login.py", paths)
        self.assertIn("main.py", paths)

    def test_select_prioritizes_auth_and_prefilter(self):
        sel, hits = select_files(collect_files(self.root), self.root)
        self.assertEqual(sel[0]["path"], "src/auth/login.py")
        self.assertIn("src/auth/login.py", hits)

    def test_chunks_are_built(self):
        sel, _ = select_files(collect_files(self.root), self.root)
        chunks = make_chunks(self.root, sel)
        self.assertGreaterEqual(len(chunks), 1)
        self.assertIn("--- FILE: src/auth/login.py ---", chunks[0])


class TestExtractJson(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(_extract_json('{"findings": []}'), {"findings": []})

    def test_fenced(self):
        self.assertEqual(_extract_json('```json\n{"findings": [1]}\n```'), {"findings": [1]})

    def test_with_prose(self):
        self.assertEqual(_extract_json('Here you go:\n{"findings": []} hope that helps'), {"findings": []})

    def test_garbage_raises(self):
        with self.assertRaises(ValueError):
            _extract_json("sorry, no json here")


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import server.server as srv
        cls.srv = srv
        cls.tmp = tempfile.TemporaryDirectory()
        webdir = os.path.join(cls.tmp.name, "web")
        os.makedirs(webdir)
        open(os.path.join(webdir, "index.html"), "w").write("<html>ok</html>")
        cls.httpd = srv.make_server("127.0.0.1", 0,
                                    db_path=os.path.join(cls.tmp.name, "t.db"),
                                    web_dir=webdir)
        cls.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.tmp.cleanup()

    def setUp(self):
        self.srv.limiter.hits.clear()  # test isolation from the rate limiter
        self.srv._conn.execute("DELETE FROM scans")
        self.srv._conn.commit()

    def _post(self, body):
        req = urllib.request.Request(self.base + "/api/v1/scans",
                                     data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or "{}")

    def _get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=5) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or "{}")

    def _scan(self, **over):
        b = {"repo_url": "github.com/a/b", "commit_sha": "a" * 40, "model": "m",
             "files_scanned": 3, "reporter_id": "0123456789abcdef0123456789abcdef",
             "findings": [{"file": "x.py", "line": 3, "severity": "high",
                           "title": "t", "description": "d"}]}
        b.update(over)
        return b

    def test_rate_limit_rejects_after_ten(self):
        bad = self._scan(commit_sha="z" * 40)  # 400s: nothing stored, but still counted
        codes = [self._post(bad)[0] for _ in range(12)]
        self.assertEqual(codes[:10], [400] * 10)
        self.assertEqual(codes[10:], [429, 429])

    def test_roundtrip(self):
        s, b = self._get("/api/v1/stats")
        self.assertEqual(s, 200)
        self.assertEqual(b["total_scans"], 0)
        s, b = self._post(self._scan())
        self.assertEqual(s, 201)
        self.assertFalse(b["duplicate"])
        s, b = self._post(self._scan())
        self.assertEqual(s, 201)
        self.assertTrue(b["duplicate"])
        s, b = self._get("/api/v1/scans?repo=github.com/a/b")
        self.assertEqual(b["scans"], 1)
        self.assertEqual(b["vulnerabilities"], 1)
        self.assertEqual(len(b["history"]), 1)
        self.assertNotIn("findings", b["history"][0])  # finding details never leave the server
        s, b = self._get(f"/api/v1/scans?repo=github.com/a/b&sha={'a' * 40}")
        self.assertEqual(b["commit"]["scans"], 1)
        s, b = self._get("/api/v1/stats")
        self.assertEqual(b["total_scans"], 1)
        self.assertEqual(b["total_vulnerabilities"], 1)
        self.assertEqual(b["high_vulnerabilities"], 1)
        self.assertEqual(b["top_repos"][0]["repo"], "github.com/a/b")
        self.assertEqual(b["scans_last_24h"], 1)
        r = urllib.request.urlopen(self.base + "/", timeout=5)
        self.assertEqual(r.status, 200)
        self.assertIn(b"ok", r.read())
        s, _ = self._get("/definitely-not-here")
        self.assertEqual(s, 404)

    def test_validation_and_normalization(self):
        s, _ = self._post(self._scan(commit_sha="zzz"))
        self.assertEqual(s, 400)
        s, _ = self._post(self._scan(findings="nope"))
        self.assertEqual(s, 400)
        s, _ = self._post(self._scan(reporter_id="short"))
        self.assertEqual(s, 400)
        s, _ = self._post(self._scan(line="not-a-number"))
        self.assertEqual(s, 201)  # bad line coerced, not a 500
        s, b = self._post(self._scan(repo_url="https://github.com/a/b"))
        self.assertEqual(s, 201)
        self.assertTrue(b["duplicate"])  # full URL normalizes to the canonical key
        s, b = self._get("/api/v1/stats")
        self.assertEqual(b["total_scans"], 1)


class TestScanChunks(unittest.TestCase):
    def test_merges_dedupes_and_counts_errors(self):
        import gitsafe.llm as llm
        orig = llm._post
        calls = []

        def fake_post(key, model, content, timeout=120):
            calls.append(1)
            if len(calls) == 1:
                return ('{"findings": ['
                        '{"file": "a.py", "line": 1, "severity": "high", '
                        '"title": "hardcoded secret", "description": "d"}, '
                        '{"file": "a.py", "line": 1, "severity": "high", '
                        '"title": "Hardcoded Secret", "description": "dup"}]}')
            return "the model declined to produce JSON today"

        llm._post = fake_post
        try:
            findings, errs = llm.scan_chunks("k", "m", ["chunk one", "chunk two"])
        finally:
            llm._post = orig
        self.assertEqual(len(findings), 1)   # deduped by (file, line, title.lower())
        self.assertEqual(findings[0]["title"], "hardcoded secret")
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(len(errs), 1)       # garbage chunk failed after retries
        self.assertEqual(len(calls), 3)      # 1 good call + 2 retries



class TestSettings(unittest.TestCase):
    def setUp(self):
        import tempfile
        from unittest import mock
        tmp = tempfile.mkdtemp(prefix="gitsafe-cfg-")
        p = mock.patch("gitsafe.settings.Path.home", lambda: Path(tmp))
        p.start()
        self.addCleanup(p.stop)
        self.env = {k: os.environ.pop(k, None)
                    for k in ("OPENROUTER_API_KEY", "OPENROUTER_MODEL")}

    def tearDown(self):
        for k, v in self.env.items():
            if v is not None:
                os.environ[k] = v

    def test_key_roundtrip_env_precedence_and_remove(self):
        import gitsafe.settings as st
        self.assertIsNone(st.get_key())
        st.set_key("sk-or-v1-" + "a" * 30)
        self.assertEqual(st.get_key(), st.stored_key())
        os.environ["OPENROUTER_API_KEY"] = "env-wins-0123456789"
        self.assertEqual(st.get_key(), "env-wins-0123456789")
        del os.environ["OPENROUTER_API_KEY"]
        self.assertTrue(st.remove_key())
        self.assertFalse(st.remove_key())
        self.assertIsNone(st.get_key())

    def test_model_roundtrip(self):
        import gitsafe.settings as st
        self.assertIsNone(st.get_model())
        st.set_model("openai/gpt-oss-120b")
        self.assertEqual(st.get_model(), "openai/gpt-oss-120b")
        os.environ["OPENROUTER_MODEL"] = "env-model"
        self.assertEqual(st.get_model(), "env-model")
        del os.environ["OPENROUTER_MODEL"]
        self.assertTrue(st.remove_model())
        self.assertIsNone(st.get_model())


if __name__ == "__main__":
    unittest.main()
