#!/usr/bin/env python3
"""git-safe server: public scan database API + static stats site. Stdlib only."""
import argparse
import json
import os
import re
import sqlite3
import sys
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gitsafe.normalize import normalize  # noqa: E402

DB_PATH = "git-safe.db"
WEB_DIR = "web"
MAX_BODY = 1_000_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_url TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  scanned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  model TEXT NOT NULL,
  files_scanned INTEGER NOT NULL,
  vulnerabilities INTEGER NOT NULL,
  telemetry INTEGER NOT NULL DEFAULT 0,
  high INTEGER NOT NULL,
  medium INTEGER NOT NULL,
  low INTEGER NOT NULL,
  findings_json TEXT NOT NULL,
  reporter_id TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique ON scans(repo_url, commit_sha, reporter_id);
CREATE INDEX IF NOT EXISTS idx_repo ON scans(repo_url);
"""

_conn = None
_dblock = threading.Lock()


def init_db():
    global _conn
    d = os.path.dirname(os.path.abspath(DB_PATH))
    os.makedirs(d, exist_ok=True)
    _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.executescript(SCHEMA)
    try:  # migrate pre-0.2 databases that lack the telemetry column
        _conn.execute("ALTER TABLE scans ADD COLUMN telemetry INTEGER NOT NULL DEFAULT 0")
        _conn.commit()
    except sqlite3.OperationalError:
        pass
    _conn.commit()


class RateLimiter:
    def __init__(self, limit=10, window=3600.0):
        self.limit, self.window = limit, window
        self.hits = defaultdict(list)
        self.lock = threading.Lock()

    def allow(self, ip):
        now = time.monotonic()
        with self.lock:
            q = [t for t in self.hits[ip] if now - t < self.window]
            ok = len(q) < self.limit
            if ok:
                q.append(now)
            self.hits[ip] = q
            return ok


limiter = RateLimiter()
SEVERITIES = {"high", "medium", "low", "info"}


def validate_scan(body):
    if not isinstance(body, dict):
        return None, "body must be a JSON object"
    try:
        canon = normalize(str(body.get("repo_url", "")))["canonical"]
    except ValueError:
        return None, "repo_url must be a public repository URL"
    sha = str(body.get("commit_sha", ""))
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        return None, "commit_sha must be a 40-char hex sha"
    model = str(body.get("model", ""))[:120]
    if not model:
        return None, "model is required"
    rid = str(body.get("reporter_id", ""))
    if not re.fullmatch(r"[0-9a-fA-F]{8,64}", rid):
        return None, "reporter_id must be 8-64 hex chars"
    try:
        files = int(body.get("files_scanned", 0))
    except (TypeError, ValueError):
        return None, "files_scanned must be an integer"
    if not 0 <= files <= 100000:
        return None, "files_scanned out of range"
    findings = body.get("findings")
    if not isinstance(findings, list) or len(findings) > 500:
        return None, "findings must be a list of at most 500 items"
    clean = []
    for f in findings:
        if not isinstance(f, dict):
            return None, "each finding must be an object"
        title = str(f.get("title", ""))[:200]
        if not title:
            return None, "each finding needs a title"
        try:
            line = max(0, int(f.get("line") or 0))
        except (TypeError, ValueError):
            line = 0
        sev = str(f.get("severity", "medium"))
        category = ("telemetry"
                    if str(f.get("category", "vulnerability")).strip().lower() == "telemetry"
                    else "vulnerability")
        if category == "telemetry":
            sev = "info"
        elif sev not in ("high", "medium", "low"):
            sev = "medium"
        clean.append({
            "file": str(f.get("file", "?"))[:512],
            "line": line,
            "category": category,
            "severity": sev,
            "title": title,
            "description": str(f.get("description", ""))[:2000],
        })
    vulns = sum(1 for f in clean if f["category"] == "vulnerability")
    tele = len(clean) - vulns
    counts = {s: sum(1 for f in clean if f["severity"] == s) for s in SEVERITIES}
    return {
        "repo": canon, "sha": sha, "model": model, "files": files, "rid": rid.lower(),
        "findings": clean, "vulns": vulns, "tele": tele,
        "high": counts["high"], "medium": counts["medium"], "low": counts["low"],
    }, None


class Handler(BaseHTTPRequestHandler):
    server_version = "git-safe/0.1"

    # ---- helpers -------------------------------------------------------
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self._cors()
        self.end_headers()
        self.wfile.write(data)

    def _client_ip(self):
        if self.client_address[0].startswith("127.") or self.client_address[0] == "::1":
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()
        return self.client_address[0]

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # ---- verbs ---------------------------------------------------------
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/v1/stats":
            return self._stats()
        if u.path == "/api/v1/scans":
            return self._scans(parse_qs(u.query))
        if u.path.startswith("/api/"):
            return self._json(404, {"error": "not found"})
        return self._static(u.path)

    def do_POST(self):
        if urlparse(self.path).path != "/api/v1/scans":
            return self._json(404, {"error": "not found"})
        if not limiter.allow(self._client_ip()):
            return self._json(429, {"error": "rate limited \u2014 max 10 scans/hour per IP"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY:
            return self._json(413, {"error": "body too large or missing"})
        try:
            body = json.loads(self.rfile.read(n).decode())
        except (ValueError, UnicodeDecodeError):
            return self._json(400, {"error": "invalid JSON"})
        v, error = validate_scan(body)
        if error:
            return self._json(400, {"error": error})
        with _dblock:
            row = _conn.execute(
                "SELECT id FROM scans WHERE repo_url=? AND commit_sha=? AND reporter_id=?",
                (v["repo"], v["sha"], v["rid"]),
            ).fetchone()
            if row:
                return self._json(201, {"id": row["id"], "duplicate": True})
            cur = _conn.execute(
                "INSERT INTO scans(repo_url,commit_sha,model,files_scanned,vulnerabilities,"
                "telemetry,high,medium,low,findings_json,reporter_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (v["repo"], v["sha"], v["model"], v["files"], v["vulns"], v["tele"],
                 v["high"], v["medium"], v["low"], json.dumps(v["findings"]), v["rid"]),
            )
            _conn.commit()
        return self._json(201, {"id": cur.lastrowid, "duplicate": False})

    # ---- API endpoints --------------------------------------------------
    def _scans(self, qs):
        repo = (qs.get("repo") or [""])[0]
        if not repo:
            return self._json(400, {"error": "repo query param required"})
        try:
            canon = normalize(repo)["canonical"]
        except ValueError:
            return self._json(400, {"error": "not a valid repository URL"})
        with _dblock:
            n, vulns, tele, last, last_model = _conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(vulnerabilities),0), COALESCE(SUM(telemetry),0), "
                "MAX(scanned_at), "
                "(SELECT model FROM scans s2 WHERE s2.repo_url=scans.repo_url ORDER BY scanned_at DESC LIMIT 1) "
                "FROM scans WHERE repo_url=?", (canon,),
            ).fetchone()
            history = [dict(r) for r in _conn.execute(
                "SELECT commit_sha, scanned_at, model, files_scanned, vulnerabilities, telemetry "
                "FROM scans WHERE repo_url=? ORDER BY scanned_at DESC LIMIT 20", (canon,),
            )]
            out = {"repo": canon, "scans": n, "vulnerabilities": vulns, "telemetry": tele,
                   "last_scanned": last, "last_model": last_model, "history": history}
            sha = (qs.get("sha") or [""])[0]
            if re.fullmatch(r"[0-9a-f]{40}", sha):
                cs, cv, ct = _conn.execute(
                    "SELECT COUNT(*), COALESCE(SUM(vulnerabilities),0), COALESCE(SUM(telemetry),0) "
                    "FROM scans WHERE repo_url=? AND commit_sha=?", (canon, sha),
                ).fetchone()
                out["commit"] = {"sha": sha, "scans": cs, "vulnerabilities": cv, "telemetry": ct}
        self._json(200, out)

    def _stats(self):
        with _dblock:
            tot, repos, vulns, tele, high = _conn.execute(
                "SELECT COUNT(*), COUNT(DISTINCT repo_url), COALESCE(SUM(vulnerabilities),0), "
                "COALESCE(SUM(telemetry),0), COALESCE(SUM(high),0) FROM scans"
            ).fetchone()
            day = _conn.execute(
                "SELECT COUNT(*) FROM scans WHERE scanned_at >= datetime('now','-1 day')"
            ).fetchone()[0]
            top = [dict(r) for r in _conn.execute(
                "SELECT repo_url AS repo, COUNT(*) AS scans, COALESCE(SUM(vulnerabilities),0) AS vulnerabilities, "
                "COALESCE(SUM(telemetry),0) AS telemetry "
                "FROM scans GROUP BY repo_url ORDER BY scans DESC LIMIT 10"
            )]
        self._json(200, {
            "total_scans": tot, "unique_repos": repos, "total_vulnerabilities": vulns,
            "total_telemetry": tele,
            "high_vulnerabilities": high, "scans_last_24h": day, "top_repos": top,
        })

    # ---- static site -----------------------------------------------------
    TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
             ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png",
             ".ico": "image/x-icon", ".txt": "text/plain; charset=utf-8"}

    def _static(self, path):
        if path == "/":
            path = "/index.html"
        full = os.path.realpath(os.path.join(WEB_DIR, path.lstrip("/")))
        root = os.path.realpath(WEB_DIR)
        if not full.startswith(root + os.sep) or not os.path.isfile(full):
            return self._json(404, {"error": "not found"})
        with open(full, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", self.TYPES.get(os.path.splitext(full)[1], "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self._cors()
        self.end_headers()
        self.wfile.write(data)


def make_server(host, port, db_path=None, web_dir=None):
    global DB_PATH, WEB_DIR
    if db_path:
        DB_PATH = db_path
    if web_dir:
        WEB_DIR = web_dir
    init_db()
    return ThreadingHTTPServer((host, port), Handler)


def main():
    ap = argparse.ArgumentParser(prog="git-safe-server")
    ap.add_argument("--addr", default=os.environ.get("GITSAFE_ADDR", "127.0.0.1:8080"))
    ap.add_argument("--db", default=os.environ.get("GITSAFE_DB", "git-safe.db"))
    ap.add_argument("--web", default=os.environ.get("GITSAFE_WEB",
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "web")))
    a = ap.parse_args()
    host, _, port = a.addr.rpartition(":")
    httpd = make_server(host or "127.0.0.1", int(port), a.db, a.web)
    print(f"git-safe server \u2192 http://{host or '127.0.0.1'}:{port}  (db: {a.db}, web: {a.web})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
