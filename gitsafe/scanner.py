"""Shallow clone, file collection, prioritization and chunking."""
import os
import re
import shutil
import subprocess
import tempfile


class ScanError(Exception):
    pass


class RepoTooBig(ScanError):
    pass


SKIP_DIRS = {
    ".git", ".hg", ".svn", ".github", ".gitlab", "node_modules", "vendor",
    "dist", "build", "out", "target", ".venv", "venv", "__pycache__", ".next",
    ".nuxt", "coverage", ".idea", ".vscode", ".cache", ".tox", ".mypy_cache",
}
SKIP_NAME = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "go.sum", "Cargo.lock", "poetry.lock", "composer.lock", "Gemfile.lock", "Pipfile.lock",
}
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz",
    ".tar", ".bz2", ".xz", ".7z", ".so", ".dylib", ".dll", ".exe", ".bin", ".woff",
    ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4", ".mov", ".avi", ".webm",
    ".sqlite", ".db", ".class", ".jar", ".pyc", ".o", ".a", ".map", ".svg", ".sum",
}
MAX_FILES = 5000
MAX_TOTAL = 50 * 1024 * 1024
MAX_FILE_BYTES = 200 * 1024
MAX_SCAN_FILES = 40
CHUNK_BYTES = 14 * 1024
MAX_FILE_IN_CHUNK = 8 * 1024

PATTERNS = [
    (re.compile(r"(?i)(?:api[_-]?key|secret|password|passwd|access[_-]?token)\s*[:=]\s*[\"'][^\"']{8,}"), "possible hardcoded secret"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key material"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"(?i)\bsk-[a-z0-9]{20,}\b"), "possible API key literal"),
    (re.compile(r"(?i)verify\s*=\s*False"), "TLS verification disabled"),
    (re.compile(r"InsecureSkipVerify\s*:\s*true"), "TLS verification disabled"),
    (re.compile(r"rejectUnauthorized\s*:\s*false"), "TLS verification disabled"),
    (re.compile(r"(?i)\b(eval|exec)\s*\("), "dynamic code execution"),
    (re.compile(r"(?i)shell\s*=\s*True|os\.system\(|child_process"), "process execution"),
    (re.compile(r"(?i)pickle\.loads|yaml\.load\((?![^)]*Loader)"), "unsafe deserialization"),
]

HIGH_VALUE_NAMES = {
    "package.json", "requirements.txt", "go.mod", "cargo.toml", "pyproject.toml",
    "pom.xml", "build.gradle", "composer.json", "gemfile", "dockerfile",
    ".env", ".env.example", "settings.py", "config.py", "application.properties",
    "app.py", "manage.py", "wsgi.py", "asgi.py", "main.go", "index.js", "server.js",
}
HIGH_VALUE_FRAGMENTS = (
    "auth", "login", "session", "token", "secret", "credential", "crypto",
    "security", "admin", "permission", "oauth", "jwt", "middleware", "upload",
)


def shallow_clone(url, dst=None, timeout=60):
    dst = dst or tempfile.mkdtemp(prefix="gitsafe-")
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        p = subprocess.run(
            ["git",
             "-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=15",
             "clone", "--quiet", "--depth", "1", "--single-branch", url, dst],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(dst, ignore_errors=True)
        raise ScanError(f"clone timed out after {timeout}s — network unreachable or repo too large") from None
    if p.returncode != 0:
        shutil.rmtree(dst, ignore_errors=True)
        lines = [l for l in (p.stderr or "").strip().splitlines() if l.strip()]
        tail = lines[-1] if lines else "unknown git error"
        low = tail.lower()
        if "not found" in low or "authentication" in low or "could not read" in low or "terminal prompts disabled" in low:
            raise ScanError("clone failed \u2014 repo not found or private (git safe only scans public repos)")
        raise ScanError("clone failed: " + tail)
    r = subprocess.run(["git", "-C", dst, "rev-parse", "HEAD"], capture_output=True, text=True)
    if r.returncode != 0:
        raise ScanError("could not resolve HEAD commit")
    return dst, r.stdout.strip()


def _is_binary(path):
    try:
        with open(path, "rb") as f:
            return b"\0" in f.read(512)
    except OSError:
        return True


def collect_files(root):
    out, total = [], 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info"))
        for fn in sorted(filenames):
            if fn in SKIP_NAME or fn.endswith(".min.js"):
                continue
            if os.path.splitext(fn)[1].lower() in SKIP_EXT:
                continue
            full = os.path.join(dirpath, fn)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size == 0 or size > MAX_FILE_BYTES:
                continue
            total += size
            if len(out) >= MAX_FILES or total > MAX_TOTAL:
                raise RepoTooBig("repo too large for v1 (cap: 5,000 files / 50 MB)")
            if _is_binary(full):
                continue
            out.append({"path": os.path.relpath(full, root).replace(os.sep, "/"), "full": full, "size": size})
    return out


def prefilter_hits(files):
    hits = {}
    for e in files:
        try:
            text = open(e["full"], encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        notes = [note for rx, note in PATTERNS if rx.search(text)]
        if notes:
            hits[e["path"]] = notes
    return hits


def select_files(files, root=None):
    hits = prefilter_hits(files)

    def score(e):
        s = 0
        pl, pn = e["path"].lower(), os.path.basename(e["path"]).lower()
        if pn in HIGH_VALUE_NAMES or pn.startswith(".env"):
            s += 50
        if any(f in pl for f in HIGH_VALUE_FRAGMENTS):
            s += 25
        s += min(40, 10 * len(hits.get(e["path"], [])))
        return s

    ranked = sorted(files, key=score, reverse=True)
    return ranked[:MAX_SCAN_FILES], hits


def make_chunks(root, selected):
    chunks, cur, cur_len = [], [], 0
    for e in selected:
        try:
            text = open(e["full"], encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if len(text.encode()) > MAX_FILE_IN_CHUNK:
            text = text[:MAX_FILE_IN_CHUNK] + "\n... (truncated)"
        block = f"\n--- FILE: {e['path']} ---\n{text}"
        if cur and cur_len + len(block) > CHUNK_BYTES:
            chunks.append("".join(cur))
            cur, cur_len = [], 0
        cur.append(block)
        cur_len += len(block)
    if cur:
        chunks.append("".join(cur))
    return chunks
