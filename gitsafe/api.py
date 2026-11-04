"""HTTP client for the git-safe database API (stdlib only)."""
import json
import urllib.error
import urllib.parse
import urllib.request


class APIError(Exception):
    pass


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def _req(self, path, method="GET", body=None, timeout=30):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Content-Type": "application/json", "User-Agent": "git-safe/0.1"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read().decode()).get("error", "")
            except Exception:
                detail = e.reason
            raise APIError(f"{e.code} {detail}".strip()) from None
        except (urllib.error.URLError, OSError) as e:
            raise APIError(f"cannot reach {self.base}: {getattr(e, 'reason', e)}") from None

    def repo_scans(self, canonical: str, sha: str | None = None):
        q = {"repo": canonical}
        if sha:
            q["sha"] = sha
        return self._req("/api/v1/scans?" + urllib.parse.urlencode(q))

    def submit(self, payload: dict):
        return self._req("/api/v1/scans", "POST", payload, timeout=60)

    def stats(self):
        return self._req("/api/v1/stats")
