"""Canonical public-repo URL handling. Any common git URL form collapses to one cache key."""
from urllib.parse import urlparse


def normalize(text: str) -> dict:
    s = (text or "").strip().strip("/")
    if s.endswith(".git"):
        s = s[:-4]
    if s.startswith("git@"):
        s = s[4:].replace(":", "/", 1)
    if "://" not in s:
        first = s.split("/")[0]
        if "." not in first:  # bare owner/repo shorthand -> assume GitHub
            s = "github.com/" + s
        s = "https://" + s
    u = urlparse(s)
    host = (u.hostname or "").lower()
    parts = [p for p in u.path.split("/") if p][:2]
    if not host or "." not in host or len(parts) < 2:
        raise ValueError(f"not a public repository URL: {text!r} (want owner/repo)")
    owner, name = parts
    clone = (f"https://{host}/{owner.lower()}/{name.lower()}.git"
             if host == "github.com"
             else f"https://{host}/{owner}/{name}.git")
    return {
        "canonical": f"{host}/{owner.lower()}/{name.lower()}",
        "clone_url": clone,
        "host": host,
        "owner": owner,
        "name": name,
    }
