"""Anonymous per-install id used to attribute scans (never a secret)."""
import secrets
from pathlib import Path


def reporter_id() -> str:
    d = Path.home() / ".config" / "git-safe"
    d.mkdir(parents=True, exist_ok=True)
    f = d / "id"
    if f.exists():
        v = f.read_text().strip()
        if 8 <= len(v) <= 64:
            return v
    v = secrets.token_hex(16)
    f.write_text(v + "\n")
    return v
