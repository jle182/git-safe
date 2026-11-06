"""Local settings for git-safe: OpenRouter key + preferred model.

Everything lives under ~/.config/git-safe/ next to the anonymous id.
The key is stored unencrypted with chmod 600 -- the same trust model
as most CLI tools storing tokens. If you prefer memory-only, set the
OPENROUTER_API_KEY env var instead (env always wins over the file).
"""
import os
from pathlib import Path


def _dir():
    return Path.home() / ".config" / "git-safe"


def _path(name):
    return _dir() / name


def stored_key():
    """The key saved on disk (ignores the env var), or None."""
    try:
        v = _path("key").read_text().strip()
        return v or None
    except OSError:
        return None


def get_key():
    """Env var wins over the stored file."""
    env = os.environ.get("OPENROUTER_API_KEY", "").strip()
    return env or stored_key()


def set_key(key):
    _dir().mkdir(parents=True, exist_ok=True)
    f = _path("key")
    f.write_text(key.strip() + "\n")
    f.chmod(0o600)


def remove_key():
    try:
        _path("key").unlink()
        return True
    except FileNotFoundError:
        return False


def get_model():
    env = os.environ.get("OPENROUTER_MODEL", "").strip()
    if env:
        return env
    try:
        v = _path("model").read_text().strip()
        return v or None
    except OSError:
        return None


def set_model(model):
    _dir().mkdir(parents=True, exist_ok=True)
    _path("model").write_text(model.strip() + "\n")


def remove_model():
    try:
        _path("model").unlink()
        return True
    except FileNotFoundError:
        return False


def mask(key):
    if len(key) > 20:
        return key[:12] + "..." + key[-4:]
    return "****"
