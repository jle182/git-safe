"""Terminal output helpers — pithy by design."""
import os
import sys


def _wrap(code, s):
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return s
    return f"\033[{code}m{s}\033[0m"


def c(s, kind=""):
    m = {"bold": "1", "dim": "2", "green": "32", "red": "31", "yellow": "33"}
    return _wrap(m.get(kind, "0"), s)


def dim(s):
    return c(s, "dim")


def ok(s):
    return c("\u2713 ", "green") + s


def warn(s):
    print("  " + c("! ", "yellow") + c(s, "yellow"))


def err(s):
    print("  " + c("\u2717 ", "red") + c(str(s), "red"), file=sys.stderr)


def kv(k, v):
    print(f"  {dim(k + ':')} {v}")


def confirm(prompt):
    try:
        a = input(f"  {prompt} [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return a in ("y", "yes")
