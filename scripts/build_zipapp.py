#!/usr/bin/env python3
"""Package the CLI as a single-file executable: dist/git-safe.pyz"""
import os
import shutil
import tempfile
import zipapp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
stage = tempfile.mkdtemp(prefix="gitsafe-build-")
try:
    shutil.copytree(os.path.join(ROOT, "gitsafe"), os.path.join(stage, "gitsafe"),
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    with open(os.path.join(stage, "__main__.py"), "w") as f:
        f.write("#!/usr/bin/env python3\nfrom gitsafe.__main__ import main\nmain()\n")
    out = os.path.join(ROOT, "dist", "git-safe.pyz")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    if os.path.exists(out):
        os.remove(out)
    zipapp.create_archive(stage, target=out, interpreter="/usr/bin/env python3")
    print("built", out, f"({os.path.getsize(out)} bytes)")
finally:
    shutil.rmtree(stage, ignore_errors=True)
