"""git safe — the CLI. Flow: cache check -> pithy summary -> confirm -> scan -> save."""
import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

from . import __version__
from .api import APIError, Client
from .identity import reporter_id
from .llm import DEFAULT_MODEL, KeyRejected, LLMError, estimate_cost, scan_chunks
from .normalize import normalize
from .scanner import RepoTooBig, ScanError, collect_files, make_chunks, select_files, shallow_clone
from .ui import c, confirm, dim, err, kv, warn

ARROW = c("\u2192", "green")


def _save_report(owner, name, sha, report) -> Path:
    d = Path.home() / ".cache" / "git-safe"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{owner}_{name}_{sha[:12]}.json"
    p.write_text(json.dumps(report, indent=2))
    return p


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="git safe",
        description="scan public git repos for vulnerabilities with your own OpenRouter key",
    )
    ap.add_argument("repo", nargs="?", help="owner/repo or any public repository URL")
    ap.add_argument("--api", default=os.environ.get("GITSAFE_API", "http://localhost:8080"),
                    help="git-safe database API base URL (default: $GITSAFE_API)")
    ap.add_argument("--model", default=os.environ.get("OPENROUTER_MODEL", DEFAULT_MODEL),
                    help="OpenRouter model (default: $OPENROUTER_MODEL or %s)" % DEFAULT_MODEL)
    ap.add_argument("-y", "--yes", action="store_true", help="skip confirmation prompts")
    ap.add_argument("--version", action="version", version=f"git-safe {__version__}")
    a = ap.parse_args(argv)
    if not a.repo:
        ap.error("usage: git safe <owner/repo>")

    print()
    print(f"  {c('git safe', 'bold')}  {dim('v' + __version__)}")
    try:
        r = normalize(a.repo)
    except ValueError as e:
        err(str(e))
        sys.exit(2)
    kv("repo", r["canonical"])

    client = Client(a.api)
    summary = None
    try:
        summary = client.repo_scans(r["canonical"])
    except APIError as e:
        warn(f"database unreachable ({e})")

    if summary is not None:
        n, v = summary.get("scans", 0), summary.get("vulnerabilities", 0)
        line = (f"{n} scans done \u00b7 {v} vulnerabilities found" if n
                else "0 scans so far \u2014 first look at this repo")
        print("  " + ARROW + " " + c(line, "bold"))
        if n and summary.get("last_scanned"):
            print(dim(f"    last scanned {str(summary['last_scanned'])[:10]} with {summary.get('last_model', '?')}"))

    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        print(f"\n  {c('no key no scan', 'bold')}")
        print(dim("    set OPENROUTER_API_KEY to scan this repo yourself \u00b7 https://openrouter.ai/keys"))
        print(dim("    (the summary above comes from other people's scans)"))
        sys.exit(0)

    print(dim("    cloning (shallow)…"))
    try:
        workdir, sha = shallow_clone(r["clone_url"])
    except ScanError as e:
        err(str(e))
        sys.exit(1)
    kv("commit", sha[:12])

    try:
        ci = (client.repo_scans(r["canonical"], sha=sha).get("commit") or {})
        if ci.get("scans"):
            line = f"this exact commit: {ci['scans']} scans \u00b7 {ci['vulnerabilities']} vulnerabilities"
            print("  " + ARROW + " " + c(line, "bold"))
            if not (a.yes or confirm("rescan anyway?")):
                print(dim("nothing done."))
                sys.exit(0)
    except APIError:
        pass

    try:
        files = collect_files(workdir)
        selected, hits = select_files(files, workdir)
        chunks = make_chunks(workdir, selected)
    except RepoTooBig as e:
        shutil.rmtree(workdir, ignore_errors=True)
        err(str(e))
        sys.exit(1)
    shutil.rmtree(workdir, ignore_errors=True)
    if not chunks:
        err("nothing scannable found in this repo")
        sys.exit(1)

    est = estimate_cost(a.model, sum(f["size"] for f in selected), len(chunks))
    print(dim(f"    plan: {len(selected)} files \u2192 {len(chunks)} chunks \u00b7 est ${est:.2f} ({a.model})"))
    if not (a.yes or confirm("proceed with scan on YOUR OpenRouter key?")):
        print(dim("aborted \u2014 nothing scanned, nothing saved."))
        sys.exit(0)

    t0 = time.monotonic()

    def prog(done, total):
        end = "\n" if done == total else ""
        print(f"\r  scanning {done}/{total} chunks\u2026{end}", end="", flush=True)

    print()
    try:
        findings, errs = scan_chunks(key, a.model, chunks, prog)
    except (KeyRejected, LLMError) as e:
        err(str(e))
        sys.exit(1)
    if errs:
        warn(f"{len(errs)} chunk(s) failed: {errs[0]}")
    dt = time.monotonic() - t0
    high = sum(1 for f in findings if f["severity"] == "high")
    med = sum(1 for f in findings if f["severity"] == "medium")
    low = len(findings) - high - med
    line = f"done in {dt:.0f}s \u00b7 {len(findings)} vulnerabilities found ({high} high \u00b7 {med} medium \u00b7 {low} low)"
    print("  " + ARROW + " " + c(line, "bold"))

    report = {"repo": r["canonical"], "commit": sha, "model": a.model,
              "files_scanned": len(selected), "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "findings": findings}
    rep_path = _save_report(r["owner"], r["name"], sha, report)
    payload = {"repo_url": r["canonical"], "commit_sha": sha, "model": a.model,
               "files_scanned": len(selected), "findings": findings, "reporter_id": reporter_id()}
    try:
        res = client.submit(payload)
        print("  " + c(f"saved to the public database \u00b7 scan #{res.get('id')}", "green"))
    except APIError as e:
        warn(f"couldn't save to the database ({e}) \u2014 report kept locally")
    print(dim(f"full report: {rep_path}"))
    for f in findings[:10]:
        print(f"    [{f['severity'][:1].upper()}] {f['file']}:{f['line']} \u2014 {f['title']}")
    if len(findings) > 10:
        print(dim(f"    … and {len(findings) - 10} more in the full report"))
    print()


if __name__ == "__main__":
    main()
