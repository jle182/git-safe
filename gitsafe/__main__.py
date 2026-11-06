"""git safe \u2014 the CLI. Flow: cache check -> pithy summary -> confirm -> scan -> save."""
import argparse
import getpass
import json
import os
import shutil
import sys
import time
from pathlib import Path

from . import __version__
from .api import APIError, Client
from .identity import reporter_id
from .llm import DEFAULT_MODEL, KeyRejected, LLMError, estimate_cost, fetch_models, scan_chunks, verify_key
from .normalize import normalize
from .scanner import RepoTooBig, ScanError, collect_files, make_chunks, select_files, shallow_clone
from .settings import (get_key, get_model, mask, remove_key, remove_model,
                       set_key, set_model, stored_key)
from .ui import c, confirm, dim, err, kv, warn

ARROW = c("\u2192", "green")


def _save_report(owner, name, sha, report) -> Path:
    d = Path.home() / ".cache" / "git-safe"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{owner}_{name}_{sha[:12]}.json"
    p.write_text(json.dumps(report, indent=2))
    return p


def _cmd_key(args):
    if "-r" in args or "--remove" in args:
        print("  key removed." if remove_key() else "  no stored key found.")
        return
    cur = stored_key()
    if cur:
        print(f"  a key is already stored ({mask(cur)})")
        if not confirm("replace it?"):
            return
    k = getpass.getpass("  OpenRouter key (input hidden): ").strip()
    if len(k) < 20:
        err("that doesn't look like an OpenRouter key (too short) \u2014 nothing saved")
        sys.exit(1)
    set_key(k)
    print("  " + c("key saved to ~/.config/git-safe/key (chmod 600)", "green"))
    print(dim("    checking with OpenRouter\u2026"), end=" ", flush=True)
    try:
        verify_key(k)
        print(c("key is valid \u2713", "green"))
    except KeyRejected as e:
        print(c(f"WARNING: {e}", "yellow"))
    except LLMError as e:
        print(c(f"couldn't reach OpenRouter to verify ({e}) \u2014 it may still work", "yellow"))


def _cmd_model(args):
    vals = [a for a in args if not a.startswith("-")]
    if "-r" in args or "--remove" in args or "--unset" in args:
        print("  default model cleared." if remove_model() else "  no stored default model.")
        return
    if vals:
        set_model(vals[0])
        print("  " + c(f"default model set to {vals[0]}", "green"))
        return
    cur = get_model()
    print("  current default: " + (cur or f"{DEFAULT_MODEL} (built-in)"))
    print(dim("    set one:    git safe model openai/gpt-oss-120b"))
    print(dim("    browse all: git safe models         (free only: git safe models free)"))


def _cmd_models(args):
    flt = args[0] if args and not args[0].startswith("-") else None
    print(dim("    fetching model list from OpenRouter..."))
    try:
        raw = fetch_models()
    except LLMError as e:
        err(str(e))
        sys.exit(1)
    rows = []
    for m in raw:
        try:
            pin = float((m.get("pricing") or {}).get("prompt") or 0) * 1e6
            pout = float((m.get("pricing") or {}).get("completion") or 0) * 1e6
        except (TypeError, ValueError):
            pin = pout = 0.0
        rows.append((str(m.get("id", "?")), pin, pout, int(m.get("context_length") or 0)))
    rows.sort(key=lambda r: (r[1], r[2]))

    def show(rs, limit):
        for mid, pin, pout, ctx in rs[:limit]:
            ctxs = f"{ctx / 1000:.0f}k" if ctx >= 1000 else str(ctx)
            if pin == 0 and pout == 0:
                price = "free"
            else:
                price = f"${pin:.2f} in / ${pout:.2f} out"
            print(f"    {mid:<46} {price:>22}   {ctxs:>6} ctx")

    if flt == "free":
        free = [r for r in rows if r[1] == 0 and r[2] == 0]
        print(f"\n  {len(free)} free models (of {len(rows)} total) - set one: git safe model <id>\n")
        show(free, 40)
        if len(free) > 40:
            print(dim(f"    ... and {len(free) - 40} more"))
        return
    if flt:
        q = flt.lower()
        hits = [r for r in rows if q in r[0].lower()]
        if not hits:
            print("  no models match.")
            return
        print(f"\n  {len(hits)} models matching '{flt}' (of {len(rows)} total)\n")
        show(hits, 40)
        if len(hits) > 40:
            print(dim(f"    ... and {len(hits) - 40} more - narrow the search"))
        return

    free = [r for r in rows if r[1] == 0 and r[2] == 0]
    paid = [r for r in rows if not (r[1] == 0 and r[2] == 0)]
    print(f"\n  {len(rows)} models on OpenRouter: {len(free)} free \u00b7 {len(paid)} paid\n")
    print(c("  FREE", "green"))
    show(free, 8)
    if len(free) > 8:
        print(dim(f"    ... {len(free) - 8} more - git safe models free"))
    print()
    print(c("  PAID, cheapest first", "bold"))
    show(paid, 30)
    if len(paid) > 30:
        print(dim(f"    ... and {len(paid) - 30} more - search: git safe models <name, e.g. openai>"))
    print(dim("\n    set one: git safe model <id>"))

def _cli(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "key":
        _cmd_key(args[1:])
        return
    if args and args[0] == "model":
        _cmd_model(args[1:])
        return
    if args and args[0] == "models":
        _cmd_models(args[1:])
        return

    ap = argparse.ArgumentParser(
        prog="git safe",
        description="scan public git repos for vulnerabilities with your own OpenRouter key",
    )
    ap.add_argument("repo", nargs="?", help="owner/repo or any public repository URL")
    ap.add_argument("--api", default=os.environ.get("GITSAFE_API", "http://localhost:8080"),
                    help="git-safe database API base URL (default: $GITSAFE_API)")
    ap.add_argument("--model", default=None,
                    help="model for this scan (overrides: $OPENROUTER_MODEL, git safe model default)")
    ap.add_argument("-y", "--yes", action="store_true", help="skip confirmation prompts")
    ap.add_argument("--version", action="version", version=f"git-safe {__version__}")
    a = ap.parse_args(args)
    if not a.repo:
        ap.error("usage: git safe <owner/repo>  (or: git safe key | model | models)")

    model = a.model or get_model() or DEFAULT_MODEL

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
        n = summary.get("scans", 0)
        v = summary.get("vulnerabilities", 0)
        t = summary.get("telemetry", 0)
        line = (f"{n} scans done \u00b7 {v} vulnerabilities \u00b7 {t} telemetry signals found" if n
                else "0 scans so far \u2014 first look at this repo")
        print("  " + ARROW + " " + c(line, "bold"))
        if n and summary.get("last_scanned"):
            print(dim(f"    last scanned {str(summary['last_scanned'])[:10]} with {summary.get('last_model', '?')}"))

    key = get_key()
    if not key:
        print(f"\n  {c('no key no scan', 'bold')}")
        print(dim("    set OPENROUTER_API_KEY, run: git safe key, or enter one now"))
        if sys.stdin.isatty() and not a.yes and confirm("enter your OpenRouter key now?"):
            k = getpass.getpass("  OpenRouter key (input hidden): ").strip()
            if len(k) >= 20:
                set_key(k)
                key = k
                print("  " + c("key saved \u2014 it will be reused for future scans", "green"))
            else:
                warn("that was too short to be a key \u2014 continuing without one")
        if not key:
            print(dim("    (the summary above comes from other people's scans)"))
            sys.exit(0)

    print(dim("    cloning (shallow)\u2026"))
    try:
        workdir, sha = shallow_clone(r["clone_url"])
    except ScanError as e:
        err(str(e))
        sys.exit(1)
    kv("commit", sha[:12])

    try:
        ci = (client.repo_scans(r["canonical"], sha=sha).get("commit") or {})
        if ci.get("scans"):
            line = (f"this exact commit: {ci['scans']} scans \u00b7 {ci['vulnerabilities']} "
                    f"vulnerabilities \u00b7 {ci.get('telemetry', 0)} telemetry signals")
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

    est = estimate_cost(model, sum(f["size"] for f in selected), len(chunks))
    print(dim(f"    plan: {len(selected)} files \u2192 {len(chunks)} chunks \u00b7 est ${est:.2f} ({model})"))
    if not (a.yes or confirm("proceed with scan on YOUR OpenRouter key?")):
        print(dim("aborted \u2014 nothing scanned, nothing saved."))
        sys.exit(0)

    t0 = time.monotonic()

    def prog(done, total):
        end = "\n" if done == total else ""
        print(f"\r  scanning {done}/{total} chunks\u2026{end}", end="", flush=True)

    print()
    try:
        findings, errs = scan_chunks(key, model, chunks, prog)
    except (KeyRejected, LLMError) as e:
        err(str(e))
        sys.exit(1)
    if errs:
        warn(f"{len(errs)} chunk(s) failed: {errs[0]}")
    if len(errs) == len(chunks):
        err("every chunk failed \u2014 scan aborted, nothing saved")
        sys.exit(1)
    dt = time.monotonic() - t0
    vulns = [f for f in findings if f.get("category") == "vulnerability"]
    tels = [f for f in findings if f.get("category") == "telemetry"]
    high = sum(1 for f in vulns if f["severity"] == "high")
    med = sum(1 for f in vulns if f["severity"] == "medium")
    low = len(vulns) - high - med
    line = (f"done in {dt:.0f}s \u00b7 {len(vulns)} vulnerabilities "
            f"({high} high \u00b7 {med} medium \u00b7 {low} low)"
            f" \u00b7 {len(tels)} telemetry signals")
    print("  " + ARROW + " " + c(line, "bold"))

    report = {"repo": r["canonical"], "commit": sha, "model": model,
              "files_scanned": len(selected), "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "findings": findings}
    rep_path = _save_report(r["owner"], r["name"], sha, report)
    payload = {"repo_url": r["canonical"], "commit_sha": sha, "model": model,
               "files_scanned": len(selected), "findings": findings, "reporter_id": reporter_id()}
    try:
        res = client.submit(payload)
        print("  " + c(f"saved to the public database \u00b7 scan #{res.get('id')}", "green"))
    except APIError as e:
        warn(f"couldn't save to the database ({e}) \u2014 report kept locally")
    print(dim(f"full report: {rep_path}"))
    for f in findings[:10]:
        if f.get("category") == "telemetry":
            tag = "T"
        else:
            tag = f["severity"][:1].upper()
        print(f"    [{tag}] {f['file']}:{f['line']} \u2014 {f['title']}")
    if len(findings) > 10:
        print(dim(f"    \u2026 and {len(findings) - 10} more in the full report"))
    print()


def main(argv=None):
    try:
        _cli(argv)
    except (KeyboardInterrupt, EOFError):
        print("\n  cancelled.")
        sys.exit(130)


if __name__ == "__main__":
    main()
