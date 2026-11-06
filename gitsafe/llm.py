"""OpenRouter integration: chunked security + telemetry review with the user's own key."""
import json
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-4o-mini"
PRICES = {"openai/gpt-4o-mini": (0.15, 0.60), "openai/gpt-oss-120b": (0.07, 0.30)}

SYSTEM = (
    "You are git-safe, a static analyzer for open-source repositories. You receive source "
    "files and report findings in exactly two categories.\n"
    'category "vulnerability": security issues only - hardcoded secrets or keys, SQL/command/'
    "path injection, unsafe deserialization, disabled TLS verification, auth bypass, clearly "
    "dangerous patterns. severity: high = directly exploitable or leaked credential; medium = "
    "risky pattern; low = hardening suggestion.\n"
    'category "telemetry": code that collects or transmits usage data - analytics SDKs, '
    "tracking pixels, session recorders, crash reporters, ads trackers, usage beacons, or "
    "update checkers that phone home. Telemetry findings always use severity \"info\" and are "
    "NOT vulnerabilities; legitimate projects include them, you surface them so users can "
    "decide.\n"
    "Ignore style issues and anything you are not confident about. Respond ONLY with a JSON "
    "object of the form "
    '{"findings": [{"file": "path", "line": 0, "category": "vulnerability|telemetry", '
    '"severity": "high|medium|low|info", "title": "short title", "description": "one sentence"}]}. '
    'If nothing found: {"findings": []}'
)


class LLMError(Exception):
    pass


class KeyRejected(LLMError):
    pass


def _post(key, model, content, timeout=120):
    body = json.dumps({
        "model": model, "temperature": 0, "max_tokens": 1500,
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": content}],
    }).encode()
    req = urllib.request.Request(OPENROUTER_URL, data=body, method="POST", headers={
        "Authorization": "Bearer " + key, "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/jle182/git-safe", "X-Title": "git-safe",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read().decode()).get("error", {}).get("message", "")
        except Exception:
            pass
        if e.code in (401, 403):
            raise KeyRejected(f"OpenRouter rejected the key ({e.code}) {detail}".strip())
        if e.code == 402:
            raise KeyRejected("OpenRouter: this key has no credits left (402)")
        if e.code == 429:
            raise LLMError("rate limited by OpenRouter (429) \u2014 wait a moment and retry")
        raise LLMError(f"OpenRouter error {e.code}: {detail or e.reason}")
    except (urllib.error.URLError, OSError) as e:
        raise LLMError(f"cannot reach OpenRouter: {getattr(e, 'reason', e)}")
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise LLMError("unexpected OpenRouter response shape")


def _extract_json(text):
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.S)
    i, j = t.find("{"), t.rfind("}")
    if i == -1 or j <= i:
        raise ValueError("no JSON object in model response")
    return json.loads(t[i:j + 1])


def _scan_one(key, model, chunk, tries=2):
    last = None
    for _ in range(tries):
        try:
            data = _extract_json(_post(key, model, chunk))
            found = data.get("findings") if isinstance(data, dict) else None
            if not isinstance(found, list):
                raise ValueError("missing findings array")
            out = []
            for f in found:
                if not isinstance(f, dict):
                    continue
                title = str(f.get("title", ""))[:200]
                if not title:
                    continue
                try:
                    line = int(f.get("line") or 0)
                except (TypeError, ValueError):
                    line = 0
                category = ("telemetry"
                            if str(f.get("category", "")).strip().lower() == "telemetry"
                            else "vulnerability")
                sev = str(f.get("severity", "medium")).lower()
                if category == "telemetry":
                    sev = "info"
                elif sev not in ("high", "medium", "low"):
                    sev = "medium"
                out.append({
                    "file": str(f.get("file", "?"))[:512], "line": line,
                    "category": category, "severity": sev,
                    "title": title, "description": str(f.get("description", ""))[:2000],
                })
            return out
        except (ValueError, LLMError) as e:
            if isinstance(e, KeyRejected):
                raise
            last = e
            time.sleep(1)
    raise LLMError(f"model did not return valid JSON: {last}")


SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def scan_chunks(key, model, chunks, on_progress=None):
    findings, errs = [], []
    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = [ex.submit(_scan_one, key, model, ch) for ch in chunks]
        for i, fut in enumerate(as_completed(futs), 1):
            try:
                findings.extend(fut.result())
            except LLMError as e:
                errs.append(str(e))
            if on_progress:
                on_progress(i, len(chunks))
    seen, uniq = set(), []
    for f in findings:
        k = (f["file"], f["line"], f["title"].lower(), f["category"])
        if k in seen:
            continue
        seen.add(k)
        if f["severity"] not in SEV_ORDER:
            f["severity"] = "info" if f["category"] == "telemetry" else "medium"
        uniq.append(f)
    uniq.sort(key=lambda f: SEV_ORDER[f["severity"]])
    return uniq, errs


def estimate_cost(model, total_bytes, n_chunks):
    tin = total_bytes / 4 + n_chunks * 800
    tout = n_chunks * 900
    pin, pout = PRICES.get(model, (0.15, 0.60))
    return tin / 1e6 * pin + tout / 1e6 * pout
