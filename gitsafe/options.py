"""git-safe options: user preferences + model tiers.

Stored at ~/.config/git-safe/options.json. Every option has a default,
so the file is optional; it is created by the first-run wizard or by
quick-set commands like: git safe options display all
"""
import json
from pathlib import Path

DEFAULTS = {"display": "top1", "telemetry": "show", "findings": "none"}
VALID_KEYS = {
    "display": {"top1", "top3", "all"},
    "telemetry": {"show", "hide"},
    "findings": {"none", "10", "all"},
}


def _path():
    return Path.home() / ".config" / "git-safe" / "options.json"


def load():
    opts = dict(DEFAULTS)
    try:
        data = json.loads(_path().read_text())
    except (OSError, ValueError):
        return opts
    for k, v in data.items():
        if k in VALID_KEYS and v in VALID_KEYS[k]:
            opts[k] = v
    return opts


def save(opts):
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    clean = {k: (v if v in VALID_KEYS.get(k) else DEFAULTS[k])
             for k, v in opts.items() if k in VALID_KEYS}
    p.write_text(json.dumps(clean, indent=2) + "\n")


def first_run_needed():
    return not _path().exists()


# --- model tiers, curated from PrimeVul (ICSE'25) leaderboard results -----
# Substring matches on OpenRouter model ids; re-curated each release.
# Tiers are a rough guide to vuln-detection quality, not gospel.
TIER_PATTERNS = [
    ("A", ("gpt-4.1", "gpt-5", "gemini-2.5", "claude-opus-4", "deepseek-v3", "qwen3-coder")),
    ("B", ("gpt-4o", "claude-sonnet-4", "claude-haiku-4", "gemini-2.0", "mistral-large",
           "grok-3", "grok-4", "llama-4", "qwen3", "deepseek")),
]
TIER_RANK = {"A": 0, "B": 1, "C": 2}
LEGEND = "tiers: [A] leading vuln-detection (PrimeVul) - [B] strong - [C] baseline/unknown"


def tier_of(model_id):
    mid = (model_id or "").lower()
    for tier, pats in TIER_PATTERNS:
        if any(p in mid for p in pats):
            return tier
    return "C"


def select_scans(history, mode):
    """Pick which stored scans to display: best tier first, newest first within a tier."""
    if not history:
        return []
    ranked = sorted(history, key=lambda h: str(h.get("scanned_at") or ""), reverse=True)
    ranked.sort(key=lambda h: TIER_RANK.get(tier_of(h.get("model", "")), 2))
    if mode == "top1":
        return ranked[:1]
    if mode == "top3":
        return ranked[:3]
    return ranked
