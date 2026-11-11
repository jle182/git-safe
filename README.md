# 🛡 git safe

**A git wrapper that scans public repos for vulnerabilities — with your own OpenRouter key — and shares the counts so nobody has to pay twice.**

```console
$ git safe tiangolo/fastapi

  git safe  v0.1.0
  repo:       github.com/tiangolo/fastapi
  → 3 scans done · 5 vulnerabilities found
    last scanned 2026-11-02 with openai/gpt-4o-mini
    cloning (shallow)…
  commit:     a1b2c3d4e5f6
  → this exact commit: 2 scans · 5 vulnerabilities
  rescan anyway? [y/N] n
  nothing done.
```

`git-safe` on your `PATH` becomes `git safe` — git turns any `git-*` executable into a subcommand automatically.

## The flow

1. **Ask first.** `git safe owner/repo` checks the shared scan database: *“N scans done · X vulnerabilities found”*.
2. **No key, no scan.** Without `OPENROUTER_API_KEY` you get the summary from other people's scans — and nothing else happens.
3. **Scan with your key.** Confirm the cost estimate, and it shallow-clones, pre-filters the risky files (secrets patterns, auth code, dependency manifests), reviews them with your chosen OpenRouter model, and prints the findings.
4. **Share the counts.** The result is saved to the public database so the next person sees the summary first. Full findings stay in a local report at `~/.cache/git-safe/`.

## Install

**One-liner** (downloads `git-safe.pyz` from GitHub Releases — single executable file, stdlib-only Python):

```console
curl -fsSL https://raw.githubusercontent.com/jle182/git-safe/main/install.sh | sh
```

**Manual:** grab `git-safe.pyz` from [Releases](https://github.com/jle182/git-safe/releases), drop it on your `PATH` as `git-safe`, `chmod +x`, done.

**From source:**

```console
git clone https://github.com/jle182/git-safe && cd git-safe
python3 scripts/build_zipapp.py && cp dist/git-safe.pyz ~/.local/bin/git-safe
```

Requires: Python 3.9+ and git.

## Usage

```console
git safe owner/repo              # any URL form works: full https, .git, git@, owner/repo
git safe https://gitlab.com/o/r  # any public git host
```

| Environment variable | Meaning | Default |
|---|---|---|
| `OPENROUTER_API_KEY` | **required to scan** — your key, used only from your machine | — |
| `OPENROUTER_MODEL` | model for the review pass | `openai/gpt-4o-mini` |
| `GITSAFE_API` | git-safe database API base URL | `http://localhost:8080` |

Flags: `--api URL` · `--model NAME` · `-y` (skip prompts) · `--version`

### Results display

```console
git safe options              # first-run wizard / re-run it anytime
git safe options display top1|top3|all
git safe options telemetry show|hide
git safe options findings none|10|all
```

Scan summaries show the best-ranked models first ([A]/[B]/[C] tiers curated from the PrimeVul vulnerability benchmark; unknown models count as C).

### Key & model management

`git safe help` lists every command with examples.

```console
git safe key            # store/replace your OpenRouter key (hidden input, chmod 600)
git safe key --remove   # forget the stored key
git safe model          # show your current default model
git safe model <id>     # set the default, e.g. openai/gpt-oss-120b
git safe models         # browse OpenRouter's catalog, cheapest first
git safe models free    # zero-cost models only
```

Precedence - model: `--model` flag > `OPENROUTER_MODEL` > stored default > built-in. Key: `OPENROUTER_API_KEY` env > stored key (chmod 600 file).

Guards: public repos only · 5,000-file / 50 MB cap · cost estimate before scanning · duplicate scans per commit+reporter are deduped server-side.

## The server (API + stats site)

One stdlib-only Python process serves the public JSON API **and** the stats website:

```console
python3 server/server.py --addr 127.0.0.1:8080 --db git-safe.db --web web/
```

| Endpoint | What it returns |
|---|---|
| `GET /api/v1/scans?repo=owner/repo` | scan count, vulnerability count, last model, per-commit history (counts only) |
| `GET /api/v1/scans?repo=…&sha=…` | + counts for one exact commit |
| `POST /api/v1/scans` | submit a scan result (validated, rate-limited to 10/h/IP) |
| `GET /api/v1/stats` | totals for the website: scans, repos, vulnerabilities, top repos |

Finding **details** never leave the server — the API publishes counts only.

## Deploy (Vultr, ~$6/mo)

```console
# on a fresh Ubuntu 24.04 box, with this repo checked out:
sudo bash deploy/setup.sh            # uses <ip>.nip.io placeholder domain
sudo bash deploy/setup.sh my.domain  # or a real domain pointed at the box
```

Installs Caddy (auto-HTTPS), a hardened systemd unit, SQLite in WAL mode. Backups = copy the one `.db` file.

## Development

```console
python3 -m unittest discover -s tests -v   # test suite (no network needed)
python3 scripts/build_zipapp.py            # build dist/git-safe.pyz
GITSAFE_API=http://localhost:8080 python3 -m gitsafe owner/repo   # run from source
```

## Honest limitations (v1)

- Findings are **LLM-generated leads, not an audit** — verify everything.
- Scan submissions are anonymous and **spoofable** (rate-limited, shape-validated; verification pass planned).
- Scans are cached per `repo + commit SHA` — different commit, different result.

## Roadmap

- [ ] server-side verification pass on submitted findings
- [ ] telemetry detection as a separate, labeled category
- [ ] web page showing full (opt-in) public reports
- [ ] signed scans from registered reporters

MIT licensed. Not affiliated with OpenRouter or GitHub.
