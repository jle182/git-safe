"use strict";

// ↓ change this once you've created the GitHub repo
const GITHUB_URL = "https://github.com/jle182/git-safe";

const $ = (id) => document.getElementById(id);
const fmt = (n) => Number(n || 0).toLocaleString("en-US");
const esc = (s) => {
  const d = document.createElement("div");
  d.textContent = String(s ?? "");
  return d.innerHTML;
};

document.querySelectorAll("[data-gh]").forEach((a) => (a.href = GITHUB_URL));

const repoPath = GITHUB_URL.replace("https://github.com/", "");
$("install-cmd").textContent =
  `curl -fsSL https://raw.githubusercontent.com/${repoPath}/main/install.sh | sh`;

$("copy-btn").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("install-cmd").textContent.trim());
    $("copy-btn").textContent = "copied ✓";
    setTimeout(() => ($("copy-btn").textContent = "copy"), 1500);
  } catch {}
});

function offline(on) {
  $("offline-banner").classList.toggle("hidden", !on);
}

async function loadStats() {
  try {
    const r = await fetch("/api/v1/stats");
    if (!r.ok) throw new Error("status " + r.status);
    const s = await r.json();
    offline(false);
    $("st-scans").textContent = fmt(s.total_scans);
    $("st-repos").textContent = fmt(s.unique_repos);
    $("st-vulns").textContent = fmt(s.total_vulnerabilities);
    $("st-day").textContent = fmt(s.scans_last_24h);

    const top = s.top_repos || [];
    const max = Math.max(1, ...top.map((t) => t.scans));
    $("top-repos").innerHTML = top.length
      ? `<thead><tr><th>repo</th><th>scans</th><th>vulnerabilities</th><th></th></tr></thead><tbody>` +
        top
          .map(
            (t) => `<tr><td class="mono">${esc(t.repo)}</td><td>${fmt(t.scans)}</td><td>${fmt(t.vulnerabilities)}</td><td class="bar"><span style="width:${(t.scans / max) * 100}%"></span></td></tr>`
          )
          .join("") +
        `</tbody>`
      : `<tr><td colspan="4" class="empty">no scans yet — be the first: <span class="mono">git safe owner/repo</span></td></tr>`;
  } catch {
    offline(true);
  }
}

$("lookup-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const q = $("lookup-input").value.trim();
  if (!q) return;
  const box = $("lookup-result");
  box.classList.remove("hidden");
  box.textContent = "checking…";
  $("lookup-history").classList.add("hidden");
  try {
    const r = await fetch("/api/v1/scans?repo=" + encodeURIComponent(q));
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || "error " + r.status);
    if (!data.scans) {
      box.innerHTML = `→ <b>0 scans so far</b> — first look at this repo`;
    } else {
      box.innerHTML =
        `→ <b>${fmt(data.scans)} scans done · ${fmt(data.vulnerabilities)} vulnerabilities found</b>` +
        `<span class="dim"> · last scanned ${esc(String(data.last_scanned || "").slice(0, 10))} with ${esc(data.last_model || "?")}</span>`;
    }
    const hist = data.history || [];
    if (hist.length) {
      $("lookup-history").classList.remove("hidden");
      $("lookup-history").innerHTML =
        `<thead><tr><th>commit</th><th>date</th><th>model</th><th>files</th><th>vulnerabilities</th></tr></thead><tbody>` +
        hist
          .map(
            (h) => `<tr><td class="mono">${esc(String(h.commit_sha).slice(0, 10))}</td><td>${esc(String(h.scanned_at).slice(0, 10))}</td><td class="mono">${esc(h.model)}</td><td>${fmt(h.files_scanned)}</td><td>${fmt(h.vulnerabilities)}</td></tr>`
          )
          .join("") +
        `</tbody>`;
    }
  } catch (err) {
    box.textContent = "lookup failed — " + (err.message || "server unreachable");
  }
});

loadStats();
setInterval(loadStats, 30000);
