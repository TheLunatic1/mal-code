/**
 * GitHub Malware Scanner Dashboard — Frontend Logic
 */

// ── Electron integration ──────────────────────────────────────────────────────
// When running inside Electron, window.electronAPI is injected by preload.cjs
if (window.electronAPI?.isElectron) {
  document.body.classList.add("is-electron");
  document.getElementById("electron-titlebar").classList.remove("hidden");

  document.getElementById("btn-min").addEventListener("click",   () => window.electronAPI.minimize());
  document.getElementById("btn-max").addEventListener("click",   () => window.electronAPI.maximize());
  document.getElementById("btn-close").addEventListener("click", () => window.electronAPI.close());

  // Update maximize button icon on state change
  window.electronAPI.onMaximizeChange?.((maximized) => {
    document.getElementById("btn-max").textContent = maximized ? "❐" : "□";
  });
}


const state = {
  repos: [],
  patterns: [],
  scanResults: {},   // { "owner/repo": { status, files: [] } }
  activeScan: null,  // active EventSource
  cleanTarget: null, // { owner, repo, filePath }
};

// ── DOM shortcuts ──────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const el = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
};

// ── API helpers ────────────────────────────────────────────────────────────────
async function api(method, path, body) {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "API error");
  return data;
}

// ── Tabs ───────────────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach((c) => c.classList.add("hidden"));
    tab.classList.add("active");
    $(`tab-${tab.dataset.tab}`).classList.remove("hidden");
    if (tab.dataset.tab === "log") loadLog();
    if (tab.dataset.tab === "patterns") loadPatterns();
  });
});

// ── Modals ─────────────────────────────────────────────────────────────────────
function openModal(id) { $(id).classList.remove("hidden"); }
function closeModal(id) { $(id).classList.add("hidden"); }
document.querySelectorAll(".modal-close, [data-modal]").forEach((btn) => {
  btn.addEventListener("click", () => closeModal(btn.dataset.modal || btn.closest(".modal-overlay").id));
});
document.querySelectorAll(".modal-overlay").forEach((overlay) => {
  overlay.addEventListener("click", (e) => { if (e.target === overlay) closeModal(overlay.id); });
});

// ══════════════════════════════════════════════════
// CONNECT / DISCONNECT
// ══════════════════════════════════════════════════
$("connect-btn").addEventListener("click", connect);
$("pat-input").addEventListener("keydown", (e) => { if (e.key === "Enter") connect(); });

async function connect() {
  const token = $("pat-input").value.trim();
  if (!token) return;
  $("connect-btn").disabled = true;
  $("connect-btn").textContent = "Connecting…";
  $("connect-error").classList.add("hidden");
  try {
    const user = await api("POST", "/api/connect", { token });
    $("user-login").textContent = user.login;
    $("user-avatar").src = user.avatar_url;
    $("connect-screen").classList.add("hidden");
    $("app").classList.remove("hidden");
    $("pat-input").value = ""; // clear from DOM immediately
    await loadRepos();
  } catch (err) {
    $("connect-error").textContent = "❌ " + err.message;
    $("connect-error").classList.remove("hidden");
  } finally {
    $("connect-btn").disabled = false;
    $("connect-btn").textContent = "Connect";
  }
}

$("disconnect-btn").addEventListener("click", async () => {
  await api("POST", "/api/disconnect");
  $("app").classList.add("hidden");
  $("connect-screen").classList.remove("hidden");
  state.repos = [];
  state.scanResults = {};
});

// ══════════════════════════════════════════════════
// REPOS
// ══════════════════════════════════════════════════
$("refresh-repos-btn").addEventListener("click", loadRepos);

async function loadRepos() {
  $("repo-list").innerHTML = `<div class="skeleton-list">
    <div class="skeleton"></div><div class="skeleton"></div>
    <div class="skeleton"></div><div class="skeleton"></div>
    <div class="skeleton"></div></div>`;
  try {
    state.repos = await api("GET", "/api/repos");
    renderRepos();
    updateStats();
    populateDeepScanSelect();
  } catch (err) {
    $("repo-list").innerHTML = `<p style="padding:12px;color:var(--danger)">Failed to load repos: ${err.message}</p>`;
  }
}

function renderRepos(filter = "") {
  const list = $("repo-list");
  list.innerHTML = "";
  const filtered = state.repos.filter((r) => r.full_name.toLowerCase().includes(filter.toLowerCase()));
  $("repo-count").textContent = filtered.length;

  filtered.forEach((repo) => {
    const scanResult = state.scanResults[repo.full_name];
    const statusIcon = scanResult
      ? scanResult.infected ? "🦠" : "✅"
      : repo.protected ? "🛡️" : "⬜";

    const item = el("div", `repo-item${scanResult?.infected ? " infected" : ""}`);
    item.innerHTML = `<span class="repo-status-icon">${statusIcon}</span>
      <span class="repo-name" title="${repo.full_name}">${repo.name}</span>
      ${repo.private ? '<span style="font-size:0.7rem;color:var(--text-dim)">🔒</span>' : ""}`;
    item.addEventListener("click", () => {
      document.querySelectorAll(".repo-item").forEach((i) => i.classList.remove("active"));
      item.classList.add("active");
      // Switch to scan tab and trigger deep scan
      document.querySelector('[data-tab="scan"]').click();
      $("deep-scan-repo").value = repo.full_name;
    });
    list.appendChild(item);
  });
}

$("repo-search").addEventListener("input", (e) => renderRepos(e.target.value));

function populateDeepScanSelect() {
  const sel = $("deep-scan-repo");
  sel.innerHTML = `<option value="">— Select a repository —</option>`;
  state.repos.forEach((r) => {
    const opt = document.createElement("option");
    opt.value = r.full_name;
    opt.textContent = r.full_name;
    sel.appendChild(opt);
  });
}

function updateStats() {
  $("stat-total").textContent = state.repos.length;
  const protected_ = state.repos.filter((r) => r.protected).length;
  $("stat-protected").textContent = protected_;

  const scanned = Object.keys(state.scanResults);
  if (scanned.length === 0) {
    $("stat-infected").textContent = "—";
    $("stat-clean").textContent = "—";
    return;
  }
  const infected = scanned.filter((r) => state.scanResults[r].infected).length;
  $("stat-infected").textContent = infected;
  $("stat-clean").textContent = scanned.length - infected;
}

// ══════════════════════════════════════════════════
// SCANNERS (SSE)
// ══════════════════════════════════════════════════
$("scan-all-btn").addEventListener("click", () => startScan("/api/scan/all", "scan-all-btn", "🔍 Scan All (Fast)"));

$("deep-scan-all-btn").addEventListener("click", async () => {
  if (!window.electronAPI) return alert("Requires desktop app.");
  const dest = await window.electronAPI.openFolder();
  if (!dest) return;
  startScan(`/api/scan/deep-all?dest=${encodeURIComponent(dest)}`, "deep-scan-all-btn", "🔬 Deep Scan All");
});

$("scan-local-btn").addEventListener("click", async () => {
  if (!window.electronAPI) return alert("Requires desktop app.");
  const folder = await window.electronAPI.openFolder();
  if (!folder) return;
  startScan(`/api/scan/local?folder=${encodeURIComponent(folder)}`, "scan-local-btn", "📁 Scan Local Folder");
});

function startScan(url, btnId, btnText) {
  if (state.activeScan) { state.activeScan.close(); state.activeScan = null; }

  $("scan-progress").classList.remove("hidden");
  $("infected-panel").classList.add("hidden");
  $("live-feed").innerHTML = "";
  $("progress-label").textContent = "Scanning…";
  $("progress-stats").textContent = "";
  $(btnId).disabled = true;
  $(btnId).textContent = "⏳ Scanning…";

  const infectedReposMap = {};

  const es = new EventSource(url);
  state.activeScan = es;

  es.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    addFeedEntry(msg);

    if (msg.type === "infected") {
      if (!infectedReposMap[msg.repo]) infectedReposMap[msg.repo] = { files: [], patterns: [] };
      
      const fileObj = {
        display: msg.displayPath || msg.file,
        absolute: msg.file
      };
      
      if (!infectedReposMap[msg.repo].files.find(f => f.absolute === fileObj.absolute)) {
        infectedReposMap[msg.repo].files.push(fileObj);
      }
      
      infectedReposMap[msg.repo].patterns.push({ id: msg.patternId, name: msg.patternName, severity: msg.severity });

      state.scanResults[msg.repo] = { infected: true, files: infectedReposMap[msg.repo].files };
    }

    if (msg.type === "done") {
      es.close();
      state.activeScan = null;
      $(btnId).disabled = false;
      $(btnId).textContent = btnText;
      $("progress-label").textContent = "✅ Scan complete";
      $("progress-stats").textContent = `${msg.summary.totalInfected} infected repo(s) found`;
      updateStats();
      renderRepos($("repo-search").value);
      renderInfectedPanel(infectedReposMap);
    }
  };

  es.onerror = () => {
    es.close();
    state.activeScan = null;
    $(btnId).disabled = false;
    $(btnId).textContent = btnText;
    addFeedEntry({ type: "error", message: "Connection lost." });
  };
}

function addFeedEntry(msg) {
  const feed = $("live-feed");
  const entry = el("div", `feed-entry ${msg.type}`);
  const time = new Date().toLocaleTimeString();
  if (msg.type === "infected") {
    entry.innerHTML = `<span style="color:var(--text-dim)">${time}</span>  🦠 <strong>${msg.repo}</strong> — <span style="color:var(--warning)">${msg.file}</span> [${msg.patternName}]`;
  } else {
    entry.innerHTML = `<span style="color:var(--text-dim)">${time}</span>  ${msg.message || JSON.stringify(msg)}`;
  }
  feed.prepend(entry);
}

function renderInfectedPanel(infectedMap) {
  const repos = Object.keys(infectedMap);
  if (repos.length === 0) return;

  $("infected-panel").classList.remove("hidden");
  const list = $("infected-list");
  list.innerHTML = "";

  repos.forEach((repoName) => {
    const data = infectedMap[repoName];
    // For local scans, there is no owner (no /)
    const [owner, repo] = repoName.includes("/") ? repoName.split("/") : [null, null];
    const card = el("div", "infected-repo-card");

    // data.files now contains objects: { display: "...", absolute: "..." }
    const uniqueFiles = data.files.filter((v, i, a) => a.findIndex(t => (t.display === v.display)) === i);
    const patternSet = [...new Map(data.patterns.map((p) => [p.id, p])).values()];

    card.innerHTML = `
      <div class="infected-repo-header">
        <div>
          <div class="infected-repo-name">🦠 ${repoName}</div>
          <div style="font-size:0.8rem;color:var(--text-muted);margin-top:3px">${uniqueFiles.length} infected file(s)</div>
        </div>
        <div class="infected-repo-actions">
          ${owner ? `<button class="btn btn-sm btn-outline" onclick="triggerDeepScan('${owner}','${repo}')">🔬 Deep Scan</button>
                     <button class="btn btn-sm btn-danger" onclick="deployAction('${owner}','${repo}',this)">🛡️ Re-Deploy Action</button>` 
                  : `<span class="badge">Local Folder</span>`}
        </div>
      </div>
      ${uniqueFiles.map((f) => `
        <div class="infected-file">
          <span class="infected-file-path">${f.display}</span>
          <div class="infected-file-patterns">
            ${patternSet.map((p) => `<span class="severity-tag severity-${p.severity}">${p.severity}</span>`).join("")}
            <button class="btn btn-sm btn-danger" onclick="confirmClean('${owner || ''}','${repo || ''}','${f.absolute.replace(/\\/g, '\\\\')}')">🧹 Clean</button>
          </div>
        </div>`).join("")}
    `;
    list.appendChild(card);
  });
}

// ══════════════════════════════════════════════════
// DEEP SCAN (single repo, SSE)
// ══════════════════════════════════════════════════
$("deep-scan-btn").addEventListener("click", () => {
  const val = $("deep-scan-repo").value;
  if (!val) return;
  const [owner, repo] = val.split("/");
  triggerDeepScan(owner, repo);
});

function triggerDeepScan(owner, repo) {
  document.querySelector('[data-tab="scan"]').click();
  $("deep-scan-repo").value = `${owner}/${repo}`;

  const resultsEl = $("deep-scan-results");
  const filesEl = $("deep-scan-files");
  resultsEl.classList.remove("hidden");
  filesEl.innerHTML = `<div style="padding:20px;color:var(--text-muted);text-align:center">🔬 Scanning ${owner}/${repo}…</div>`;
  $("deep-scan-title").textContent = `${owner}/${repo}`;
  $("deep-scan-badges").innerHTML = "";
  $("deep-scan-btn").disabled = true;

  let infectedCount = 0, scannedCount = 0;

  const es = new EventSource(`/api/scan/${owner}/${repo}`);
  es.onmessage = (e) => {
    const msg = JSON.parse(e.data);

    if (msg.type === "start" || msg.type === "info") {
      filesEl.innerHTML = "";
      return;
    }

    if (msg.type === "infected") {
      infectedCount++;
      scannedCount++;
      const item = el("div", "file-item infected");
      const matchesHtml = msg.matches.map((m) =>
        `<span class="severity-tag severity-${m.severity}">${m.patternName}</span>
         <div class="match-preview" title="${m.preview}">${m.preview}</div>
         ${m.autoClean ? `<button class="btn btn-sm btn-danger" onclick="confirmClean('${owner}','${repo}','${msg.file}')">🧹 Clean</button>` : ""}`
      ).join("");
      item.innerHTML = `<span class="file-path">${msg.file}</span><div class="file-matches">${matchesHtml}</div>`;
      filesEl.appendChild(item);
    }

    if (msg.type === "clean") {
      scannedCount++;
      const item = el("div", "file-item");
      item.innerHTML = `<span class="file-path">${msg.file}</span><span style="color:var(--success);font-size:0.8rem">✅ clean</span>`;
      filesEl.appendChild(item);
    }

    if (msg.type === "done") {
      es.close();
      $("deep-scan-btn").disabled = false;
      $("deep-scan-title").textContent = `${owner}/${repo} — ${msg.summary.filesScanned} files scanned`;
      $("deep-scan-badges").innerHTML = infectedCount > 0
        ? `<span class="severity-tag severity-critical">🦠 ${infectedCount} infected</span>`
        : `<span class="severity-tag" style="background:var(--success-glow);color:var(--success)">✅ All clean</span>`;
      state.scanResults[`${owner}/${repo}`] = { infected: infectedCount > 0, files: [] };
      updateStats();
      renderRepos($("repo-search").value);
    }

    if (msg.type === "error") {
      es.close();
      $("deep-scan-btn").disabled = false;
      filesEl.innerHTML = `<div style="padding:20px;color:var(--danger)">❌ ${msg.message}</div>`;
    }
  };
  es.onerror = () => { es.close(); $("deep-scan-btn").disabled = false; };
}

// ══════════════════════════════════════════════════
// CLEAN
// ══════════════════════════════════════════════════
function confirmClean(owner, repo, filePath) {
  state.cleanTarget = { owner, repo, filePath };
  $("clean-target-display").textContent = `${owner}/${repo}  →  ${filePath}`;
  openModal("modal-clean");
}

$("confirm-clean-btn").addEventListener("click", async () => {
  const { owner, repo, filePath } = state.cleanTarget;
  $("confirm-clean-btn").disabled = true;
  $("confirm-clean-btn").textContent = "Cleaning…";
  try {
    const result = await api("POST", "/api/clean", { owner, repo, filePath });
    closeModal("modal-clean");
    alert(`✅ ${result.patched ? `Cleaned! Patterns removed: ${result.patternsRemoved.join(", ")}` : result.message}`);
    loadLog();
  } catch (err) {
    alert("❌ " + err.message);
  } finally {
    $("confirm-clean-btn").disabled = false;
    $("confirm-clean-btn").textContent = "🧹 Clean File";
  }
});

// ══════════════════════════════════════════════════
// DEPLOY ACTION
// ══════════════════════════════════════════════════
$("deploy-all-btn").addEventListener("click", async () => {
  if (!confirm("Are you sure you want to deploy the auto-scanner workflow to ALL repositories?")) return;

  $("deploy-all-btn").disabled = true;
  $("deploy-all-btn").textContent = "⏳ Deploying…";

  try {
    const res = await fetch("/api/deploy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ all: true })
    });
    const data = await res.json();
    alert(`Successfully deployed to ${data.ok?.length || 0} repositories.\nFailed: ${data.error?.length || 0}`);
  } catch (err) {
    alert("Error: " + err.message);
  }

  $("deploy-all-btn").disabled = false;
  $("deploy-all-btn").textContent = "🛡️ Deploy Action to All";
});

$("remove-action-btn").addEventListener("click", async () => {
  if (!confirm("Are you sure you want to REMOVE the auto-scanner workflow from ALL repositories?")) return;

  $("remove-action-btn").disabled = true;
  $("remove-action-btn").textContent = "⏳ Removing…";

  try {
    const res = await fetch("/api/action/remove", {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });
    const data = await res.json();
    alert(`Successfully removed from ${data.ok?.length || 0} repositories.\nFailed: ${data.error?.length || 0}`);
  } catch (err) {
    alert("Error: " + err.message);
  }

  $("remove-action-btn").disabled = false;
  $("remove-action-btn").textContent = "🗑️ Remove Action from All";
});

async function deployAction(owner, repo, btn) {
  btn.disabled = true;
  btn.textContent = "⏳";
  try {
    await api("POST", "/api/deploy", { owner, repo });
    btn.textContent = "✅ Deployed";
    btn.classList.remove("btn-danger");
    btn.classList.add("btn-outline");
  } catch (err) {
    btn.disabled = false;
    btn.textContent = "❌ Retry";
    alert("Deploy failed: " + err.message);
  }
}

// ══════════════════════════════════════════════════
// PATTERNS
// ══════════════════════════════════════════════════
async function loadPatterns() {
  state.patterns = await api("GET", "/api/patterns");
  renderPatterns();
}

function renderPatterns() {
  const list = $("pattern-list");
  list.innerHTML = "";
  state.patterns.forEach((p) => {
    const card = el("div", "pattern-card");
    card.innerHTML = `
      <div>
        <div class="pattern-card-header">
          <span class="severity-tag severity-${p.severity}">${p.severity}</span>
          <span class="pattern-card-name">${p.name}</span>
          ${p.autoClean ? '<span class="autoclean-tag">⚡ Auto-Clean</span>' : ""}
        </div>
        <div class="pattern-card-desc">${p.description || "No description."}</div>
        ${p.literal ? `<div style="font-size:0.78rem;color:var(--text-muted);margin-bottom:6px">🔍 Literal: <code style="color:var(--warning)">${p.literal}</code></div>` : ""}
        <div class="pattern-regex">${p.regex}</div>
      </div>
      <div class="pattern-card-actions">
        ${p.id !== "a11-backdoor" ? `<button class="btn btn-sm btn-ghost" onclick="deletePattern('${p.id}', this)">🗑</button>` : '<span style="font-size:0.7rem;color:var(--text-dim)">built-in</span>'}
      </div>`;
    list.appendChild(card);
  });
}

async function deletePattern(id, btn) {
  if (!confirm(`Delete pattern "${id}"?`)) return;
  btn.disabled = true;
  try {
    await api("DELETE", `/api/patterns/${id}`);
    await loadPatterns();
  } catch (err) {
    alert("❌ " + err.message);
    btn.disabled = false;
  }
}

// Add pattern modal
$("add-pattern-btn").addEventListener("click", () => openModal("modal-add-pattern"));

$("np-regex").addEventListener("input", () => {
  const errEl = $("np-regex-error");
  try { new RegExp($("np-regex").value); errEl.classList.add("hidden"); }
  catch (e) { errEl.textContent = "Invalid regex: " + e.message; errEl.classList.remove("hidden"); }
});

$("save-pattern-btn").addEventListener("click", async () => {
  const pattern = {
    id: $("np-id").value.trim(),
    name: $("np-name").value.trim(),
    description: $("np-description").value.trim(),
    literal: $("np-literal").value.trim(),
    regex: $("np-regex").value.trim(),
    severity: $("np-severity").value,
    autoClean: $("np-autoclean").value === "true",
    extensions: ["js", "ts", "tsx", "jsx"],
  };
  if (!pattern.id || !pattern.name || !pattern.regex) return alert("ID, Name, and Regex are required.");
  try {
    await api("POST", "/api/patterns", pattern);
    closeModal("modal-add-pattern");
    ["np-id","np-name","np-description","np-literal","np-regex"].forEach((id) => $(id).value = "");
    await loadPatterns();
  } catch (err) { alert("❌ " + err.message); }
});

// Import patterns
$("import-pattern-btn").addEventListener("click", () => openModal("modal-import-pattern"));

$("do-import-btn").addEventListener("click", async () => {
  const raw = $("import-json").value.trim();
  const errEl = $("import-error");
  let patterns;
  try { patterns = JSON.parse(raw); }
  catch (e) { errEl.textContent = "Invalid JSON: " + e.message; errEl.classList.remove("hidden"); return; }
  errEl.classList.add("hidden");
  try {
    const result = await api("POST", "/api/patterns/import", { patterns, mode: $("import-mode").value });
    closeModal("modal-import-pattern");
    $("import-json").value = "";
    alert(`✅ Import complete: ${result.added} added, ${result.updated} updated. Total: ${result.total} patterns.`);
    await loadPatterns();
  } catch (err) { errEl.textContent = "❌ " + err.message; errEl.classList.remove("hidden"); }
});

// ══════════════════════════════════════════════════
// ACTIVITY LOG
// ══════════════════════════════════════════════════
async function loadLog() {
  try {
    const entries = await api("GET", "/api/log");
    const logEl = $("activity-log");
    logEl.innerHTML = "";
    if (entries.length === 0) {
      logEl.innerHTML = `<p style="color:var(--text-muted);padding:12px">No activity yet.</p>`;
      return;
    }
    entries.forEach((entry) => {
      const e = el("div", `log-entry ${entry.type}`);
      const t = new Date(entry.timestamp).toLocaleTimeString();
      e.innerHTML = `<span class="log-time">${t}</span><span class="log-msg">${entry.message}</span>`;
      logEl.appendChild(e);
    });
  } catch (_) {}
}

$("clear-log-btn").addEventListener("click", () => {
  $("activity-log").innerHTML = `<p style="color:var(--text-muted);padding:12px">Log cleared (session only).</p>`;
});

// ── Init ───────────────────────────────────────────────────────────────────────
(async function init() {
  // Check if already connected (e.g. page refresh with active session)
  try {
    const status = await api("GET", "/api/status");
    if (status.connected) {
      $("user-login").textContent = status.login;
      $("connect-screen").classList.add("hidden");
      $("app").classList.remove("hidden");
      await loadRepos();
      await loadPatterns();
    }
  } catch (_) {}
})();
