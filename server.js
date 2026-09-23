/**
 * GitHub Malware Scanner Dashboard — Backend Server
 * ==================================================
 * Run:  node server.js
 * Open: http://localhost:4000
 */

import express from "express";
import { Octokit } from "@octokit/rest";
import fs from "fs";
import path from "path";
import AdmZip from "adm-zip";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 4000;

// ── In-memory session (PAT never written to disk from UI) ─────────────────────
let session = { token: null, login: null, octokit: null };

// ── Activity log (in-memory, resets on restart) ───────────────────────────────
const activityLog = [];
function addLog(type, message, meta = {}) {
  const entry = { id: Date.now(), type, message, meta, timestamp: new Date().toISOString() };
  activityLog.unshift(entry);
  if (activityLog.length > 200) activityLog.pop();
  return entry;
}

// ── Patterns file ─────────────────────────────────────────────────────────────
// In Electron, main.js sets PATTERNS_FILE to the writable userData path.
// When run standalone (node server.js), fall back to the local file.
const PATTERNS_FILE = process.env.PATTERNS_FILE || path.join(__dirname, "patterns.json");
function loadPatterns() {
  return JSON.parse(fs.readFileSync(PATTERNS_FILE, "utf8"));
}
function savePatterns(patterns) {
  fs.writeFileSync(PATTERNS_FILE, JSON.stringify(patterns, null, 2), "utf8");
}

// ── GitHub Actions workflow template ──────────────────────────────────────────
const WORKFLOW_YAML = `# Malware Auto-Scanner
# Scans every push for obfuscated payloads, Ethereum RPC worms, and hidden scripts and auto-removes them.
name: Malware Auto-Scanner

on:
  push:
    branches: ["**"]

permissions:
  contents: write

concurrency:
  group: malware-scan-\${{ github.ref }}
  cancel-in-progress: true

jobs:
  scan-and-clean:
    name: Scan & Remove Malicious Payload
    runs-on: ubuntu-latest
    if: "!contains(github.event.head_commit.message, '[skip ci]')"

    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 1

      - name: Scan and remove malicious payloads
        id: scan
        run: |
          set -euo pipefail
<<<<<<< Updated upstream
          FOUND=0
          while IFS= read -r -d '' file; do
            if grep -qF '
<<<<<<< Updated upstream
=======
=======

          node -e '
            const fs = require("fs");
            const path = require("path");

            const JS_EXTS = new Set([".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"]);
            const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", ".turbo", ".cache", "coverage"]);

            const CLEAN_PATTERNS = [
              /[ \\t]{20,}function\\s+[a-zA-Z0-9_$]+_padNcYwam[\\s\\S]*/g,
              /[ \\t]{20,}const\\s+BEf\\$CYFUWXrAiwaYBJ[\\s\\S]*/g,
              /global\\.i="A11-#"([\\s\\S]*)/g,
              /global\\[["\x27]i["\x27]\\]\\s*=\\s*[^;]+;[\\s\\S]*/g,
              /[ \\t]{40,}(?:function|const|var|let|eval|spawn|global|\\(|\\[)[\\s\\S]*/g,
              /withRpcEndpoints[\\s\\S]*/g,
              /_padNcYwam[\\s\\S]*/g
            ];

            const INFECTION_CHECK = /GSkqNNyuJw|withRpcEndpoints|WlysIxGuPMcViepbraDjp|_padNcYwam|candidateBlocks|NONCE_FANOUT|BLOCK_MULTIPLE|global\\.i\\s*=\\s*["\x27]A11-#|BEf\\$CYFUWXrAiwaYBJ/;

            let patchedCount = 0;

            function walk(dir) {
              let entries;
              try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch(e) { return; }
              for (const entry of entries) {
                if (entry.isDirectory()) {
                  if (!SKIP_DIRS.has(entry.name)) walk(path.join(dir, entry.name));
                } else if (entry.isFile()) {
                  const ext = path.extname(entry.name).toLowerCase();
                  if (JS_EXTS.has(ext)) {
                    const filePath = path.join(dir, entry.name);
                    try {
                      const src = fs.readFileSync(filePath, "utf8");
                      if (INFECTION_CHECK.test(src)) {
                        let cleaned = src;
                        for (const pat of CLEAN_PATTERNS) {
                          cleaned = cleaned.replace(pat, "");
                        }
                        cleaned = cleaned.trimEnd() + "\\n";
                        if (cleaned !== src) {
                          fs.writeFileSync(filePath, cleaned, "utf8");
                          console.log("🩹 Patched:", filePath);
                          patchedCount++;
                        }
                      }
                    } catch (e) {}
                  }
                }
              }
            }

            walk(".");
            fs.appendFileSync(process.env.GITHUB_OUTPUT, \`found=\${patchedCount > 0 ? "1" : "0"}\\n\`);
          '

      - name: Commit and push clean code
        if: steps.scan.outputs.found == '1'
        run: |
          git config user.name  "Malware Scanner"
          git config user.email "malware-scanner@github-actions"
          git add -A
          git commit -m "chore: remove malicious payload [skip ci]"
          git push
`;

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

// Auth guard
function requireAuth(req, res, next) {
  if (!session.token) return res.status(401).json({ error: "Not connected. Please provide your PAT." });
  next();
}

// ── SSE helper ────────────────────────────────────────────────────────────────
function sseSetup(res) {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();
}
function sseSend(res, data) {
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

// ── Rate limit helper ─────────────────────────────────────────────────────────
async function withRetry(fn, label = "") {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (err.status === 403 || err.status === 429) {
        const wait = 62_000;
        console.log(`Rate limited on ${label}, waiting ${wait / 1000}s…`);
        await new Promise((r) => setTimeout(r, wait));
      } else {
        throw err;
      }
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// ── POST /api/connect ─────────────────────────────────────────────────────────
app.post("/api/connect", async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: "Token is required." });
  try {
    const octokit = new Octokit({ auth: token });
    const { data: user } = await octokit.rest.users.getAuthenticated();
    session = { token, login: user.login, octokit };
    addLog("info", `Connected as ${user.login}`);
    res.json({ login: user.login, avatar_url: user.avatar_url, name: user.name });
  } catch (err) {
    res.status(401).json({ error: "Invalid token or GitHub API error: " + err.message });
  }
});

// ── POST /api/disconnect ──────────────────────────────────────────────────────
app.post("/api/disconnect", (req, res) => {
  session = { token: null, login: null, octokit: null };
  res.json({ ok: true });
});

// ── GET /api/repos ────────────────────────────────────────────────────────────
app.get("/api/repos", requireAuth, async (req, res) => {
  try {
    const repos = await session.octokit.paginate(
      session.octokit.rest.repos.listForAuthenticatedUser,
      { per_page: 100, affiliation: "owner", sort: "updated" }
    );

    // Check protection status in parallel (batched to avoid rate limits)
    const BATCH = 10;
    const results = [];
    for (let i = 0; i < repos.length; i += BATCH) {
      const batch = repos.slice(i, i + BATCH);
      const checked = await Promise.all(
        batch.map(async (repo) => {
          let protected_ = false;
          try {
            await session.octokit.rest.repos.getContent({
              owner: repo.owner.login,
              repo: repo.name,
              path: ".github/workflows/malware-scan.yml",
            });
            protected_ = true;
          } catch (_) {}
          return {
            id: repo.id,
            full_name: repo.full_name,
            name: repo.name,
            owner: repo.owner.login,
            private: repo.private,
            language: repo.language,
            updated_at: repo.updated_at,
            html_url: repo.html_url,
            protected: protected_,
            scanStatus: "unscanned",
          };
        })
      );
      results.push(...checked);
    }

    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/scan/all (SSE) ───────────────────────────────────────────────────
// Uses GitHub Code Search — fast, no cloning needed
app.get("/api/scan/all", requireAuth, async (req, res) => {
  sseSetup(res);
  const patterns = loadPatterns();
  const infectedMap = {}; // { "owner/repo": { files: [], patterns: [] } }

  sseSend(res, { type: "start", message: `Scanning with ${patterns.length} pattern(s) via GitHub Code Search…` });
  addLog("scan", `Full scan started by ${session.login}`);

  for (const pattern of patterns) {
    if (!pattern.literal) continue;
    const langs = ["JavaScript", "TypeScript"];

    for (const lang of langs) {
      const query = `${pattern.literal} user:${session.login} language:${lang}`;
      sseSend(res, { type: "progress", message: `Searching: [${pattern.name}] in ${lang}…` });

      let page = 1;
      while (true) {
        let result;
        try {
          result = await withRetry(
            () => session.octokit.rest.search.code({ q: query, per_page: 100, page }),
            `search page ${page}`
          );
        } catch (err) {
          sseSend(res, { type: "error", message: `Search error for pattern "${pattern.name}": ${err.message}` });
          break;
        }

        for (const item of result.data.items) {
          const repoName = item.repository.full_name;
          if (!infectedMap[repoName]) infectedMap[repoName] = { files: [], patternIds: new Set() };
          infectedMap[repoName].files.push(item.path);
          infectedMap[repoName].patternIds.add(pattern.id);
          sseSend(res, {
            type: "infected",
            repo: repoName,
            file: item.path,
            patternId: pattern.id,
            patternName: pattern.name,
            severity: pattern.severity,
          });
        }

        // Small delay to respect secondary rate limits
        await new Promise((r) => setTimeout(r, 500));
        if (result.data.items.length < 100) break;
        page++;
      }
    }
  }

  // Build summary
  const infectedRepos = Object.keys(infectedMap);
  const summary = {
    totalInfected: infectedRepos.length,
    infectedRepos: infectedRepos.map((r) => ({
      repo: r,
      files: [...new Set(infectedMap[r].files)],
      patternIds: [...infectedMap[r].patternIds],
    })),
  };

  if (infectedRepos.length === 0) {
    addLog("success", "Full scan complete — no infections found");
  } else {
    addLog("warning", `Full scan complete — ${infectedRepos.length} repo(s) infected`);
  }

  sseSend(res, { type: "done", summary });
  res.end();
});

// ── GET /api/scan/:owner/:repo (SSE) — deep per-file scan ─────────────────────
app.get("/api/scan/:owner/:repo", requireAuth, async (req, res) => {
  const { owner, repo } = req.params;
  sseSetup(res);
  const patterns = loadPatterns();

  sseSend(res, { type: "start", message: `Deep scanning ${owner}/${repo}…` });

  try {
    // Get full file tree
    const { data: treeData } = await session.octokit.rest.git.getTree({
      owner, repo,
      tree_sha: "HEAD",
      recursive: "1",
    });

    const jsFiles = treeData.tree.filter(
      (f) =>
        f.type === "blob" &&
        /\.(js|ts|tsx|jsx|mjs|cjs)$/.test(f.path) &&
        !f.path.startsWith("node_modules/")
    );

    sseSend(res, { type: "info", message: `Found ${jsFiles.length} JS/TS file(s) to scan.` });

    const infected = [];

    for (const file of jsFiles) {
      let content;
      try {
        const { data } = await session.octokit.rest.repos.getContent({
          owner, repo, path: file.path,
        });
        content = Buffer.from(data.content, "base64").toString("utf8");
      } catch (_) {
        continue; // skip binary or inaccessible files
      }

      const fileMatches = [];
      for (const pattern of patterns) {
        try {
          const rx = new RegExp(pattern.regex, "g");
          const matches = [...content.matchAll(rx)];
          if (matches.length > 0) {
            fileMatches.push({
              patternId: pattern.id,
              patternName: pattern.name,
              severity: pattern.severity,
              autoClean: pattern.autoClean,
              count: matches.length,
              preview: matches[0][0].slice(0, 120),
            });
          }
        } catch (_) {}
      }

      if (fileMatches.length > 0) {
        infected.push({ file: file.path, matches: fileMatches });
        sseSend(res, { type: "infected", file: file.path, matches: fileMatches });
      } else {
        sseSend(res, { type: "clean", file: file.path });
      }

      await new Promise((r) => setTimeout(r, 50)); // small delay
    }

    const summary = { repo: `${owner}/${repo}`, filesScanned: jsFiles.length, infectedFiles: infected.length, infected };
    addLog(infected.length > 0 ? "warning" : "success", `Deep scan of ${owner}/${repo}: ${infected.length} infected file(s)`, summary);
    sseSend(res, { type: "done", summary });
  } catch (err) {
    sseSend(res, { type: "error", message: err.message });
    addLog("error", `Deep scan failed for ${owner}/${repo}: ${err.message}`);
  }

  res.end();
});

// ── GET /api/scan/deep-all (SSE) ──────────────────────────────────────────────
app.get("/api/scan/deep-all", requireAuth, async (req, res) => {
  const destFolder = req.query.dest;
  sseSetup(res);
  const patterns = loadPatterns();

  if (!destFolder) {
    sseSend(res, { type: "error", message: "Destination folder is required." });
    return res.end();
  }

  sseSend(res, { type: "start", message: `Fetching repository list…` });
  addLog("scan", `Deep Scan All started by ${session.login}`);

  try {
    const repos = await session.octokit.paginate(
      session.octokit.rest.repos.listForAuthenticatedUser,
      { per_page: 100, affiliation: "owner", sort: "updated" }
    );

    const infectedMap = {};

    let count = 0;
    for (const repo of repos) {
      count++;
      const owner = repo.owner.login;
      const repoName = repo.name;
      const fullRepoName = `${owner}/${repoName}`;

      sseSend(res, { type: "progress", message: `[${count}/${repos.length}] Downloading & scanning ${fullRepoName}…` });

      try {
        const { data: zipData } = await withRetry(
          () => session.octokit.request('GET /repos/{owner}/{repo}/zipball/{ref}', {
            owner, repo: repoName, ref: repo.default_branch
          }),
          `zipball ${fullRepoName}`
        );

        const zip = new AdmZip(Buffer.from(zipData));
        const extractPath = path.join(destFolder, repoName);
        
        // Extract to local disk as requested
        zip.extractAllTo(extractPath, true);

        // Scan the extracted files
        const files = [];
        function walk(dir) {
          const list = fs.readdirSync(dir);
          for (const file of list) {
            const filepath = path.join(dir, file);
            const stat = fs.statSync(filepath);
            if (stat.isDirectory()) {
              if (file !== "node_modules") walk(filepath);
            } else if (/\.(js|ts|tsx|jsx|mjs|cjs)$/.test(file)) {
              files.push(filepath);
            }
          }
        }
        
        if (fs.existsSync(extractPath)) walk(extractPath);

        let repoInfected = false;
        for (const file of files) {
          let content;
          try { content = fs.readFileSync(file, "utf8"); } catch (_) { continue; }

          for (const pattern of patterns) {
            try {
              const rx = new RegExp(pattern.regex, "g");
              const matches = [...content.matchAll(rx)];
              if (matches.length > 0) {
                if (!infectedMap[fullRepoName]) infectedMap[fullRepoName] = { files: [], patternIds: new Set() };
                
                // Keep relative paths for UI
                const relPath = path.relative(extractPath, file).replace(/\\/g, '/');
                infectedMap[fullRepoName].files.push(relPath);
                infectedMap[fullRepoName].patternIds.add(pattern.id);
                repoInfected = true;

                sseSend(res, {
                  type: "infected",
                  repo: fullRepoName,
                  file: file, // Absolute path for local cleaning
                  displayPath: relPath, // Relative path for UI
                  patternId: pattern.id,
                  patternName: pattern.name,
                  severity: pattern.severity,
                });
              }
            } catch (_) {}
          }
        }
        
        if (!repoInfected) sseSend(res, { type: "clean", file: fullRepoName });
        await new Promise((r) => setTimeout(r, 100)); // slight delay
      } catch (err) {
        // repo might be empty
      }
    }

    const infectedRepos = Object.keys(infectedMap);
    const summary = {
      totalInfected: infectedRepos.length,
      infectedRepos: infectedRepos.map((r) => ({
        repo: r,
        files: [...new Set(infectedMap[r].files)],
        patternIds: [...infectedMap[r].patternIds],
      })),
    };

    addLog(infectedRepos.length > 0 ? "warning" : "success", `Deep Scan All complete: ${infectedRepos.length} repo(s) infected`);
    sseSend(res, { type: "done", summary });
  } catch (err) {
    sseSend(res, { type: "error", message: `Scan error: ${err.message}` });
  }

  res.end();
});

// ── GET /api/scan/local (SSE) ──────────────────────────────────────────────────
app.get("/api/scan/local", requireAuth, async (req, res) => {
  const folderPath = req.query.folder;
  sseSetup(res);
  const patterns = loadPatterns();

  if (!folderPath || !fs.existsSync(folderPath)) {
    sseSend(res, { type: "error", message: "Invalid or missing folder path." });
    return res.end();
  }

  sseSend(res, { type: "start", message: `Scanning local folder: ${folderPath}` });
  addLog("scan", `Local scan started on ${folderPath}`);

  try {
    const files = [];
    function walk(dir) {
      const list = fs.readdirSync(dir);
      for (const file of list) {
        const filepath = path.join(dir, file);
        const stat = fs.statSync(filepath);
        if (stat.isDirectory()) {
          if (file !== "node_modules" && file !== ".git") walk(filepath);
        } else if (/\.(js|ts|tsx|jsx|mjs|cjs)$/.test(file)) {
          files.push(filepath);
        }
      }
    }
    walk(folderPath);

    const infectedMap = {};
    let repoInfected = false;
    const repoName = path.basename(folderPath);

    for (const file of files) {
      let content;
      try { content = fs.readFileSync(file, "utf8"); } catch (_) { continue; }

      for (const pattern of patterns) {
        try {
          const rx = new RegExp(pattern.regex, "g");
          const matches = [...content.matchAll(rx)];
          if (matches.length > 0) {
            if (!infectedMap[repoName]) infectedMap[repoName] = { files: [], patternIds: new Set() };
            
            const relPath = path.relative(folderPath, file).replace(/\\/g, '/');
            infectedMap[repoName].files.push(relPath);
            infectedMap[repoName].patternIds.add(pattern.id);
            repoInfected = true;

            sseSend(res, {
              type: "infected",
              repo: repoName,
              file: file, // Absolute path for local cleaning
              displayPath: relPath, // Relative path for UI
              patternId: pattern.id,
              patternName: pattern.name,
              severity: pattern.severity,
            });
          }
        } catch (_) {}
      }
    }

    if (!repoInfected) sseSend(res, { type: "clean", file: repoName });

    const infectedRepos = Object.keys(infectedMap);
    const summary = {
      totalInfected: infectedRepos.length,
      infectedRepos: infectedRepos.map((r) => ({
        repo: r,
        files: [...new Set(infectedMap[r].files)],
        patternIds: [...infectedMap[r].patternIds],
      })),
    };

    addLog(infectedRepos.length > 0 ? "warning" : "success", `Local scan complete: ${infectedRepos.length} folder(s) infected`);
    sseSend(res, { type: "done", summary });
  } catch (err) {
    sseSend(res, { type: "error", message: `Scan error: ${err.message}` });
  }

  res.end();
});
// ── POST /api/clean ───────────────────────────────────────────────────────────
// body: { owner, repo, filePath }
app.post("/api/clean", requireAuth, async (req, res) => {
  const { owner, repo, filePath } = req.body;
  
  if (!filePath) {
    return res.status(400).json({ error: "filePath is required." });
  }

  const patterns = loadPatterns();
  const isLocal = !owner || !repo;

  try {
    let original, sha;
    
    if (isLocal) {
      if (!fs.existsSync(filePath)) throw new Error("Local file not found.");
      original = fs.readFileSync(filePath, "utf8");
    } else {
      const { data: fileData } = await session.octokit.rest.repos.getContent({
        owner, repo, path: filePath,
      });
      original = Buffer.from(fileData.content, "base64").toString("utf8");
      sha = fileData.sha;
    }

    let cleaned = original;
    const applied = [];

    for (const pattern of patterns) {
      try {
        const before = cleaned;
        const rx = new RegExp(pattern.regex, "g");
        cleaned = cleaned.replace(rx, "");
        if (cleaned !== before) applied.push(pattern.name);
      } catch (_) {}
    }

    if (cleaned === original) {
      return res.json({ patched: false, message: "No patterns matched in this file." });
    }

    if (isLocal) {
      fs.writeFileSync(filePath, cleaned, "utf8");
      addLog("success", `Cleaned local file ${filePath}`, { patternsRemoved: applied });
    } else {
      await session.octokit.rest.repos.createOrUpdateFileContents({
        owner, repo, path: filePath,
        message: "chore: remove malicious payload [skip ci]",
        content: Buffer.from(cleaned).toString("base64"),
        sha,
      });
      addLog("success", `Cleaned ${filePath} in ${owner}/${repo}`, { patternsRemoved: applied });
    }

    res.json({ patched: true, patternsRemoved: applied, file: filePath });
  } catch (err) {
    addLog("error", `Clean failed for ${filePath}: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/deploy ──────────────────────────────────────────────────────────
// body: { owner, repo } OR { all: true }
app.post("/api/deploy", requireAuth, async (req, res) => {
  const { owner, repo, all } = req.body;
  const content = Buffer.from(WORKFLOW_YAML).toString("base64");

  async function deployToRepo(o, r) {
    let sha;
    try {
      const { data } = await session.octokit.rest.repos.getContent({
        owner: o, repo: r, path: ".github/workflows/malware-scan.yml",
      });
      sha = data.sha;
    } catch (_) {}

    await session.octokit.rest.repos.createOrUpdateFileContents({
      owner: o, repo: r,
      path: ".github/workflows/malware-scan.yml",
      message: "ci: add malware auto-scanner workflow [skip ci]",
      content,
      ...(sha ? { sha } : {}),
    });
  }

  try {
    if (all) {
      const repos = await session.octokit.paginate(
        session.octokit.rest.repos.listForAuthenticatedUser,
        { per_page: 100, affiliation: "owner" }
      );
      const results = { ok: [], error: [] };
      for (const r of repos) {
        try {
          await deployToRepo(r.owner.login, r.name);
          results.ok.push(r.full_name);
          await new Promise((resolve) => setTimeout(resolve, 300));
        } catch (err) {
          results.error.push({ repo: r.full_name, error: err.message });
        }
      }
      addLog("success", `Action deployed to ${results.ok.length} repo(s)`);
      return res.json(results);
    } else {
      await deployToRepo(owner, repo);
      addLog("success", `Action deployed to ${owner}/${repo}`);
      return res.json({ ok: true });
    }
  } catch (err) {
    addLog("error", `Deploy failed: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/action/remove ───────────────────────────────────────────────────
app.post("/api/action/remove", requireAuth, async (req, res) => {
  async function removeAction(owner, repo) {
    let sha;
    try {
      const { data } = await session.octokit.rest.repos.getContent({
        owner, repo, path: ".github/workflows/malware-scan.yml",
      });
      sha = data.sha;
    } catch (_) { return; } // not found
    
    await session.octokit.rest.repos.deleteFile({
      owner, repo,
      path: ".github/workflows/malware-scan.yml",
      message: "ci: remove malware auto-scanner workflow [skip ci]",
      sha,
    });
  }

  try {
    const repos = await session.octokit.paginate(
      session.octokit.rest.repos.listForAuthenticatedUser,
      { per_page: 100, affiliation: "owner" }
    );
    const results = { ok: [], error: [] };
    for (const r of repos) {
      try {
        await removeAction(r.owner.login, r.name);
        results.ok.push(r.full_name);
        await new Promise((resolve) => setTimeout(resolve, 300));
      } catch (err) {
        results.error.push({ repo: r.full_name, error: err.message });
      }
    }
    addLog("success", `Action removed from ${results.ok.length} repo(s)`);
    return res.json(results);
  } catch (err) {
    addLog("error", `Action removal failed: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/patterns ─────────────────────────────────────────────────────────
app.get("/api/patterns", (req, res) => {
  res.json(loadPatterns());
});

// ── POST /api/patterns — add single pattern ───────────────────────────────────
app.post("/api/patterns", (req, res) => {
  const p = req.body;
  if (!p.id || !p.name || !p.regex)
    return res.status(400).json({ error: "id, name, and regex are required." });

  // Validate regex
  try { new RegExp(p.regex); } catch (_) {
    return res.status(400).json({ error: "Invalid regex." });
  }

  const patterns = loadPatterns();
  if (patterns.find((x) => x.id === p.id))
    return res.status(409).json({ error: `Pattern with id "${p.id}" already exists.` });

  const newPattern = {
    id: p.id,
    name: p.name,
    description: p.description || "",
    literal: p.literal || "",
    regex: p.regex,
    severity: p.severity || "medium",
    extensions: p.extensions || ["js", "ts"],
    autoClean: p.autoClean || false,
  };
  patterns.push(newPattern);
  savePatterns(patterns);
  addLog("info", `Pattern added: "${p.name}"`);
  res.status(201).json(newPattern);
});

// ── DELETE /api/patterns/:id ──────────────────────────────────────────────────
app.delete("/api/patterns/:id", (req, res) => {
  let patterns = loadPatterns();
  const before = patterns.length;
  patterns = patterns.filter((p) => p.id !== req.params.id);
  if (patterns.length === before)
    return res.status(404).json({ error: "Pattern not found." });
  savePatterns(patterns);
  addLog("info", `Pattern deleted: ${req.params.id}`);
  res.json({ ok: true });
});

// ── POST /api/patterns/import ─────────────────────────────────────────────────
// body: { patterns: [...], mode: "merge" | "replace" }
app.post("/api/patterns/import", (req, res) => {
  const { patterns: incoming, mode = "merge" } = req.body;
  if (!Array.isArray(incoming))
    return res.status(400).json({ error: "Expected { patterns: [...] }" });

  // Validate each
  for (const p of incoming) {
    if (!p.id || !p.name || !p.regex)
      return res.status(400).json({ error: `Pattern missing id/name/regex: ${JSON.stringify(p)}` });
    try { new RegExp(p.regex); } catch (_) {
      return res.status(400).json({ error: `Invalid regex in pattern "${p.id}"` });
    }
  }

  let existing = loadPatterns();
  let added = 0, updated = 0;

  if (mode === "replace") {
    savePatterns(incoming);
    added = incoming.length;
  } else {
    // Merge: upsert by id
    for (const p of incoming) {
      const idx = existing.findIndex((x) => x.id === p.id);
      if (idx >= 0) { existing[idx] = p; updated++; }
      else { existing.push(p); added++; }
    }
    savePatterns(existing);
  }

  addLog("info", `Patterns imported: ${added} added, ${updated} updated`);
  res.json({ ok: true, added, updated, total: loadPatterns().length });
});

// ── GET /api/log ──────────────────────────────────────────────────────────────
app.get("/api/log", requireAuth, (req, res) => {
  res.json(activityLog.slice(0, 100));
});

// ── GET /api/status ───────────────────────────────────────────────────────────
app.get("/api/status", (req, res) => {
  res.json({ connected: !!session.token, login: session.login });
});

// ── Start server ──────────────────────────────────────────────────────────────
app.listen(PORT, "127.0.0.1", () => {
  console.log(`\n[Server] Malware Scanner Dashboard`);
  console.log(`         Running on http://localhost:${PORT}\n`);
});
>>>>>>> Stashed changes
>>>>>>> Stashed changes
