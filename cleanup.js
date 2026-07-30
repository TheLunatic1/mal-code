#!/usr/bin/env node
/**
 * GitHub Malware Cleanup Script
 * ─────────────────────────────
 * Searches all your repositories for the malicious payload
 * `global.i="A11-#"` and surgically removes it.
 *
 * Usage:
 *   node cleanup.js [--dry-run] [--repo <owner/name>]
 *
 * Flags:
 *   --dry-run          Scan and report without committing any changes.
 *   --repo owner/name  Only process a single specific repository.
 */

import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import os from "os";
import { Octokit } from "@octokit/rest";
import dotenv from "dotenv";

// ── 0. Config ────────────────────────────────────────────────────────────────

dotenv.config();

const TOKEN = process.env.GITHUB_TOKEN;
if (!TOKEN) {
  console.error(
    "❌  GITHUB_TOKEN not found in .env  –  see README for setup instructions."
  );
  process.exit(1);
}

// The exact string that identifies infected files.
// A regex is used so we can precisely remove just this segment.
const MALICIOUS_MARKER = `global.i="A11-#"`;

// We match from the marker up to the end of the obfuscated expression.
// Adjust the pattern if the payload has a consistent terminator (e.g. a semicolon).
// The current pattern removes everything from the marker to the next semicolon
// (inclusive), covering common single-line injections.
const MALICIOUS_REGEX = /global\.i="A11-#".*/g;

const DRY_RUN = process.argv.includes("--dry-run");
const SINGLE_REPO = (() => {
  const idx = process.argv.indexOf("--repo");
  return idx !== -1 ? process.argv[idx + 1] : null;
})();

const COMMIT_MESSAGE = "chore: remove malicious payload";
const GIT_AUTHOR_NAME = process.env.GIT_AUTHOR_NAME || "Cleanup Bot";
const GIT_AUTHOR_EMAIL =
  process.env.GIT_AUTHOR_EMAIL || "cleanup@localhost";

// ── 1. Octokit client ────────────────────────────────────────────────────────

const octokit = new Octokit({ auth: TOKEN });

// ── 2. Helpers ───────────────────────────────────────────────────────────────

function log(emoji, msg) {
  console.log(`${emoji}  ${msg}`);
}

function run(cmd, cwd) {
  return execSync(cmd, {
    cwd,
    stdio: "pipe",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME,
      GIT_AUTHOR_EMAIL,
      GIT_COMMITTER_NAME: GIT_AUTHOR_NAME,
      GIT_COMMITTER_EMAIL: GIT_AUTHOR_EMAIL,
    },
  })
    .toString()
    .trim();
}

/** Recursively yield every .js file path under a directory */
function* walkJs(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (
      entry.isDirectory() &&
      entry.name !== "node_modules" &&
      entry.name !== ".git"
    ) {
      yield* walkJs(full);
    } else if (entry.isFile() && entry.name.endsWith(".js")) {
      yield full;
    }
  }
}

/** Return true if the file content contains the malicious marker */
function isInfected(content) {
  return content.includes(MALICIOUS_MARKER);
}

/** Remove the malicious payload and return the cleaned content */
function removeMalware(content) {
  return content.replace(MALICIOUS_REGEX, "");
}

/** Delete a directory tree, ignoring errors */
function cleanupDir(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (_) {
    // best-effort
  }
}

// ── 3. GitHub API helpers ────────────────────────────────────────────────────

/** Return the authenticated user's login */
async function getLogin() {
  const { data } = await octokit.rest.users.getAuthenticated();
  return data.login;
}

/**
 * Use GitHub Code Search to pre-filter only repos that contain
 * the malicious marker string.  Returns a Set of "owner/repo" strings.
 *
 * Note: Code Search has rate limits (10 req/min unauthenticated,
 * 30 req/min authenticated). We handle this with a small retry loop.
 */
async function searchInfectedRepos(login) {
  const infected = new Set();
  const query = `global.i="A11-#" user:${login} language:JavaScript`;
  log("🔍", `Code Search query: ${query}`);

  let page = 1;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    let result;
    try {
      result = await octokit.rest.search.code({
        q: query,
        per_page: 100,
        page,
      });
    } catch (err) {
      if (err.status === 403 && err.message.includes("rate limit")) {
        log("⏳", "Search rate-limited – waiting 60 s …");
        await new Promise((r) => setTimeout(r, 60_000));
        continue;
      }
      throw err;
    }

    for (const item of result.data.items) {
      infected.add(item.repository.full_name);
    }

    if (result.data.items.length < 100) break;
    page++;
  }

  return infected;
}

// ── 4. Per-repo cleanup ───────────────────────────────────────────────────────

async function processRepo(repo) {
  const fullName = repo.full_name; // e.g. "alice/my-project"
  const cloneUrl = repo.clone_url; // https://github.com/alice/my-project.git

  // Inject the token into the clone URL so git does not prompt for credentials
  const authedUrl = cloneUrl.replace(
    "https://",
    `https://x-access-token:${TOKEN}@`
  );

  const tmpBase = os.tmpdir();
  const tmpDir = path.join(tmpBase, `gh-cleanup-${Date.now()}`);

  log("📦", `Processing: ${fullName}`);

  try {
    // ── 4a. Clone ──────────────────────────────────────────────────────────
    log("  ⬇️ ", `Cloning into ${tmpDir} …`);
    run(`git clone --depth=1 "${authedUrl}" "${tmpDir}"`);

    // ── 4b. Scan every .js file ────────────────────────────────────────────
    const infectedFiles = [];
    for (const filePath of walkJs(tmpDir)) {
      const content = fs.readFileSync(filePath, "utf8");
      if (isInfected(content)) {
        infectedFiles.push(filePath);
      }
    }

    if (infectedFiles.length === 0) {
      log("  ✅", "No infected files found (Code Search may have false-positived).");
      return { repo: fullName, status: "clean", filesPatched: 0 };
    }

    log("  🦠", `Found ${infectedFiles.length} infected file(s):`);
    for (const f of infectedFiles) {
      log("     •", path.relative(tmpDir, f));
    }

    if (DRY_RUN) {
      log("  🚫", "[DRY-RUN] Skipping patch + commit.");
      return { repo: fullName, status: "dry-run", filesPatched: infectedFiles.length };
    }

    // ── 4c. Patch each file ────────────────────────────────────────────────
    for (const filePath of infectedFiles) {
      const original = fs.readFileSync(filePath, "utf8");
      const cleaned = removeMalware(original);
      fs.writeFileSync(filePath, cleaned, "utf8");
      log("  🩹", `Patched: ${path.relative(tmpDir, filePath)}`);
    }

    // ── 4d. Commit & push ──────────────────────────────────────────────────
    run(`git add -A`, tmpDir);
    run(`git commit -m "${COMMIT_MESSAGE}"`, tmpDir);
    run(`git push`, tmpDir);
    log("  🚀", `Pushed clean commit to ${fullName}.`);

    return { repo: fullName, status: "fixed", filesPatched: infectedFiles.length };
  } catch (err) {
    log("  ❌", `Error processing ${fullName}: ${err.message}`);
    return { repo: fullName, status: "error", error: err.message };
  } finally {
    // ── 4e. Always clean up the temp clone ────────────────────────────────
    cleanupDir(tmpDir);
    log("  🗑️ ", `Temp folder removed.`);
  }
}

// ── 5. Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log("═══════════════════════════════════════════════════════");
  console.log("  GitHub Malware Cleanup Script");
  if (DRY_RUN) console.log("  ⚠️  DRY-RUN MODE — no changes will be committed");
  console.log("═══════════════════════════════════════════════════════\n");

  const login = await getLogin();
  log("👤", `Authenticated as: ${login}`);

  let reposToProcess;

  if (SINGLE_REPO) {
    // User specified a single repo via --repo flag
    const [owner, name] = SINGLE_REPO.split("/");
    const { data } = await octokit.rest.repos.get({ owner, repo: name });
    reposToProcess = [data];
    log("🎯", `Single-repo mode: ${SINGLE_REPO}`);
  } else {
    // Use Code Search to pre-filter infected repos (faster & avoids cloning everything)
    log("🔍", "Searching for infected repositories via GitHub Code Search …\n");
    const infectedNames = await searchInfectedRepos(login);

    if (infectedNames.size === 0) {
      log("🎉", "Code Search found no matches. Your repositories appear clean!");
      process.exit(0);
    }

    log("⚠️ ", `Code Search identified ${infectedNames.size} potentially infected repo(s):\n`);
    for (const name of infectedNames) console.log(`     • ${name}`);
    console.log();

    // Fetch full repo metadata for each hit
    reposToProcess = await Promise.all(
      [...infectedNames].map(async (fullName) => {
        const [owner, repo] = fullName.split("/");
        const { data } = await octokit.rest.repos.get({ owner, repo });
        return data;
      })
    );
  }

  // ── Process each repo sequentially to avoid rate-limit issues ─────────────
  const results = [];
  for (const repo of reposToProcess) {
    const result = await processRepo(repo);
    results.push(result);
    console.log();
  }

  // ── Summary report ─────────────────────────────────────────────────────────
  console.log("═══════════════════════════════════════════════════════");
  console.log("  SUMMARY");
  console.log("═══════════════════════════════════════════════════════");

  const fixed   = results.filter((r) => r.status === "fixed");
  const clean   = results.filter((r) => r.status === "clean");
  const dryRun  = results.filter((r) => r.status === "dry-run");
  const errors  = results.filter((r) => r.status === "error");

  if (fixed.length)
    console.log(`\n✅  Cleaned & pushed (${fixed.length}):`);
  for (const r of fixed) console.log(`     • ${r.repo}  (${r.filesPatched} file(s) patched)`);

  if (dryRun.length)
    console.log(`\n🔍  Would have been fixed – dry-run (${dryRun.length}):`);
  for (const r of dryRun) console.log(`     • ${r.repo}  (${r.filesPatched} file(s) infected)`);

  if (clean.length)
    console.log(`\n🟢  False positives / already clean (${clean.length}):`);
  for (const r of clean) console.log(`     • ${r.repo}`);

  if (errors.length)
    console.log(`\n❌  Errors (${errors.length}):`);
  for (const r of errors) console.log(`     • ${r.repo}: ${r.error}`);

  console.log("\n═══════════════════════════════════════════════════════\n");

  if (errors.length > 0) process.exit(1);
}

main().catch((err) => {
  console.error("\n💥  Fatal error:", err.message);
  process.exit(1);
});
