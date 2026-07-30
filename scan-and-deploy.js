#!/usr/bin/env node
/**
 * One-shot: Scan all repos + deploy malware-scan GitHub Action to infected ones.
 * Run: node scan-and-deploy.js
 */
import { Octokit } from "@octokit/rest";
import dotenv from "dotenv";
dotenv.config();

const TOKEN = process.env.GITHUB_TOKEN;
const octokit = new Octokit({ auth: TOKEN });

const MARKER = `global.i="A11-#"`;

// ── The GitHub Actions workflow YAML that will be committed into each repo ──
const WORKFLOW_YAML = `# Malware Auto-Scanner
# Injected by security remediation — do NOT remove.
# Scans every push for malicious payload and auto-removes it.
name: Malware Auto-Scanner

on:
  push:
    branches: ["**"]

# Allow the workflow to push a cleanup commit back
permissions:
  contents: write

# Prevent parallel runs on the same branch (avoids race conditions).
# Does NOT cancel or interfere with any other workflow.
concurrency:
  group: malware-scan-\${{ github.ref }}
  cancel-in-progress: true

jobs:
  scan-and-clean:
    name: Scan & Remove Malicious Payload
    runs-on: ubuntu-latest
    # Skip if this is our own cleanup commit (prevents infinite loops)
    if: "!contains(github.event.head_commit.message, '[skip ci]')"

    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 1

      - name: Scan and remove malicious payload
        id: scan
        run: |
          set -euo pipefail

          MARKER='global.i="A11-#"'
          FOUND=0

          # Find all JS/TS files (excluding node_modules and .git)
          while IFS= read -r -d '' file; do
            if grep -qF "\$MARKER" "\$file"; then
              echo "🦠 Infected: \$file"
              # Remove from the marker to the next semicolon (inclusive)
              node -e "
                const fs = require('fs');
                const p = process.argv[1];
                const src = fs.readFileSync(p, 'utf8');
                const cleaned = src.replace(/global\\.i=\\"A11-#\\"[^;]*;?/g, '');
                if (cleaned !== src) {
                  fs.writeFileSync(p, cleaned, 'utf8');
                  console.log('  Patched:', p);
                }
              " "\$file"
              FOUND=1
            fi
          done < <(find . \\
            -not -path './.git/*' \\
            -not -path './node_modules/*' \\
            \\( -name '*.js' -o -name '*.ts' -o -name '*.tsx' -o -name '*.jsx' \\) \\
            -print0)

          echo "found=\$FOUND" >> "\$GITHUB_OUTPUT"

      - name: Commit and push clean code
        if: steps.scan.outputs.found == '1'
        run: |
          git config user.name  "Malware Scanner"
          git config user.email "malware-scanner@github-actions"
          git add -A
          git commit -m "chore: remove malicious payload [skip ci]"
          git push
`;

async function run() {
  const { data: user } = await octokit.rest.users.getAuthenticated();
  const login = user.login;
  console.log(`\n👤 Authenticated as: ${login}\n`);

  // ── 1. Code Search for infected repos ──────────────────────────────────────
  console.log(`🔍 Searching all repos for: ${MARKER}\n`);
  const infectedRepos = new Set();

  let page = 1;
  while (true) {
    let result;
    try {
      result = await octokit.rest.search.code({
        q: `global.i="A11-#" user:${login} language:JavaScript`,
        per_page: 100,
        page,
      });
    } catch (err) {
      if (err.status === 403) {
        console.log("⏳ Rate limited — waiting 60s...");
        await new Promise(r => setTimeout(r, 60000));
        continue;
      }
      throw err;
    }
    for (const item of result.data.items) {
      infectedRepos.add(item.repository.full_name);
    }
    if (result.data.items.length < 100) break;
    page++;
  }

  // Also check TypeScript
  page = 1;
  while (true) {
    let result;
    try {
      result = await octokit.rest.search.code({
        q: `global.i="A11-#" user:${login} language:TypeScript`,
        per_page: 100,
        page,
      });
    } catch (err) {
      if (err.status === 403) {
        await new Promise(r => setTimeout(r, 60000));
        continue;
      }
      throw err;
    }
    for (const item of result.data.items) {
      infectedRepos.add(item.repository.full_name);
    }
    if (result.data.items.length < 100) break;
    page++;
  }

  if (infectedRepos.size === 0) {
    console.log("🎉 Code Search found no infected repos.");
  } else {
    console.log(`⚠️  Infected repos found (${infectedRepos.size}):`);
    for (const r of infectedRepos) console.log(`   • ${r}`);
  }

  // ── 2. Get ALL repos to deploy the Action everywhere ──────────────────────
  console.log(`\n📋 Fetching full repo list to deploy the scanner Action...\n`);
  const allRepos = await octokit.paginate(
    octokit.rest.repos.listForAuthenticatedUser,
    { per_page: 100, affiliation: "owner" }
  );
  console.log(`   Found ${allRepos.length} repo(s) owned by ${login}\n`);

  // ── 3. Deploy workflow to ALL repos ───────────────────────────────────────
  const results = { ok: [], skipped: [], error: [] };

  for (const repo of allRepos) {
    const [owner, name] = [repo.owner.login, repo.name];
    const filePath = ".github/workflows/malware-scan.yml";
    const content = Buffer.from(WORKFLOW_YAML).toString("base64");

    process.stdout.write(`  📦 ${repo.full_name} ... `);

    try {
      // Check if file already exists (to get its SHA for update)
      let sha;
      try {
        const { data } = await octokit.rest.repos.getContent({
          owner, repo: name, path: filePath,
        });
        sha = data.sha;
      } catch (_) {
        sha = undefined; // file doesn't exist yet
      }

      await octokit.rest.repos.createOrUpdateFileContents({
        owner,
        repo: name,
        path: filePath,
        message: "ci: add malware auto-scanner workflow [skip ci]",
        content,
        ...(sha ? { sha } : {}),
      });

      const tag = infectedRepos.has(repo.full_name) ? "✅ (WAS INFECTED)" : "✅";
      console.log(tag);
      results.ok.push(repo.full_name);
    } catch (err) {
      console.log(`❌ ${err.message}`);
      results.error.push({ repo: repo.full_name, err: err.message });
    }

    // Small delay to respect secondary rate limits
    await new Promise(r => setTimeout(r, 300));
  }

  // ── 4. Summary ────────────────────────────────────────────────────────────
  console.log("\n═══════════════════════════════════════");
  console.log("  DONE");
  console.log("═══════════════════════════════════════");
  console.log(`✅ Deployed:   ${results.ok.length} repo(s)`);
  console.log(`❌ Errors:     ${results.error.length} repo(s)`);
  if (results.error.length) {
    for (const e of results.error) console.log(`   • ${e.repo}: ${e.err}`);
  }
  console.log(`\n🦠 Infected repos that now have auto-scanner:`);
  for (const r of infectedRepos) console.log(`   • ${r}`);
  console.log("\n⚠️  REVOKE YOUR PAT NOW: https://github.com/settings/tokens\n");
}

run().catch(e => { console.error("Fatal:", e.message); process.exit(1); });
