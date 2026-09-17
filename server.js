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
const WORKFLOW_YAML = `# Malware Auto-Scanner — do NOT remove
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
      - uses: actions/checkout@v4
        with:
          fetch-depth: 1

      - name: Scan and remove malicious payload
        id: scan
        run: |
          set -euo pipefail
          FOUND=0
          while IFS= read -r -d '' file; do
            if grep -qF '
