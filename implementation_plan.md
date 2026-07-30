# Standalone GitHub Malware Scanner & Cleaner — Implementation Plan

## What This Builds

A **self-contained local web application** you run on your machine.
It gives you a full security dashboard to monitor, scan, and clean all your
GitHub repositories — with a live pattern library you can extend over time.

```
┌──────────────────────────────────────────────────────────────────┐
│              🛡️  GitHub Malware Security Dashboard               │
│                      localhost:4000                              │
├──────────────────────────────────────────────────────────────────┤
│  PAT: [●●●●●●●●●●●●●]  [Connect]        👤 TheLunatic1          │
├───────────────┬──────────────────────────────────────────────────┤
│  🗂 Repos (71)│  📊 Dashboard                                    │
│  ─────────────│  ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  homes-pets ✅│  │ 71 Repos │ │  0 Dirty │ │ 71 Safe  │         │
│  vanta      ✅│  └──────────┘ └──────────┘ └──────────┘         │
│  jobpulse   ✅│                                                  │
│  luxe-store ✅│  [🔍 Scan All]  [🧹 Clean All]  [🛡 Deploy All] │
│  ...          │                                                  │
│               │  📋 Activity Log                                 │
│               │  ✅ 10:15  homes-pets-backend — clean            │
│               │  🧹 10:14  vanta — 1 file patched & pushed      │
│               │  🔍 10:13  Scan started for all 71 repos...     │
└───────────────┴──────────────────────────────────────────────────┘
```

---

## Architecture

```
mALWARE fIX/
├── server.js            ← Express backend (API + SSE streaming)
├── patterns.json        ← Malware signature library (extensible)
├── package.json
├── .env.example
└── public/
    ├── index.html       ← Single-page app (premium dark UI)
    ├── app.js           ← Frontend logic (fetch + SSE)
    └── style.css        ← Glassmorphism dark theme
```

---

## Core Features

### 1. 🔌 Secure PAT Session
- PAT entered in UI, held **only in memory** on the Express server
- Session expires on server restart — never written to disk
- Clear visual indicator showing connected GitHub username

### 2. 📋 Repo Dashboard
- Lists all owned repos in a sidebar
- Each repo shows:
  - 🛡️ Action protection status (has `malware-scan.yml` or not)
  - 🟢 Clean / 🔴 Infected / ⬜ Not scanned yet
  - Last scan timestamp

### 3. 🔍 Smart Scanning (Two Modes)

**Fast Mode** — GitHub Code Search API
- Searches all repos in seconds without cloning
- No rate-limit issues for small/medium accounts
- Results streamed live to the UI via Server-Sent Events (SSE)

**Deep Mode** — Per-file content fetch via API
- For repos flagged by fast scan, fetches actual file content
- Confirms exact match (avoids false positives)
- Shows the infected line with context in the UI

### 4. 🧹 Auto-Cleaner
- For each infected file: fetches content → removes payload → pushes back via API
- No local cloning needed for most cases
- Falls back to clone→patch→push for binary-encoded or minified files
- Commit message: `chore: remove malicious payload [skip ci]`

### 5. 🛡️ Action Protection Manager
- Shows which repos have the `malware-scan.yml` workflow
- One-click "Deploy to All Unprotected" button
- One-click per-repo toggle

### 6. 📚 Pattern Library (Extensible)
- `patterns.json` — a list of malware signatures, each with:
  - `id`, `name`, `description`, `regex`, `severity` (critical/high/medium)
- Pre-loaded with known patterns:
  - `global.i="A11-#"` (current threat)
  - Common obfuscated eval patterns
  - Suspicious `process.env` exfiltration patterns
  - Base64-encoded payload patterns
- UI allows adding new patterns without touching code

### 7. 📋 Activity Log
- Scrollable live log in the UI
- Timestamped entries for every scan, clean, and deploy event
- Color-coded: 🟢 clean, 🔴 infected, 🧹 patched, 🚀 pushed

### 8. 📊 Summary Stats Card
- Total repos scanned
- Infected / Clean / Unscanned counts
- Files patched total
- Last full scan timestamp

---

## Malware Pattern Library (`patterns.json`)

```json
[
  {
    "id": "A11-backdoor",
    "name": "A11 Global Backdoor",
    "description": "Obfuscated global injection beginning with global.i=\"A11-#\"",
    "regex": "global\\.i=\"A11-#\"[^;]*;?",
    "severity": "critical",
    "language": ["js", "ts", "tsx", "jsx"]
  },
  {
    "id": "eval-obfuscated",
    "name": "Obfuscated eval()",
    "description": "eval() calls with base64 or hex-encoded strings",
    "regex": "eval\\((?:atob|Buffer\\.from)\\(['\"][A-Za-z0-9+/=]{40,}['\"]\\)\\)",
    "severity": "high",
    "language": ["js", "ts"]
  },
  {
    "id": "env-exfil",
    "name": "Environment Variable Exfiltration",
    "description": "Sends process.env to external URL via fetch/axios",
    "regex": "(?:fetch|axios)\\(['\"]https?://(?!api\\.github)[^'\"]+['\"],\\s*\\{[^}]*process\\.env",
    "severity": "high",
    "language": ["js", "ts"]
  }
]
```

---

## Files to Build

### Backend
#### [NEW] `server.js`
Express server with endpoints:
- `POST /api/connect` — accept PAT, validate with GitHub, store in memory
- `GET  /api/repos` — list all repos with protection status
- `GET  /api/scan/all` — SSE stream: scans all repos via Code Search
- `GET  /api/scan/:owner/:repo` — SSE stream: deep scan single repo
- `POST /api/clean/:owner/:repo` — clean infected files via GitHub API
- `POST /api/deploy/:owner/:repo` — deploy malware-scan.yml to a repo
- `POST /api/deploy/all` — deploy to all unprotected repos
- `GET  /api/patterns` — return patterns.json
- `POST /api/patterns` — add new pattern

#### [NEW] `patterns.json`
Extensible malware signature library with 5 pre-loaded patterns.

#### [MODIFY] `package.json`
Add `express`, keep `@octokit/rest` and `dotenv`.

### Frontend
#### [NEW] `public/index.html`
Full single-page app with:
- Premium glassmorphism dark UI (deep navy/charcoal + electric accent)
- Sidebar repo list with live status badges
- Main panel with tabs: Dashboard / Scan / Patterns / Log
- SSE-powered live progress feed

#### [NEW] `public/style.css`
Premium dark theme:
- Google Font: Inter
- Deep dark background (`#0a0e1a`)
- Glassmorphism cards
- Neon green/red status indicators
- Smooth animations on status updates

#### [NEW] `public/app.js`
Frontend JS:
- PAT connect flow
- SSE listener for live scan updates
- Repo list rendering with status badges
- Pattern CRUD UI
- Activity log renderer

---

## Open Questions

> [!IMPORTANT]
> **Should this app handle repos you collaborate on (not just repos you own)?**
> Currently the plan covers only repos where you are the owner. Collaborator repos
> would need `repo` scope and different API endpoints. Let me know if you want this.

> [!NOTE]
> **Port preference?** Default is `localhost:4000`. Change this if needed.

> [!NOTE]
> **Should the Pattern Library be editable from the UI only, or also support
> importing a JSON file?** Default: both.

---

## Verification Plan
1. Run `npm start` → open `localhost:4000`
2. Enter new PAT → verify connection shows `TheLunatic1`
3. Click **Scan All** → verify SSE streams repo statuses live
4. Manually inject test payload into a test repo → scan → confirm detected
5. Click **Clean** → verify file patched, commit appears on GitHub with `[skip ci]`
6. Verify other workflows in that repo still run normally
7. Add a new pattern via UI → verify it's used in subsequent scans
