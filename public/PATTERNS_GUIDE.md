# 🧬 Malware Pattern Library — Guide

This guide explains how to add new malware signatures to the scanner.
Patterns are stored in `patterns.json` and can be added via:
- The **Patterns tab → + Add Pattern** button in the UI
- The **Patterns tab → 📥 Import JSON** button (paste a JSON array)
- Directly editing `patterns.json` and restarting the server

---

## Pattern Object Format

```json
{
  "id": "unique-kebab-case-id",
  "name": "Human Readable Name",
  "description": "What this pattern detects and why it is dangerous.",
  "literal": "exact string for GitHub Code Search",
  "regex": "JavaScript regex (no /slashes/, no flags)",
  "severity": "critical | high | medium | low",
  "extensions": ["js", "ts", "tsx", "jsx", "mjs", "cjs"],
  "autoClean": false
}
```

### Field Reference

| Field | Required | Notes |
|---|---|---|
| `id` | ✅ | Unique, kebab-case, no spaces. e.g. `eval-atob-v2` |
| `name` | ✅ | Short human label shown in the UI |
| `description` | ❌ | Explains what it detects and why it is dangerous |
| `literal` | ❌ | **Strongly recommended.** A plain substring used for the fast GitHub Code Search scan. Must be a literal string — no regex metacharacters. If omitted, the pattern only runs during Deep Scan. |
| `regex` | ✅ | JavaScript regex **without surrounding slashes or flags**. It is compiled as `new RegExp(regex, 'g')`. Must be valid JS regex syntax. |
| `severity` | ❌ | `critical` / `high` / `medium` / `low`. Default: `medium` |
| `extensions` | ❌ | File extensions to scan. Default: `["js","ts"]` |
| `autoClean` | ❌ | `true` = the scanner will remove the match entirely without user confirmation. **Only set true if the entire match is safe to delete without leaving broken code.** Default: `false` |

---

## Tips for Writing Good Patterns

### 1. Use a `literal` whenever possible
GitHub Code Search is much faster than cloning files. If your pattern has a
constant substring (e.g. `eval(atob(`), put it in `literal`. The deep-scan
regex then confirms the match in the actual file content.

```json
"literal": "eval(atob(",
"regex": "eval\\s*\\(\\s*atob\\s*\\([^)]+\\)\\s*\\)"
```

### 2. Escape backslashes in the JSON
Since the regex is stored as a JSON string, every regex backslash `\`
must be doubled to `\\`:

```
Regex you want:  \d+\.\d+
In JSON:         "\\d+\\.\\d+"
```

### 3. Keep regexes narrow — avoid false positives
Overly broad regexes like `eval\(.*\)` will match legitimate code.
Target specific patterns:

```json
// Too broad ❌
"regex": "eval\\(.*\\)"

// Targeted ✅
"regex": "eval\\s*\\(\\s*atob\\s*\\([A-Za-z0-9+/=]{40,}\\)\\)"
```

### 4. Only set `autoClean: true` for self-contained payloads
If the malicious code is injected as a standalone statement that can be
removed without breaking surrounding code (like the A11 backdoor), set
`autoClean: true`. For patterns that are mixed into legitimate expressions,
set `autoClean: false` so a human can review before cleaning.

---

## Example: Adding a New Pattern via JSON Import

1. Open the **Patterns** tab in the dashboard.
2. Click **📥 Import JSON**.
3. Paste your pattern array and select **Merge**:

```json
[
  {
    "id": "discord-token-grabber",
    "name": "Discord Token Grabber",
    "description": "Exfiltrates Discord tokens via a webhook URL.",
    "literal": "discord.com/api/webhooks/",
    "regex": "fetch\\s*\\(['\"]https://discord\\.com/api/webhooks/[^'\"]+['\"]",
    "severity": "critical",
    "extensions": ["js", "ts", "mjs"],
    "autoClean": false
  },
  {
    "id": "npm-lifecycle-exfil",
    "name": "NPM postinstall Exfiltration",
    "description": "Reads sensitive files and POSTs them to an external server in package postinstall scripts.",
    "literal": "postinstall",
    "regex": "\"postinstall\"\\s*:\\s*\"[^\"]*(?:curl|wget|fetch)[^\"]*http",
    "severity": "high",
    "extensions": ["json"],
    "autoClean": false
  }
]
```

4. Click **Import**. The new patterns are saved to `patterns.json` immediately
   and used in the next scan.

---

## Exporting Your Pattern Library

To back up or share your patterns, copy the contents of `patterns.json`.
You can re-import it on any instance of the dashboard using the Import feature.

```powershell
# Quick backup
copy patterns.json patterns.backup.json
```
