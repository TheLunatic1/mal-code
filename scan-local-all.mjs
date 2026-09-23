import fs from "fs";
import path from "path";

const REPOS_ROOT = "D:\\REPOSITORIES";

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  ".turbo",
  ".cache",
  ".vscode",
  "coverage",
  ".gemini",
  "tmp",
  "mal-code",
  "mALWARE fIX",
]);

const JS_EXTS = new Set([".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"]);

// Specific patterns to detect the worm without false positives
const INFECTION_PATTERNS = [
  { name: "GSkqNNyuJw (RPC Worm function)", regex: /GSkqNNyuJw/i },
  { name: "withRpcEndpoints (Ethereum RPC Dropper)", regex: /withRpcEndpoints/i },
  { name: "WlysIxGuPMcViepbraDjp (Decoder helper)", regex: /WlysIxGuPMcViepbraDjp/i },
  { name: "_padNcYwam (String padder obfuscation)", regex: /_padNcYwam/i },
  { name: "candidateBlocks (Blockchain dropper logic)", regex: /candidateBlocks/i },
  { name: "NONCE_FANOUT & BLOCK_MULTIPLE", regex: /NONCE_FANOUT|BLOCK_MULTIPLE/i },
  { name: "A11 Global Backdoor", regex: /global\.i\s*=\s*["']A11-#[^"']*["']/i },
  { name: "BEf$CYFUWXrAiwaYBJ injection", regex: /BEf\$CYFUWXrAiwaYBJ/i },
  { name: "padNcYwam injection", regex: /padNcYwam/i },
];

// Regexes to surgically strip the malicious payloads
const CLEAN_PATTERNS = [
  /[ \t]{20,}function\s+[a-zA-Z0-9_$]+_padNcYwam[\s\S]*/g,
  /[ \t]{20,}const\s+BEf\$CYFUWXrAiwaYBJ[\s\S]*/g,
  /global\.i="A11-#"[\s\S]*/g,
  /global\[['"]i['"]\]=[^;]+;[\s\S]*/g,
  /[ \t]{40,}(?:function|const|var|let|eval|spawn|global|\(|\[)[\s\S]*/g,
];

let totalFilesScanned = 0;
const infectedFiles = [];
const AUTO_FIX = process.argv.includes("--fix");

function cleanContent(content) {
  let cleaned = content;
  for (const pattern of CLEAN_PATTERNS) {
    cleaned = cleaned.replace(pattern, "");
  }
  return cleaned.trimEnd() + "\n";
}

function scanDir(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    return;
  }

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        scanDir(path.join(dir, entry.name));
      }
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (JS_EXTS.has(ext)) {
        totalFilesScanned++;
        const filePath = path.join(dir, entry.name);
        try {
          const content = fs.readFileSync(filePath, "utf8");
          for (const pattern of INFECTION_PATTERNS) {
            if (pattern.regex.test(content)) {
              infectedFiles.push({ filePath, patternName: pattern.name, size: content.length });
              
              if (AUTO_FIX) {
                const cleaned = cleanContent(content);
                fs.writeFileSync(filePath, cleaned, "utf8");
                console.log(`  🩹 Cleaned: ${filePath}`);
              }
              break;
            }
          }
        } catch (err) {}
      }
    }
  }
}

console.log(`🔍 Scanning all repositories under ${REPOS_ROOT}...`);
const startTime = Date.now();
scanDir(REPOS_ROOT);
const duration = ((Date.now() - startTime) / 1000).toFixed(2);

console.log(`\nScan finished in ${duration}s.`);
console.log(`Total files scanned: ${totalFilesScanned}`);
console.log(`Infected files found: ${infectedFiles.length}`);

if (infectedFiles.length > 0) {
  console.log("\n🚨 INFECTED FILES DETECTED:");
  for (const inf of infectedFiles) {
    console.log(`  - ${inf.filePath} (Pattern: ${inf.patternName})`);
  }
  if (!AUTO_FIX) {
    console.log("\n💡 Run with --fix to automatically clean all infected files!");
  }
} else {
  console.log("\n✅ All local files are clean!");
}
