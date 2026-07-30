/**
 * Electron Main Process
 * ─────────────────────
 * Starts the Express server internally and opens a frameless BrowserWindow.
 */

import { app, BrowserWindow, ipcMain, shell, nativeTheme, dialog } from "electron";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import http from "http";
import net from "net";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
let mainWindow = null;

// ── Find a free port (prefers 4000, falls back to OS-assigned) ────────────────
function findFreePort(preferred = 4000) {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.listen(preferred, () => {
      const port = probe.address().port;
      probe.close(() => resolve(port));
    });
    probe.on("error", () => {
      // Preferred port is busy — ask OS for any free port
      const fallback = net.createServer();
      fallback.listen(0, () => {
        const port = fallback.address().port;
        fallback.close(() => resolve(port));
      });
    });
  });
}


// ── 1. Copy patterns.json to writable userData on first launch ─────────────────
// The app bundle (asar) is read-only; we use userData so users can add patterns.
function ensurePatternsFile() {
  const userDataPath = app.getPath("userData");
  const dest = path.join(userDataPath, "patterns.json");
  if (!fs.existsSync(dest)) {
    const src = path.join(__dirname, "patterns.json");
    if (fs.existsSync(src)) fs.copyFileSync(src, dest);
  }
  // Tell server.js where to read/write patterns
  process.env.PATTERNS_FILE = dest;
}

// ── 2. Wait until Express is ready ───────────────────────────────────────────
function waitForServer(port, timeoutMs = 12000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    function probe() {
      http
        .get(`http://localhost:${port}/api/status`, (res) => {
          if (res.statusCode < 500) resolve();
          else retry();
        })
        .on("error", retry);
    }
    function retry() {
      if (Date.now() > deadline) {
        reject(new Error("Express server did not start within timeout."));
      } else {
        setTimeout(probe, 300);
      }
    }
    probe();
  });
}

// ── 3. Create the BrowserWindow ───────────────────────────────────────────────
async function createWindow() {
  nativeTheme.themeSource = "dark";
  ensurePatternsFile();

  // Pick a free port (4000 preferred, falls back automatically if busy)
  const PORT = await findFreePort(4000);
  process.env.PORT = String(PORT);

  // Start Express (server.js reads process.env.PORT, auto-calls app.listen on import)
  await import("./server.js");
  await waitForServer(PORT);


  mainWindow = new BrowserWindow({
    width: 1400,
    height: 860,
    minWidth: 1000,
    minHeight: 640,
    frame: false,          // custom titlebar in the renderer
    transparent: false,
    backgroundColor: "#080c14",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,      // needed to allow preload to use require()
    },
    icon: path.join(__dirname, "assets", "icon.png"),
    show: false,
    title: "GitHub Malware Scanner",
  });

  mainWindow.loadURL(`http://localhost:${PORT}`);

  // Show window only after page has painted (avoids white flash)
  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
    mainWindow.focus();
  });

  // Open all external <a target="_blank"> links in the OS browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

// ── 4. IPC — window controls ──────────────────────────────────────────────────
ipcMain.on("win:minimize", () => mainWindow?.minimize());
ipcMain.on("win:maximize", () => {
  if (mainWindow?.isMaximized()) mainWindow.unmaximize();
  else mainWindow?.maximize();
});
ipcMain.on("win:close", () => mainWindow?.close());
ipcMain.handle("win:isMaximized", () => mainWindow?.isMaximized() ?? false);

// ── 5. Dialogs ────────────────────────────────────────────────────────────────
ipcMain.handle("dialog:openFolder", async () => {
  if (!mainWindow) return null;
  const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
    properties: ["openDirectory"],
  });
  if (canceled || filePaths.length === 0) return null;
  return filePaths[0];
});

// ── 5. App lifecycle ──────────────────────────────────────────────────────────
app.commandLine.appendSwitch("disable-gpu-shader-disk-cache");
app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("activate", () => {
  if (!mainWindow) createWindow();
});
