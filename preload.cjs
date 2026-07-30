/**
 * Electron Preload Script (CommonJS)
 * ───────────────────────────────────
 * Exposes a safe, narrow API to the renderer via contextBridge.
 * The renderer can call window.electronAPI.minimize() etc.
 */
"use strict";

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("electronAPI", {
  isElectron: true,

  // Window controls
  minimize:    () => ipcRenderer.send("win:minimize"),
  maximize:    () => ipcRenderer.send("win:maximize"),
  close:       () => ipcRenderer.send("win:close"),
  isMaximized: () => ipcRenderer.invoke("win:isMaximized"),
  
  // Dialogs
  openFolder:  () => ipcRenderer.invoke("dialog:openFolder"),

  // Listen for maximize/restore events from main
  onMaximizeChange: (cb) => {
    ipcRenderer.on("win:maximized",   () => cb(true));
    ipcRenderer.on("win:unmaximized", () => cb(false));
  },
});
