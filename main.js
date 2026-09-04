const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const path = require("path");
const fs = require("fs");

const isMac = process.platform === "darwin";

function userDataPath(filename) {
  return path.join(app.getPath("userData"), filename);
}

function readJsonSafe(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const raw = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(raw);
  } catch (err) {
    return null;
  }
}

function writeJsonSafe(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data), "utf-8");
}

function createWindow() {
  const win = new BrowserWindow({
    width: 960,
    height: 720,
    minWidth: 760,
    minHeight: 580,
    backgroundColor: "#09090b",
    title: "Krypt",
    icon: path.join(__dirname, "build", "icon.png"),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.setMenuBarVisibility(false);
  win.loadFile(path.join(__dirname, "src", "index.html"));
}

app.whenReady().then(() => {
  if (isMac) {
    try { app.dock.setIcon(path.join(__dirname, "build", "icon.png")); } catch {}
  }
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (!isMac) app.quit();
});

/* ------------------------------------------------------------------ */
/*  IPC: almacenamiento local cifrado (los archivos viven en el        */
/*  perfil de datos del usuario del sistema operativo, nunca en la     */
/*  nube ni se envian a ningun servidor)                               */
/* ------------------------------------------------------------------ */

ipcMain.handle("krypt:loadUser", () => readJsonSafe(userDataPath("krypt-user.json")));
ipcMain.handle("krypt:saveUser", (_e, data) => {
  writeJsonSafe(userDataPath("krypt-user.json"), data);
  return true;
});
ipcMain.handle("krypt:deleteUser", () => {
  const p = userDataPath("krypt-user.json");
  if (fs.existsSync(p)) fs.unlinkSync(p);
  return true;
});

ipcMain.handle("krypt:loadEntries", () => readJsonSafe(userDataPath("krypt-entries.json")) || []);
ipcMain.handle("krypt:saveEntries", (_e, data) => {
  writeJsonSafe(userDataPath("krypt-entries.json"), data);
  return true;
});
ipcMain.handle("krypt:deleteEntries", () => {
  const p = userDataPath("krypt-entries.json");
  if (fs.existsSync(p)) fs.unlinkSync(p);
  return true;
});

/* ------------------------------------------------------------------ */
/*  IPC: exportar / importar copia de seguridad.                       */
/*  Los datos ya estan cifrados en disco, asi que exportar es solo      */
/*  copiar ese contenido cifrado a un archivo .kryptbak elegido por     */
/*  el usuario (util para llevarlo a otro equipo o guardarlo aparte).   */
/* ------------------------------------------------------------------ */

ipcMain.handle("krypt:exportBackup", async () => {
  const user = readJsonSafe(userDataPath("krypt-user.json"));
  const entries = readJsonSafe(userDataPath("krypt-entries.json")) || [];
  if (!user) return { ok: false, reason: "no-user" };
  const { canceled, filePath } = await dialog.showSaveDialog({
    title: "Exportar copia de seguridad de Krypt-app",
    defaultPath: "krypt-backup.kryptbak",
    filters: [{ name: "Krypt backup", extensions: ["kryptbak"] }],
  });
  if (canceled || !filePath) return { ok: false, reason: "canceled" };
  writeJsonSafe(filePath, { version: 1, user, entries });
  return { ok: true, filePath };
});

ipcMain.handle("krypt:importBackup", async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({
    title: "Importar copia de seguridad de Krypt-app",
    properties: ["openFile"],
    filters: [{ name: "Krypt backup", extensions: ["kryptbak", "json"] }],
  });
  if (canceled || !filePaths[0]) return { ok: false, reason: "canceled" };
  const backup = readJsonSafe(filePaths[0]);
  if (!backup || !backup.user) return { ok: false, reason: "invalid" };
  writeJsonSafe(userDataPath("krypt-user.json"), backup.user);
  writeJsonSafe(userDataPath("krypt-entries.json"), backup.entries || []);
  return { ok: true };
});
