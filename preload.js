const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("krypt", {
  loadUser: () => ipcRenderer.invoke("krypt:loadUser"),
  saveUser: (data) => ipcRenderer.invoke("krypt:saveUser", data),
  deleteUser: () => ipcRenderer.invoke("krypt:deleteUser"),
  loadEntries: () => ipcRenderer.invoke("krypt:loadEntries"),
  saveEntries: (data) => ipcRenderer.invoke("krypt:saveEntries", data),
  deleteEntries: () => ipcRenderer.invoke("krypt:deleteEntries"),
  exportBackup: () => ipcRenderer.invoke("krypt:exportBackup"),
  importBackup: () => ipcRenderer.invoke("krypt:importBackup"),
});
