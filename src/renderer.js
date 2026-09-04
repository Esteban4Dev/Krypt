"use strict";

/* ====================================================================== */
/*  Crypto helpers (Web Crypto API - PBKDF2 + AES-GCM, cifrado por sobre)  */
/*  Disponible de forma nativa en el renderer de Electron (Chromium).      */
/* ====================================================================== */

const enc = new TextEncoder();
const dec = new TextDecoder();

function bytesToB64(bytes) {
  const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
function randomBytesB64(n) {
  const arr = new Uint8Array(n);
  crypto.getRandomValues(arr);
  return bytesToB64(arr);
}

async function deriveKEK(secret, saltB64) {
  const salt = b64ToBytes(saltB64);
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function wrapBytes(kek, bytesB64) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kek, b64ToBytes(bytesB64));
  return { iv: bytesToB64(iv), data: bytesToB64(cipher) };
}
async function unwrapBytes(kek, ivB64, dataB64) {
  const iv = b64ToBytes(ivB64);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, kek, b64ToBytes(dataB64));
  return bytesToB64(plain);
}
async function importMek(mekB64) {
  return crypto.subtle.importKey("raw", b64ToBytes(mekB64), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function encryptField(mekKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, mekKey, enc.encode(plaintext));
  return { iv: bytesToB64(iv), data: bytesToB64(cipher) };
}
async function decryptField(mekKey, ivB64, dataB64) {
  const iv = b64ToBytes(ivB64);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, mekKey, b64ToBytes(dataB64));
  return dec.decode(plain);
}

/* ====================================================================== */
/*  Generador de contrasenas                                               */
/* ====================================================================== */

const CHARSETS = {
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lower: "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?~",
};
function generatePassword(length, opts) {
  let pool = "";
  if (opts.upper) pool += CHARSETS.upper;
  if (opts.lower) pool += CHARSETS.lower;
  if (opts.numbers) pool += CHARSETS.numbers;
  if (opts.symbols) pool += CHARSETS.symbols;
  if (!pool) pool = CHARSETS.lower;
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  let out = "";
  for (let i = 0; i < length; i++) out += pool[arr[i] % pool.length];
  return out;
}
function estimateStrength(length, opts) {
  let pool = 0;
  if (opts.upper) pool += 26;
  if (opts.lower) pool += 26;
  if (opts.numbers) pool += 10;
  if (opts.symbols) pool += 28;
  if (pool === 0) pool = 26;
  const entropy = length * Math.log2(pool);
  if (entropy < 40) return { level: "weak", pct: 25, color: "var(--rose)" };
  if (entropy < 70) return { level: "fair", pct: 50, color: "var(--amber)" };
  if (entropy < 100) return { level: "good", pct: 75, color: "var(--teal)" };
  return { level: "strong", pct: 100, color: "var(--emerald)" };
}

/* ====================================================================== */
/*  Traducciones                                                           */
/* ====================================================================== */

const STR = {
  es: {
    appName: "Krypt",
    navGenerator: "Generador",
    navVault: "Boveda",
    genTitle: "Genera una contrasena segura al instante",
    genSubtitle: "Ajusta la longitud y los tipos de caracteres para crear una contrasena aleatoria.",
    length: "Longitud de la contrasena",
    upper: "Mayusculas", lower: "Minusculas", numbers: "Numeros", symbols: "Simbolos",
    copy: "Copiar", copied: "Copiada", regenerate: "Generar otra",
    strengthWeak: "Debil", strengthFair: "Aceptable", strengthGood: "Buena", strengthStrong: "Fuerte",
    saveToVault: "Guardar en la boveda",
    vaultIntroTitle: "Tu boveda de contrasenas",
    vaultIntroBody: "Crea un usuario local protegido con una contrasena maestra. Todo se cifra y se guarda solo en este equipo, sin servidores ni correos: ni siquiera Krypt-app puede leerlo sin tu contrasena maestra.",
    username: "Usuario", masterPassword: "Contrasena maestra", masterPasswordConfirm: "Confirma la contrasena maestra",
    createBtn: "Crear boveda segura",
    errUsername: "Escribe un nombre de usuario.",
    errPwShort: "La contrasena maestra debe tener al menos 8 caracteres.",
    errPwMatch: "Las contrasenas maestras no coinciden.",
    noRecoveryTitle: "Importante antes de continuar",
    noRecoveryBody: "Esta boveda no usa correo ni tiene un servidor para recuperar tu contrasena. Si la olvidas, los datos guardados no se pueden recuperar. Guarda tu contrasena maestra en un lugar seguro, y usa \"Exportar copia de seguridad\" desde la boveda para tener un respaldo.",
    understood: "Entendido, crear boveda",
    lockedTitle: "Boveda bloqueada",
    lockedBody: "Ingresa tu contrasena maestra para desbloquear.",
    unlock: "Desbloquear",
    errBadPassword: "Contrasena maestra incorrecta.",
    vaultTitle: "Boveda", newEntry: "Nueva entrada",
    site: "Sitio o app", entryUsername: "Usuario / correo", entryPassword: "Contrasena",
    generateNew: "Generar nueva", addEntry: "Anadir a la boveda",
    searchPlaceholder: "Buscar por sitio o usuario...",
    empty: "Tu boveda esta vacia. Anade tu primera entrada.",
    reveal: "Ver", hide: "Ocultar", copyPassword: "Copiar",
    del: "Eliminar", logout: "Cerrar sesion",
    reauthTitle: "Confirma tu contrasena maestra",
    reauthBody: "Por seguridad, vuelve a ingresar tu contrasena maestra para ver esta contrasena.",
    confirm: "Confirmar", cancel: "Cancelar",
    dangerZone: "Zona de peligro",
    exportBackup: "Exportar copia de seguridad",
    importBackup: "Importar copia de seguridad",
    deleteVault: "Eliminar boveda de este equipo",
    confirmDeleteVault: "Esto borra tu usuario y todas las entradas guardadas en este equipo, sin posibilidad de deshacerlo. Continuar?",
    createdOn: "Creada el",
    backupOk: "Copia de seguridad exportada",
    backupImportedOk: "Copia de seguridad importada. Inicia sesion con su contrasena maestra.",
    backupCanceled: "Operacion cancelada",
    backupInvalid: "El archivo de copia de seguridad no es valido",
  },
  en: {
    appName: "Krypt",
    navGenerator: "Generator", navVault: "Vault",
    genTitle: "Generate a strong password instantly",
    genSubtitle: "Adjust the length and character types to create a random password.",
    length: "Password length",
    upper: "Uppercase", lower: "Lowercase", numbers: "Numbers", symbols: "Symbols",
    copy: "Copy", copied: "Copied", regenerate: "Generate another",
    strengthWeak: "Weak", strengthFair: "Fair", strengthGood: "Good", strengthStrong: "Strong",
    saveToVault: "Save to vault",
    vaultIntroTitle: "Your password vault",
    vaultIntroBody: "Create a local account protected by a master password. Everything is encrypted and stored only on this computer, no servers or emails: not even Krypt-app can read it without your master password.",
    username: "Username", masterPassword: "Master password", masterPasswordConfirm: "Confirm master password",
    createBtn: "Create secure vault",
    errUsername: "Enter a username.",
    errPwShort: "Master password must be at least 8 characters.",
    errPwMatch: "Master passwords don't match.",
    noRecoveryTitle: "Important before continuing",
    noRecoveryBody: "This vault has no email or server to recover your password. If you forget it, saved data cannot be recovered. Keep your master password somewhere safe, and use \"Export backup\" from the vault to have a copy.",
    understood: "Understood, create vault",
    lockedTitle: "Vault locked",
    lockedBody: "Enter your master password to unlock.",
    unlock: "Unlock",
    errBadPassword: "Incorrect master password.",
    vaultTitle: "Vault", newEntry: "New entry",
    site: "Site or app", entryUsername: "Username / email", entryPassword: "Password",
    generateNew: "Generate new", addEntry: "Add to vault",
    searchPlaceholder: "Search by site or username...",
    empty: "Your vault is empty. Add your first entry.",
    reveal: "View", hide: "Hide", copyPassword: "Copy",
    del: "Delete", logout: "Log out",
    reauthTitle: "Confirm your master password",
    reauthBody: "For security, re-enter your master password to view this password.",
    confirm: "Confirm", cancel: "Cancel",
    dangerZone: "Danger zone",
    exportBackup: "Export backup",
    importBackup: "Import backup",
    deleteVault: "Delete vault from this computer",
    confirmDeleteVault: "This erases your account and every saved entry on this computer, with no way to undo it. Continue?",
    createdOn: "Created on",
    backupOk: "Backup exported",
    backupImportedOk: "Backup imported. Log in with its master password.",
    backupCanceled: "Operation canceled",
    backupInvalid: "The backup file is not valid",
  },
};

/* ====================================================================== */
/*  Estado                                                                 */
/* ====================================================================== */

const state = {
  lang: "es",
  view: "generator",
  gen: {
    length: 16,
    opts: { upper: true, lower: true, numbers: true, symbols: true },
    password: "",
    copied: false,
  },
  vault: {
    loading: true,
    user: null,
    entries: [],
    locked: true,
    mekB64: null,
    showAck: false, // aviso "sin recuperacion" antes de crear cuenta
    signup: { username: "", pw: "", pw2: "" },
    signupErr: "",
    signupBusy: false,
    loginPw: "",
    loginErr: "",
    loginBusy: false,
    showLoginPw: false,
    newEntry: { site: "", username: "", password: "" },
    showNewEntryPw: false,
    entryBusy: false,
    search: "",
    revealed: {},
    revealTimers: {},
    reauth: null, // { entryId, action, pw, err }
    confirmingDeleteVault: false,
    prefillPassword: null,
  },
  toast: null,
};
state.gen.password = generatePassword(state.gen.length, state.gen.opts);

function t() { return STR[state.lang]; }
function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
function showToast(msg) {
  state.toast = msg;
  render();
  setTimeout(() => { state.toast = null; render(); }, 2200);
}

/* ====================================================================== */
/*  Acciones                                                               */
/* ====================================================================== */

const actions = {
  setLang() {
    state.lang = state.lang === "es" ? "en" : "es";
    render();
  },
  setView(v) {
    state.view = v;
    render();
  },

  /* ---- generador ---- */
  regenerate() {
    state.gen.password = generatePassword(state.gen.length, state.gen.opts);
    state.gen.copied = false;
    render();
  },
  setLength(v) {
    state.gen.length = Number(v);
    state.gen.password = generatePassword(state.gen.length, state.gen.opts);
    render();
  },
  toggleOpt(key) {
    const next = { ...state.gen.opts, [key]: !state.gen.opts[key] };
    if (!next.upper && !next.lower && !next.numbers && !next.symbols) return; // al menos una opcion
    state.gen.opts = next;
    state.gen.password = generatePassword(state.gen.length, next);
    render();
  },
  async copyGenerated() {
    await navigator.clipboard.writeText(state.gen.password);
    state.gen.copied = true;
    render();
    setTimeout(() => { state.gen.copied = false; render(); }, 1600);
  },
  saveGeneratedToVault() {
    state.vault.prefillPassword = state.gen.password;
    state.view = "vault";
    render();
  },

  /* ---- signup ---- */
  showSignupAck() {
    const s = state.vault.signup;
    state.vault.signupErr = "";
    if (!s.username.trim()) return (state.vault.signupErr = t().errUsername, render());
    if (s.pw.length < 8) return (state.vault.signupErr = t().errPwShort, render());
    if (s.pw !== s.pw2) return (state.vault.signupErr = t().errPwMatch, render());
    state.vault.showAck = true;
    render();
  },
  cancelSignupAck() {
    state.vault.showAck = false;
    render();
  },
  async confirmSignup() {
    const v = state.vault;
    v.signupBusy = true;
    render();
    try {
      const mek = randomBytesB64(32);
      const saltPw = randomBytesB64(16);
      const kekPw = await deriveKEK(v.signup.pw, saltPw);
      const wrappedPw = await wrapBytes(kekPw, mek);
      const record = {
        username: v.signup.username.trim(),
        saltPw, wrappedPw,
        createdAt: new Date().toISOString(),
      };
      await window.krypt.saveUser(record);
      v.user = record;
      v.mekB64 = mek;
      v.locked = false;
      v.showAck = false;
      v.signup = { username: "", pw: "", pw2: "" };
    } catch (err) {
      v.signupErr = String((err && err.message) || err);
    } finally {
      v.signupBusy = false;
      render();
    }
  },

  /* ---- login ---- */
  toggleLoginPwVisible() {
    state.vault.showLoginPw = !state.vault.showLoginPw;
    render();
  },
  async login(e) {
    if (e) e.preventDefault();
    const v = state.vault;
    v.loginErr = "";
    v.loginBusy = true;
    render();
    try {
      const kekPw = await deriveKEK(v.loginPw, v.user.saltPw);
      const mek = await unwrapBytes(kekPw, v.user.wrappedPw.iv, v.user.wrappedPw.data);
      v.mekB64 = mek;
      v.locked = false;
      v.loginPw = "";
    } catch {
      v.loginErr = t().errBadPassword;
    } finally {
      v.loginBusy = false;
      render();
    }
  },
  logout() {
    state.vault.mekB64 = null;
    state.vault.locked = true;
    state.vault.loginPw = "";
    render();
  },

  /* ---- nueva entrada ---- */
  toggleNewEntryPwVisible() {
    state.vault.showNewEntryPw = !state.vault.showNewEntryPw;
    render();
  },
  generateForEntry() {
    state.vault.newEntry.password = generatePassword(16, { upper: true, lower: true, numbers: true, symbols: true });
    render();
  },
  async addEntry(e) {
    if (e) e.preventDefault();
    const v = state.vault;
    if (!v.newEntry.site.trim() || !v.newEntry.password) return;
    v.entryBusy = true;
    render();
    try {
      const mekKey = await importMek(v.mekB64);
      const encPw = await encryptField(mekKey, v.newEntry.password);
      const record = {
        id: (crypto.randomUUID && crypto.randomUUID()) || String(Date.now()) + Math.random(),
        site: v.newEntry.site.trim(),
        username: v.newEntry.username.trim(),
        pwIv: encPw.iv,
        pwData: encPw.data,
        createdAt: new Date().toISOString(),
      };
      const next = [record, ...v.entries];
      await window.krypt.saveEntries(next);
      v.entries = next;
      v.newEntry = { site: "", username: "", password: "" };
      v.showNewEntryPw = false;
    } finally {
      v.entryBusy = false;
      render();
    }
  },
  async deleteEntry(id) {
    const v = state.vault;
    const next = v.entries.filter((en) => en.id !== id);
    await window.krypt.saveEntries(next);
    v.entries = next;
    render();
  },

  /* ---- revelar / copiar contrasena guardada (pide contrasena maestra) ---- */
  openReauth(entryId, action) {
    state.vault.reauth = { entryId, action, pw: "", err: "" };
    render();
  },
  closeReauth() {
    state.vault.reauth = null;
    render();
  },
  async confirmReauth(e) {
    if (e) e.preventDefault();
    const v = state.vault;
    const r = v.reauth;
    if (!r) return;
    try {
      const kekPw = await deriveKEK(r.pw, v.user.saltPw);
      await unwrapBytes(kekPw, v.user.wrappedPw.iv, v.user.wrappedPw.data); // lanza error si es incorrecta
      const entry = v.entries.find((en) => en.id === r.entryId);
      const mekKey = await importMek(v.mekB64);
      const plain = await decryptField(mekKey, entry.pwIv, entry.pwData);
      if (r.action === "copy") {
        await navigator.clipboard.writeText(plain);
        showToast(t().copyPassword + " \u2713");
      } else {
        v.revealed[entry.id] = plain;
        clearTimeout(v.revealTimers[entry.id]);
        v.revealTimers[entry.id] = setTimeout(() => {
          delete v.revealed[entry.id];
          render();
        }, 15000);
      }
      v.reauth = null;
      render();
    } catch {
      v.reauth.pw = "";
      v.reauth.err = t().errBadPassword;
      render();
    }
  },
  hideRevealed(id) {
    clearTimeout(state.vault.revealTimers[id]);
    delete state.vault.revealed[id];
    render();
  },
  setSearch(val) {
    state.vault.search = val;
    render();
  },

  /* ---- backup ---- */
  async exportBackup() {
    const res = await window.krypt.exportBackup();
    if (res && res.ok) showToast(t().backupOk);
    else if (res && res.reason !== "canceled") showToast(t().backupCanceled);
  },
  async importBackup() {
    const res = await window.krypt.importBackup();
    if (res && res.ok) {
      state.vault.user = await window.krypt.loadUser();
      state.vault.entries = await window.krypt.loadEntries();
      state.vault.locked = true;
      state.vault.mekB64 = null;
      showToast(t().backupImportedOk);
      render();
    } else if (res && res.reason === "invalid") {
      showToast(t().backupInvalid);
    }
  },

  /* ---- eliminar boveda ---- */
  askDeleteVault() {
    state.vault.confirmingDeleteVault = true;
    render();
  },
  cancelDeleteVault() {
    state.vault.confirmingDeleteVault = false;
    render();
  },
  async deleteVault() {
    await window.krypt.deleteUser();
    await window.krypt.deleteEntries();
    const v = state.vault;
    v.user = null;
    v.entries = [];
    v.locked = true;
    v.mekB64 = null;
    v.confirmingDeleteVault = false;
    render();
  },
};
window.actions = actions;

/* ====================================================================== */
/*  Render                                                                 */
/* ====================================================================== */

function render() {
  const s = t();
  const root = document.getElementById("app");
  root.innerHTML = `
    <aside class="sidebar">
      <div class="brand">
        <img class="brand-badge" src="assets/logo.png" alt="Krypt" />
        <div class="brand-name">${s.appName}</div>
      </div>
      <nav class="nav">
        <button class="nav-btn ${state.view === "generator" ? "active" : ""}" onclick="actions.setView('generator')">${s.navGenerator}</button>
        <button class="nav-btn ${state.view === "vault" ? "active" : ""}" onclick="actions.setView('vault')">${s.navVault}</button>
      </nav>
      <div class="sidebar-footer">
        <button class="lang-btn" onclick="actions.setLang()">${state.lang === "es" ? "EN" : "ES"}</button>
      </div>
    </aside>
    <main class="main">
      <div class="container">
        ${state.view === "generator" ? renderGenerator(s) : renderVault(s)}
      </div>
    </main>
    ${state.vault.reauth ? renderReauthModal(s) : ""}
    ${state.toast ? `<div class="toast">${escapeHtml(state.toast)}</div>` : ""}
  `;
}

function renderGenerator(s) {
  const g = state.gen;
  const strength = estimateStrength(g.length, g.opts);
  const strengthLabel = { weak: s.strengthWeak, fair: s.strengthFair, good: s.strengthGood, strong: s.strengthStrong }[strength.level];
  const optRow = (key, label) => `
    <label class="checkbox-row">
      <input type="checkbox" ${g.opts[key] ? "checked" : ""} onchange="actions.toggleOpt('${key}')" />
      ${label}
    </label>`;
  return `
    <h1>${s.genTitle}</h1>
    <p class="subtitle">${s.genSubtitle}</p>

    <div class="card">
      <div class="pw-row">
        <div class="pw-display">${escapeHtml(g.password)}</div>
        <button class="btn btn-ghost btn-icon" title="${s.regenerate}" onclick="actions.regenerate()">&#8635;</button>
      </div>
      <div class="strength-row">
        <div class="strength-track"><div class="strength-fill" style="width:${strength.pct}%;background:${strength.color}"></div></div>
        <span class="strength-label">${strengthLabel}</span>
      </div>
      <div class="btn-row">
        <button class="btn btn-primary" style="flex:1" onclick="actions.copyGenerated()">${g.copied ? "&#10003; " + s.copied : s.copy}</button>
        <button class="btn btn-ghost" onclick="actions.saveGeneratedToVault()">${s.saveToVault}</button>
      </div>
    </div>

    <div class="card">
      <div class="slider-row">
        <span class="eyebrow">${s.length}</span>
        <span class="slider-value">${g.length}</span>
      </div>
      <input type="range" min="8" max="200" value="${g.length}" oninput="actions.setLength(this.value)" />
      <div class="checkbox-grid">
        ${optRow("upper", s.upper)}
        ${optRow("lower", s.lower)}
        ${optRow("numbers", s.numbers)}
        ${optRow("symbols", s.symbols)}
      </div>
    </div>
  `;
}

function renderVault(s) {
  const v = state.vault;
  if (v.loading) return `<p class="subtitle">...</p>`;
  if (!v.user) return renderSignup(s);
  if (v.locked) return renderLogin(s);
  return renderUnlockedVault(s);
}

function renderSignup(s) {
  const v = state.vault;
  if (v.showAck) {
    return `
      <div class="warn-box">
        <div class="warn-title">&#9888; ${s.noRecoveryTitle}</div>
        <p class="subtitle" style="margin-top:8px">${s.noRecoveryBody}</p>
        <div class="btn-row">
          <button class="btn btn-ghost" style="flex:1" onclick="actions.cancelSignupAck()">${s.cancel}</button>
          <button class="btn btn-primary" style="flex:1" ${v.signupBusy ? "disabled" : ""} onclick="actions.confirmSignup()">${s.understood}</button>
        </div>
      </div>
    `;
  }
  return `
    <h1>${s.vaultIntroTitle}</h1>
    <p class="subtitle">${s.vaultIntroBody}</p>
    <form class="card" onsubmit="return false">
      <div class="field">
        <span class="eyebrow field-label">${s.username}</span>
        <input class="input" value="${escapeHtml(v.signup.username)}" oninput="state.vault.signup.username=this.value" />
      </div>
      <div class="field">
        <span class="eyebrow field-label">${s.masterPassword}</span>
        <input class="input" type="password" value="${escapeHtml(v.signup.pw)}" oninput="state.vault.signup.pw=this.value" />
      </div>
      <div class="field">
        <span class="eyebrow field-label">${s.masterPasswordConfirm}</span>
        <input class="input" type="password" value="${escapeHtml(v.signup.pw2)}" oninput="state.vault.signup.pw2=this.value" />
      </div>
      ${v.signupErr ? `<p class="error-text">&#9888; ${escapeHtml(v.signupErr)}</p>` : ""}
      <button class="btn btn-primary btn-block" style="margin-top:14px" onclick="actions.showSignupAck()">${s.createBtn}</button>
    </form>
  `;
}

function renderLogin(s) {
  const v = state.vault;
  return `
    <h1>${s.lockedTitle}</h1>
    <p class="subtitle">${s.lockedBody}</p>
    <form class="card" onsubmit="actions.login(event)">
      <div class="field">
        <span class="eyebrow field-label">${s.masterPassword}</span>
        <div class="input-wrap">
          <input class="input" type="${v.showLoginPw ? "text" : "password"}" autofocus value="${escapeHtml(v.loginPw)}" oninput="state.vault.loginPw=this.value" />
          <button type="button" class="input-icon-btn" onclick="actions.toggleLoginPwVisible()">${v.showLoginPw ? "&#128584;" : "&#128065;"}</button>
        </div>
      </div>
      ${v.loginErr ? `<p class="error-text">&#9888; ${escapeHtml(v.loginErr)}</p>` : ""}
      <button class="btn btn-primary btn-block" style="margin-top:14px" type="submit" ${v.loginBusy ? "disabled" : ""}>${s.unlock}</button>
    </form>
  `;
}

function renderUnlockedVault(s) {
  const v = state.vault;
  if (v.prefillPassword) {
    v.newEntry.password = v.prefillPassword;
    v.prefillPassword = null;
  }
  const q = v.search.trim().toLowerCase();
  const filtered = v.entries.filter((en) => !q || en.site.toLowerCase().includes(q) || en.username.toLowerCase().includes(q));

  const entryRows = filtered.map((en) => {
    const revealedVal = v.revealed[en.id];
    return `
      <div class="entry-card">
        <div class="entry-top">
          <div>
            <div class="entry-site">${escapeHtml(hostnameOf(en.site))}</div>
            ${en.username ? `<div class="entry-user">${escapeHtml(en.username)}</div>` : ""}
          </div>
          <button class="entry-del" title="${s.del}" onclick="actions.deleteEntry('${en.id}')">&#128465;</button>
        </div>
        <div class="entry-pw-row">
          <div class="entry-pw-display">${revealedVal ? escapeHtml(revealedVal) : "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"}</div>
          ${revealedVal
            ? `<button class="entry-action-btn" title="${s.hide}" onclick="actions.hideRevealed('${en.id}')">&#128584;</button>`
            : `<button class="entry-action-btn" title="${s.reveal}" onclick="actions.openReauth('${en.id}','view')">&#128065;</button>`}
          <button class="entry-action-btn" title="${s.copyPassword}" onclick="actions.openReauth('${en.id}','copy')">&#8942;&#8942;</button>
        </div>
      </div>
    `;
  }).join("");

  return `
    <div style="display:flex;align-items:center;justify-content:space-between">
      <h1>${s.vaultTitle}</h1>
      <button class="link-btn" onclick="actions.logout()">${s.logout}</button>
    </div>
    <p class="hint">${escapeHtml(v.user.username)}</p>

    <form class="card" onsubmit="actions.addEntry(event)">
      <div class="section-title">${s.newEntry}</div>
      <div class="field" style="margin-top:12px">
        <input class="input" placeholder="${s.site}" value="${escapeHtml(v.newEntry.site)}" oninput="state.vault.newEntry.site=this.value" />
      </div>
      <div class="field">
        <input class="input" placeholder="${s.entryUsername}" value="${escapeHtml(v.newEntry.username)}" oninput="state.vault.newEntry.username=this.value" />
      </div>
      <div class="field" style="display:flex;gap:8px">
        <div class="input-wrap" style="flex:1">
          <input class="input mono" placeholder="${s.entryPassword}" type="${v.showNewEntryPw ? "text" : "password"}" value="${escapeHtml(v.newEntry.password)}" oninput="state.vault.newEntry.password=this.value" />
          <button type="button" class="input-icon-btn" onclick="actions.toggleNewEntryPwVisible()">${v.showNewEntryPw ? "&#128584;" : "&#128065;"}</button>
        </div>
        <button type="button" class="btn btn-ghost btn-icon" title="${s.generateNew}" onclick="actions.generateForEntry()">&#10024;</button>
      </div>
      <button class="btn btn-primary btn-block" style="margin-top:6px" type="submit" ${v.entryBusy ? "disabled" : ""}>${s.addEntry}</button>
    </form>

    ${v.entries.length > 0 ? `
      <div class="field" style="margin-top:20px">
        <input class="input" placeholder="${s.searchPlaceholder}" value="${escapeHtml(v.search)}" oninput="actions.setSearch(this.value)" />
      </div>` : ""}

    <div style="margin-top:14px">
      ${v.entries.length === 0 ? `<div class="empty-state">${s.empty}</div>` : entryRows}
    </div>

    <div class="danger-zone">
      <div class="danger-title">${s.dangerZone}</div>
      <div class="btn-row" style="margin-top:10px">
        <button class="btn btn-ghost" style="flex:1" onclick="actions.exportBackup()">${s.exportBackup}</button>
        <button class="btn btn-ghost" style="flex:1" onclick="actions.importBackup()">${s.importBackup}</button>
      </div>
      ${v.confirmingDeleteVault ? `
        <p class="hint" style="margin-top:12px">${s.confirmDeleteVault}</p>
        <div class="btn-row">
          <button class="btn btn-ghost" style="flex:1" onclick="actions.cancelDeleteVault()">${s.cancel}</button>
          <button class="btn btn-danger" style="flex:1" onclick="actions.deleteVault()">${s.confirm}</button>
        </div>
      ` : `
        <button class="link-btn" style="margin-top:10px;color:var(--rose)" onclick="actions.askDeleteVault()">${s.deleteVault}</button>
      `}
    </div>
  `;
}

function renderReauthModal(s) {
  const r = state.vault.reauth;
  return `
    <div class="modal-overlay">
      <form class="modal-card" onsubmit="actions.confirmReauth(event)">
        <div class="section-title">&#128274; ${s.reauthTitle}</div>
        <p class="hint" style="margin-top:6px">${s.reauthBody}</p>
        <div class="field" style="margin-top:12px">
          <input class="input" type="password" autofocus placeholder="${s.masterPassword}" value="${escapeHtml(r.pw)}" oninput="state.vault.reauth.pw=this.value" />
        </div>
        ${r.err ? `<p class="error-text">&#9888; ${escapeHtml(r.err)}</p>` : ""}
        <div class="btn-row">
          <button type="button" class="btn btn-ghost" style="flex:1" onclick="actions.closeReauth()">${s.cancel}</button>
          <button type="submit" class="btn btn-primary" style="flex:1">${s.confirm}</button>
        </div>
      </form>
    </div>
  `;
}

function hostnameOf(site) {
  try {
    const url = new URL(site.includes("://") ? site : `https://${site}`);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return site;
  }
}

/* ====================================================================== */
/*  Arranque                                                               */
/* ====================================================================== */

(async function init() {
  state.vault.user = await window.krypt.loadUser();
  state.vault.entries = await window.krypt.loadEntries();
  state.vault.loading = false;
  render();
})();
