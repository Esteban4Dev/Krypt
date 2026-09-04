# 🔐 Krypt

**Gestor de contraseñas local y cifrado — sin servidores, sin nube, solo tu equipo.**

[![Electron](https://img.shields.io/badge/Electron-31.0.0-47848F?logo=electron&logoColor=white)](https://www.electronjs.org/)
[![License](https://img.shields.io/badge/license-MIT-brightgreen)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)]()

---

## ✨ Características

- 🔑 **Generador de contraseñas seguras** — longitud ajustable (8-200) y selección de caracteres (mayúsculas, minúsculas, números, símbolos).
- 🛡️ **Bóveda local cifrada** — todas las contraseñas se almacenan cifradas con AES-GCM de 256 bits.
- 🔒 **Contraseña maestra única** — protege toda tu bóveda con una sola clave.
- 🌐 **Sin servidores ni internet** — los datos nunca salen de tu equipo.
- 🧠 **Autenticación adicional** — ver o copiar una contraseña requiere reingresar tu contraseña maestra.
- 💾 **Copias de seguridad** — exporta/importa tu bóveda cifrada para migrar entre equipos.
- 🌍 **Bilingüe** — español e inglés, conmutación en un clic.
- 🎨 **Interfaz moderna** — diseño oscuro limpio e intuitivo.

---

## 🛡️ Seguridad

Krypt está diseñado con un enfoque **"zero-knowledge"** local:

| Mecanismo | Descripción |
|-----------|-------------|
| **PBKDF2** | 150,000 iteraciones para derivar la clave desde tu contraseña maestra. |
| **AES-GCM** | Cifrado autenticado de 256 bits para todas las contraseñas. |
| **MEK** | Clave maestra de cifrado de 256 bits, generada aleatoriamente. |
| **IV único** | Cada contraseña cifrada tiene su propio vector de inicialización. |
| **Sin recuperación** | No hay correo ni servidor para restablecer tu contraseña maestra — por diseño. |

> ⚠️ **Importante**: Si olvidas tu contraseña maestra, los datos almacenados **no se pueden recuperar**. Guarda tu contraseña en un lugar seguro y realiza copias de seguridad periódicas.

---

## 🚀 Instalación

### Prerrequisitos

- [Node.js](https://nodejs.org) 18 o superior
- npm o yarn

### Clonar y ejecutar en desarrollo

```bash
git clone https://github.com/tu-usuario/krypt-app.git
cd krypt-app
npm install
npm start
