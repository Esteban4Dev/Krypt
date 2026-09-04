# Krypt-app (Electron)

Generador de contraseñas + bóveda local cifrada, sin servidor, sin correo.
Bilingüe ES/EN.

## Cómo funciona la seguridad

- Al crear la cuenta se genera una **clave maestra de cifrado (MEK)** aleatoria de 256 bits.
- Tu **contraseña maestra** nunca se guarda: solo se usa (junto a PBKDF2, 150 000 iteraciones)
  para derivar una clave que envuelve (cifra) esa MEK con AES-GCM.
- Cada contraseña guardada en la bóveda se cifra con la MEK, con su propio IV.
- Al iniciar sesión, tu contraseña maestra se usa para desenvolver la MEK en memoria
  (nunca se guarda en disco). Si la contraseña es incorrecta, el descifrado falla y no entra.
- Ver o copiar una contraseña guardada pide la contraseña maestra otra vez, como capa extra.
- **No hay recuperación por correo ni por servidor.** Si olvidas tu contraseña maestra, los
  datos no se pueden recuperar — por diseño. Usa "Exportar copia de seguridad" para tener
  un respaldo del archivo cifrado en otro lugar.

Los datos se guardan como archivos JSON cifrados en la carpeta de datos de usuario del
sistema operativo (`app.getPath('userData')`), nunca se envían a internet.

## Requisitos

- [Node.js](https://nodejs.org) 18 o superior

## Instalar y ejecutar en modo desarrollo

```bash
cd krypt-app-electron
npm install
npm start
```

## Generar un instalador (Windows / macOS / Linux)

```bash
npm run dist
```

Esto usa `electron-builder` y deja el instalador en la carpeta `dist/`.
Puedes ajustar el `productName`, `appId` e íconos en la sección `build` de `package.json`.

## Estructura del proyecto

```
krypt-app-electron/
├── package.json
├── main.js         # proceso principal: ventana + acceso a archivos locales (IPC)
├── preload.js       # puente seguro entre main y renderer (contextIsolation activo)
└── src/
    ├── index.html
    ├── styles.css
    └── renderer.js  # generador + lógica de la bóveda + cifrado (Web Crypto API)
```

## Ícono de la app

Para usar el escudo de Krypt-app como ícono, coloca un `.ico` (Windows), `.icns` (macOS)
y/o `.png` de 512x512 (Linux) dentro de `build/` y referencia las rutas en la sección
`build` de `package.json` (`"icon": "build/icon.ico"`, etc.).
