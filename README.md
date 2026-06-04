# RevPass 🔐

RevPass is a modern, zero-knowledge, local-first password vault built with **Tauri v2**, **Svelte 5**, **TypeScript**, and **Tailwind CSS v4**. 

Unlike traditional password managers that rely on master passwords or cloud servers, RevPass uses the cutting-edge **WebAuthn PRF (Pseudo-Random Function) Extension** to secure your local database. Your vault is unlocked using your device's biometrics (like Windows Hello or Touch ID) or hardware security keys (like YubiKeys) without any master password memorization.

---

## 🌟 Key Features

- **Passwordless Security**: Unlock your database securely via biometrics or hardware keys utilizing the WebAuthn PRF extension.
- **Zero-Knowledge Architecture**: All data (titles, URLs, usernames, passwords, and notes) is encrypted client-side using **256-bit AES-GCM** before being written to disk.
- **Local-First & Offline**: Your credentials are saved to a local SQLite database (`vault.db`) in your system's app data directory. No cloud, no trackers, absolute privacy.
- **Robust Recovery System**: Generates a 120-bit entropy human-readable recovery key (`VLT-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`) derived via PBKDF2-HMAC-SHA256 with 100,000 iterations.
- **Multi-Passkey Support**: Add backup passkeys (e.g. secondary security keys or platform authenticators) to prevent lockout if your primary authenticator becomes unavailable.
- **Password Generator**: Integrated cryptographically secure generator to spin up strong, random 20-character passwords.
- **Modern UI/UX**: Designed using Svelte 5 (utilizing reactive runes), Tailwind CSS v4, and `shadcn-svelte` components with automatic light/dark theme tracking.

---

## 🔒 Cryptographic Architecture

RevPass operates entirely in a zero-knowledge state, meaning no plaintext keys are ever saved to disk or transmitted:

1. **Master Encryption Key (MEK)**: A cryptographically secure 256-bit random key is generated on vault initialization. The MEK is used to encrypt and decrypt the individual credential records in the database.
2. **Passkey Derived Key (PDK)**: Derived by running the hardware-backed WebAuthn PRF secret output through **HKDF-SHA256** using the credential ID as salt. The PDK is used to encrypt the MEK.
3. **Recovery Derived Key (RecoveryDK)**: Derived from the 120-bit human-readable recovery key using **PBKDF2-HMAC-SHA256** (100,000 iterations, 128-bit salt). The RecoveryDK serves as an alternative encryption key for the MEK.
4. **Data Storage**: The database stores the encrypted MEK (wrapped in PDK and/or RecoveryDK) and the SQLite records encrypted under the MEK. Unlocking the vault imports the decrypted MEK bytes into volatile memory (`CryptoKey`) and never writes them to disk.

---

## 🛠️ Tech Stack

- **Framework**: [Tauri v2](https://tauri.app/) (Rust backend / Webview2 frontend)
- **Frontend**: [Svelte 5 / SvelteKit](https://svelte.dev/) (SPA mode)
- **Styling**: [Tailwind CSS v4](https://tailwindcss.com/)
- **UI Components**: [shadcn-svelte](https://shadcn-svelte.com/) & [Bits UI](https://bits-ui.com/)
- **Database**: SQLite (via `@tauri-apps/plugin-sql` plugin)
- **Icons**: [Lucide Svelte](https://lucide.dev/)

---

## 🚀 Getting Started

### Prerequisites

Ensure you have the following installed on your machine:
1. **Node.js** (v18+)
2. **Rust & Cargo** (v1.75+)
3. **Tauri Prerequisites**: Follow the [Tauri Setup Guide](https://v2.tauri.app/start/prerequisites/) for your operating system.
   - *On Windows:* Install the C++ build tools via Visual Studio Build Tools.
   - *Important Note:* The WebAuthn PRF extension requires platform support (e.g. Windows Hello setup or a compatible security key plugged in).

### Installation

1. Clone the repository and navigate to the project directory:
   ```bash
   git clone https://github.com/absktoday/revpass.git
   cd revpass
   ```

2. Install the frontend dependencies:
   ```bash
   pnpm install
   # or npm install / yarn install
   ```

### Development

Run the application in development mode:
```bash
pnpm tauri dev
# or npm run tauri dev
```
This boots up the Vite development server on `http://localhost:1420` and launches the native Tauri desktop window.

### Production Build

To compile a production-ready installer for your host operating system:
```bash
pnpm tauri build
# or npm run tauri build
```
The compiled binaries will be outputted to `src-tauri/target/release/bundle/`.

---

## 📂 Project Structure

```
revpass/
├── src/                    # Frontend Svelte codebase
│   ├── lib/
│   │   ├── components/     # UI elements & ThemeToggle
│   │   ├── crypto.ts       # SubtleCrypto wrappers (AES-GCM, HKDF, PBKDF2)
│   │   ├── db.ts           # SQLite wrappers & SQL schema migration
│   │   ├── webauthn.ts     # navigator.credentials WebAuthn PRF extension bindings
│   │   └── utils.ts        # Helper scripts
│   └── routes/
│       ├── +layout.svelte  # App layout wrapper
│       └── +page.svelte    # Main router state (loading, setup, locked, dashboard)
├── src-tauri/              # Rust backend & configurations
│   ├── src/
│   │   ├── main.rs         # Tauri entry point
│   │   └── lib.rs          # Setup plugins (SQL, Opener) & Invoke handlers
│   ├── Cargo.toml          # Rust dependencies (tauri, serde, tauri-plugin-sql)
│   └── tauri.conf.json     # Tauri app configuration (permissions, window configurations)
├── package.json            # Node devDependencies, scripts, and dependencies
└── tsconfig.json           # TypeScript configuration
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
