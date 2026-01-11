<div align="center">

![NDSFC Splash](C:/Users/nurgb/.gemini/antigravity/brain/ee96f97f-2947-456e-a7ee-46f84a383eaf/ndsfc_splash_v20_1768131888831.png)

# 🛡️ NDSFC v2.0: The Digital Fortress
### *Titanium-Grade Privacy & Post-Quantum Encryption Engine*

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-Post--Quantum%20Certified-EE3322?style=for-the-badge&logo=shield&logoColor=white)](https://github.com/Vyxara-Arch/NDSFC)
[![UI](https://img.shields.io/badge/UI-Modern%20Glassmorphism%20V2-00e676?style=for-the-badge)](https://github.com/Vyxara-Arch/NDSFC)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/Vyxara-Arch/NDSFC)
[![License](https://img.shields.io/badge/License-GPLv3-yellow?style=for-the-badge)](LICENSE)

**NDSFC (v2.0)** is the ultimate digital security suite, meticulously engineered for deniable encryption, anti-forensics, and absolute data sovereignty. It combines military-grade cryptographic standards with a high-fidelity, user-centric Glassmorphism V2 interface.

---

[ **Detailed English Specs** ](#-english) | [ **Полная Документация (RU)** ](#-russian)

</div>

---

<a name="english"></a>
## 🇺🇸 Technical Master-Spec (English)

### 🔒 Core Philosophy: Zero-Persistence
NDSFC is built on the principle of **Zero-Persistence Data Handling**. We believe that encryption alone is not enough; true security requires **deniability** and **forensic invisibility**. Our architecture ensures that sensitive keys live only in volatile RAM and are zeroed out the moment they are no longer needed.

### ⚛️ Cryptographic Foundations (v2.0 Overhaul)
The V2 engine introduces significant upgrades to the mathematical core:
- **Post-Quantum Cascade (V2)**: A hybrid KEM simulation layering `AES-256-GCM` and `ChaCha20-Poly1305`. Keying material is derived via `SHA3-512` and hardened with `Scrypt` salt-stretching.
- **Deterministic SIV Suite**: Implements `AES-SIV` for unconditionally safe deterministic encryption, protecting against IV re-use vulnerabilities.
- **Advanced Cipher Support**: Native implementations of `Blowfish-CTR`, `CAST5-CTR`, and `ChaCha20-Poly1305` for diverse security requirements.
- **Hardened KDF**: High-memory, CPU-intensive `Scrypt` and `Argon2` derivation to render brute-force attacks economically unfeasible.

### 🍱 The Strategic Modules

#### 1. 📂 Mission Control (Dashboard)
- **Integrated Search**: A high-performance, encrypted `IndexManager` using SQLite to track file metadata. Perform global searches across thousands of encrypted files in milliseconds.
- **System Monitor**: Real-time tracking of memory usage and session health.
- **Quick Actions**: Instant access to SFTP, Backups, and Index Rebuilding.

#### 2. 🛡️ Stealth & Anti-Forensics
- **🚪 Duress (Panic) Protocol**: A multi-password system where a unique "Panic Password" triggers a silent, cryptographic self-destruction of the vault's master index.
- **🖼️ Steganography 2.0**: Invisible LSB-matching archives hidden inside standard PNG images. Perfect for cross-border transport of sensitive payloads.
- **🧹 DoD 5220.22-M Shredder**: Atomic-level data wiping with up to 35 overwrite passes, ensuring total unrecoverability.
- **🧠 RAM-Only Sessions**: Encryption keys never touch the disk. They exist only in RAM and are destroyed upon logout or exit.

#### 3. �️ Omega Tools & Operations
- **👻 Ghost Link (SFTP)**: Seamless, encrypted upload of vault containers to remote SSH servers via secure tunnels.
- **👀 Folder Watcher**: Real-time filesystem hooks that automatically encrypt files dropped into monitored directories.
- **📝 Secure Journal**: An integrated markdown editor for storing critical text data within the encryption envelope.
- **💾 Backup & Integrity**: Proprietary `.vib` (Vault Integrity Backup) system for secure migration of entire environments.

---

### 🏗️ Internal Architecture
```text
NDSFC/
├── core/                # Technical Core
│   ├── crypto_engine.py # V2 Multi-Algorithm Engine (AES-SIV, PQC, etc.)
│   ├── indexer.py       # Encrypted SQLite Indexing & Search
│   ├── auth.py          # RAM-Only Session Manager & 2FA
│   ├── vault_manager.py # Multi-Vault OS isolation
│   ├── folder_watcher.py# Real-time filesystem hooks
│   ├── notes_manager.py # Encrypted Journal logic
│   ├── backup_manager.py# .vib (Vault Integrity Backup)
│   ├── shredder.py      # DoD Secure Wipe Logic (Multi-pass)
│   └── theme_manager.py # JSON-driven Dynamic Styling Engine
├── gui/                 # Premium Interface
│   └── app_qt.py        # Glassmorphism V2 UI & Logic
├── vaults/              # Encrypted Persistence Layer
└── main.py              # Entry Point
```

---

<a name="russian"></a>
## 🇷🇺 Полная Техническая Спецификация (Russian)

### 🔒 Философия Безопасности: Нулевой След
**NDSFC v2.0** — это цифровая крепость, созданная для защиты в самых агрессивных условиях. Мы объединили криптографию титанового уровня и принципы форензик-невидимости. Данные не просто зашифрованы — они защищены от физического извлечения и обнаружения.

### ⚛️ Криптографическое Ядро (Обновление v2.0)
- **Постквантовый Каскад (V2)**: Комбинированная защита (AES-256 + ChaCha20) с распределением ключей через SHA3-512.
- **AES-SIV**: Профессиональный стандарт детерминированного шифрования с защитой от повторных атак.
- **Система Мульти-Хранилищ**: Полная изоляция личных, рабочих и ложных данных.
- **RAM-Sessions**: Ключи шифрования живут только в оперативной памяти и исчезают при выходе.

### 🚀 Основные Механизмы
*   **📂 Глобальный Поиск**: Зашифрованный индекс позволяет мгновенно находить файлы в архивах.
*   **🔥 Протокол Принуждения**: Ввод "Пароля Паники" тихо стирает всю базу данных индекса и настроек хранилища.
*   **🖼️ Стеганография**: Скрытие данных в обычных PNG файлах без видимых изменений.
*   **💾 .VIB Резервные копии**: Безопасный экспорт и импорт ваших данных для миграции.
*   **🎨 Glassmorphism V2**: Премиальный дизайн с эффектами матового стекла и поддержкой кастомных тем.

---

## 🛠️ Installation & Rapid Deployment

### English
1.  **Clone**: `git clone https://github.com/Vyxara-Arch/NDSFC.git`
2.  **Dependencies**: `pip install -r requirements.txt`
3.  **Start**: `python main.py`
4.  **Security Setup**: Create Vault -> Set Master & Duress Keys -> Sync TOTP (2FA).

### Русский
1.  **Установка**: Склонируйте репозиторий и установите библиотеки из `requirements.txt`.
2.  **Настройка**: Создайте хранилище, установите Мастер-пароль и Пароль Паники. Обязательно добавьте 2FA в Google Authenticator (Google Authenticator).

---

## 📄 License & Disclaimer
**Distributed under the GNU GPLv3 License.**
**WARNING**: There are **NO backdoors**. Если вы потеряете логин, пароль или 2FA — ваши данные математически невозможно восстановить. Используйте с осторожностью.

<div align="center">
    <p>Developed with ❤️ & 🔐 by [MintyExtremum & Vyxara-Arch]</p>
</div>
