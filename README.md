<div align="center">

# 🛡️ NDSFC v2.0
## Not Detectable System File Cryptographer
### *Titanium-Grade Privacy & Deniable Encryption Suite*

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-Post--Quantum%20Ready-EE3322?style=for-the-badge&logo=shield&logoColor=white)](https://github.com/Vyxara-Arch/NDSFC)
[![UI](https://img.shields.io/badge/UI-Glassmorphism%20V2-00e676?style=for-the-badge)](https://github.com/Vyxara-Arch/NDSFC)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/Vyxara-Arch/NDSFC)

**[ English Documentation ](#-english) | [ Документация на Русском ](#-russian)**

</div>

---

<a name="english"></a>
## 🇺🇸 Project Overview

**NDSFC (v2.0)** is an advanced security ecosystem designed for individuals and professionals operating in high-risk digital environments. It transcends simple encryption by providing a multi-layered fortress that focuses on **Plausible Deniability**, **Anti-Forensics**, and **Titanium-Grade Cryptography**.

Every feature is engineered to leave **zero footprint** on the host system while providing a seamless, modern, and high-fidelity user experience.

---

## � Features & Capabilities

### 1. ⚛️ Advanced Cryptography Suite
The heart of NDSFC is a versatile engine supporting multiple encryption standards:
- **Post-Quantum Cascade (V2)**: A proprietary hybrid KEM simulation. Data is first processed with `AES-256-GCM`, then wrapped in a second layer of `ChaCha20-Poly1305` with `SHA3-512` derived keys.
- **AES-SIV (Synthetic IV)**: Deterministic encryption with built-in protection against replay attacks and nonce-misuse.
- **ChaCha20-Poly1305**: High-speed, modern authenticated encryption.
- **Blowfish & CAST5 (CTR)**: Specialized ciphers for high-entropy requirements and variable block sizes.
- **Scrypt KDF**: Industry-standard key derivation with high iteration counts and random 16-byte salts.

### 2. 🛡️ Anti-Forensics & Deniability
- **RAM-Only Sessions**: Encryption keys and decrypted buffers are kept strictly in volatile memory. They are wiped instantly upon logout, timeout, or application crash.
- **🔥 Duress (Panic) Protocol**: A secondary "Duress Password" can be set for every vault. Entering this password at login **silently and permanently destroys** the vault's metadata and index, leaving a clean environment.
- **🖼️ Steganography 2.0**: Completely hide your encrypted containers inside standard PNG images. These images remain viewable but carry hidden, bit-perfect data payloads.
- **👻 Ghost Link (SFTP)**: Upload your files directly to a remote secure server via an encrypted SSH tunnel, bypassing local network snooping.

### 3. 📂 Productivity & Management
- **� Secure Search Index**: A dedicated `IndexManager` maintains an encrypted SQLite database of your vault's contents. Search for filenames or paths instantly without having to decrypt individual items.
- **🧹 DoD 5220.22-M Shredder**: Overwrites files up to 35 times with random patterns to ensure they are unrecoverable by forensic software.
- **👀 Folder Watcher**: Monitor specific directories; files dropped there are automatically encrypted and indexed according to your presets.
- **📝 Encrypted Journal**: A built-in markdown-ready editor for storing sensitive notes, passwords, and instructions inside your vault.

### 4. 🎨 Modern Interface (Glassmorphism V2)
- **Ultra-Modern Style**: Translucent "glass" cards, smooth animations, and high-fidelity icons.
- **Theme Manager**: Includes 7+ built-in themes (Matrix, Cyberpunk, Ghost, etc.) and a **Live Theme Creator** to design your own color palettes.

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.10 or higher
- Windows OS (Optimized for 10/11)

### Quick Start
```bash
# Clone the repository
git clone https://github.com/Vyxara-Arch/NDSFC.git
cd NDSFC

# Install dependencies
pip install -r requirements.txt

# Launch the fortress
python main.py
```

### Initial Configuration
1. Click **"Create New Environment"**.
2. Set a strong **Master Password** and a separate **Duress Password**.
3. **CRITICAL**: Scan the QR code with Google Authenticator or any TOTP app. **There is no recovery if you lose your 2FA.**

---

<a name="russian"></a>
## 🇷🇺 Описание проекта (Russian)

**NDSFC (v2.0)** — это не просто программа для шифрования, это полноценная цифровая крепость. Система спроектирована так, чтобы не оставлять следов в системе и обеспечивать максимальный уровень **Планомерного Отрицания (Plausible Deniability)**.

### ✨ Ключевые Возможности
- **⚛️ Постквантовая защита**: Гибридное каскадное шифрование (AES-256 + ChaCha20) для защиты от угроз будущего.
- **🔥 Режим Паники**: Специальный пароль, который при вводе имитирует обычный вход, но на самом деле безвозвратно удаляет зашифрованное хранилище.
- **🖼️ Стеганография**: Скрытие данных внутри обычных фотографий (PNG).
- **� Умный поиск**: Мгновенный поиск по зашифрованным файлам через зашифрованную базу данных индекса.
- **🧠 Работа в RAM**: Ни один ключ шифрования никогда не записывается на диск — всё хранится только в оперативной памяти и исчезает при закрытии приложения.

---

## 📄 License & Disclaimer

**License**: Distributed under the **GNU GPLv3 License**.

**DISCLAIMER**: This software is provided "as is", without warranty of any kind. The authors are not responsible for data loss, damages, or illicit use. Use at your own risk. There are **NO backdoors**—if you lose your credentials, your data is lost forever.

<div align="center">
    <p>Developed with ❤️ & 🔐 by [MintyExtremum & Vyxara-Arch]</p>
</div>
