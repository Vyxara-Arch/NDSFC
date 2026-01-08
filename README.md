<div align="center">

# 🛡️ NDSFC
### Not Detectable System File Cryptographer

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Security-Military%20Grade-red?style=for-the-badge&logo=shield)
![Platform](https://img.shields.io/badge/Platform-Windows%20(Local)-0078D6?style=for-the-badge&logo=windows)
![GUI](https://img.shields.io/badge/GUI-PyQt6-green?style=for-the-badge)

**[ English ](#-english-documentation) | [ Русский ](#-документация-на-русском)**

</div>

---

<a name="english"></a>
## 🇺🇸 English Documentation

### 🔒 Project Overview
**NDSFC** is a high-security, local-first data fortress designed for specialized environments. It features a modern dark UI (PyQt6), multi-vault architecture, and post-quantum encryption capabilities. It operates strictly offline (except for user-initiated SFTP) and utilizes RAM-only session handling to prevent forensic recovery.

### ✨ Key Features

*   **🗄️ Multi-Vault Architecture**: Create separate isolated environments (Work, Personal, Decoy) with independent keys and settings.
*   **⚛️ Quantum-Resistant Encryption**:
    *   **Standard**: AES-256-GCM or ChaCha20-Poly1305.
    *   **PQC Cascade**: A hybrid layer combining AES-256 + ChaCha20 for defense against future quantum attacks. (Currently not working as needed. In Beta.)
    *   **2FA File Lock**: Files are encrypted using a password AND a secret answer.
*   **🖼️ Steganography 2.0**: Hide encrypted archives inside PNG images with bit-perfect extraction logic. (Instable Beta , Not recommended to use this function)
*   **👻 Ghost Link (SFTP)**: Securely upload sensitive data to remote servers via SSH tunnels directly from the app. (Currently in Beta)
*   **🔥 Panic Mode & Shredder**:
    *   **Duress Password**: Entering a specific "Panic Password" at login silently wipes the vault database.
    *   **DoD Shredding**: Files are overwritten 3+ times before deletion.
*   **🧠 RAM-Only Session**: Decryption keys exist only in volatile memory and are wiped upon logout or exit.

### 🛠️ Installation

1.  **Prerequisites**: Python 3.10 or higher.
2.  **Clone & Setup**:
    ```bash
    git clone https://github.com/Vyxara-Arch/NDSFC.git
    cd NDSFC
    pip install -r requirements.txt
    ```

### 🚀 Usage

1.  **Launch the System**:
    ```bash
    python main.py
    ```
2.  **Initialization**:
    *   Click **"Create New Environment"**.
    *   Set a Username, Master Password, and a **Duress (Panic) Password**.
    *   Scan the QR Code (or copy the Secret) into **Google Authenticator**.
3.  **Dashboard**:
    *   **Drag & Drop** files to encrypt/decrypt.
    *   Use **Omega Tools** for Steganography or Metadata Cleaning.

### ⚠️ Security Notice
This tool is designed for **educational and defensive purposes**.
*   If you forget your password or 2FA, **data is permanently lost**. There are no backdoors. (Right now is not working.)
*   The **Duress Password** destroys the active vault configuration immediately. Use with caution.

---

<a name="russian"></a>
## 🇷🇺 Документация на Русском

### 🔒 О проекте
**NDSFC** — это автономная цифровая крепость для защиты данных. Программа создана для работы в агрессивных средах, использует современный интерфейс на PyQt6, поддерживает множество изолированных хранилищ и постквантовое шифрование. Система работает локально и использует сессии только в оперативной памяти (RAM-Only), чтобы предотвратить форензику (восстановление данных экспертами).

### ✨ Ключевые возможности

*   **🗄️ Система Мульти-Хранилищ**: Создавайте изолированные среды (Рабочая, Личная, Ложная) с разными ключами и настройками.
*   **⚛️ Квантовая Стойкость (PQC)**:
    *   **Стандарт**: AES-256-GCM или ChaCha20-Poly1305.
    *   **PQC Каскад**: Гибридное шифрование (AES-256 поверх ChaCha20) для защиты от квантовых компьютеров. (Спорная функция,в данный момент в бете)
    *   **2FA Блокировка Файлов**: Файл шифруется паролем + секретным ответом. Без обоих компонентов файл не открыть.
*   **🖼️ Стеганография 2.0**: Скрытие зашифрованных архивов внутри PNG-изображений без потери данных. (Работает нестабильно,сейчас рефакторится)
*   **👻 Ghost Link (SFTP)**: Безопасная передача данных на удаленные серверы через SSH-туннель. (Пока что в бете)
*   **🔥 Режим Паники и Шредер**:
    *   **Пароль под принуждением**: Ввод специального "Panic Password" при входе вызывает тихое уничтожение базы данных хранилища. (Будет введено в будущем)
    *   **DoD Уничтожение**: Файлы перезаписываются (1-35 проходов) перед удалением.
*   **🧠 Сессии в RAM**: Ключи расшифровки живут только в оперативной памяти и обнуляются при выходе.

### 🛠️ Установка

1.  **Требования**: Python 3.10 или выше.
2.  **Установка**:
    ```bash
    git clone https://github.com/Vyxara-Arch/NDSFC.git
    cd NDSFC
    pip install -r requirements.txt
    ```

### 🚀 Использование

1.  **Запуск**:
    ```bash
    python main.py
    ```
2.  **Первичная настройка**:
    *   Нажмите **"Create New Environment"** (Создать среду).
    *   Придумайте Логин, Мастер-пароль и **Пароль Паники**.
    *   Добавьте секретный код в **Google Authenticator**.
3.  **Панель управления**:
    *   Перетаскивайте файлы (**Drag & Drop**) для шифрования.
    *   Используйте вкладку **Omega Tools** для стеганографии или очистки метаданных (GPS) из фото.

### ⚠️ Предупреждение о безопасности
Инструмент создан для защиты приватности.
*   Если вы забудете пароль или потеряете 2FA — **данные восстановить невозможно**. Бэкдоров нет.
*   Ввод **Пароля Паники** безвозвратно удаляет конфигурацию активного хранилища. Будьте осторожны.

---

## 🗺️ Roadmap & TO-DO

We are constantly evolving NDSFC to meet military-grade standards. Here is what's coming next:

### 🇺🇸 Upcoming Features (English)
- [ ] **Hardware Key Support**: Integration with YubiKey/Nitrokey for physical 2FA authentication.
- [ ] **Tor Network Integration**: Native `.onion` routing for the Ghost Link (SFTP) module without external proxy configuration.
- [ ] **Decoy Operating System**: A bootloader hook that boots into a fake Windows environment if the wrong password is typed at system startup.
- [ ] **Cloud Obfuscation**: Split encrypted files into chunks and distribute them across multiple free cloud providers (Google Drive, Dropbox) so no single provider has the full file.
- [ ] **Mobile Companion App**: A Flutter-based mobile app to decrypt NDSFC containers on Android (Local only via USB-OTG).
- [ ] **Self-Destruct USB**: Feature to automatically wipe the vault if a specific USB "Key" is removed from the PC. (Not planning rn)

### 🇷🇺 Планы развития (Russian)
- [ ] **Поддержка аппаратных ключей**: Интеграция с YubiKey и Nitrokey для физической двухфакторной аутентификации.
- [ ] **Встроенный Tor**: Нативная маршрутизация через сеть `.onion` для модуля Ghost Link (SFTP) без необходимости ручной настройки прокси.
- [ ] **Ложная ОС (Decoy OS)**: Хук загрузчика, который загружает фальшивую, "чистую" Windows, если при включении компьютера введен неправильный пароль.
- [ ] **Облачная обфускация**: Разделение зашифрованного файла на части и распределение их по разным облакам (Google Drive, Dropbox), чтобы ни один провайдер не имел полного файла.
- [ ] **Мобильное приложение**: Приложение-компаньон на Android для расшифровки контейнеров NDSFC (только локально через USB-OTG).
- [ ] **USB-Детонатор**: Функция автоматического стирания хранилища, если из компьютера извлекается специальная USB-флешка ("Ключ"). (Пока что очень спорное решение)

---

## 📄 License

Distributed under the GNU GPLv3 License. See `LICENSE` for more information.

**DISCLAIMER:** This software is provided "as is", without warranty of any kind. The authors are not responsible for data loss, damages, or illicit use of this software. Use at your own risk.

## 📄 Лицензия

Распространяется под лицензией GNU GPLv3. См. файл `LICENSE` для получения дополнительной информации.

**ОТКАЗ ОТ ОТВЕТСТВЕННОСТИ:** Данное программное обеспечение предоставляется «как есть», без каких-либо гарантий. Авторы не несут ответственности за потерю данных, ущерб или незаконное использование данного ПО. Используйте на свой страх и риск.

---

<div align="center">
    <p>Developed with ❤️ & 🔐 by [MintyExtremum & Vyxara-Arch]</p>
</div>
