<div align="center">

<img src="assets/Noxium.png" width="360" alt="NOXIUM logo"/>

# NOXIUM
### Secure Vault • PQC Hybrid • Anti-Forensics • Windows Only

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Qt](https://img.shields.io/badge/GUI-PyQt6-41CD52?style=for-the-badge&logo=qt&logoColor=white)](#)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?style=for-the-badge&logo=windows&logoColor=white)](#)
[![Status](https://img.shields.io/badge/Status-Beta%2FExperimental-ef4444?style=for-the-badge)](#)
[![License](https://img.shields.io/badge/License-GPLv3-yellow?style=for-the-badge)](LICENSE)

</div>

---

## Кратко
- NOXIUM — это настольное приложение для безопасных хранилищ, шифрования файлов и защищенных заметок.
- Поддерживает гибкие алгоритмы (ChaCha20-Poly1305, AES-256-GCM) и гибридный PQC режим (Kyber, через `pqcrypto`).
- Работает с vault‑файлами в бинарном формате, JSON больше не используется.
- Интерфейс минималистичный, с анимациями, темной/светлой темой и кастомными акцентами.

> ⚠️ Важно: часть функций экспериментальна и может работать нестабильно. Смотрите раздел **Бета/Experimental**.

---

## Виджеты интерфейса (основные экраны)
<table>
  <tr>
    <td width="50%">
      <h3>Mission Control</h3>
      <ul>
        <li>Мониторинг системы (CPU/RAM)</li>
        <li>Аудит действий (Security Audit Log)</li>
        <li>Поиск по зашифрованному индексу</li>
        <li>Быстрые действия: Encrypt, GhostLink, Rebuild Index</li>
      </ul>
    </td>
    <td width="50%">
      <h3>Cryptography</h3>
      <ul>
        <li>Очередь файлов и статистика</li>
        <li>Выбор режима шифрования</li>
        <li>Сжатие, шредер, PQC гибрид</li>
        <li>Драг‑энд‑дроп файлов</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>Omega Tools</h3>
      <ul>
        <li>Steganography (PNG LSB)</li>
        <li>Ghost Link (SFTP)</li>
        <li>PassGen (генератор паролей)</li>
        <li>Secure Journal (зашифрованные заметки)</li>
        <li>Folder Watcher (авто‑шифрование)</li>
      </ul>
    </td>
    <td width="50%">
      <h3>Environment</h3>
      <ul>
        <li>Темы: Light/Dark + кастомные акценты</li>
        <li>Auto‑Lock (таймер)</li>
        <li>Настройки PQC</li>
        <li>Backup .vib + Recovery Shares</li>
      </ul>
    </td>
  </tr>
</table>

---

## Функциональность (подробно)

### Vault и безопасность
- **Vault v2 (бинарный формат .vault)** с обёрнутым ключом и шифрованным blob‑контейнером.
- **Автомиграция** со старых JSON‑vaultов: конвертация + удаление JSON.
- **2FA (TOTP)** и **Duress Password** (аварийное уничтожение).
- **Сессии в памяти** + авто‑блокировка по таймеру.
- **Audit Log** для локальных событий (в памяти).

### Криптографический движок
- **Файловое шифрование**: ChaCha20‑Poly1305 или AES‑256‑GCM.
- **PQC Hybrid (Kyber)**: гибридный ключ через KEM + HKDF (опционально).
- **KDF**: Argon2id (основное), Scrypt (legacy blobs).
- **Сжатие перед шифрованием** (опционально).
- **Legacy‑decrypt**: поддержка старых форматов (AES‑SIV, Blowfish‑CTR, CAST‑CTR, ранние PQC‑контейнеры).
- **Secure Shredder** (DoD 5220.22‑M, до 35 проходов).

### Хранилище и данные
- **Индексатор**: in‑memory SQLite + зашифрованный `index.db.enc`.
- **Заметки**: `.note` файлы с шифрованным содержимым.
- **Бэкапы**: `.vib` архивы, зашифрованные на экспорт/импорт.
- **Файлы**: `.ndsfc` для зашифрованных файлов.

### Инструменты и сеть
- **Ghost Link (SFTP)** с опциональным SOCKS5.
- **Folder Watcher**: авто‑шифрование новых файлов в папке.
- **Steganography**: скрытие/извлечение данных в PNG.
- **PassGen**: генератор паролей с авто‑очисткой буфера.

### UI/UX
- Light/Dark режимы, кастомные акценты.
- Плавные переходы (FadeStack).
- Минималистичные карточки и визуальные статусы.

---

## Самодельные (кастомные) компоненты
- **NFX1 контейнер** для файлового шифрования (структурированный заголовок + флаги).
- **NDSB/NDSK blob‑форматы** для данных и обёрнутого ключа.
- **Algebraic Recovery Shares** (на базе Shamir Secret Sharing).
- **Автомиграция legacy‑форматов** с уничтожением JSON‑артефактов.

> ⚠️ Эти компоненты не проходили независимый аудит. Используйте осознанно.

---

## Бета / Experimental
Некоторые функции находятся в бете и могут работать нестабильно:
- PQC Hybrid (Kyber) и связанная инфраструктура ключей.
- Steganography (скрытие в PNG).
- Ghost Link (SFTP) и SOCKS5 прокси.
- Folder Watcher (фоновый режим).
- Recovery Shares (Shamir‑разделение ключа).
- Индексатор и поиск (in‑memory + encrypted save).

---

## Форматы хранения
```
vaults/
  <vault>.vault           # бинарный vault v2
  <vault>/index.db.enc    # зашифрованный индекс
  <vault>/notes/*.note    # зашифрованные заметки
```

---

## Установка
```bash
git clone https://github.com/Vyxara-Arch/NOXIUM.git
cd NOXIUM
pip install -r requirements.txt
python main.py
```

---

## Требования
- Windows 10/11
- Python 3.10+
- Библиотеки из `requirements.txt`

---

## Авторы и вклад
```
MintyExtremum  - Core Cryptography
Vyxara-Arch    - Architecture & UI
Blooder        - Security Research & Testing
```

---

## Лицензия
GNU GPLv3. Приложение поставляется "как есть" без гарантий.

<div align="center">
NOXIUM — Leave Nothing Behind
</div>
