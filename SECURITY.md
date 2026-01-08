# Security Policy

**[ English ](#-reporting-a-vulnerability) | [ Русский ](#-сообщение-об-уязвимости)**

---

## 🇺🇸 Reporting a Vulnerability

We take the security of NDSFC seriously. Because this software handles sensitive encryption and data destruction, we appreciate the efforts of security researchers and the community in helping us ensure its integrity.

### Supported Versions

Only the latest stable release and the main branch are currently supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.2.1   | :white_check_mark: |
| 0.1.0   | :x:                |
| < 0.3   | :x:                |

### How to Report

If you believe you have found a security vulnerability in NDSFC, please **DO NOT** open a public issue. This allows us to fix the vulnerability before it can be exploited.

1.  **Email**: Send a detailed report to **[coringnight@gmail.com]**.
2.  **Encryption (Optional but Recommended)**: If the report contains sensitive Proof-of-Concept (PoC) code, please encrypt your email using our PGP Key:
    *   **Key ID**: `6423D0DB66664CFD`

### What to Include

*   The specific version of NDSFC affected.
*   Steps to reproduce the vulnerability.
*   Proof of concept (PoC) code or screenshots.
*   Impact assessment (e.g., Data Leak, Auth Bypass, RAM Persistence).

### Scope

**In Scope:**
*   Cryptographic weaknesses (e.g., issues with AES/ChaCha implementation).
*   Authentication bypass (2FA skip, Password bruteforce flaws).
*   Data persistence in RAM after session closure.
*   Steganography detection (statistical analysis revealing hidden data).
*   Failure of the Shredder mechanism.

**Out of Scope:**
*   Attacks requiring physical access to an unlocked machine *before* NDSFC is launched.
*   Social engineering or phishing attacks against users.
*   Denial of Service (DoS) attacks that do not compromise data.

### Response Timeline

*   **Acknowledge**: We will respond to your report within **48 hours**.
*   **Assessment**: We will confirm the vulnerability within **1 week**.
*   **Fix**: We aim to release a patch or workaround as soon as possible, depending on severity.

---

## 🇷🇺 Сообщение об уязвимости

Мы крайне серьезно относимся к безопасности NDSFC. Поскольку это ПО предназначено для защиты критических данных, мы приветствуем помощь исследователей безопасности.

### Поддерживаемые версии

Обновления безопасности выходят только для последней стабильной версии.

| Версия  | Поддержка          |
| ------- | ------------------ |
| 0.2.1   | :white_check_mark: |
| 0.1.0   | :x:                |
| < 0.3   | :x:                |

### Процесс сообщения

Если вы нашли уязвимость, пожалуйста, **НЕ СОЗДАВАЙТЕ** публичный Issue на GitHub. Это может поставить под угрозу других пользователей.

1.  **Email**: Отправьте детальный отчет на **[coringnight@gmail.com]**.
2.  **Шифрование (Рекомендуется)**: Если отчет содержит рабочий эксплойт, зашифруйте письмо нашим PGP ключом:
    *   **Key ID**: `6423D0DB66664CFD`

### Что включить в отчет

*   Версия NDSFC, в которой найдена ошибка.
*   Пошаговая инструкция по воспроизведению.
*   Proof of Concept (PoC) или скриншоты.
*   Оценка влияния (например: утечка ключей, обход 2FA, остаточные данные в RAM).

### Область действия (Scope)

**Входит в Scope:**
*   Криптографические слабости (ошибки в реализации AES/ChaCha).
*   Обход аутентификации или 2FA.
*   Сохранение ключей в оперативной памяти после закрытия сессии.
*   Обнаружение стеганографии (если скрытый контейнер можно детектировать статистически).
*   Сбой алгоритмов уничтожения данных (Shredder).

**Не входит в Scope:**
*   Атаки, требующие физического доступа к разблокированному ПК *до* запуска программы.
*   Социальная инженерия.
*   DDoS атаки, которые не приводят к утечке данных.

### Сроки реакции

*   **Подтверждение получения**: Мы ответим в течение **48 часов**.
*   **Анализ**: Мы подтвердим наличие уязвимости в течение **1 недели**.
*   **Исправление**: Патч будет выпущен в кратчайшие сроки в зависимости от критичности бага.
