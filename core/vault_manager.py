import os
import json
from core.auth import AuthManager

VAULT_DIR = "vaults"


class VaultManager:
    def __init__(self):
        if not os.path.exists(VAULT_DIR):
            os.makedirs(VAULT_DIR)

    def list_vaults(self):
        """Возвращает список доступных хранилищ (файлов .json)."""
        return [
            f.replace(".json", "") for f in os.listdir(VAULT_DIR) if f.endswith(".json")
        ]

    def create_vault(self, name, username, password, duress_password):
        """Создает новую изолированную среду."""
        path = os.path.join(VAULT_DIR, f"{name}.json")
        if os.path.exists(path):
            return False, "Vault already exists!"

        # Используем AuthManager для генерации хешей, но сохраняем в конкретный файл
        auth = AuthManager()

        from argon2 import PasswordHasher
        import pyotp

        ph = PasswordHasher()

        from core.crypto_engine import CryptoEngine

        totp_secret = pyotp.random_base32()

        # Data to be encrypted
        sensitive_data = json.dumps(
            {
                "totp_secret": totp_secret,
                "settings": {
                    "algo": "ChaCha20-Poly1305",
                    "shred_passes": 1,
                    "theme_accent": "#00e676",
                },
            }
        ).encode()

        encrypted_blob = CryptoEngine.data_encrypt(sensitive_data, password)

        # Public metadata (hashes are one-way) + Encrypted Blob
        data = {
            "username": username,
            "hash": ph.hash(password),
            "duress_hash": ph.hash(duress_password),
            "vault_data": encrypted_blob,
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=4)

        return True, totp_secret

    def get_vault_path(self, name):
        return os.path.join(VAULT_DIR, f"{name}.json")
