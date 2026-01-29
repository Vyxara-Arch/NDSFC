import json
import os
import pyotp
from argon2 import PasswordHasher

from core.shredder import Shredder
from core.audit import AuditLog
from core.vault_storage import VaultStorage, VAULT_EXT
from core.crypto_engine import CryptoEngine


class AuthManager:
    def __init__(self):
        self.ph = PasswordHasher()
        self.active_vault_path = None
        self.settings = {}
        self.vault_key = None
        self.vault_content = None

    def set_active_vault(self, path):
        self.active_vault_path = path

    def login(self, password, totp_code):
        if not self.active_vault_path or not os.path.exists(self.active_vault_path):
            return False, "Vault not selected"

        try:
            data = VaultStorage.read_vault(self.active_vault_path)
        except Exception:
            return False, "Invalid Vault Format"

        try:
            self.ph.verify(data["duress_hash"], password)
            self.trigger_panic()
            return False, "PANIC_TRIGGERED"
        except Exception:
            pass

        try:
            self.ph.verify(data["hash"], password)

            vault_key, vault_content = self._decrypt_vault_data(data, password)
            totp_secret = vault_content.get("totp_secret")
            if not totp_secret:
                return False, "Invalid Vault Data"

            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(totp_code):
                return False, "Invalid 2FA Code"

            self.vault_key = vault_key
            self.vault_content = vault_content
            changed = self._normalize_settings(vault_content)
            self.settings = vault_content.get("settings", {})

            if data.get("format") == "legacy_json" or data.get("version") == VaultStorage.VERSION_V1:
                new_path, new_key = self._migrate_to_v2(
                    data, vault_content, password, vault_key
                )
                if new_path:
                    self.active_vault_path = new_path
                    self.vault_key = new_key
            elif changed and vault_key:
                vault_blob = CryptoEngine.data_encrypt_key_blob(
                    json.dumps(vault_content).encode("utf-8"),
                    vault_key,
                    context="vault-data",
                )
                VaultStorage.write_vault(
                    self.active_vault_path,
                    data["username"],
                    data["hash"],
                    data["duress_hash"],
                    vault_blob,
                    wrapped_key=data.get("wrapped_key"),
                )

            return True, "SUCCESS"

        except Exception:
            return False, "Invalid Password or Data Corruption"

    def update_setting(self, key, value, password):
        if not self.active_vault_path:
            return

        try:
            data = VaultStorage.read_vault(self.active_vault_path)
        except Exception:
            return

        try:
            vault_key, vault_content = self._decrypt_vault_data(data, password)
            if not vault_content:
                return

            vault_content.setdefault("settings", {})
            vault_content["settings"][key] = value
            self.settings[key] = value

            if data.get("format") == "legacy_json" or data.get("version") == VaultStorage.VERSION_V1:
                new_path, new_key = self._migrate_to_v2(
                    data, vault_content, password, vault_key
                )
                if new_path:
                    self.active_vault_path = new_path
                    vault_key = new_key
            else:
                vault_blob = CryptoEngine.data_encrypt_key_blob(
                    json.dumps(vault_content).encode("utf-8"),
                    vault_key,
                    context="vault-data",
                )
                VaultStorage.write_vault(
                    self.active_vault_path,
                    data["username"],
                    data["hash"],
                    data["duress_hash"],
                    vault_blob,
                    wrapped_key=data.get("wrapped_key"),
                )

            self.vault_key = vault_key
            self.vault_content = vault_content

        except Exception as e:
            print(f"Failed to update settings: {e}")

    def trigger_panic(self):
        if self.active_vault_path:
            Shredder.wipe_file(self.active_vault_path)
        AuditLog.log("PANIC", "Vault Destroyed")

    def get_pqc_material(self):
        if not self.vault_content:
            return None, None, None
        pqc = self.vault_content.get("pqc", {})
        return pqc.get("public"), pqc.get("private"), pqc.get("kem", "kyber512")

    def get_pqc_public_key(self):
        pub, _, _ = self.get_pqc_material()
        if not pub:
            return None
        return CryptoEngine.decode_pqc_key(pub)

    def get_pqc_private_key(self):
        _, priv, _ = self.get_pqc_material()
        if not priv:
            return None
        return CryptoEngine.decode_pqc_key(priv)

    def ensure_pqc_keys(self, password, kem_name=None):
        if not self.vault_content:
            return False
        if not CryptoEngine.pqc_available():
            return False

        if not self.vault_key and self.active_vault_path:
            try:
                data = VaultStorage.read_vault(self.active_vault_path)
            except Exception:
                data = None
            if data and (
                data.get("format") == "legacy_json"
                or data.get("version") == VaultStorage.VERSION_V1
            ):
                new_path, new_key = self._migrate_to_v2(
                    data, self.vault_content, password, self.vault_key
                )
                if new_path:
                    self.active_vault_path = new_path
                    self.vault_key = new_key
            if not self.vault_key:
                return False

        pub, priv, kem = self.get_pqc_material()
        target_kem = kem_name or kem or "kyber512"

        if not pub or not priv or kem != target_kem:
            try:
                pub, priv = CryptoEngine.generate_pqc_keypair(target_kem)
            except Exception:
                return False
            self.vault_content["pqc"] = {
                "kem": target_kem,
                "public": pub,
                "private": priv,
            }
        else:
            return True

        vault_blob = CryptoEngine.data_encrypt_key_blob(
            json.dumps(self.vault_content).encode("utf-8"),
            self.vault_key,
            context="vault-data",
        )
        try:
            data = VaultStorage.read_vault(self.active_vault_path)
            VaultStorage.write_vault(
                self.active_vault_path,
                data["username"],
                data["hash"],
                data["duress_hash"],
                vault_blob,
                wrapped_key=data.get("wrapped_key"),
            )
            return True
        except Exception:
            return False

    def _decrypt_vault_data(self, data, password):
        if data.get("wrapped_key"):
            vault_key = CryptoEngine.data_decrypt_blob(
                data["wrapped_key"], password, context="vault-wrap"
            )
            vault_blob = data["vault_blob"]
            decrypted_bytes = CryptoEngine.data_decrypt_key_blob(
                vault_blob, vault_key, context="vault-data"
            )
            vault_content = json.loads(decrypted_bytes.decode("utf-8"))
            return vault_key, vault_content

        if "vault_blob" in data:
            decrypted_bytes = CryptoEngine.data_decrypt_blob(
                data["vault_blob"], password, context="vault-data"
            )
            vault_content = json.loads(decrypted_bytes.decode("utf-8"))
            return None, vault_content

        if "vault_data" in data:
            decrypted_bytes = CryptoEngine.data_decrypt(data["vault_data"], password)
            vault_content = json.loads(decrypted_bytes.decode("utf-8"))
            return None, vault_content

        if "totp_secret" in data:
            return None, {
                "totp_secret": data["totp_secret"],
                "settings": data.get("settings", {}),
            }

        return None, None

    def _migrate_to_v2(self, data, vault_content, password, vault_key):
        try:
            if not vault_key:
                vault_key = os.urandom(32)

            wrapped_key = CryptoEngine.data_encrypt_blob(
                vault_key, password, context="vault-wrap"
            )
            vault_blob = CryptoEngine.data_encrypt_key_blob(
                json.dumps(vault_content).encode("utf-8"),
                vault_key,
                context="vault-data",
            )

            if data.get("format") == "legacy_json":
                new_path = VaultStorage.migrate_legacy(
                    self.active_vault_path,
                    data.get("username", "user"),
                    data["hash"],
                    data["duress_hash"],
                    vault_blob,
                    wrapped_key,
                )
                Shredder.wipe_file(self.active_vault_path)
                return new_path, vault_key

            VaultStorage.write_vault(
                self.active_vault_path,
                data["username"],
                data["hash"],
                data["duress_hash"],
                vault_blob,
                wrapped_key=wrapped_key,
            )
            return self.active_vault_path, vault_key
        except Exception:
            return None, None

    def _normalize_settings(self, vault_content):
        settings = vault_content.setdefault("settings", {})
        changed = False

        if "file_algo" not in settings:
            legacy_algo = settings.get("algo")
            if legacy_algo == "ChaCha20-Poly1305":
                settings["file_algo"] = "chacha20-poly1305"
            elif legacy_algo == "AES-256-GCM":
                settings["file_algo"] = "aes-256-gcm"
            else:
                settings["file_algo"] = "chacha20-poly1305"
            changed = True

        if "file_compress" not in settings:
            settings["file_compress"] = False
            changed = True

        if "theme_mode" not in settings:
            settings["theme_mode"] = "light"
            changed = True

        if "theme_name" not in settings:
            if settings.get("theme"):
                settings["theme_name"] = settings.get("theme")
            else:
                settings["theme_name"] = "Noxium Teal"
            changed = True

        if "pqc_enabled" not in settings:
            settings["pqc_enabled"] = False
            changed = True

        if "pqc_kem" not in settings:
            pqc = vault_content.get("pqc", {})
            settings["pqc_kem"] = pqc.get("kem", "kyber512")
            changed = True

        if "auto_lock_minutes" not in settings:
            settings["auto_lock_minutes"] = 10
            changed = True

        if "device_lock_enabled" not in settings:
            settings["device_lock_enabled"] = False
            changed = True

        if "shred" not in settings and "shred_passes" in settings:
            settings["shred"] = settings.get("shred_passes", 3)
            changed = True

        return changed
