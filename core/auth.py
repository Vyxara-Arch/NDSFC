import json
import os
import pyotp
from argon2 import PasswordHasher
from core.shredder import Shredder
from core.audit import AuditLog


class AuthManager:
    def __init__(self):
        self.ph = PasswordHasher()
        self.active_vault_path = None
        self.settings = {}

    def set_active_vault(self, path):
        self.active_vault_path = path

    def login(self, password, totp_code):
        if not self.active_vault_path or not os.path.exists(self.active_vault_path):
            return False, "Vault not selected"

        with open(self.active_vault_path, "r") as f:
            data = json.load(f)

        try:
            self.ph.verify(data["duress_hash"], password)
            self.trigger_panic()
            return False, "PANIC_TRIGGERED"
        except:
            pass

        try:
            from core.crypto_engine import CryptoEngine

            self.ph.verify(data["hash"], password)

            # Decrypt Vault Data
            if "vault_data" in data:
                decrypted_bytes = CryptoEngine.data_decrypt(
                    data["vault_data"], password
                )
                vault_content = json.loads(decrypted_bytes)

                totp_secret = vault_content["totp_secret"]
                self.settings = vault_content.get("settings", {})
            else:
                totp_secret = data["totp_secret"]
                self.settings = data.get("settings", {})

            totp = pyotp.TOTP(totp_secret)
            if totp.verify(totp_code):
                return True, "SUCCESS"
            else:
                return False, "Invalid 2FA Code"

        except Exception as e:
            return False, "Invalid Password or Data Corruption"

    def update_setting(self, key, value, password):
        if not self.active_vault_path:
            return

        from core.crypto_engine import CryptoEngine
        import json

        with open(self.active_vault_path, "r") as f:
            data = json.load(f)

        if "vault_data" not in data:
            return

        try:
            decrypted_bytes = CryptoEngine.data_decrypt(data["vault_data"], password)
            vault_content = json.loads(decrypted_bytes)

            if "settings" not in vault_content:
                vault_content["settings"] = {}

            vault_content["settings"][key] = value
            self.settings[key] = value

            new_blob_bytes = json.dumps(vault_content).encode()
            encrypted_blob = CryptoEngine.data_encrypt(new_blob_bytes, password)

            data["vault_data"] = encrypted_blob

            with open(self.active_vault_path, "w") as f:
                json.dump(data, f, indent=4)

        except Exception as e:
            print(f"Failed to update settings: {e}")

    def trigger_panic(self):
        if self.active_vault_path:
            Shredder.wipe_file(self.active_vault_path)
        AuditLog.log("PANIC", "Vault Destroyed")
