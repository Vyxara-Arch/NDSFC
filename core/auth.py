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

        # 1. Check Duress
        try:
            self.ph.verify(data["duress_hash"], password)
            self.trigger_panic()
            return False, "PANIC_TRIGGERED"
        except:
            pass

        # 2. Normal Login
        try:
            self.ph.verify(data["hash"], password)
            totp = pyotp.TOTP(data["totp_secret"])
            if totp.verify(totp_code):
                self.settings = data.get("settings", {})
                return True, "SUCCESS"
            else:
                return False, "Invalid 2FA Code"
        except Exception as e:
            return False, "Invalid Password"

    def update_setting(self, key, value):
        if not self.active_vault_path:
            return
        with open(self.active_vault_path, "r") as f:
            data = json.load(f)

        if "settings" not in data:
            data["settings"] = {}
        data["settings"][key] = value
        self.settings[key] = value

        with open(self.active_vault_path, "w") as f:
            json.dump(data, f)

    def trigger_panic(self):
        if self.active_vault_path:
            Shredder.wipe_file(self.active_vault_path)
        AuditLog.log("PANIC", "Vault Destroyed")
