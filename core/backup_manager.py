import os
import shutil
import zipfile
import datetime

from core.crypto_engine import CryptoEngine
from core.vault_storage import VAULT_EXT
from core.tools import SecurityTools
from core.shredder import Shredder


class BackupManager:
    """Manages secure vault export and import (backup/restore)."""

    def __init__(self, vaults_dir="vaults"):
        self.vaults_dir = vaults_dir
        os.makedirs(self.vaults_dir, exist_ok=True)

    def export_vault(self, vault_name, output_dir, password):
        ok, issues = SecurityTools.validate_password(password)
        if not ok:
            return False, "Weak password: " + "; ".join(issues)
        vault_path = os.path.join(self.vaults_dir, f"{vault_name}{VAULT_EXT}")
        legacy_path = os.path.join(self.vaults_dir, f"{vault_name}.json")
        vault_data_dir = os.path.join(self.vaults_dir, vault_name)

        if not os.path.exists(vault_path):
            if os.path.exists(legacy_path):
                vault_path = legacy_path
            else:
                return False, "Vault not found"

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_zip = f"temp_backup_{timestamp}.zip"

        try:
            with zipfile.ZipFile(temp_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                ext = os.path.splitext(vault_path)[1]
                zf.write(vault_path, arcname=f"{vault_name}{ext}")

                if os.path.exists(vault_data_dir):
                    for root, dirs, files in os.walk(vault_data_dir):
                        for file in files:
                            abs_path = os.path.join(root, file)
                            rel_path = os.path.relpath(abs_path, self.vaults_dir)
                            zf.write(abs_path, arcname=rel_path)

            ok, enc_path = CryptoEngine.encrypt_file(
                temp_zip, password, "chacha20-poly1305", context="backup"
            )
            if ok:
                final_name = f"{vault_name}_backup_{timestamp}.vib"
                final_path = os.path.join(output_dir, final_name)

                if os.path.exists(final_path):
                    os.remove(final_path)

                shutil.move(enc_path, final_path)
                return True, final_path
            return False, enc_path

        except Exception as e:
            return False, str(e)
        finally:
            if os.path.exists(temp_zip):
                Shredder.wipe_file(temp_zip)
            if os.path.exists(temp_zip + CryptoEngine.ENCRYPTED_EXT):
                Shredder.wipe_file(temp_zip + CryptoEngine.ENCRYPTED_EXT)

    def import_vault(self, backup_path, password):
        if not os.path.exists(backup_path):
            return False, "Backup file not found"

        temp_enc = "temp_restore_" + os.path.basename(backup_path) + CryptoEngine.ENCRYPTED_EXT
        temp_zip = temp_enc.replace(CryptoEngine.ENCRYPTED_EXT, "")

        shutil.copy(backup_path, temp_enc)

        try:
            ok, dec_path = CryptoEngine.decrypt_file(temp_enc, password)
            if not ok:
                return False, dec_path

            if not zipfile.is_zipfile(dec_path):
                return False, "Decrypted file is not a valid archive. Wrong password?"

            with zipfile.ZipFile(dec_path, "r") as zf:
                for info in zf.infolist():
                    name = info.filename.replace("\\", "/")
                    if name.startswith("/") or name.startswith("../") or "/../" in name:
                        return False, "Unsafe path in backup archive"
                    if ":" in name.split("/")[0]:
                        return False, "Unsafe path in backup archive"
                    target = os.path.abspath(os.path.join(self.vaults_dir, name))
                    if not target.startswith(os.path.abspath(self.vaults_dir) + os.sep):
                        return False, "Unsafe path in backup archive"
                zf.extractall(self.vaults_dir)

            return True, "Vault restored successfully"

        except Exception as e:
            return False, f"Restore failed: {str(e)}"
        finally:
            if os.path.exists(temp_enc):
                Shredder.wipe_file(temp_enc)
            if os.path.exists(temp_zip):
                try:
                    Shredder.wipe_file(temp_zip)
                except Exception:
                    pass
