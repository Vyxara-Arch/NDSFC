import os
import shutil
import zipfile
import datetime
from core.crypto_engine import CryptoEngine


class BackupManager:
    """Manages secure vault export and import (backup/restore)"""

    def __init__(self, vaults_dir="vaults"):
        self.vaults_dir = vaults_dir
        os.makedirs(self.vaults_dir, exist_ok=True)

    def export_vault(self, vault_name, output_dir, password):
        """
        Creates an encrypted backup (.vib) of a vault.
        Includes the vault JSON configuration and any associated data (notes, etc).
        """
        vault_path = os.path.join(self.vaults_dir, f"{vault_name}.json")
        vault_data_dir = os.path.join(self.vaults_dir, vault_name)

        if not os.path.exists(vault_path):
            return False, "Vault not found"

        # Create localized temporary zip
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_zip = f"temp_backup_{timestamp}.zip"

        try:
            with zipfile.ZipFile(temp_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                # Add vault config
                zf.write(vault_path, arcname=f"{vault_name}.json")

                # Add vault data directory if it exists (notes, etc.)
                if os.path.exists(vault_data_dir):
                    for root, dirs, files in os.walk(vault_data_dir):
                        for file in files:
                            abs_path = os.path.join(root, file)
                            # Rel path should start with vault_name/...
                            # root is e.g. "vaults/MyVault/notes"
                            # rel_path should be "MyVault/notes/..."
                            rel_path = os.path.relpath(abs_path, self.vaults_dir)
                            zf.write(abs_path, arcname=rel_path)

            # Encrypt the zip using Standard Mode (ChaCha20-Poly1305)
            # This creates temp_zip.ndsfc
            ok, enc_path = CryptoEngine.encrypt_advanced(temp_zip, password, "standard")

            if ok:
                # Move/Rename to final destination
                final_name = f"{vault_name}_backup_{timestamp}.vib"
                final_path = os.path.join(output_dir, final_name)

                if os.path.exists(final_path):
                    os.remove(final_path)

                shutil.move(enc_path, final_path)
                return True, final_path
            else:
                return False, enc_path  # Error message

        except Exception as e:
            return False, str(e)
        finally:
            # Cleanup
            if os.path.exists(temp_zip):
                os.remove(temp_zip)
            # CryptoEngine output might persist if move failed
            if os.path.exists(temp_zip + ".ndsfc"):
                os.remove(temp_zip + ".ndsfc")

    def import_vault(self, backup_path, password):
        """
        Restores a vault from a .vib backup file.
        """
        if not os.path.exists(backup_path):
            return False, "Backup file not found"

        # Prepare temp file for decryption
        # We assume export used encrypt_advanced which appends .ndsfc
        # Logic: copy .vib -> .zip.ndsfc -> decrypt -> .zip -> extract

        temp_enc = "temp_restore_" + os.path.basename(backup_path) + ".ndsfc"
        temp_zip = temp_enc.replace(".ndsfc", "")  # temp_restore_....vib

        # Actually backup_path is .vib. We need to feed decrypt_advanced a file that looks like it.
        # But decrypt_advanced just takes a path, reads bits, and writes to path stripped of .ndsfc
        # So if we pass "foo.vib", it will try to write to "foo" (no extension?).
        # Let's verify decrypt_advanced logic:
        # out_path = input_path.replace(".ndsfc", "")
        # if input_path doesn't have .ndsfc, it just appends nothing? No, string replace would fail or do nothing.
        # So we MUST ensure input path ends in .ndsfc for the logic to correctly name output.

        shutil.copy(backup_path, temp_enc)

        try:
            ok, dec_path = CryptoEngine.decrypt_advanced(temp_enc, password)
            if not ok:
                return False, dec_path  # Error message

            # dec_path is now the decrypted zip file
            if not zipfile.is_zipfile(dec_path):
                return False, "Decrypted file is not a valid archive. Wrong password?"

            # Extract
            with zipfile.ZipFile(dec_path, "r") as zf:
                # Check for files
                # We extract directly to vaults directory
                zf.extractall(self.vaults_dir)

            return True, "Vault restored successfully"

        except Exception as e:
            return False, f"Restore failed: {str(e)}"
        finally:
            if os.path.exists(temp_enc):
                os.remove(temp_enc)
            if os.path.exists(temp_zip):
                try:
                    os.remove(temp_zip)
                except:
                    pass
