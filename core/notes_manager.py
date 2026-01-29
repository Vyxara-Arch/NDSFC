import os
import json
import time
from datetime import datetime

from core.crypto_engine import CryptoEngine


class NotesManager:
    def __init__(self, vault_name, vault_key=None):
        self.vault_name = vault_name
        self.vault_key = vault_key
        self.notes_dir = os.path.join("vaults", vault_name, "notes")
        os.makedirs(self.notes_dir, exist_ok=True)

    def create_note(self, title, content, password=None):
        note_id = str(int(time.time() * 1000))
        note_data = {
            "id": note_id,
            "title": title,
            "content": content,
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat(),
        }

        note_json = json.dumps(note_data).encode("utf-8")
        final_data = self._encrypt_payload(note_json, password)

        note_path = os.path.join(self.notes_dir, f"{note_id}.note")
        with open(note_path, "wb") as f:
            f.write(final_data)

        return note_id

    def get_note(self, note_id, password=None):
        note_path = os.path.join(self.notes_dir, f"{note_id}.note")

        if not os.path.exists(note_path):
            return None

        try:
            with open(note_path, "rb") as f:
                file_content = f.read()

            decrypted = self._decrypt_payload(file_content, password)
            note_data = json.loads(decrypted.decode("utf-8"))
            return note_data
        except Exception:
            return None

    def update_note(self, note_id, title, content, password=None):
        existing = self.get_note(note_id, password)
        if not existing:
            return False

        note_data = {
            "id": note_id,
            "title": title,
            "content": content,
            "created": existing["created"],
            "modified": datetime.now().isoformat(),
        }

        note_json = json.dumps(note_data).encode("utf-8")
        final_data = self._encrypt_payload(note_json, password)

        note_path = os.path.join(self.notes_dir, f"{note_id}.note")
        with open(note_path, "wb") as f:
            f.write(final_data)

        return True

    def delete_note(self, note_id):
        note_path = os.path.join(self.notes_dir, f"{note_id}.note")
        if os.path.exists(note_path):
            os.remove(note_path)
            return True
        return False

    def list_notes(self):
        if not os.path.exists(self.notes_dir):
            return []

        notes = []
        for filename in os.listdir(self.notes_dir):
            if filename.endswith(".note"):
                note_id = filename.replace(".note", "")
                notes.append(
                    {
                        "id": note_id,
                        "filename": filename,
                        "path": os.path.join(self.notes_dir, filename),
                    }
                )

        return sorted(notes, key=lambda x: x["id"], reverse=True)

    def search_notes(self, query, password=None):
        results = []
        for note_info in self.list_notes():
            note = self.get_note(note_info["id"], password)
            if note:
                if (
                    query.lower() in note["title"].lower()
                    or query.lower() in note["content"].lower()
                ):
                    results.append(note)

        return results

    def _encrypt_payload(self, payload: bytes, password):
        if self.vault_key:
            return CryptoEngine.data_encrypt_key_blob(
                payload, self.vault_key, context="notes"
            )
        if not password:
            raise ValueError("Password required")
        return CryptoEngine.data_encrypt_blob(payload, password, context="notes")

    def _decrypt_payload(self, payload: bytes, password):
        if payload.startswith(CryptoEngine.KEY_MAGIC):
            if not self.vault_key:
                raise ValueError("Vault key required")
            return CryptoEngine.data_decrypt_key_blob(
                payload, self.vault_key, context="notes"
            )
        if payload.startswith(CryptoEngine.DATA_MAGIC):
            if not password:
                raise ValueError("Password required")
            return CryptoEngine.data_decrypt_blob(payload, password, context="notes")
        encrypted_dict = json.loads(payload.decode("utf-8"))
        if not password:
            raise ValueError("Password required")
        return CryptoEngine.data_decrypt(encrypted_dict, password)
