import os
import json
import time
from datetime import datetime
from core.crypto_engine import CryptoEngine


class NotesManager:

    def __init__(self, vault_name):
        self.vault_name = vault_name
        self.notes_dir = os.path.join("vaults", vault_name, "notes")
        os.makedirs(self.notes_dir, exist_ok=True)

    def create_note(self, title, content, password):
        note_id = str(int(time.time() * 1000))
        note_data = {
            "id": note_id,
            "title": title,
            "content": content,
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat(),
        }

        note_json = json.dumps(note_data).encode()
        encrypted_dict = CryptoEngine.data_encrypt(note_json, password)

        # Serialize encryption artifacts to JSON bytes
        final_data = json.dumps(encrypted_dict).encode()

        note_path = os.path.join(self.notes_dir, f"{note_id}.note")
        with open(note_path, "wb") as f:
            f.write(final_data)

        return note_id

    def get_note(self, note_id, password):
        note_path = os.path.join(self.notes_dir, f"{note_id}.note")

        if not os.path.exists(note_path):
            return None

        try:
            with open(note_path, "rb") as f:
                file_content = f.read()

            # Load encryption artifacts
            encrypted_dict = json.loads(file_content.decode())

            decrypted = CryptoEngine.data_decrypt(encrypted_dict, password)
            note_data = json.loads(decrypted.decode())
            return note_data
        except Exception as e:
            # print(f"Error decrypting note: {e}")
            return None

    def update_note(self, note_id, title, content, password):
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

        # Encrypt and save
        note_json = json.dumps(note_data).encode()
        encrypted_dict = CryptoEngine.data_encrypt(note_json, password)
        final_data = json.dumps(encrypted_dict).encode()

        note_path = os.path.join(self.notes_dir, f"{note_id}.note")
        with open(note_path, "wb") as f:
            f.write(final_data)

        return True

    def delete_note(self, note_id):
        """Delete a note"""
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

    def search_notes(self, query, password):
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
