import os
import json
import time
from datetime import datetime
from core.crypto_engine import CryptoEngine


class NotesManager:
    """Manages encrypted notes/journal entries"""

    def __init__(self, vault_name):
        self.vault_name = vault_name
        self.notes_dir = os.path.join("vaults", vault_name, "notes")
        os.makedirs(self.notes_dir, exist_ok=True)

    def create_note(self, title, content, password):
        """Create a new encrypted note"""
        note_id = str(int(time.time() * 1000))
        note_data = {
            "id": note_id,
            "title": title,
            "content": content,
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat(),
        }

        # Encrypt the note content
        note_json = json.dumps(note_data).encode()
        encrypted = CryptoEngine.data_encrypt(note_json, password)

        # Save encrypted note
        note_path = os.path.join(self.notes_dir, f"{note_id}.note")
        with open(note_path, "wb") as f:
            f.write(encrypted)

        return note_id

    def get_note(self, note_id, password):
        """Retrieve and decrypt a note"""
        note_path = os.path.join(self.notes_dir, f"{note_id}.note")

        if not os.path.exists(note_path):
            return None

        try:
            with open(note_path, "rb") as f:
                encrypted = f.read()

            decrypted = CryptoEngine.data_decrypt(encrypted, password)
            note_data = json.loads(decrypted.decode())
            return note_data
        except:
            return None

    def update_note(self, note_id, title, content, password):
        """Update an existing note"""
        # Get existing note to preserve created date
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
        encrypted = CryptoEngine.data_encrypt(note_json, password)

        note_path = os.path.join(self.notes_dir, f"{note_id}.note")
        with open(note_path, "wb") as f:
            f.write(encrypted)

        return True

    def delete_note(self, note_id):
        """Delete a note"""
        note_path = os.path.join(self.notes_dir, f"{note_id}.note")
        if os.path.exists(note_path):
            os.remove(note_path)
            return True
        return False

    def list_notes(self):
        """List all note IDs and filenames"""
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
        """Search notes by title or content"""
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
