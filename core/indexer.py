import sqlite3
import json
import os
import uuid
from datetime import datetime

from core.crypto_engine import CryptoEngine


class IndexManager:
    def __init__(self, vault_name, password=None, vault_key=None):
        self.vault_name = vault_name
        self.password = password
        self.vault_key = vault_key
        self.index_path = os.path.join("vaults", vault_name, "index.db.enc")

        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._init_db()
        self.load_index()

    def _init_db(self):
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                filename TEXT,
                path TEXT,
                size INTEGER,
                algo TEXT,
                c_time TEXT,
                tags TEXT
            )
        """
        )
        self.cursor.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(filename, tags)"
        )
        self.conn.commit()

    def add_file(self, path, algo="Standard"):
        if not os.path.exists(path):
            return

        stat = os.stat(path)
        fid = str(uuid.uuid4())
        name = os.path.basename(path)

        self.cursor.execute("SELECT id FROM files WHERE path = ?", (path,))
        if self.cursor.fetchone():
            return

        self.cursor.execute(
            """
            INSERT INTO files (id, filename, path, size, algo, c_time, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (fid, name, path, stat.st_size, algo, datetime.now().isoformat(), ""),
        )

        self.cursor.execute(
            "INSERT INTO files_fts (filename, tags) VALUES (?, ?)", (name, "")
        )
        self.conn.commit()
        self.save_index()

    def scan_directory(self, directory):
        if not os.path.exists(directory):
            return

        for root, dirs, files in os.walk(directory):
            for f in files:
                if f.endswith(CryptoEngine.ENCRYPTED_EXT):
                    self.add_file(os.path.join(root, f), "Encrypted")
        self.save_index()

    def search(self, query):
        if not query:
            self.cursor.execute("SELECT * FROM files ORDER BY c_time DESC")
        else:
            self.cursor.execute(
                "SELECT * FROM files WHERE filename LIKE ?", (f"%{query}%",)
            )

        return [
            dict(zip(["id", "filename", "path", "size", "algo", "c_time", "tags"], row))
            for row in self.cursor.fetchall()
        ]

    def save_index(self):
        self.cursor.execute("SELECT * FROM files")
        rows = self.cursor.fetchall()
        data = [
            dict(zip(["id", "filename", "path", "size", "algo", "c_time", "tags"], r))
            for r in rows
        ]

        json_bytes = json.dumps(data).encode("utf-8")
        try:
            if self.vault_key:
                final_data = CryptoEngine.data_encrypt_key_blob(
                    json_bytes, self.vault_key, context="index"
                )
            else:
                if not self.password:
                    raise ValueError("Password required")
                final_data = CryptoEngine.data_encrypt_blob(
                    json_bytes, self.password, context="index"
                )

            with open(self.index_path, "wb") as f:
                f.write(final_data)
        except Exception as e:
            print(f"Index Save Error: {e}")

    def load_index(self):
        if not os.path.exists(self.index_path):
            return

        try:
            with open(self.index_path, "rb") as f:
                raw = f.read()

            if raw.startswith(CryptoEngine.KEY_MAGIC):
                if not self.vault_key:
                    raise ValueError("Vault key required")
                plain_bytes = CryptoEngine.data_decrypt_key_blob(
                    raw, self.vault_key, context="index"
                )
            elif raw.startswith(CryptoEngine.DATA_MAGIC):
                if not self.password:
                    raise ValueError("Password required")
                plain_bytes = CryptoEngine.data_decrypt_blob(
                    raw, self.password, context="index"
                )
            else:
                enc_dict = json.loads(raw.decode("utf-8"))
                if not self.password:
                    raise ValueError("Password required")
                plain_bytes = CryptoEngine.data_decrypt(enc_dict, self.password)

            data = json.loads(plain_bytes.decode("utf-8"))

            for d in data:
                self.cursor.execute(
                    """
                    INSERT OR IGNORE INTO files (id, filename, path, size, algo, c_time, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        d["id"],
                        d["filename"],
                        d["path"],
                        d["size"],
                        d.get("algo", "Standard"),
                        d["c_time"],
                        d.get("tags", ""),
                    ),
                )

                self.cursor.execute(
                    "INSERT INTO files_fts (filename, tags) VALUES (?, ?)",
                    (d["filename"], d.get("tags", "")),
                )

            self.conn.commit()
        except Exception as e:
            print(f"Index Load Error: {e}")
