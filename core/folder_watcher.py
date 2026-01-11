import os
import time
import threading
from PyQt6.QtCore import QObject, pyqtSignal


class FolderWatcher(QObject):
    """
    Background service to monitor folders and auto-encrypt new files.
    Emits signals for UI updates.
    """

    file_processed = pyqtSignal(str, str)  # path, status

    def __init__(self, crypto_engine, password, mode="standard"):
        super().__init__()
        self.crypto_engine = crypto_engine
        self.password = password
        self.mode = mode
        self.folders = set()
        self.running = False
        self.thread = None
        self._lock = threading.Lock()

    def add_folder(self, path):
        with self._lock:
            if os.path.exists(path) and os.path.isdir(path):
                self.folders.add(path)
                return True
        return False

    def remove_folder(self, path):
        with self._lock:
            if path in self.folders:
                self.folders.remove(path)

    def get_folders(self):
        return list(self.folders)

    def start(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)

    def _run(self):
        # Initial scan to establish baseline (optional, or just process everything?)
        # For "Auto-encrypt", usually implies new files. But if we drop a file, we want it encrypted.
        # Let's process ANY unencrypted file found.

        while self.running:
            with self._lock:
                current_folders = list(self.folders)

            for folder in current_folders:
                if not os.path.exists(folder):
                    continue

                try:
                    for filename in os.listdir(folder):
                        if not self.running:
                            break

                        path = os.path.join(folder, filename)

                        # Skip directories
                        if os.path.isdir(path):
                            continue

                        # Skip already encrypted files
                        if filename.endswith(".ndsfc"):
                            continue

                        # Check if file has an encrypted version already?
                        # If "doc.txt" exists and "doc.txt.ndsfc" exists, skip?
                        # Or re-encrypt? Safer to skip to verify we don't loop or duplicate.
                        if os.path.exists(path + ".ndsfc"):
                            continue

                        # Encrypt
                        self.process_file(path)
                except Exception as e:
                    print(f"Watcher error: {e}")

            time.sleep(2)  # Poll interval

    def process_file(self, path):
        # Wait for file to be fully written?
        # Simple check: try to rename?
        try:
            # Encrypt
            ok, msg = self.crypto_engine.encrypt_advanced(
                path, self.password, self.mode
            )
            if ok:
                # Shred original
                from core.shredder import Shredder

                Shredder.wipe_file(path)
                self.file_processed.emit(os.path.basename(path), "Encrypted & Shredded")
            else:
                self.file_processed.emit(os.path.basename(path), f"Failed: {msg}")
        except Exception as e:
            self.file_processed.emit(os.path.basename(path), f"Error: {str(e)}")
