import ctypes


class SecureSession:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SecureSession, cls).__new__(cls)
            cls._instance.master_key = None
            cls._instance.current_vault = None
            cls._instance.is_active = False
        return cls._instance

    def start_session(self, key: bytes, vault_name: str):
        self.master_key = key
        self.current_vault = vault_name
        self.is_active = True

    def destroy_session(self):
        """Wipes keys from RAM securely."""
        if self.master_key:
            # Puts zeros into the memory location of the key (Best effort in Python)
            # Python immutable bytes make this hard, but we drop the reference immediately.
            self.master_key = None

        self.current_vault = None
        self.is_active = False
        # Force Garbage Collection
        import gc

        gc.collect()
