import os
import secrets


class Shredder:
    @staticmethod
    def wipe_file(file_path: str):
        """
        Overwrites file according to DoD 5220.22-M (3 passes) and deletes it.
        """
        if not os.path.exists(file_path):
            return

        file_size = os.path.getsize(file_path)

        with open(file_path, "wb") as f:
            # Pass 1: All Zeros
            f.write(b"\x00" * file_size)
            f.flush()
            os.fsync(f.fileno())
            f.seek(0)

            # Pass 2: All Ones
            f.write(b"\xff" * file_size)
            f.flush()
            os.fsync(f.fileno())
            f.seek(0)

            # Pass 3: Random Data
            f.write(secrets.token_bytes(file_size))
            f.flush()
            os.fsync(f.fileno())

        # Final Step: Delete file
        os.remove(file_path)
