import os
import struct
import hashlib
from Crypto.Cipher import ChaCha20_Poly1305, AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from core.shredder import Shredder


class CryptoEngine:
    MAGIC_STD = b"NDS1"
    MAGIC_2FA = b"NDS2"
    MAGIC_PQC = b"NDSQ"  # PQC Int

    @staticmethod
    def derive_key(password: str, salt: bytes, length=32) -> bytes:
        # Reinforced KDF
        return scrypt(password.encode(), salt, length, N=2**15, r=8, p=1)

    @staticmethod
    def encrypt_advanced(input_path, password, mode, sec_q=None, sec_a=None):
        """
        mode: 'standard', 'pqc' (Quantum), '2fa'
        sec_q: Вопрос (для 2FA)
        sec_a: Ответ (для 2FA)
        """
        salt = get_random_bytes(16)
        out_path = input_path + ".ndsfc"

        # 1. CaptchaKey
        key = CryptoEngine.derive_key(password, salt)

        # 2. Header
        header = bytearray()
        header.extend(salt)

        with open(input_path, "rb") as f:
            plaintext = f.read()

        ciphertext = b""
        tag = b""
        nonce = b""
        final_magic = b""

        if mode == "pqc":
            # === QUANTUM RESISTANT CASCADE === ()
            # Layer 1: AES-256
            final_magic = CryptoEngine.MAGIC_PQC
            cipher1 = AES.new(key, AES.MODE_GCM)
            temp_cipher, tag1 = cipher1.encrypt_and_digest(plaintext)

            # Layer 2: ChaCha20
            key2 = hashlib.sha256(key).digest()  # Changed Key for second Layer
            cipher2 = ChaCha20_Poly1305.new(key=key2)
            final_cipher, tag2 = cipher2.encrypt_and_digest(
                temp_cipher + tag1 + cipher1.nonce
            )

            nonce = cipher2.nonce
            tag = tag2
            ciphertext = final_cipher

        elif mode == "2fa":
            # === 2FA FILE LOCK ===
            final_magic = CryptoEngine.MAGIC_2FA
            # Hash response
            ans_hash = hashlib.sha256(sec_a.lower().strip().encode()).digest()
            # Encryption AES, Using KeyPass XOR KeyRes
            mixed_key = bytes(a ^ b for a, b in zip(key, ans_hash))

            cipher = ChaCha20_Poly1305.new(key=mixed_key)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)

            # Sec.Question
            q_bytes = sec_q.encode("utf-8")
            q_len = struct.pack(">I", len(q_bytes))
            header.extend(q_len)
            header.extend(q_bytes)

        else:
            # === STANDARD ===
            final_magic = CryptoEngine.MAGIC_STD
            cipher = ChaCha20_Poly1305.new(key=key)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # File Write
        with open(out_path, "wb") as f:
            f.write(final_magic)  # 4 bytes
            f.write(header)  # Salt with CSPRNG
            f.write(nonce)  # 12 or 16 bytes
            f.write(tag)  # 16 bytes
            f.write(ciphertext)

        return True, out_path

    @staticmethod
    def decrypt_advanced(input_path, password, sec_a_input=None):
        try:
            with open(input_path, "rb") as f:
                magic = f.read(4)
                salt = f.read(16)
                key = CryptoEngine.derive_key(password, salt)
                if magic == CryptoEngine.MAGIC_PQC:
                    nonce = f.read(12)
                    tag = f.read(16)
                    ciphertext = f.read()

                    key2 = hashlib.sha256(key).digest()
                    cipher2 = ChaCha20_Poly1305.new(key=key2, nonce=nonce)
                    inner_data = cipher2.decrypt_and_verify(ciphertext, tag)

                    # [AES_CIPHER][AES_TAG:16][AES_NONCE:16]
                    aes_nonce = inner_data[-16:]
                    aes_tag = inner_data[-32:-16]
                    aes_cipher = inner_data[:-32]

                    cipher1 = AES.new(key, AES.MODE_GCM, nonce=aes_nonce)
                    plaintext = cipher1.decrypt_and_verify(aes_cipher, aes_tag)

                elif magic == CryptoEngine.MAGIC_2FA:
                    q_len = struct.unpack(">I", f.read(4))[0]
                    f.read(q_len)

                    nonce = f.read(12)
                    tag = f.read(16)
                    ciphertext = f.read()

                    if not sec_a_input:
                        raise ValueError("2FA Answer Required")

                    ans_hash = hashlib.sha256(
                        sec_a_input.lower().strip().encode()
                    ).digest()
                    mixed_key = bytes(a ^ b for a, b in zip(key, ans_hash))

                    cipher = ChaCha20_Poly1305.new(key=mixed_key, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

                elif magic == CryptoEngine.MAGIC_STD:
                    nonce = f.read(12)
                    tag = f.read(16)
                    ciphertext = f.read()

                    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                else:
                    return False, "Unknown File Format"

            # Save
            out_path = input_path.replace(".ndsfc", "")
            with open(out_path, "wb") as f:
                f.write(plaintext)

            return True, out_path

        except ValueError:
            return False, "DECRYPTION FAILED: Wrong password or integrity corrupted."
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_2fa_question(input_path):
        """Извлекает вопрос из заголовка файла без расшифровки."""
        with open(input_path, "rb") as f:
            magic = f.read(4)
            if magic != CryptoEngine.MAGIC_2FA:
                return None
            f.read(16)  # salt
            q_len = struct.unpack(">I", f.read(4))[0]
            question = f.read(q_len).decode("utf-8")
            return question

    @staticmethod
    def data_encrypt(data: bytes, password: str) -> dict:
        """Encrypts bytes in memory using ChaCha20-Poly1305. Returns dict with hex-encoded artifacts."""
        salt = get_random_bytes(16)
        key = CryptoEngine.derive_key(password, salt)
        cipher = ChaCha20_Poly1305.new(key=key)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return {
            "salt": salt.hex(),
            "nonce": cipher.nonce.hex(),
            "tag": tag.hex(),
            "ciphertext": ciphertext.hex(),
        }

    @staticmethod
    def data_decrypt(enc_dict: dict, password: str) -> bytes:
        """Decrypts data from dictionary artifacts."""
        try:
            salt = bytes.fromhex(enc_dict["salt"])
            nonce = bytes.fromhex(enc_dict["nonce"])
            tag = bytes.fromhex(enc_dict["tag"])
            ciphertext = bytes.fromhex(enc_dict["ciphertext"])

            key = CryptoEngine.derive_key(password, salt)
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError):
            raise ValueError("Decryption Failed")
