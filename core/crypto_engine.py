import os
import struct
import hashlib
import hmac
import zlib
import base64
from typing import Optional

try:
    import psutil
except Exception:
    psutil = None

from Crypto.Cipher import ChaCha20_Poly1305, AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from argon2.low_level import hash_secret_raw, Type

from core.device_lock import get_device_fingerprint


_PQC_ERROR = None
try:
    from pqcrypto.kem import kyber512, kyber768, kyber1024

    _PQC_KEMS = {
        "kyber512": kyber512,
        "kyber768": kyber768,
        "kyber1024": kyber1024,
    }
    _PQC_ORDER = ["kyber512", "kyber768", "kyber1024"]
    HAS_PQC = True
except Exception as e:
    _PQC_KEMS = {}
    _PQC_ORDER = []
    HAS_PQC = False
    _PQC_ERROR = str(e) or "pqcrypto import failed"

_PQC_SIZES = {}


class CryptoEngine:
    FILE_MAGIC = b"NFX1"
    FILE_VERSION_V1 = 1
    FILE_VERSION_V2 = 2
    FILE_VERSION = FILE_VERSION_V2

    DATA_MAGIC = b"NDSB"
    DATA_VERSION_V1 = 1
    DATA_VERSION_V2 = 2
    DATA_VERSION = DATA_VERSION_V1

    KEY_MAGIC = b"NDSK"
    KEY_VERSION_V1 = 1
    KEY_VERSION_V2 = 2
    KEY_VERSION = KEY_VERSION_V1

    MAGIC_STD = b"NDS1"
    MAGIC_PQC = b"NDSQ"
    MAGIC_SIV = b"NDS3"
    MAGIC_BLF = b"NDS4"
    MAGIC_CST = b"NDS5"

    ALG_CHACHA20 = 1
    ALG_AESGCM = 2
    ALG_PQC_HYBRID = 3
    ALG_LETNOX_256 = 4
    ALG_LETNOX_512 = 5
    ALG_LEGACY_WRAP = 6

    KDF_ARGON2ID = 1

    FLAG_COMPRESS = 1
    FLAG_PQC = 2
    FLAG_DEVICE = 4

    LETNOX_MAGIC = b"LNXC"
    LETNOX_VERSION = 1
    LETNOX_HASH_SHA256 = 1
    LETNOX_HASH_SHA512 = 2

    DEFAULT_MEM_KIB = 65536
    DEFAULT_TIME_COST = 3
    DEFAULT_PARALLELISM = 2

    MIN_MEM_KIB = 16384
    MAX_MEM_KIB = 262144
    MIN_TIME_COST = 2
    MAX_TIME_COST = 6
    MIN_PARALLELISM = 1
    MAX_PARALLELISM = 8

    STREAM_CHUNK_SIZE = 1024 * 1024
    NONCE_PREFIX_LEN = 4
    NONCE_COUNTER_LEN = 8
    MAX_CHUNK_LEN_MULTIPLIER = 4
    COMMIT_LEN = 16

    CTX_GENERIC = 0
    CTX_FILE = 1
    CTX_BACKUP = 2
    CTX_VAULT_WRAP = 3
    CTX_VAULT_DATA = 4
    CTX_INDEX = 5
    CTX_NOTES = 6

    ENCRYPTED_EXT = ".ndsfc"

    @staticmethod
    def pqc_available() -> bool:
        return HAS_PQC

    @staticmethod
    def pqc_status() -> tuple[bool, str]:
        if HAS_PQC:
            return True, "PQC available"
        return False, _PQC_ERROR or "PQC unavailable"

    @staticmethod
    def pqc_kem_names() -> list[str]:
        return [name for name in _PQC_ORDER if name in _PQC_KEMS]

    @staticmethod
    def classify_file(path: str) -> str:
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
        except Exception:
            return "unknown"
        if magic == CryptoEngine.FILE_MAGIC:
            return "nfx1"
        if magic in (
            CryptoEngine.MAGIC_STD,
            CryptoEngine.MAGIC_PQC,
            CryptoEngine.MAGIC_SIV,
            CryptoEngine.MAGIC_BLF,
            CryptoEngine.MAGIC_CST,
        ):
            return "legacy"
        return "unknown"

    @staticmethod
    def _select_kdf_params() -> tuple[int, int, int]:
        mem_kib = CryptoEngine.DEFAULT_MEM_KIB
        time_cost = CryptoEngine.DEFAULT_TIME_COST
        parallelism = CryptoEngine.DEFAULT_PARALLELISM

        if psutil:
            try:
                total_kib = psutil.virtual_memory().total // 1024
                mem_kib = min(mem_kib, max(CryptoEngine.MIN_MEM_KIB, total_kib // 8))
            except Exception:
                pass

        cpu_count = os.cpu_count() or 1
        parallelism = min(parallelism, cpu_count)
        mem_kib = min(mem_kib, CryptoEngine.MAX_MEM_KIB)
        return mem_kib, time_cost, max(1, parallelism)

    @staticmethod
    def _validate_kdf_params(mem_kib: int, time_cost: int, parallelism: int) -> None:
        if mem_kib < CryptoEngine.MIN_MEM_KIB or mem_kib > CryptoEngine.MAX_MEM_KIB:
            raise ValueError("KDF memory cost out of allowed range")
        if time_cost < CryptoEngine.MIN_TIME_COST or time_cost > CryptoEngine.MAX_TIME_COST:
            raise ValueError("KDF time cost out of allowed range")
        if parallelism < CryptoEngine.MIN_PARALLELISM or parallelism > CryptoEngine.MAX_PARALLELISM:
            raise ValueError("KDF parallelism out of allowed range")

    @staticmethod
    def _get_kem(kem_name: str):
        kem = _PQC_KEMS.get(kem_name)
        if not kem:
            raise ValueError("Unsupported PQC KEM")
        return kem

    @staticmethod
    def _pqc_expected_sizes(kem_name: str) -> dict:
        if kem_name in _PQC_SIZES:
            return _PQC_SIZES[kem_name]
        kem = CryptoEngine._get_kem(kem_name)
        pub, priv = CryptoEngine._kem_keypair(kem_name)
        ct, _shared = CryptoEngine._kem_encapsulate(kem_name, pub)
        sizes = {"pub": len(pub), "priv": len(priv), "ct": len(ct)}
        _PQC_SIZES[kem_name] = sizes
        return sizes

    @staticmethod
    def _kem_keypair(kem_name: str) -> tuple[bytes, bytes]:
        kem = CryptoEngine._get_kem(kem_name)
        if hasattr(kem, "generate_keypair"):
            return kem.generate_keypair()
        if hasattr(kem, "keypair"):
            return kem.keypair()
        raise ValueError("PQC KEM missing keypair method")

    @staticmethod
    def _kem_encapsulate(kem_name: str, public_key: bytes) -> tuple[bytes, bytes]:
        kem = CryptoEngine._get_kem(kem_name)
        if hasattr(kem, "encrypt"):
            return kem.encrypt(public_key)
        if hasattr(kem, "encapsulate"):
            return kem.encapsulate(public_key)
        raise ValueError("PQC KEM missing encapsulate method")

    @staticmethod
    def _kem_decapsulate(kem_name: str, private_key: bytes, ciphertext: bytes) -> bytes:
        kem = CryptoEngine._get_kem(kem_name)
        if hasattr(kem, "decrypt"):
            return kem.decrypt(private_key, ciphertext)
        if hasattr(kem, "decapsulate"):
            return kem.decapsulate(private_key, ciphertext)
        raise ValueError("PQC KEM missing decapsulate method")

    @staticmethod
    def generate_pqc_keypair(kem_name: str) -> tuple[str, str]:
        if not HAS_PQC:
            raise RuntimeError("PQC library not available")
        pub, priv = CryptoEngine._kem_keypair(kem_name)
        return (
            base64.b64encode(pub).decode("ascii"),
            base64.b64encode(priv).decode("ascii"),
        )

    @staticmethod
    def decode_pqc_key(b64_value: str) -> bytes:
        return base64.b64decode(b64_value.encode("ascii"))

    @staticmethod
    def derive_key_argon2id(
        password: str,
        salt: bytes,
        length: int = 32,
        mem_kib: int = DEFAULT_MEM_KIB,
        time_cost: int = DEFAULT_TIME_COST,
        parallelism: int = DEFAULT_PARALLELISM,
    ) -> bytes:
        return hash_secret_raw(
            password.encode("utf-8"),
            salt,
            time_cost=time_cost,
            memory_cost=mem_kib,
            parallelism=parallelism,
            hash_len=length,
            type=Type.ID,
        )

    @staticmethod
    def derive_key_scrypt(password: str, salt: bytes, length: int = 32) -> bytes:
        return scrypt(password.encode("utf-8"), salt, length, N=2**15, r=8, p=1)

    @staticmethod
    def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
        return hmac.new(salt, ikm, hashlib.sha256).digest()

    @staticmethod
    def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
        out = b""
        counter = 1
        last = b""
        while len(out) < length:
            last = hmac.new(prk, last + info + bytes([counter]), hashlib.sha256).digest()
            out += last
            counter += 1
        return out[:length]

    @staticmethod
    def _hkdf(ikm: bytes, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
        if not salt:
            salt = b"\x00" * 32
        prk = CryptoEngine._hkdf_extract(salt, ikm)
        return CryptoEngine._hkdf_expand(prk, info, length)

    @staticmethod
    def _context_info(context: str | int) -> tuple[int, bytes]:
        if isinstance(context, int):
            ctx_id = context
        else:
            ctx_map = {
                "generic": CryptoEngine.CTX_GENERIC,
                "file": CryptoEngine.CTX_FILE,
                "backup": CryptoEngine.CTX_BACKUP,
                "vault-wrap": CryptoEngine.CTX_VAULT_WRAP,
                "vault-data": CryptoEngine.CTX_VAULT_DATA,
                "index": CryptoEngine.CTX_INDEX,
                "notes": CryptoEngine.CTX_NOTES,
            }
            ctx_id = ctx_map.get(context, CryptoEngine.CTX_GENERIC)

        info_map = {
            CryptoEngine.CTX_GENERIC: b"noxium-ctx-generic",
            CryptoEngine.CTX_FILE: b"noxium-ctx-file",
            CryptoEngine.CTX_BACKUP: b"noxium-ctx-backup",
            CryptoEngine.CTX_VAULT_WRAP: b"noxium-ctx-vault-wrap",
            CryptoEngine.CTX_VAULT_DATA: b"noxium-ctx-vault-data",
            CryptoEngine.CTX_INDEX: b"noxium-ctx-index",
            CryptoEngine.CTX_NOTES: b"noxium-ctx-notes",
        }
        return ctx_id, info_map.get(ctx_id, info_map[CryptoEngine.CTX_GENERIC])

    @staticmethod
    def _is_valid_context_id(ctx_id: int) -> bool:
        return ctx_id in (
            CryptoEngine.CTX_GENERIC,
            CryptoEngine.CTX_FILE,
            CryptoEngine.CTX_BACKUP,
            CryptoEngine.CTX_VAULT_WRAP,
            CryptoEngine.CTX_VAULT_DATA,
            CryptoEngine.CTX_INDEX,
            CryptoEngine.CTX_NOTES,
        )

    @staticmethod
    def _derive_context_key(base_key: bytes, salt: bytes, context: str | int) -> bytes:
        _ctx_id, info = CryptoEngine._context_info(context)
        return CryptoEngine._hkdf(base_key, salt, info, 32)

    @staticmethod
    def _letnox_wrap(data: bytes, variant: int) -> bytes:
        if variant == 256:
            digest = hashlib.sha256(data).digest()
            algo = CryptoEngine.LETNOX_HASH_SHA256
        elif variant == 512:
            digest = hashlib.sha512(data).digest()
            algo = CryptoEngine.LETNOX_HASH_SHA512
        else:
            raise ValueError("Unsupported LetNox variant")
        return data + CryptoEngine.LETNOX_MAGIC + bytes([CryptoEngine.LETNOX_VERSION, algo]) + digest

    @staticmethod
    def _letnox_unwrap(data: bytes, variant: int) -> bytes:
        if variant == 256:
            digest_len = 32
            algo = CryptoEngine.LETNOX_HASH_SHA256
            hasher = hashlib.sha256
        elif variant == 512:
            digest_len = 64
            algo = CryptoEngine.LETNOX_HASH_SHA512
            hasher = hashlib.sha512
        else:
            raise ValueError("Unsupported LetNox variant")

        meta_len = len(CryptoEngine.LETNOX_MAGIC) + 2 + digest_len
        if len(data) < meta_len:
            raise ValueError("Missing LetNox integrity tag")
        meta = data[-meta_len:]
        if meta[: len(CryptoEngine.LETNOX_MAGIC)] != CryptoEngine.LETNOX_MAGIC:
            raise ValueError("LetNox tag not found")
        version = meta[len(CryptoEngine.LETNOX_MAGIC)]
        algo_id = meta[len(CryptoEngine.LETNOX_MAGIC) + 1]
        if version != CryptoEngine.LETNOX_VERSION or algo_id != algo:
            raise ValueError("LetNox tag mismatch")
        digest = meta[len(CryptoEngine.LETNOX_MAGIC) + 2 :]
        payload = data[:-meta_len]
        if digest != hasher(payload).digest():
            raise ValueError("LetNox integrity check failed")
        return payload

    @staticmethod
    def _build_header(
        version: int,
        alg_id: int,
        flags: int,
        salt: bytes,
        mem_kib: int,
        time_cost: int,
        parallelism: int,
        nonce_len: int,
        tag_len: int,
        chunk_size: Optional[int] = None,
        nonce_prefix: Optional[bytes] = None,
        context_id: Optional[int] = None,
        kem_id: Optional[int] = None,
        kem_ct: Optional[bytes] = None,
    ) -> bytes:
        base = struct.pack(
            ">4sBBBB16sIIBBB",
            CryptoEngine.FILE_MAGIC,
            version,
            alg_id,
            CryptoEngine.KDF_ARGON2ID,
            flags,
            salt,
            mem_kib,
            time_cost,
            parallelism,
            nonce_len,
            tag_len,
        )
        extra = b""
        if version == CryptoEngine.FILE_VERSION_V2:
            if chunk_size is None or nonce_prefix is None or context_id is None:
                raise ValueError("Missing streaming header fields")
            if len(nonce_prefix) != CryptoEngine.NONCE_PREFIX_LEN:
                raise ValueError("Invalid nonce prefix length")
            extra = struct.pack(">I4sB", chunk_size, nonce_prefix, context_id)
        if kem_id is None or kem_ct is None:
            return base + extra
        if len(kem_ct) > 65535:
            raise ValueError("KEM ciphertext too large")
        return base + extra + struct.pack(">BH", kem_id, len(kem_ct)) + kem_ct

    @staticmethod
    def _parse_header(data: bytes) -> tuple[dict, int]:
        if len(data) < 35:
            raise ValueError("Invalid file header")
        (
            magic,
            version,
            alg_id,
            kdf_id,
            flags,
            salt,
            mem_kib,
            time_cost,
            parallelism,
            nonce_len,
            tag_len,
        ) = struct.unpack(">4sBBBB16sIIBBB", data[:35])
        if magic != CryptoEngine.FILE_MAGIC:
            raise ValueError("Unknown file magic")
        if version not in (CryptoEngine.FILE_VERSION_V1, CryptoEngine.FILE_VERSION_V2):
            raise ValueError("Unsupported file version")
        offset = 35
        chunk_size = None
        nonce_prefix = None
        context_id = None
        context_id = None
        if version == CryptoEngine.FILE_VERSION_V2:
            if len(data) < offset + 9:
                raise ValueError("Invalid streaming header")
            chunk_size, nonce_prefix, context_id = struct.unpack(
                ">I4sB", data[offset : offset + 9]
            )
            offset += 9
        kem_id = None
        kem_ct = None
        if flags & CryptoEngine.FLAG_PQC:
            if len(data) < offset + 3:
                raise ValueError("Invalid PQC header")
            kem_id, kem_len = struct.unpack(">BH", data[offset : offset + 3])
            offset += 3
            kem_ct = data[offset : offset + kem_len]
            if len(kem_ct) != kem_len:
                raise ValueError("Invalid KEM ciphertext")
            offset += kem_len
        return (
            {
                "version": version,
                "alg_id": alg_id,
                "kdf_id": kdf_id,
                "flags": flags,
                "salt": salt,
                "mem_kib": mem_kib,
                "time_cost": time_cost,
                "parallelism": parallelism,
                "nonce_len": nonce_len,
                "tag_len": tag_len,
                "chunk_size": chunk_size,
                "nonce_prefix": nonce_prefix,
                "context_id": context_id,
                "kem_id": kem_id,
                "kem_ct": kem_ct,
            },
            offset,
        )

    @staticmethod
    def _read_header_from_file(f, magic: bytes) -> tuple[dict, bytes]:
        rest = f.read(31)
        if len(rest) != 31:
            raise ValueError("Invalid file header")
        base = magic + rest
        (
            _magic,
            version,
            alg_id,
            kdf_id,
            flags,
            salt,
            mem_kib,
            time_cost,
            parallelism,
            nonce_len,
            tag_len,
        ) = struct.unpack(">4sBBBB16sIIBBB", base)
        if _magic != CryptoEngine.FILE_MAGIC:
            raise ValueError("Unknown file magic")
        if version not in (CryptoEngine.FILE_VERSION_V1, CryptoEngine.FILE_VERSION_V2):
            raise ValueError("Unsupported file version")

        header_bytes = base
        chunk_size = None
        nonce_prefix = None
        if version == CryptoEngine.FILE_VERSION_V2:
            extra = f.read(9)
            if len(extra) != 9:
                raise ValueError("Invalid streaming header")
            chunk_size, nonce_prefix, context_id = struct.unpack(">I4sB", extra)
            header_bytes += extra

        kem_id = None
        kem_ct = None
        if flags & CryptoEngine.FLAG_PQC:
            kem_hdr = f.read(3)
            if len(kem_hdr) != 3:
                raise ValueError("Invalid PQC header")
            kem_id, kem_len = struct.unpack(">BH", kem_hdr)
            kem_ct = f.read(kem_len)
            if len(kem_ct) != kem_len:
                raise ValueError("Invalid KEM ciphertext")
            header_bytes += kem_hdr + kem_ct

        return (
            {
                "version": version,
                "alg_id": alg_id,
                "kdf_id": kdf_id,
                "flags": flags,
                "salt": salt,
                "mem_kib": mem_kib,
                "time_cost": time_cost,
                "parallelism": parallelism,
                "nonce_len": nonce_len,
                "tag_len": tag_len,
                "chunk_size": chunk_size,
                "nonce_prefix": nonce_prefix,
                "context_id": context_id,
                "kem_id": kem_id,
                "kem_ct": kem_ct,
            },
            header_bytes,
        )

    @staticmethod
    def _derive_chunk_nonce(prefix: bytes, counter: int) -> bytes:
        return prefix + counter.to_bytes(CryptoEngine.NONCE_COUNTER_LEN, "big")

    @staticmethod
    def _iter_plain_chunks(in_f, compress: bool, letnox_variant: Optional[int], chunk_size: int):
        hasher = None
        algo_id = None
        if letnox_variant == 256:
            hasher = hashlib.sha256()
            algo_id = CryptoEngine.LETNOX_HASH_SHA256
        elif letnox_variant == 512:
            hasher = hashlib.sha512()
            algo_id = CryptoEngine.LETNOX_HASH_SHA512

        buffer = b""
        if compress:
            compressor = zlib.compressobj()
            while True:
                raw = in_f.read(chunk_size)
                if not raw:
                    break
                buffer += compressor.compress(raw)
                while len(buffer) >= chunk_size:
                    chunk = buffer[:chunk_size]
                    buffer = buffer[chunk_size:]
                    if hasher:
                        hasher.update(chunk)
                    yield chunk
            buffer += compressor.flush()
        else:
            while True:
                raw = in_f.read(chunk_size)
                if not raw:
                    break
                buffer += raw
                while len(buffer) >= chunk_size:
                    chunk = buffer[:chunk_size]
                    buffer = buffer[chunk_size:]
                    if hasher:
                        hasher.update(chunk)
                    yield chunk

        if buffer:
            if hasher:
                hasher.update(buffer)
            yield buffer

        if hasher and algo_id:
            digest = hasher.digest()
            meta = CryptoEngine.LETNOX_MAGIC + bytes([CryptoEngine.LETNOX_VERSION, algo_id]) + digest
            yield meta

    @staticmethod
    def encrypt_file(
        input_path: str,
        password: str,
        algo: str,
        pqc_public_key: Optional[bytes] = None,
        pqc_kem: str = "kyber512",
        compress: bool = False,
        device_lock: bool = False,
        chunk_size: int = STREAM_CHUNK_SIZE,
        context: str | int = "file",
    ) -> tuple[bool, str]:
        if not os.path.exists(input_path):
            return False, "Input file missing"

        flags = 0
        if compress:
            flags |= CryptoEngine.FLAG_COMPRESS

        salt = get_random_bytes(16)
        mem_kib, time_cost, parallelism = CryptoEngine._select_kdf_params()
        try:
            CryptoEngine._validate_kdf_params(mem_kib, time_cost, parallelism)
        except Exception as e:
            return False, f"KDF params error: {e}"

        base_key = CryptoEngine.derive_key_argon2id(
            password,
            salt,
            length=32,
            mem_kib=mem_kib,
            time_cost=time_cost,
            parallelism=parallelism,
        )

        alg_map = {
            "chacha20-poly1305": CryptoEngine.ALG_CHACHA20,
            "aes-256-gcm": CryptoEngine.ALG_AESGCM,
            "pqc-hybrid": CryptoEngine.ALG_PQC_HYBRID,
            "letnox-256": CryptoEngine.ALG_LETNOX_256,
            "letnox-512": CryptoEngine.ALG_LETNOX_512,
            "legacy-wrap": CryptoEngine.ALG_LEGACY_WRAP,
        }
        alg_id = alg_map.get(algo)
        if not alg_id:
            return False, "Unsupported algorithm"
        if alg_id == CryptoEngine.ALG_LEGACY_WRAP and compress:
            return False, "Compression not supported for legacy wrapper"

        kem_id = None
        kem_ct = None
        context_id, _ctx_info = CryptoEngine._context_info(context)
        context_key = CryptoEngine._derive_context_key(base_key, salt, context_id)
        final_key = context_key
        device_binding = None

        if alg_id == CryptoEngine.ALG_PQC_HYBRID:
            if not HAS_PQC:
                return False, "PQC library not available"
            if not pqc_public_key:
                return False, "PQC public key required"
            if pqc_kem not in CryptoEngine.pqc_kem_names():
                return False, "Unsupported PQC KEM"
            sizes = CryptoEngine._pqc_expected_sizes(pqc_kem)
            if len(pqc_public_key) != sizes["pub"]:
                return False, "Invalid PQC public key size"
            kem_id = CryptoEngine.pqc_kem_names().index(pqc_kem) + 1
            kem_ct, shared = CryptoEngine._kem_encapsulate(pqc_kem, pqc_public_key)
            if len(kem_ct) != sizes["ct"]:
                return False, "Invalid PQC ciphertext size"
            final_key = CryptoEngine._hkdf(context_key + shared, salt, b"noxium-pqc", 32)
            flags |= CryptoEngine.FLAG_PQC
        letnox_variant = None
        if alg_id in (CryptoEngine.ALG_LETNOX_256, CryptoEngine.ALG_LETNOX_512):
            letnox_variant = 256 if alg_id == CryptoEngine.ALG_LETNOX_256 else 512

        if device_lock:
            try:
                device_binding = get_device_fingerprint()
            except Exception:
                return False, "Device lock unavailable"
            final_key = CryptoEngine._hkdf(
                final_key + device_binding, salt, b"noxium-device", 32
            )
            flags |= CryptoEngine.FLAG_DEVICE

        if chunk_size <= 0 or chunk_size > CryptoEngine.STREAM_CHUNK_SIZE * CryptoEngine.MAX_CHUNK_LEN_MULTIPLIER:
            return False, "Invalid chunk size"

        nonce_prefix = get_random_bytes(CryptoEngine.NONCE_PREFIX_LEN)
        tag_len = 16
        header = CryptoEngine._build_header(
            CryptoEngine.FILE_VERSION_V2,
            alg_id,
            flags,
            salt,
            mem_kib,
            time_cost,
            parallelism,
            CryptoEngine.NONCE_PREFIX_LEN + CryptoEngine.NONCE_COUNTER_LEN,
            tag_len,
            chunk_size=chunk_size,
            nonce_prefix=nonce_prefix,
            context_id=context_id,
            kem_id=kem_id,
            kem_ct=kem_ct,
        )

        out_path = input_path + CryptoEngine.ENCRYPTED_EXT
        try:
            with open(input_path, "rb") as in_f, open(out_path, "wb") as out_f:
                commit_key = CryptoEngine._hkdf(final_key, salt, b"noxium-commit", 32)
                commitment = hmac.new(commit_key, header, hashlib.sha256).digest()[
                    : CryptoEngine.COMMIT_LEN
                ]
                out_f.write(header)
                out_f.write(commitment)
                counter = 0
                for plain_chunk in CryptoEngine._iter_plain_chunks(
                    in_f, compress, letnox_variant, chunk_size
                ):
                    nonce = CryptoEngine._derive_chunk_nonce(nonce_prefix, counter)
                    if alg_id == CryptoEngine.ALG_AESGCM:
                        cipher = AES.new(final_key, AES.MODE_GCM, nonce=nonce)
                    else:
                        cipher = ChaCha20_Poly1305.new(key=final_key, nonce=nonce)
                    cipher.update(header + struct.pack(">Q", counter))
                    ciphertext, tag = cipher.encrypt_and_digest(plain_chunk)
                    out_f.write(struct.pack(">I", len(ciphertext)))
                    out_f.write(nonce)
                    out_f.write(tag)
                    out_f.write(ciphertext)
                    counter += 1
                out_f.write(struct.pack(">I", 0))
            return True, out_path
        except Exception as e:
            try:
                if os.path.exists(out_path):
                    from core.shredder import Shredder

                    Shredder.wipe_file(out_path)
            except Exception:
                pass
            return False, f"Encryption Error: {e}"

    @staticmethod
    def decrypt_file(
        input_path: str,
        password: str,
        pqc_private_key: Optional[bytes] = None,
        allow_legacy: bool = False,
    ) -> tuple[bool, str]:
        if not os.path.exists(input_path):
            return False, "Input file missing"

        with open(input_path, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                return False, "Invalid file"
            if magic != CryptoEngine.FILE_MAGIC:
                if not allow_legacy:
                    return False, "Legacy format blocked (explicit opt-in required)"
                return CryptoEngine._decrypt_legacy(input_path, password)

            try:
                header, header_bytes = CryptoEngine._read_header_from_file(f, magic)
            except Exception as e:
                return False, f"Header error: {e}"

            if header["kdf_id"] != CryptoEngine.KDF_ARGON2ID:
                return False, "Unsupported KDF"
            try:
                CryptoEngine._validate_kdf_params(
                    header["mem_kib"], header["time_cost"], header["parallelism"]
                )
            except Exception as e:
                return False, f"KDF params error: {e}"

            if header["nonce_len"] != 12 or header["tag_len"] != 16:
                return False, "Unsupported nonce/tag size"

            base_key = CryptoEngine.derive_key_argon2id(
                password,
                header["salt"],
                length=32,
                mem_kib=header["mem_kib"],
                time_cost=header["time_cost"],
                parallelism=header["parallelism"],
            )

            if header["version"] == CryptoEngine.FILE_VERSION_V2:
                context_id = header.get("context_id", CryptoEngine.CTX_FILE)
                if not CryptoEngine._is_valid_context_id(context_id):
                    return False, "Invalid context id"
                context_key = CryptoEngine._derive_context_key(
                    base_key, header["salt"], context_id
                )
            else:
                context_key = base_key

            final_key = context_key
            if header["flags"] & CryptoEngine.FLAG_PQC:
                if not pqc_private_key:
                    return False, "PQC private key required"
                kem_id = header["kem_id"]
                if kem_id is None:
                    return False, "Missing PQC metadata"
                kem_names = CryptoEngine.pqc_kem_names()
                if kem_id - 1 >= len(kem_names):
                    return False, "Unknown PQC KEM"
                kem_name = kem_names[kem_id - 1]
                sizes = CryptoEngine._pqc_expected_sizes(kem_name)
                if len(pqc_private_key) != sizes["priv"]:
                    return False, "Invalid PQC private key size"
                if header["kem_ct"] is None or len(header["kem_ct"]) != sizes["ct"]:
                    return False, "Invalid PQC ciphertext size"
                shared = CryptoEngine._kem_decapsulate(
                    kem_name, pqc_private_key, header["kem_ct"]
                )
                final_key = CryptoEngine._hkdf(
                    context_key + shared, header["salt"], b"noxium-pqc", 32
                )

            if header["flags"] & CryptoEngine.FLAG_DEVICE:
                try:
                    device_binding = get_device_fingerprint()
                except Exception:
                    return False, "Device lock unavailable"
                final_key = CryptoEngine._hkdf(
                    final_key + device_binding, header["salt"], b"noxium-device", 32
                )

            if header["version"] == CryptoEngine.FILE_VERSION_V2:
                commit_key = CryptoEngine._hkdf(final_key, header["salt"], b"noxium-commit", 32)
                commitment = f.read(CryptoEngine.COMMIT_LEN)
                expected = hmac.new(commit_key, header_bytes, hashlib.sha256).digest()[
                    : CryptoEngine.COMMIT_LEN
                ]
                if commitment != expected:
                    return False, "Key commitment mismatch"

            if header["version"] == CryptoEngine.FILE_VERSION_V1:
                nonce = f.read(header["nonce_len"])
                tag = f.read(header["tag_len"])
                ciphertext = f.read()
                if len(nonce) != header["nonce_len"] or len(tag) != header["tag_len"]:
                    return False, "Invalid payload"

                if header["alg_id"] == CryptoEngine.ALG_AESGCM:
                    cipher = AES.new(final_key, AES.MODE_GCM, nonce=nonce)
                else:
                    cipher = ChaCha20_Poly1305.new(key=final_key, nonce=nonce)

                cipher.update(header_bytes)
                try:
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                except Exception as e:
                    return False, f"Decryption Error: {e}"

                if header["alg_id"] in (
                    CryptoEngine.ALG_LETNOX_256,
                    CryptoEngine.ALG_LETNOX_512,
                ):
                    variant = (
                        256 if header["alg_id"] == CryptoEngine.ALG_LETNOX_256 else 512
                    )
                    try:
                        plaintext = CryptoEngine._letnox_unwrap(plaintext, variant)
                    except Exception as e:
                        return False, f"LetNox Integrity Error: {e}"

                if header["flags"] & CryptoEngine.FLAG_COMPRESS:
                    try:
                        plaintext = zlib.decompress(plaintext)
                    except Exception as e:
                        return False, f"Decompression Error: {e}"

                out_path = input_path.replace(CryptoEngine.ENCRYPTED_EXT, "")
                with open(out_path, "wb") as out_f:
                    out_f.write(plaintext)
                return True, out_path

            ok, out_path = CryptoEngine._stream_decrypt_chunks(
                f, input_path, header, header_bytes, final_key
            )
            if not ok:
                return False, out_path
            if header["alg_id"] == CryptoEngine.ALG_LEGACY_WRAP:
                ok, msg = CryptoEngine._decrypt_legacy(out_path, password)
                if not ok:
                    try:
                        from core.shredder import Shredder

                        Shredder.wipe_file(out_path)
                    except Exception:
                        pass
                    return False, msg
                return True, msg
            return True, out_path

    @staticmethod
    def _stream_decrypt_chunks(f, input_path, header, header_bytes, final_key):
        chunk_size = header.get("chunk_size") or CryptoEngine.STREAM_CHUNK_SIZE
        if chunk_size <= 0 or chunk_size > CryptoEngine.STREAM_CHUNK_SIZE * CryptoEngine.MAX_CHUNK_LEN_MULTIPLIER:
            return False, "Invalid chunk size"

        max_chunk_len = max(chunk_size * CryptoEngine.MAX_CHUNK_LEN_MULTIPLIER, 1024 * 1024)
        use_compress = bool(header["flags"] & CryptoEngine.FLAG_COMPRESS)
        letnox_variant = None
        if header["alg_id"] == CryptoEngine.ALG_LETNOX_256:
            letnox_variant = 256
        elif header["alg_id"] == CryptoEngine.ALG_LETNOX_512:
            letnox_variant = 512

        decompressor = zlib.decompressobj() if use_compress else None
        out_path = input_path.replace(CryptoEngine.ENCRYPTED_EXT, "")
        counter = 0

        tail = b""
        hasher = None
        meta_len = 0
        algo_id = None
        digest_len = 0
        if letnox_variant == 256:
            hasher = hashlib.sha256()
            algo_id = CryptoEngine.LETNOX_HASH_SHA256
            digest_len = 32
        elif letnox_variant == 512:
            hasher = hashlib.sha512()
            algo_id = CryptoEngine.LETNOX_HASH_SHA512
            digest_len = 64
        if hasher:
            meta_len = len(CryptoEngine.LETNOX_MAGIC) + 2 + digest_len

        def fail(msg: str):
            raise ValueError(msg)

        try:
            with open(out_path, "wb") as out_f:
                while True:
                    len_bytes = f.read(4)
                    if not len_bytes:
                        fail("Truncated stream")
                    if len(len_bytes) != 4:
                        fail("Invalid chunk header")
                    (cipher_len,) = struct.unpack(">I", len_bytes)
                    if cipher_len == 0:
                        break
                    if cipher_len > max_chunk_len:
                        fail("Chunk too large")

                    nonce = f.read(12)
                    tag = f.read(16)
                    ciphertext = f.read(cipher_len)
                    if len(nonce) != 12 or len(tag) != 16 or len(ciphertext) != cipher_len:
                        fail("Invalid chunk payload")

                    if header["alg_id"] == CryptoEngine.ALG_AESGCM:
                        cipher = AES.new(final_key, AES.MODE_GCM, nonce=nonce)
                    else:
                        cipher = ChaCha20_Poly1305.new(key=final_key, nonce=nonce)
                    cipher.update(header_bytes + struct.pack(">Q", counter))
                    try:
                        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    except Exception as e:
                        fail(f"Decryption Error: {e}")

                    if hasher:
                        tail += plaintext
                        if len(tail) > meta_len:
                            emit = tail[:-meta_len]
                            tail = tail[-meta_len:]
                            hasher.update(emit)
                            if decompressor:
                                out_f.write(decompressor.decompress(emit))
                            else:
                                out_f.write(emit)
                    else:
                        if decompressor:
                            out_f.write(decompressor.decompress(plaintext))
                        else:
                            out_f.write(plaintext)

                    counter += 1

                if hasher:
                    if len(tail) != meta_len:
                        fail("LetNox integrity tag missing")
                    if tail[: len(CryptoEngine.LETNOX_MAGIC)] != CryptoEngine.LETNOX_MAGIC:
                        fail("LetNox tag not found")
                    version = tail[len(CryptoEngine.LETNOX_MAGIC)]
                    algo = tail[len(CryptoEngine.LETNOX_MAGIC) + 1]
                    if version != CryptoEngine.LETNOX_VERSION or algo != algo_id:
                        fail("LetNox tag mismatch")
                    digest = tail[-digest_len:]
                    if digest != hasher.digest():
                        fail("LetNox integrity check failed")

                if decompressor:
                    out_f.write(decompressor.flush())

            return True, out_path
        except Exception as e:
            try:
                if os.path.exists(out_path):
                    from core.shredder import Shredder

                    Shredder.wipe_file(out_path)
            except Exception:
                pass
            return False, f"Decryption Error: {e}"

    @staticmethod
    def _decrypt_legacy(input_path: str, password: str) -> tuple[bool, str]:
        try:
            with open(input_path, "rb") as f:
                raw = f.read()

            plaintext = CryptoEngine._decrypt_legacy_bytes(raw, password)

            out_path = input_path.replace(CryptoEngine.ENCRYPTED_EXT, "")
            with open(out_path, "wb") as f:
                f.write(plaintext)
            return True, out_path

        except Exception as e:
            return False, f"Legacy Decryption Error: {e}"

    @staticmethod
    def _decrypt_legacy_bytes(raw: bytes, password: str) -> bytes:
        if len(raw) < 20:
            raise ValueError("Invalid legacy payload")
        magic = raw[:4]
        salt = raw[4:20]
        offset = 20

        key = CryptoEngine.derive_key_scrypt(password, salt, 32)

        if magic == CryptoEngine.MAGIC_SIV:
            n_len = raw[offset]
            offset += 1
            nonce = raw[offset : offset + n_len]
            offset += n_len
            t_len = raw[offset]
            offset += 1
            tag = raw[offset : offset + t_len]
            offset += t_len
            ciphertext = raw[offset:]

            key_siv = CryptoEngine.derive_key_scrypt(password, salt, 64)
            cipher = AES.new(key_siv, AES.MODE_SIV, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)

        if magic == CryptoEngine.MAGIC_BLF:
            n_len = raw[offset]
            offset += 1
            nonce = raw[offset : offset + n_len]
            offset += n_len
            offset += 1
            ciphertext = raw[offset:]
            from Crypto.Cipher import Blowfish

            cipher = Blowfish.new(key, Blowfish.MODE_CTR, nonce=nonce)
            return cipher.decrypt(ciphertext)

        if magic == CryptoEngine.MAGIC_CST:
            n_len = raw[offset]
            offset += 1
            nonce = raw[offset : offset + n_len]
            offset += n_len
            offset += 1
            ciphertext = raw[offset:]
            from Crypto.Cipher import CAST

            key_cast = key[:16]
            cipher = CAST.new(key_cast, CAST.MODE_CTR, nonce=nonce)
            return cipher.decrypt(ciphertext)

        if magic == CryptoEngine.MAGIC_PQC:
            n_len = raw[offset]
            offset += 1
            nonce = raw[offset : offset + n_len]
            offset += n_len
            t_len = raw[offset]
            offset += 1
            tag = raw[offset : offset + t_len]
            offset += t_len
            ciphertext = raw[offset:]

            try:
                key2 = hashlib.sha3_512(key).digest()[:32]
            except Exception:
                key2 = hashlib.sha512(key).digest()[:32]

            cipher2 = ChaCha20_Poly1305.new(key=key2, nonce=nonce)
            inner = cipher2.decrypt_and_verify(ciphertext, tag)

            aes_nonce = inner[-16:]
            aes_tag = inner[-32:-16]
            aes_cipher = inner[:-32]
            cipher1 = AES.new(key, AES.MODE_GCM, nonce=aes_nonce)
            return cipher1.decrypt_and_verify(aes_cipher, aes_tag)

        if magic == CryptoEngine.MAGIC_STD:
            n_len = raw[offset]
            offset += 1
            nonce = raw[offset : offset + n_len]
            offset += n_len
            t_len = raw[offset]
            offset += 1
            tag = raw[offset : offset + t_len]
            offset += t_len
            ciphertext = raw[offset:]

            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)

        raise ValueError("Unknown legacy format")

    @staticmethod
    def data_encrypt(data: bytes, password: str) -> dict:
        salt = get_random_bytes(16)
        key = CryptoEngine.derive_key_scrypt(password, salt)
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
        try:
            salt = bytes.fromhex(enc_dict["salt"])
            nonce = bytes.fromhex(enc_dict["nonce"])
            tag = bytes.fromhex(enc_dict["tag"])
            ciphertext = bytes.fromhex(enc_dict["ciphertext"])

            key = CryptoEngine.derive_key_scrypt(password, salt)
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError):
            raise ValueError("Decryption Failed")

    @staticmethod
    def data_encrypt_blob(data: bytes, password: str, context: str | int = "generic") -> bytes:
        salt = get_random_bytes(16)
        base_key = CryptoEngine.derive_key_scrypt(password, salt)
        ctx_id, _ctx_info = CryptoEngine._context_info(context)
        key = CryptoEngine._derive_context_key(base_key, salt, ctx_id)
        cipher = ChaCha20_Poly1305.new(key=key)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce

        if len(nonce) > 255 or len(tag) > 255:
            raise ValueError("Nonce/Tag length overflow")

        return b"".join(
            [
                CryptoEngine.DATA_MAGIC,
                bytes([CryptoEngine.DATA_VERSION_V2]),
                bytes([ctx_id]),
                salt,
                bytes([len(nonce)]),
                nonce,
                bytes([len(tag)]),
                tag,
                ciphertext,
            ]
        )

    @staticmethod
    def data_decrypt_blob(blob: bytes, password: str, context: str | int = "generic") -> bytes:
        if len(blob) < 4 + 1 + 16 + 1 + 1:
            raise ValueError("Invalid blob length")

        magic = blob[:4]
        version = blob[4]
        if magic != CryptoEngine.DATA_MAGIC:
            raise ValueError("Unknown blob format")

        if version not in (CryptoEngine.DATA_VERSION_V1, CryptoEngine.DATA_VERSION_V2):
            raise ValueError("Unknown blob format")

        offset = 5
        ctx_id = CryptoEngine.CTX_GENERIC
        if version == CryptoEngine.DATA_VERSION_V2:
            ctx_id = blob[offset]
            offset += 1
            if not CryptoEngine._is_valid_context_id(ctx_id):
                raise ValueError("Invalid context id")

        expected_ctx_id, _ctx_info = CryptoEngine._context_info(context)
        if version == CryptoEngine.DATA_VERSION_V2 and ctx_id != expected_ctx_id:
            raise ValueError("Context mismatch")

        salt = blob[offset : offset + 16]
        offset += 16

        n_len = blob[offset]
        offset += 1
        nonce = blob[offset : offset + n_len]
        offset += n_len

        t_len = blob[offset]
        offset += 1
        tag = blob[offset : offset + t_len]
        offset += t_len

        ciphertext = blob[offset:]

        base_key = CryptoEngine.derive_key_scrypt(password, salt)
        if version == CryptoEngine.DATA_VERSION_V2:
            key = CryptoEngine._derive_context_key(base_key, salt, ctx_id)
        else:
            key = base_key
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    @staticmethod
    def data_encrypt_key_blob(data: bytes, key: bytes, context: str | int = "generic") -> bytes:
        ctx_id, info = CryptoEngine._context_info(context)
        ctx_key = CryptoEngine._hkdf(key, b"", info, 32)
        cipher = ChaCha20_Poly1305.new(key=ctx_key)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce

        if len(nonce) > 255 or len(tag) > 255:
            raise ValueError("Nonce/Tag length overflow")

        return b"".join(
            [
                CryptoEngine.KEY_MAGIC,
                bytes([CryptoEngine.KEY_VERSION_V2]),
                bytes([ctx_id]),
                bytes([len(nonce)]),
                nonce,
                bytes([len(tag)]),
                tag,
                ciphertext,
            ]
        )

    @staticmethod
    def data_decrypt_key_blob(blob: bytes, key: bytes, context: str | int = "generic") -> bytes:
        if len(blob) < 4 + 1 + 1 + 1:
            raise ValueError("Invalid key blob length")

        magic = blob[:4]
        version = blob[4]
        if magic != CryptoEngine.KEY_MAGIC:
            raise ValueError("Unknown key blob format")

        if version not in (CryptoEngine.KEY_VERSION_V1, CryptoEngine.KEY_VERSION_V2):
            raise ValueError("Unknown key blob format")

        offset = 5
        ctx_id = CryptoEngine.CTX_GENERIC
        if version == CryptoEngine.KEY_VERSION_V2:
            ctx_id = blob[offset]
            offset += 1
            if not CryptoEngine._is_valid_context_id(ctx_id):
                raise ValueError("Invalid context id")

        expected_ctx_id, info = CryptoEngine._context_info(context)
        if version == CryptoEngine.KEY_VERSION_V2 and ctx_id != expected_ctx_id:
            raise ValueError("Context mismatch")

        n_len = blob[offset]
        offset += 1
        nonce = blob[offset : offset + n_len]
        offset += n_len

        t_len = blob[offset]
        offset += 1
        tag = blob[offset : offset + t_len]
        offset += t_len

        ciphertext = blob[offset:]

        if version == CryptoEngine.KEY_VERSION_V2:
            ctx_key = CryptoEngine._hkdf(key, b"", info, 32)
        else:
            ctx_key = key
        cipher = ChaCha20_Poly1305.new(key=ctx_key, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    @staticmethod
    def encrypt_advanced(
        input_path,
        password,
        mode,
        compress=False,
        pqc_public_key=None,
        pqc_kem="kyber512",
        device_lock=False,
        chunk_size=STREAM_CHUNK_SIZE,
    ):
        mode_map = {
            "standard": "chacha20-poly1305",
            "siv": "aes-256-gcm",
            "blowfish": "aes-256-gcm",
            "cast": "aes-256-gcm",
            "pqc": "pqc-hybrid",
            "letnox256": "letnox-256",
            "letnox512": "letnox-512",
            "legacy-wrap": "legacy-wrap",
        }
        algo = mode_map.get(mode, "chacha20-poly1305")
        return CryptoEngine.encrypt_file(
            input_path,
            password,
            algo,
            pqc_public_key=pqc_public_key,
            pqc_kem=pqc_kem,
            compress=compress,
            device_lock=device_lock,
            chunk_size=chunk_size,
        )

    @staticmethod
    def decrypt_advanced(input_path, password, pqc_private_key=None, allow_legacy=False):
        return CryptoEngine.decrypt_file(
            input_path,
            password,
            pqc_private_key=pqc_private_key,
            allow_legacy=allow_legacy,
        )
