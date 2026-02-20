from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import hashlib


class EncryptionManager:

    def encrypt_data(self, data: bytes):
        """AES-256-GCM encryption. Returns (encrypted_bytes, b64_key, sha256_checksum)."""
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, data, None)
        checksum = hashlib.sha256(data).hexdigest()   # checksum of ORIGINAL data
        return nonce + encrypted, base64.b64encode(key).decode("utf-8"), checksum

    def decrypt_data(self, encrypted_data: bytes, key_b64: str) -> bytes:
        """Decrypt and return plaintext."""
        key = base64.b64decode(key_b64)
        aesgcm = AESGCM(key)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)

    def verify_integrity(self, data: bytes, expected_checksum: str) -> bool:
        """Verify data matches stored checksum — detects corruption."""
        actual = hashlib.sha256(data).hexdigest()
        return actual == expected_checksum

    def encrypt_with_password(self, data: bytes, password: str):
        """Encrypt using PBKDF2-derived key (customer-controlled password)."""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, data, None)
        checksum = hashlib.sha256(data).hexdigest()
        return salt + nonce + encrypted, None, checksum

    def decrypt_with_password(self, encrypted_data: bytes, password: str) -> bytes:
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def hash_file(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


_manager = EncryptionManager()


def encrypt_file_data(data: bytes):
    """Returns (encrypted_bytes, b64_key, checksum)"""
    return _manager.encrypt_data(data)


def decrypt_file_data(encrypted_data: bytes, key_b64: str) -> bytes:
    return _manager.decrypt_data(encrypted_data, key_b64)


def verify_file_integrity(data: bytes, expected_checksum: str) -> bool:
    return _manager.verify_integrity(data, expected_checksum)