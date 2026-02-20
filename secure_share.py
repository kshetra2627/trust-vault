# secure_share.py

import secrets
import string
import hashlib
import base64
from cryptography.fernet import Fernet


# ─── PASSWORD GENERATOR ─────────────────────────────────────

def generate_share_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*"),
    ]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


def derive_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(
        hashlib.sha256(password.encode("utf-8")).digest()
    )


# ─── ENCRYPT / DECRYPT ─────────────────────────────────────

def encrypt_for_share(data: bytes, password: str) -> bytes:
    return Fernet(derive_key(password)).encrypt(data)


def decrypt_from_share(encrypted: bytes, password: str) -> bytes:
    return Fernet(derive_key(password)).decrypt(encrypted)


def verify_share_password(encrypted: bytes, password: str) -> bool:
    try:
        decrypt_from_share(encrypted, password)
        return True
    except Exception:
        return False