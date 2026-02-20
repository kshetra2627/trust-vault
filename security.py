import warnings
import re

# ── Fix passlib + bcrypt >= 4.0 incompatibility ───────────────────────────────
# bcrypt 4.x removed __about__, which passlib tries to read → AttributeError → 500
try:
    import bcrypt as _bcrypt
    if not hasattr(_bcrypt, '__about__'):
        import types as _types
        _about = _types.ModuleType('bcrypt.__about__')
        _about.__version__ = getattr(_bcrypt, '__version__', '4.0.0')
        _bcrypt.__about__ = _about
except ImportError:
    pass

warnings.filterwarnings("ignore", ".*error reading bcrypt version.*")
warnings.filterwarnings("ignore", ".*bcrypt.*")

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

MIN_PASSWORD_LENGTH = 8


def hash_password(password: str) -> str:
    """Hash password with bcrypt."""
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify plain password against bcrypt hash. Never raises — returns False on error."""
    try:
        return pwd_context.verify(password, hashed)
    except Exception:
        return False


def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, ""