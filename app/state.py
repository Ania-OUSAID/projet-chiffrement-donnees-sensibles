from app.config import get_settings
from app.security.crypto import EnvelopeCrypto
from app.security.keys import KeyManager
from app.security.rate_limit import LoginRateLimiter

settings = get_settings()
key_manager = KeyManager(settings.key_dir, settings.key_passphrase)
crypto_service = EnvelopeCrypto(key_manager)
login_limiter = LoginRateLimiter(settings.max_login_attempts, settings.login_window_seconds)
