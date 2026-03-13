import hashlib
import hmac


def build_hmac_token(session_secret: str, message: str) -> str:
    return hmac.new(session_secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def verify_hmac(token: str, session_secret: str, message: str) -> bool:
    expected = build_hmac_token(session_secret, message)
    return hmac.compare_digest(token, expected)
