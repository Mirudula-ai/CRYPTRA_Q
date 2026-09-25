import base64
import hashlib
import logging
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


class EncryptionManager:
    """
    Fernet-based symmetric encryption with SHA-256 key derivation.

    SECURITY DESIGN NOTE (for reviewers):
    ──────────────────────────────────────
    Fernet is AES-128-CBC with HMAC-SHA256 authentication (authenticated
    encryption). It provides confidentiality + integrity for the ciphertext.

    Key derivation: the user-supplied session key (arbitrary string) is
    hashed with SHA-256 to produce a deterministic 32-byte key, then
    base64url-encoded for Fernet compatibility. This replaces the previous
    ljust(32) space-padding which was trivially predictable for short keys.

    Limitation: SHA-256 is NOT a password-based KDF (no salt, no work
    factor). This is acceptable here because the session key is a
    generated BB84 bit-string, NOT a human password. For human-chosen
    passwords, use PBKDF2 or Argon2id. This is documented as a
    known-limitation in the security audit.
    """

    @staticmethod
    def _derive_key(session_key: str) -> bytes:
        """
        Derives a Fernet-compatible 32-byte key from the session key string
        using SHA-256. This is deterministic and consistent across sender/receiver.
        """
        raw = hashlib.sha256(session_key.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(raw)

    @staticmethod
    def encrypt_message(msg: str, key: str) -> str:
        """Encrypts msg using Fernet (AES-128-CBC + HMAC-SHA256)."""
        try:
            key_bytes = EncryptionManager._derive_key(key)
            cipher = Fernet(key_bytes)
            return cipher.encrypt(msg.encode("utf-8")).decode("utf-8")
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise Exception("Encryption error")

    @staticmethod
    def decrypt_message(encrypted_msg: str, key: str) -> str:
        """
        Decrypts a Fernet-encrypted message.
        Raises a descriptive exception if the key is wrong or the token is
        corrupted/tampered — Fernet's HMAC verification catches both cases.
        """
        try:
            key_bytes = EncryptionManager._derive_key(key)
            cipher = Fernet(key_bytes)
            return cipher.decrypt(encrypted_msg.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            logger.warning("Fernet InvalidToken: wrong session key or tampered ciphertext.")
            raise Exception("Decryption failed — incorrect session key or tampered payload.")
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise Exception("Decryption error.")
