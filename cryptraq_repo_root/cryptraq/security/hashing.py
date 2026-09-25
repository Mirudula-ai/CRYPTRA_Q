import hashlib
import hmac
import nacl.signing
import nacl.encoding
import nacl.exceptions
import base64
import json
import time


class SecurityLayer:
    """
    Cryptographic security layer for CryptraQ.

    Provides:
      - Ed25519 signing/verification  (payload authentication)
      - Ed25519 token-binding signing (QR/PDF integrity + sender authentication)
      - HMAC-SHA256 utility           (general MAC; legacy)

    Ed25519 key lifecycle:
      A new SigningKey is generated when the Streamlit session starts and is
      held in st.session_state for the session lifetime. Keys are ephemeral
      by design — they do NOT persist across restarts. The public key is
      embedded in the QR code and PDF so receivers can verify without an
      out-of-band PKI.

    HMAC note (IMPORTANT for reviewers):
      generate_packet_hmac() uses the Ed25519 public key as the HMAC key.
      Because the public key is itself transmitted in the QR payload, any
      party who can read the QR can recompute a valid HMAC — this is NOT
      authentication; it is only a consistency/tamper-detection convenience.
      The cryptographically strong binding is provided by sign_binding() /
      verify_binding(), which require the Ed25519 private key to produce a
      valid signature. sign_binding() is the preferred method for QR/PDF
      integrity in CryptraQ v2.
    """

    def __init__(self, private_key_hex: str = None):
        if private_key_hex:
            try:
                seed = bytes.fromhex(private_key_hex)
                self.signing_key = nacl.signing.SigningKey(seed)
            except Exception:
                self.signing_key = nacl.signing.SigningKey.generate()
        else:
            self.signing_key = nacl.signing.SigningKey.generate()

        self.verify_key = self.signing_key.verify_key

    # -----------------------------------------------------------------------
    # Key accessors
    # -----------------------------------------------------------------------

    def get_public_key_hex(self) -> str:
        """Returns the 64-character hex-encoded Ed25519 verify key."""
        return self.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode("utf-8")

    def get_private_key_hex(self) -> str:
        """Returns the Ed25519 signing key seed in hex (32 bytes = 64 hex chars)."""
        return self.signing_key.encode(encoder=nacl.encoding.HexEncoder).decode("utf-8")

    # -----------------------------------------------------------------------
    # Payload signing (encrypted ciphertext authentication)
    # -----------------------------------------------------------------------

    def sign_payload(self, payload: str) -> str:
        """
        Signs the encrypted payload with the Ed25519 private key.
        The signature covers the raw ciphertext bytes — any modification to
        the ciphertext after signing will cause verification to fail.
        Returns a Base64-encoded signed message (signature || payload).
        """
        payload_bytes = payload.encode("utf-8")
        signed = self.signing_key.sign(payload_bytes, encoder=nacl.encoding.Base64Encoder)
        return signed.decode("utf-8")

    @staticmethod
    def verify_signature(payload: str, signature: str, public_key_hex: str) -> bool:
        """
        Verifies the Ed25519 signature of the encrypted payload.

        SECURITY FIX (v2.1): In addition to signature validity, we now
        explicitly verify that the message recovered from the signed blob
        matches the `payload` argument using constant-time comparison.

        Without this check, verify_key.verify() only confirms the blob is
        self-consistent — it does NOT prove the blob covers the specific
        payload we care about. An attacker with a valid signed blob for
        payload A could pass it alongside payload B and previously get True.
        """
        try:
            verify_key = nacl.signing.VerifyKey(
                public_key_hex, encoder=nacl.encoding.HexEncoder
            )
            sig_bytes = signature.encode("utf-8")
            # verify() recovers the original signed message bytes
            recovered_bytes = verify_key.verify(sig_bytes, encoder=nacl.encoding.Base64Encoder)
            # Constant-time comparison: recovered payload MUST match the claimed payload
            expected_bytes = payload.encode("utf-8")
            return hmac.compare_digest(recovered_bytes, expected_bytes)
        except nacl.exceptions.BadSignatureError:
            return False
        except Exception:
            return False

    # -----------------------------------------------------------------------
    # Token binding signature (QR / PDF integrity — STRONGER than HMAC)
    # -----------------------------------------------------------------------

    def sign_binding(self, token: str, expiration: int) -> str:
        """
        Signs the canonical binding string  "{token}:{expiration}"  with the
        sender's Ed25519 private key.

        SECURITY PROPERTY:
          Only the private key holder can produce a valid signature.
          The receiver verifies using the public key embedded in the QR/PDF.
          An attacker who intercepts the QR cannot forge a valid binding
          signature (unlike the previous HMAC-with-public-key approach, which
          was forgeable by any QR reader).

        Returns a Base64-encoded Ed25519 signed message.
        Stored in the QR as the "h" field (replaces the previous HMAC tag).
        """
        binding = f"{token}:{expiration}".encode("utf-8")
        signed = self.signing_key.sign(binding, encoder=nacl.encoding.Base64Encoder)
        return signed.decode("utf-8")

    @staticmethod
    def verify_binding(
        token: str, expiration: int, binding_sig: str, public_key_hex: str
    ) -> bool:
        """
        Verifies the Ed25519 binding signature from the QR/PDF.

        Returns True only if ALL of:
          1. The signature is cryptographically valid.
          2. The verified payload matches "{token}:{expiration}" exactly
             (prevents signature substitution attacks).
          3. The packet has not expired (time-of-check).
        """
        if time.time() > expiration:
            return False  # Reject expired packets before touching the relay
        try:
            verify_key = nacl.signing.VerifyKey(
                public_key_hex, encoder=nacl.encoding.HexEncoder
            )
            sig_bytes = binding_sig.encode("utf-8")
            verified_bytes = verify_key.verify(sig_bytes, encoder=nacl.encoding.Base64Encoder)
            # Confirm the signed content matches the expected binding exactly
            expected_binding = f"{token}:{expiration}".encode("utf-8")
            return hmac.compare_digest(verified_bytes, expected_binding)
        except (nacl.exceptions.BadSignatureError, Exception):
            return False

    # -----------------------------------------------------------------------
    # Legacy HMAC utilities (kept for backward compat; prefer sign_binding)
    # -----------------------------------------------------------------------

    @staticmethod
    def generate_hmac(key: str, message: str) -> str:
        """HMAC-SHA256. General-purpose MAC utility."""
        key_bytes = key.encode("utf-8")
        msg_bytes = message.encode("utf-8")
        return hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()

    @staticmethod
    def generate_packet_hmac(
        token: str, public_key_hex: str, payload: str, expiration: int
    ) -> str:
        """
        DEPRECATED — use sign_binding() instead.

        Generates an HMAC binding token + public_key + expiration using the
        public key as the HMAC key.

        LIMITATION: Because the HMAC key (public_key_hex) is also transmitted
        in the QR payload, any party who reads the QR can recompute a matching
        HMAC. This provides tamper-detection convenience but NOT authentication.
        sign_binding() provides proper Ed25519-authenticated binding.
        """
        binding = json.dumps(
            {"t": token, "p": public_key_hex, "x": expiration}, sort_keys=True
        )
        key_bytes = bytes.fromhex(public_key_hex[:64])
        msg_bytes = binding.encode("utf-8")
        return hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()

    @staticmethod
    def verify_packet_hmac(
        token: str, public_key_hex: str, expiration: int, hmac_tag: str
    ) -> bool:
        """DEPRECATED — use verify_binding() instead."""
        if time.time() > expiration:
            return False
        try:
            expected = SecurityLayer.generate_packet_hmac(
                token, public_key_hex, "", expiration
            )
            return hmac.compare_digest(expected, hmac_tag)
        except Exception:
            return False
