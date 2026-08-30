"""AES-256-GCM AEAD (PROJECT_SPEC.md §5.1). 12-byte CSPRNG nonce, 16-byte tag. Fails
closed: any authentication failure raises `AEADDecryptionError`, never returns partial
or unauthenticated plaintext (§11).
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
KEY_LEN = 32


class AEADDecryptionError(Exception):
    """Raised on any AEAD decryption/authentication failure. Callers must fail closed."""


def generate_nonce() -> bytes:
    return os.urandom(NONCE_LEN)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Returns (nonce, ciphertext_with_tag)."""
    if len(key) != KEY_LEN:
        raise ValueError(f"AES-256-GCM key must be {KEY_LEN} bytes, got {len(key)}")
    nonce = generate_nonce()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    if len(key) != KEY_LEN:
        raise ValueError(f"AES-256-GCM key must be {KEY_LEN} bytes, got {len(key)}")
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"AES-256-GCM nonce must be {NONCE_LEN} bytes, got {len(nonce)}")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise AEADDecryptionError("AEAD authentication failed") from exc
    except ValueError as exc:
        # e.g. ciphertext shorter than the 16-byte tag (a truncated-tag attack)
        raise AEADDecryptionError(f"AEAD decryption failed: {exc}") from exc
