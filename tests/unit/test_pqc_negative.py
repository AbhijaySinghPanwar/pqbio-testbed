"""Negative tests required by the Module A DoD (§5.1): malformed public key,
wrong-length signature, truncated AEAD tag. ("Replayed KEM ciphertext" is covered at
the protocol layer in tests/unit/test_handshake.py — see that file's docstring for why.)
"""

from __future__ import annotations

import pytest

from pqbio.pqc.aead import KEY_LEN, AEADDecryptionError, decrypt, encrypt, generate_nonce
from pqbio.pqc.kem import KemMode, get_kem
from pqbio.pqc.sign import SigMode, get_signer

MODES: list[KemMode] = ["classical", "pq"]


# --------------------------------------------------------------------------------------
# Malformed public key (KEM)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
def test_kem_encapsulate_rejects_malformed_public_key(mode: KemMode) -> None:
    kem = get_kem(mode)
    garbage_pk = b"\x00" * 10  # far shorter than any real pk for any mode
    with pytest.raises((ValueError, Exception)):
        kem.encapsulate(garbage_pk)


@pytest.mark.parametrize("mode", MODES)
def test_kem_decapsulate_rejects_wrong_length_ciphertext(mode: KemMode) -> None:
    kem = get_kem(mode)
    pk, sk = kem.keygen()
    with pytest.raises((ValueError, Exception)):
        kem.decapsulate(b"\x00" * 10, sk)


# --------------------------------------------------------------------------------------
# Wrong-length signature
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
def test_signer_verify_rejects_wrong_length_signature(mode: SigMode) -> None:
    signer = get_signer(mode)
    pk, sk = signer.keygen()
    msg = b"verify me"
    sig = signer.sign(msg, sk)

    truncated = sig[: len(sig) // 2]
    extended = sig + b"\x00" * 16

    assert signer.verify(msg, truncated, pk) is False
    assert signer.verify(msg, extended, pk) is False


# --------------------------------------------------------------------------------------
# Truncated AEAD tag
# --------------------------------------------------------------------------------------


def test_aead_round_trip() -> None:
    key = b"\x11" * KEY_LEN
    nonce, ct = encrypt(key, b"secret evidence bytes", aad=b"session-1")
    assert decrypt(key, nonce, ct, aad=b"session-1") == b"secret evidence bytes"


def test_aead_truncated_tag_rejected() -> None:
    key = b"\x22" * KEY_LEN
    nonce, ct = encrypt(key, b"payload", aad=b"")
    # AES-GCM tag is the last 16 bytes; truncate it away.
    truncated = ct[:-16]
    with pytest.raises(AEADDecryptionError):
        decrypt(key, nonce, truncated, aad=b"")


def test_aead_wrong_key_rejected() -> None:
    key = b"\x33" * KEY_LEN
    wrong_key = b"\x44" * KEY_LEN
    nonce, ct = encrypt(key, b"payload", aad=b"")
    with pytest.raises(AEADDecryptionError):
        decrypt(wrong_key, nonce, ct, aad=b"")


def test_aead_tampered_ciphertext_rejected() -> None:
    key = b"\x55" * KEY_LEN
    nonce, ct = encrypt(key, b"payload", aad=b"")
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    with pytest.raises(AEADDecryptionError):
        decrypt(key, nonce, bytes(tampered), aad=b"")


def test_aead_wrong_aad_rejected() -> None:
    key = b"\x66" * KEY_LEN
    nonce, ct = encrypt(key, b"payload", aad=b"session-A")
    with pytest.raises(AEADDecryptionError):
        decrypt(key, nonce, ct, aad=b"session-B")


def test_aead_nonce_is_fresh_each_call() -> None:
    n1 = generate_nonce()
    n2 = generate_nonce()
    assert n1 != n2
