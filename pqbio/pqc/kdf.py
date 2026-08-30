"""HKDF-SHA256 key derivation with handshake transcript binding (PROJECT_SPEC.md §5.1).

    transcript = SHA256(session_id ‖ kem_ct ‖ server_sig_pk ‖ device_sig_pk)
    K_master   = HKDF-Extract(salt=transcript, ikm=ss)
    K_c2s      = HKDF-Expand(K_master, "pqbio/v1/c2s", 32)
    K_s2c      = HKDF-Expand(K_master, "pqbio/v1/s2c", 32)

Binding the transcript (not just the shared secret) means a MITM that swaps the
session, ciphertext, or either public key changes K_master, so the mismatch is
detected on first use of the derived keys rather than trusted silently. `session_id`
is passed as bytes — callers pass its canonical byte encoding (e.g. `uuid.UUID.bytes`).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

_LABEL_C2S = b"pqbio/v1/c2s"
_LABEL_S2C = b"pqbio/v1/s2c"
_KEY_LEN = 32


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def compute_transcript(
    *,
    session_id: bytes,
    kem_ct: bytes,
    server_sig_pk: bytes,
    device_sig_pk: bytes,
) -> bytes:
    return sha256(session_id + kem_ct + server_sig_pk + device_sig_pk)


def hkdf_extract(*, salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract(salt, IKM) = HMAC-SHA256(salt, IKM)."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = _KEY_LEN) -> bytes:
    """RFC 5869 HKDF-Expand(PRK, info, L)."""
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


@dataclass(frozen=True)
class SessionKeys:
    k_master: bytes
    k_c2s: bytes
    k_s2c: bytes


def derive_session_keys(
    *,
    ss: bytes,
    session_id: bytes,
    kem_ct: bytes,
    server_sig_pk: bytes,
    device_sig_pk: bytes,
) -> SessionKeys:
    transcript = compute_transcript(
        session_id=session_id,
        kem_ct=kem_ct,
        server_sig_pk=server_sig_pk,
        device_sig_pk=device_sig_pk,
    )
    k_master = hkdf_extract(salt=transcript, ikm=ss)
    return SessionKeys(
        k_master=k_master,
        k_c2s=hkdf_expand(k_master, _LABEL_C2S),
        k_s2c=hkdf_expand(k_master, _LABEL_S2C),
    )
