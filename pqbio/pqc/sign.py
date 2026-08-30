"""ML-DSA-65 digital signatures (FIPS 204), plus a classical (Ed25519) baseline
(PROJECT_SPEC.md §5.1). The classical mode exists solely to measure PQ overhead in
§8.3 — it is a requirement, not an extra.

Same backend situation as pqbio.pqc.kem: liboqs is unavailable in this environment
(no C++ toolchain), so this module falls back to `dilithium_py.ml_dsa.ML_DSA_65` as the
live backend, documented via `SIG_BACKEND` — never a mock. See pqbio.pqc.kem's module
docstring for the full spec-amendment note and the liboqs install path for a future
session with a C toolchain available.

Verified before relying on this fallback: `dilithium_py.ml_dsa.ML_DSA_65` produces
artefacts of exactly the FIPS 204 ML-DSA-65 sizes (pk 1952B, sk 4032B, sig 3309B) and
sign/verify round-trips correctly.
"""

from __future__ import annotations

import hmac
import warnings
from typing import Literal, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

SigMode = Literal["classical", "pq"]

try:
    import oqs

    _OQS_AVAILABLE = True
except ImportError:
    _OQS_AVAILABLE = False

if _OQS_AVAILABLE:
    SIG_BACKEND: Literal["liboqs", "dilithium-py-fallback"] = "liboqs"
else:
    from dilithium_py.ml_dsa import ML_DSA_65 as _ML_DSA_65

    SIG_BACKEND = "dilithium-py-fallback"
    warnings.warn(
        "liboqs (oqs) is not importable in this environment; falling back to the "
        "pure-Python dilithium-py ML-DSA-65 reference implementation. See the "
        "pqbio.pqc.kem module docstring for the documented spec amendment.",
        RuntimeWarning,
        stacklevel=2,
    )

ML_DSA_65_ALG = "ML-DSA-65"


class Signer(Protocol):
    def keygen(self) -> tuple[bytes, bytes]: ...
    def sign(self, msg: bytes, sk: bytes) -> bytes: ...
    def verify(self, msg: bytes, sig: bytes, pk: bytes) -> bool: ...


class MLDSA65:
    """ML-DSA-65 (FIPS 204). pk 1952B, sk 4032B, sig 3309B."""

    backend = SIG_BACKEND

    def keygen(self) -> tuple[bytes, bytes]:
        if _OQS_AVAILABLE:
            with oqs.Signature(ML_DSA_65_ALG) as sig:
                pk = sig.generate_keypair()
                sk = sig.export_secret_key()
            return pk, sk
        return cast(tuple[bytes, bytes], _ML_DSA_65.keygen())

    def sign(self, msg: bytes, sk: bytes) -> bytes:
        if _OQS_AVAILABLE:
            with oqs.Signature(ML_DSA_65_ALG, secret_key=sk) as signer:
                return cast(bytes, signer.sign(msg))
        return cast(bytes, _ML_DSA_65.sign(sk, msg))

    def verify(self, msg: bytes, sig: bytes, pk: bytes) -> bool:
        if _OQS_AVAILABLE:
            with oqs.Signature(ML_DSA_65_ALG) as verifier:
                return bool(verifier.verify(msg, sig, pk))
        return bool(_ML_DSA_65.verify(pk, msg, sig))


class Ed25519Signer:
    """Classical baseline: Ed25519. Used for the C1 overhead-ablation config (§8.3)."""

    backend = "ed25519"

    def keygen(self) -> tuple[bytes, bytes]:
        sk = ed25519.Ed25519PrivateKey.generate()
        pk_bytes = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        sk_bytes = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return pk_bytes, sk_bytes

    def sign(self, msg: bytes, sk: bytes) -> bytes:
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(sk)
        return priv.sign(msg)

    def verify(self, msg: bytes, sig: bytes, pk: bytes) -> bool:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(pk)
        try:
            pub.verify(sig, msg)
            return True
        except InvalidSignature:
            return False


def get_signer(mode: SigMode) -> Signer:
    if mode == "classical":
        return Ed25519Signer()
    if mode == "pq":
        return MLDSA65()
    raise ValueError(f"unknown signer mode: {mode!r}")


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """hmac.compare_digest wrapper — use for every secret/MAC comparison (§11)."""
    return hmac.compare_digest(a, b)
