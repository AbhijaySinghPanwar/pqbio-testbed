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


# FIPS 204 ML-DSA-65 artefact sizes — fixed, not derived, so they're available for
# input-length validation before either backend ever sees a byte (see MLDSA65.sign
# below — the same reasoning as pqbio.pqc.kem.MLKEM768's constants).
ML_DSA_65_SK_LEN = 4032


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
        # Load-bearing, not defensive over-caution -- see pqbio.pqc.kem.MLKEM768's
        # docstring for the full explanation (discovered the same way: liboqs's
        # ctypes buffers silently zero-pad a too-short secret key instead of raising,
        # verified empirically with a 10-byte garbage key producing a "valid"-shaped
        # signature under liboqs where the kyber-py-family fallback raises).
        if len(sk) != ML_DSA_65_SK_LEN:
            raise ValueError(
                f"ML-DSA-65 secret key must be {ML_DSA_65_SK_LEN} bytes, got {len(sk)}"
            )
        if _OQS_AVAILABLE:
            with oqs.Signature(ML_DSA_65_ALG, secret_key=sk) as signer:
                return cast(bytes, signer.sign(msg))
        return cast(bytes, _ML_DSA_65.sign(sk, msg))

    def verify(self, msg: bytes, sig: bytes, pk: bytes) -> bool:
        # No length guard needed here (unlike sign() above): a wrong-length signature
        # must return False, not raise -- and both backends already agree on that
        # (verified: test_signer_verify_rejects_wrong_length_signature passes under
        # both kyber-py-family fallback and liboqs unchanged).
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


# ----------------------------------------------------------------------------------
# ML-DSA-65 KAT support (NOT part of the frozen Signer Protocol above).
#
# NIST ACVP's keyGen vectors supply a raw seed for the internal deterministic keygen
# rather than the public random-seeded keygen(); its sigGen vectors (the ones vendored
# here) are deterministic/non-hedged mode, which the production `sign()` deliberately
# does not use (hedged signing is the safer default against fault attacks). These are
# test-only helpers used by tests/unit/test_pqc_kat.py — never call them outside a KAT
# context.
# ----------------------------------------------------------------------------------


def ml_dsa_65_keygen_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """Deterministic keygen from the raw 32-byte seed. KAT support only.

    Unlike ML-KEM's `generate_keypair_seed`, liboqs-python's `Signature` class has no
    per-call seed parameter, so this uses `_oqs_kat.oqs_fixed_randomness` to fix the
    *global* RNG liboqs draws from during `generate_keypair()` — verified against the
    real ACVP vectors: fixing the draw to `seed` reproduces the exact expected `pk`/`sk`
    for every vendored test case.
    """
    if _OQS_AVAILABLE:
        from pqbio.pqc._oqs_kat import oqs_fixed_randomness

        with oqs_fixed_randomness(seed), oqs.Signature(ML_DSA_65_ALG) as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
        return cast(bytes, pk), cast(bytes, sk)
    return cast(tuple[bytes, bytes], _ML_DSA_65.key_derive(seed))


def ml_dsa_65_sign_deterministic(sk: bytes, msg: bytes, ctx: bytes = b"") -> bytes:
    """Deterministic (non-hedged) signing with an explicit context string, matching
    ACVP's sigGen vector format. KAT support only — production code uses `sign()`
    (hedged/randomized) via the `Signer` Protocol instead.

    "Deterministic" ML-DSA signing is FIPS 204's normal hedged signing with the
    internal 32-byte `rnd` draw fixed to all-zero, not a separate algorithm — verified
    empirically against the real ACVP vectors before relying on it here: fixing
    liboqs's RNG to 32 zero bytes during `sign_with_ctx_str` reproduces the exact
    expected signature for every vendored test case.
    """
    if _OQS_AVAILABLE:
        from pqbio.pqc._oqs_kat import oqs_fixed_randomness

        with oqs_fixed_randomness(b"\x00" * 32), oqs.Signature(ML_DSA_65_ALG, secret_key=sk) as sig:
            return cast(bytes, sig.sign_with_ctx_str(msg, ctx))
    return cast(bytes, _ML_DSA_65.sign(sk, msg, ctx=ctx, deterministic=True))


def ml_dsa_65_verify_with_context(pk: bytes, msg: bytes, sig: bytes, ctx: bytes = b"") -> bool:
    """Verify with an explicit context string. KAT support only: the frozen
    `Signer.verify(msg, sig, pk)` has no `ctx` parameter (it always verifies against
    ctx=b""), so it cannot check ACVP sigGen vectors signed with a non-empty context —
    that's a property of the frozen interface, not a bug in it (PROJECT_SPEC.md's
    Signer Protocol is defined without a context argument). Production verification
    always uses ctx=b"" via `MLDSA65().verify()`.

    Verification draws no randomness, so — unlike the two KAT functions above — this
    needs no RNG override at all; liboqs-python's `verify_with_ctx_str` takes the
    context directly.
    """
    if _OQS_AVAILABLE:
        with oqs.Signature(ML_DSA_65_ALG) as sig_obj:
            return bool(sig_obj.verify_with_ctx_str(msg, sig, ctx, pk))
    return bool(_ML_DSA_65.verify(pk, msg, sig, ctx=ctx))
