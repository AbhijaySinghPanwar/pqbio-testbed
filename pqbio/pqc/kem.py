"""ML-KEM-768 key encapsulation (FIPS 203), plus a classical (X25519) baseline
(PROJECT_SPEC.md §5.1). The classical mode exists solely to measure PQ overhead in
§8.3 — it is a requirement, not an extra.

**Backend note / spec amendment.** §4 names `liboqs-python` as the primary PQC backend,
with `kyber-py`/`dilithium-py` as a documented fallback. Building liboqs requires
CMake, Ninja, and a C compiler; this development environment has neither a usable MSVC
C++ workload nor mingw-w64 on PATH (verified: `cmake`/`ninja` absent, `cl.exe` absent,
only a 32-bit MinGW.org gcc 6.3 from 2016 present), so `import oqs` fails. This module
falls back to `kyber_py.ml_kem.ML_KEM_768` as the *live* backend, never silently to a
mock or a different algorithm. `KEM_BACKEND` records which backend is active at import
time; every call site that persists results (bench JSON, audit log) should record it too.

Verified before relying on this fallback: `kyber_py.ml_kem.ML_KEM_768` produces
artefacts of exactly the FIPS 203 ML-KEM-768 sizes (pk 1184B, sk 2400B, ct 1088B,
ss 32B) and round-trips correctly.

**Known gap, flagged rather than hidden:** the fallback has not been cross-checked
against liboqs' own KAT vectors (that requires the liboqs C source, also unavailable
here) and it is not constant-time — it exists for algorithmic/API correctness, not
timing-side-channel resistance. Recommended follow-up before any deployment or
timing-sensitive benchmark is treated as production-representative: install a C++
toolchain (Visual Studio Build Tools "Desktop development with C++" workload, or
mingw-w64) and `pip install liboqs-python`, then re-run with `KEM_BACKEND == "liboqs"`.
"""

from __future__ import annotations

import warnings
from typing import Literal, Protocol, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

KemMode = Literal["classical", "pq"]

try:
    import oqs

    _OQS_AVAILABLE = True
except ImportError:
    _OQS_AVAILABLE = False

if _OQS_AVAILABLE:
    KEM_BACKEND: Literal["liboqs", "kyber-py-fallback"] = "liboqs"
else:
    from kyber_py.ml_kem import ML_KEM_768 as _ML_KEM_768

    KEM_BACKEND = "kyber-py-fallback"
    warnings.warn(
        "liboqs (oqs) is not importable in this environment; falling back to the "
        "pure-Python kyber-py ML-KEM-768 reference implementation. See the "
        "pqbio.pqc.kem module docstring for the documented spec amendment.",
        RuntimeWarning,
        stacklevel=2,
    )

ML_KEM_768_ALG = "ML-KEM-768"

# FIPS 203 ML-KEM-768 artefact sizes — fixed, not derived, so they're available for
# input-length validation before either backend ever sees a byte (see MLKEM768 below).
ML_KEM_768_PK_LEN = 1184
ML_KEM_768_SK_LEN = 2400
ML_KEM_768_CT_LEN = 1088


class KEM(Protocol):
    def keygen(self) -> tuple[bytes, bytes]: ...  # (pk, sk)
    def encapsulate(self, pk: bytes) -> tuple[bytes, bytes]: ...  # (ct, ss)
    def decapsulate(self, ct: bytes, sk: bytes) -> bytes: ...  # ss


class MLKEM768:
    """ML-KEM-768 (FIPS 203). pk 1184B, sk 2400B, ct 1088B, ss 32B.

    **Explicit input-length checks below are load-bearing, not defensive
    over-caution.** Discovered cross-checking the two backends (PROJECT_SPEC.md §14):
    `kyber-py`'s fallback happens to raise on malformed-length input as a side effect
    of its own array-slicing internals, so `test_kem_encapsulate_rejects_malformed_
    public_key`/`test_kem_decapsulate_rejects_wrong_length_ciphertext` passed under the
    fallback purely by accident, never by a real contract this class provided. Under
    liboqs, `oqs.KeyEncapsulation.encap_secret`/`decap_secret` build their C buffers via
    `ctypes.create_string_buffer(data, expected_length)`, which *silently zero-pads or
    truncates* mismatched input instead of raising — verified empirically: a 10-byte
    garbage "public key" encapsulates without error under liboqs. CLAUDE.md's "fail
    closed" convention (§11) is a project-wide invariant, not something that should
    depend on which PQC backend happens to be active, so it is enforced explicitly
    here instead.
    """

    backend = KEM_BACKEND

    def keygen(self) -> tuple[bytes, bytes]:
        if _OQS_AVAILABLE:
            with oqs.KeyEncapsulation(ML_KEM_768_ALG) as kem:
                pk = kem.generate_keypair()
                sk = kem.export_secret_key()
            return pk, sk
        return cast(tuple[bytes, bytes], _ML_KEM_768.keygen())

    def encapsulate(self, pk: bytes) -> tuple[bytes, bytes]:
        if len(pk) != ML_KEM_768_PK_LEN:
            raise ValueError(
                f"ML-KEM-768 public key must be {ML_KEM_768_PK_LEN} bytes, got {len(pk)}"
            )
        if _OQS_AVAILABLE:
            with oqs.KeyEncapsulation(ML_KEM_768_ALG) as kem:
                ct, ss = kem.encap_secret(pk)
            return ct, ss
        ss, ct = _ML_KEM_768.encaps(pk)
        return ct, ss

    def decapsulate(self, ct: bytes, sk: bytes) -> bytes:
        if len(ct) != ML_KEM_768_CT_LEN:
            raise ValueError(
                f"ML-KEM-768 ciphertext must be {ML_KEM_768_CT_LEN} bytes, got {len(ct)}"
            )
        if len(sk) != ML_KEM_768_SK_LEN:
            raise ValueError(
                f"ML-KEM-768 secret key must be {ML_KEM_768_SK_LEN} bytes, got {len(sk)}"
            )
        if _OQS_AVAILABLE:
            with oqs.KeyEncapsulation(ML_KEM_768_ALG, secret_key=sk) as kem:
                return cast(bytes, kem.decap_secret(ct))
        return cast(bytes, _ML_KEM_768.decaps(sk, ct))


class X25519KEM:
    """Classical baseline: X25519 ECDH wrapped as a KEM (ephemeral-key encapsulation).
    Used for the C1 overhead-ablation config (§8.3).
    """

    backend = "x25519"

    @staticmethod
    def _priv_bytes(sk: x25519.X25519PrivateKey) -> bytes:
        return sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def _pub_bytes(pk: x25519.X25519PublicKey) -> bytes:
        return pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def keygen(self) -> tuple[bytes, bytes]:
        sk = x25519.X25519PrivateKey.generate()
        return self._pub_bytes(sk.public_key()), self._priv_bytes(sk)

    def encapsulate(self, pk: bytes) -> tuple[bytes, bytes]:
        peer_pk = x25519.X25519PublicKey.from_public_bytes(pk)
        eph_sk = x25519.X25519PrivateKey.generate()
        ss = eph_sk.exchange(peer_pk)
        ct = self._pub_bytes(eph_sk.public_key())
        return ct, ss

    def decapsulate(self, ct: bytes, sk: bytes) -> bytes:
        priv = x25519.X25519PrivateKey.from_private_bytes(sk)
        eph_pk = x25519.X25519PublicKey.from_public_bytes(ct)
        return priv.exchange(eph_pk)


def get_kem(mode: KemMode) -> KEM:
    if mode == "classical":
        return X25519KEM()
    if mode == "pq":
        return MLKEM768()
    raise ValueError(f"unknown KEM mode: {mode!r}")


# ----------------------------------------------------------------------------------
# ML-KEM-768 KAT support (NOT part of the frozen KEM Protocol above).
#
# NIST ACVP's keyGen/encapsulation vectors supply the raw internal randomness (the
# (d, z) seed pair for keygen; the message m for encapsulation) rather than a PRNG
# seed for the public keygen()/encapsulate() entry points, so verifying them requires
# calling each backend's *internal* deterministic primitive. These are test-only
# helpers used by tests/unit/test_pqc_kat.py — never call them outside a KAT context.
# ----------------------------------------------------------------------------------


def ml_kem_768_keygen_from_seed(d: bytes, z: bytes) -> tuple[bytes, bytes]:
    """Deterministic keygen from the raw (d, z) seed pair. KAT support only.

    liboqs-python's `generate_keypair_seed(seed)` is a genuine per-call seed parameter
    (unlike encapsulation/signing below, which need the global-RNG-override hook in
    `_oqs_kat.py`) — verified against the real ACVP vectors: `seed = d || z` reproduces
    the exact expected `ek`/`dk` for every vendored test case.
    """
    if _OQS_AVAILABLE:
        with oqs.KeyEncapsulation(ML_KEM_768_ALG) as kem:
            ek = kem.generate_keypair_seed(d + z)
            dk = kem.export_secret_key()
        return cast(bytes, ek), cast(bytes, dk)
    return cast(tuple[bytes, bytes], _ML_KEM_768.key_derive(d + z))


def ml_kem_768_encapsulate_with_randomness(ek: bytes, m: bytes) -> tuple[bytes, bytes]:
    """Deterministic encapsulation from explicit randomness `m`. Returns (ct, ss).
    KAT support only.

    liboqs-python's `encap_secret` has no explicit-randomness parameter, so this uses
    `_oqs_kat.oqs_fixed_randomness` to fix the *global* RNG liboqs draws `m` from —
    verified against the real ACVP vectors: fixing the draw to `m` reproduces the exact
    expected `ct`/`ss` for the vendored test case.
    """
    if _OQS_AVAILABLE:
        from pqbio.pqc._oqs_kat import oqs_fixed_randomness

        with oqs_fixed_randomness(m), oqs.KeyEncapsulation(ML_KEM_768_ALG) as kem:
            return cast(tuple[bytes, bytes], kem.encap_secret(ek))
    # Private by convention (leading underscore), not by enforcement: this is the
    # library's own internal-randomness entry point, which is exactly what a KAT needs.
    k, c = cast(tuple[bytes, bytes], _ML_KEM_768._encaps_internal(ek, m))
    return c, k
