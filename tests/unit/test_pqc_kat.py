"""Known-answer tests for the active PQC backend (Module A DoD item 1).

**Spec amendment, raised explicitly rather than silently resolved.** PROJECT_SPEC.md
§5.1 DoD asks for "known-answer tests pass for ML-KEM-768 and ML-DSA-65." The obvious
sources for those — NIST's own FIPS 203/204 test vectors, or liboqs' own KATs — both
require artefacts this environment does not have: liboqs' KATs live in the liboqs C
source tree (liboqs itself is unbuildable here — see pqbio/pqc/kem.py), and the
official NIST ACVP JSON vectors were not fetched into this repo. What this file
provides instead is an honest substitute with a different
guarantee: a *self-KAT*, pinning the SHA-256 digest of deterministic-seed output from
the currently active fallback backend (kyber-py / dilithium-py). It catches regressions
in this backend or its pinned dependency version; it does NOT establish that the
backend agrees with any other FIPS 203/204 implementation. Recommended follow-up:
install a C toolchain, switch to `liboqs` (`pip install -e ".[pqc-liboqs]"`), and either
run liboqs' own KAT suite or fetch the NIST ACVP vectors and replace this file.

If liboqs *is* the active backend (a future environment), these fixed-hash assertions
will legitimately fail, because liboqs and kyber-py/dilithium-py are different
implementations and are not required to be bit-for-bit identical for randomized
components (they are for the deterministic key_derive/deterministic-sign paths tested
here, since both must implement the same FIPS spec algorithm deterministically given
the same seed — but this file only pins the fallback's own output, not liboqs').
"""

from __future__ import annotations

import hashlib

import pytest

from pqbio.pqc.kem import KEM_BACKEND
from pqbio.pqc.sign import SIG_BACKEND

pytestmark = pytest.mark.skipif(
    KEM_BACKEND != "kyber-py-fallback" or SIG_BACKEND != "dilithium-py-fallback",
    reason="self-KAT pins are specific to the kyber-py/dilithium-py fallback backend",
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_ml_kem_768_deterministic_keygen_self_kat() -> None:
    from kyber_py.ml_kem import ML_KEM_768

    seed = bytes(range(64))  # ML-KEM key_derive takes a 64-byte seed (d ‖ z)
    ek, dk = ML_KEM_768.key_derive(seed)

    assert len(ek) == 1184
    assert len(dk) == 2400
    assert sha256_hex(ek) == "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9"
    assert sha256_hex(dk) == "dac268bde6a8dd238e9887117d6b664e7a7a9350ad6b7c08a948e504809572a5"


def test_ml_dsa_65_deterministic_sign_self_kat() -> None:
    from dilithium_py.ml_dsa import ML_DSA_65

    seed = bytes(range(32))
    pk, sk = ML_DSA_65.key_derive(seed)
    assert len(pk) == 1952
    assert len(sk) == 4032
    assert sha256_hex(pk) == "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9"
    assert sha256_hex(sk) == "9f1e24f47795fe50040384e3d6183988047170fa2d866406b70fe0a3f8216063"

    msg = b"pq-bio-auth KAT fixture message"
    sig = ML_DSA_65.sign(sk, msg, deterministic=True)
    assert len(sig) == 3309
    assert sha256_hex(sig) == "e4e42fca374f55c1c5a22e99175af72eb7685236153049d50548bd2297fb6dce"
    assert ML_DSA_65.verify(pk, msg, sig) is True
