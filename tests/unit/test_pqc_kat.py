"""Known-answer tests for ML-KEM-768 and ML-DSA-65 (Module A DoD item 1), verified
against real NIST ACVP vectors — see tests/vectors/README.md for provenance, exact
source URLs, and SHA-256 of both the original upstream files and what's vendored here.

This replaces an earlier "self-KAT" that only pinned the active backend's own
deterministic output: that proves output stability, not correctness — a bug in
kyber-py/dilithium-py would have locked itself in and reported green forever. These
tests instead check the active backend against an independent authority.

Goes through pqbio.pqc.kem / pqbio.pqc.sign's public KAT-support functions
(`ml_kem_768_keygen_from_seed`, `ml_kem_768_encapsulate_with_randomness`,
`ml_dsa_65_keygen_from_seed`, `ml_dsa_65_sign_deterministic`,
`ml_dsa_65_verify_with_context`) rather than importing kyber-py/dilithium-py directly,
so this file is NOT coupled to the fallback backend: decapsulation, and verification of
the one empty-context vector, go through the frozen `MLKEM768`/`MLDSA65` classes
unchanged, and the KAT-support functions already dispatch on which backend is active.
When liboqs becomes available, `KEM_BACKEND`/`SIG_BACKEND` flip to `"liboqs"` and this
file runs against it with zero edits — *except* that the KAT-support functions currently
raise `NotImplementedError` on the liboqs path (see their docstrings in kem.py/sign.py):
liboqs's own KAT mechanism reseeds its global DRBG rather than taking a per-call seed,
which is a different-enough mechanism that it needs its own implementation, never
exercised here because liboqs was unavailable in this environment. That
`NotImplementedError` is the fail-closed signal that the liboqs hook still needs
writing — not a silent skip.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pqbio.pqc.kem import (
    MLKEM768,
    ml_kem_768_encapsulate_with_randomness,
    ml_kem_768_keygen_from_seed,
)
from pqbio.pqc.sign import (
    MLDSA65,
    ml_dsa_65_keygen_from_seed,
    ml_dsa_65_sign_deterministic,
    ml_dsa_65_verify_with_context,
)

VECTORS_DIR = Path(__file__).resolve().parent.parent / "vectors"


def _load(name: str) -> dict[str, Any]:
    with (VECTORS_DIR / name).open(encoding="utf-8") as f:
        return json.load(f)


def _h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


# --------------------------------------------------------------------------------------
# ML-KEM-768 keyGen
# --------------------------------------------------------------------------------------


def test_ml_kem_768_keygen_acvp_vectors() -> None:
    vectors = _load("ML-KEM-768-keyGen.json")
    assert vectors["parameterSet"] == "ML-KEM-768"
    cases = vectors["tests"]
    assert len(cases) == 25

    for case in cases:
        ek, dk = ml_kem_768_keygen_from_seed(_h(case["d"]), _h(case["z"]))
        assert ek == _h(case["ek"]), f"tcId {case['tcId']}: ek mismatch"
        assert dk == _h(case["dk"]), f"tcId {case['tcId']}: dk mismatch"


# --------------------------------------------------------------------------------------
# ML-KEM-768 encapsulation / decapsulation
# --------------------------------------------------------------------------------------


def test_ml_kem_768_encapsulation_acvp_vectors() -> None:
    vectors = _load("ML-KEM-768-encapDecap.json")
    assert vectors["parameterSet"] == "ML-KEM-768"
    cases = vectors["encapsulation"]["tests"]
    assert len(cases) == 25

    for case in cases:
        ct, ss = ml_kem_768_encapsulate_with_randomness(_h(case["ek"]), _h(case["m"]))
        assert ct == _h(case["c"]), f"tcId {case['tcId']}: ciphertext mismatch"
        assert ss == _h(case["k"]), f"tcId {case['tcId']}: shared secret mismatch"


def test_ml_kem_768_decapsulation_acvp_vectors() -> None:
    """Goes through the frozen MLKEM768().decapsulate() unchanged — decapsulation is
    already deterministic given (dk, c), no internal-randomness hook needed, so this
    part of the KAT already exercises exactly the production code path.
    """
    vectors = _load("ML-KEM-768-encapDecap.json")
    cases = vectors["decapsulation"]["tests"]
    assert len(cases) == 10

    kem = MLKEM768()
    for case in cases:
        ss = kem.decapsulate(_h(case["c"]), _h(case["dk"]))
        assert ss == _h(case["k"]), f"tcId {case['tcId']}: shared secret mismatch"


# --------------------------------------------------------------------------------------
# ML-DSA-65 keyGen
# --------------------------------------------------------------------------------------


def test_ml_dsa_65_keygen_acvp_vectors() -> None:
    vectors = _load("ML-DSA-65-keyGen.json")
    assert vectors["parameterSet"] == "ML-DSA-65"
    cases = vectors["tests"]
    assert len(cases) == 25

    for case in cases:
        pk, sk = ml_dsa_65_keygen_from_seed(_h(case["seed"]))
        assert pk == _h(case["pk"]), f"tcId {case['tcId']}: pk mismatch"
        assert sk == _h(case["sk"]), f"tcId {case['tcId']}: sk mismatch"


# --------------------------------------------------------------------------------------
# ML-DSA-65 sigGen (deterministic/external/pure variant) + verify
# --------------------------------------------------------------------------------------


def test_ml_dsa_65_siggen_acvp_vectors() -> None:
    vectors = _load("ML-DSA-65-sigGen.json")
    assert vectors["parameterSet"] == "ML-DSA-65"
    assert vectors["deterministic"] is True
    cases = vectors["tests"]
    assert len(cases) == 15

    for case in cases:
        sig = ml_dsa_65_sign_deterministic(
            _h(case["sk"]), _h(case["message"]), ctx=_h(case["context"])
        )
        assert sig == _h(case["signature"]), f"tcId {case['tcId']}: signature mismatch"


def test_ml_dsa_65_verify_accepts_acvp_signatures() -> None:
    """Most sigGen vectors carry a non-empty `context`, which the frozen
    `Signer.verify(msg, sig, pk)` has no parameter for (PROJECT_SPEC.md's Signer
    Protocol doesn't take one — it always verifies against ctx=b""), so this uses the
    context-aware KAT helper rather than the frozen interface. See
    test_ml_dsa_65_frozen_verify_accepts_empty_context_acvp_signature below for the one
    vector where the frozen interface's ctx=b"" default is directly checkable.
    """
    vectors = _load("ML-DSA-65-sigGen.json")
    cases = vectors["tests"]

    for case in cases:
        ok = ml_dsa_65_verify_with_context(
            _h(case["pk"]), _h(case["message"]), _h(case["signature"]), ctx=_h(case["context"])
        )
        assert ok is True, f"tcId {case['tcId']}: verify rejected a valid ACVP signature"


def test_ml_dsa_65_frozen_verify_accepts_empty_context_acvp_signature() -> None:
    """The one sigGen vector with an empty context (tcId 44) is exactly what the frozen
    `MLDSA65().verify(msg, sig, pk)` interface can check directly, with zero KAT-support
    scaffolding — confirms its ctx=b"" default agrees with the vector's ctx=b"" case.
    """
    vectors = _load("ML-DSA-65-sigGen.json")
    case = next(c for c in vectors["tests"] if c["context"] == "")

    signer = MLDSA65()
    ok = signer.verify(_h(case["message"]), _h(case["signature"]), _h(case["pk"]))
    assert ok is True, f"tcId {case['tcId']}: frozen verify() rejected a valid ACVP signature"
