"""Four-configuration crypto/AI overhead ablation (PROJECT_SPEC.md §8.3).

Owner: Abhijay
Status: **stub** — only the fallback-backend guard below is implemented. The actual
C0/C1/C2/C3 workload (Module F, §5.6) has not been built yet; that lands with the rest
of the benchmark harness. Do not add it here without checking in first — this file's
job right now is narrowly to make the ablation impossible to run on invalid numbers.

Why the guard exists: `results/pqc_micro.json` shows ML-DSA-65 `sign` at ~52ms mean
under the kyber-py/dilithium-py fallback — that is rejection-sampling overhead specific
to a pure-Python implementation, not a property of ML-DSA-65 itself. liboqs is expected
to be roughly two orders of magnitude faster. Running C1/C2/C3 on the fallback would
misattribute that cost to "PQ overhead" and make §8.3's PQ-vs-AI cost split backwards in
magnitude, not just imprecise — so this must fail closed rather than produce a number.
"""

from __future__ import annotations

import sys

from pqbio.pqc.kem import KEM_BACKEND
from pqbio.pqc.sign import SIG_BACKEND

_FALLBACK_KEM_BACKENDS = {"kyber-py-fallback"}
_FALLBACK_SIG_BACKENDS = {"dilithium-py-fallback"}


class FallbackBackendActiveError(RuntimeError):
    """Raised when the overhead ablation (C1/C2/C3) is attempted while a pure-Python
    fallback PQC backend is active instead of liboqs.
    """


def guard_against_fallback_backend() -> None:
    """Refuse to proceed if either PQC backend is a pure-Python fallback. Call this
    before running configs C1 (classical), C2 (PQ only), or C3 (PQ + AI) — C0 (no
    crypto, no AI) is unaffected and does not need this guard.
    """
    kem_is_fallback = KEM_BACKEND in _FALLBACK_KEM_BACKENDS
    sig_is_fallback = SIG_BACKEND in _FALLBACK_SIG_BACKENDS
    if kem_is_fallback or sig_is_fallback:
        raise FallbackBackendActiveError(
            f"Refusing to run the overhead ablation (C1/C2/C3): KEM_BACKEND={KEM_BACKEND!r}, "
            f"SIG_BACKEND={SIG_BACKEND!r} — a pure-Python fallback is active for at least one "
            "primitive. The C2-C1 'marginal PQ cost' figure would be dominated by "
            "rejection-sampling overhead specific to that fallback, not by ML-KEM-768/"
            "ML-DSA-65 themselves (liboqs is expected to be roughly two orders of magnitude "
            "faster for ML-DSA signing — see results/pqc_micro.json). Install a C toolchain "
            '(CMake, Ninja, a C compiler) and run `pip install -e ".[pqc-liboqs]"` so both '
            "backends report 'liboqs', then re-run."
        )


def main() -> None:
    guard_against_fallback_backend()
    print(
        "Backend check passed: KEM_BACKEND and SIG_BACKEND both report liboqs. The "
        "C0-C3 ablation itself is not implemented yet (Module F, PROJECT_SPEC.md §5.6/§8.3).",
        file=sys.stderr,
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
