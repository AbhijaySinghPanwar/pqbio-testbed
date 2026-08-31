"""Integration tests for pqbio/bench/overhead.py: the fallback-backend guard, C0
running unconditionally, and C1/C2's crypto+binding code paths (verified correct with
the guard bypassed -- this environment's own KEM_BACKEND/SIG_BACKEND are the
pure-Python fallback, so the guard is expected to fire for real in every other test
here; that is the environment's actual state, not a test artefact).
"""

from __future__ import annotations

from unittest import mock

from pqbio.bench._common import is_blocked
from pqbio.bench.overhead import (
    FallbackBackendActiveError,
    guard_against_fallback_backend,
    run_c0,
    run_crypto_binding_config,
    run_overhead_ablation,
)
from pqbio.pqc.kem import KEM_BACKEND
from pqbio.pqc.sign import SIG_BACKEND


def test_guard_raises_when_fallback_backend_is_active():
    # This environment genuinely runs the pure-Python fallback (no liboqs C toolchain
    # available) -- confirms the guard's real, current behaviour, not a mocked one.
    assert KEM_BACKEND == "kyber-py-fallback"
    assert SIG_BACKEND == "dilithium-py-fallback"
    try:
        guard_against_fallback_backend()
        raised = False
    except FallbackBackendActiveError:
        raised = True
    assert raised


def test_c0_runs_unconditionally_and_produces_a_real_number():
    result = run_c0(n_iterations=5)
    assert result["config"] == "C0"
    assert result["crypto"] == "none"
    assert result["ai"] == "none"
    assert result["latency"]["n"] == 5
    assert result["latency"]["mean_ms"] > 0.0


def test_overhead_ablation_marks_c1_c2_c3_blocked_and_c0_real():
    result = run_overhead_ablation(n_iterations=5)
    assert not is_blocked(result["C0"])
    assert result["C0"]["latency"]["mean_ms"] > 0.0
    assert is_blocked(result["C1"])
    assert is_blocked(result["C2"])
    assert is_blocked(result["C3"])
    assert is_blocked(result["pq_overhead_ms"])
    assert is_blocked(result["ai_overhead_ms"])
    assert is_blocked(result["ai_to_pq_overhead_ratio"])


def test_c1_c2_crypto_binding_paths_are_correct_when_guard_bypassed():
    """Verifies the C1/C2 code itself works -- correctness, not a claim about what the
    numbers mean; the module docstring is explicit that C1/C2/C3 must never be trusted
    while the fallback is active. Bypassing the guard here is the only way to exercise
    this code before liboqs is ever installed anywhere.
    """
    with mock.patch("pqbio.bench.overhead.guard_against_fallback_backend", lambda: None):
        c1 = run_crypto_binding_config("C1", "classical", n_iterations=3)
        c2 = run_crypto_binding_config("C2", "pq", n_iterations=3)
    assert c1["config"] == "C1"
    assert c1["crypto"] == "X25519 + Ed25519"
    assert c1["latency"]["n"] == 3
    assert c1["latency"]["mean_ms"] > 0.0
    assert c2["config"] == "C2"
    assert c2["crypto"] == "ML-KEM-768 + ML-DSA-65"
    assert c2["latency"]["mean_ms"] > 0.0
