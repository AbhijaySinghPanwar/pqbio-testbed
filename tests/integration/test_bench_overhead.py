"""Integration tests for pqbio/bench/overhead.py: the fallback-backend guard, C0
running unconditionally, and the C1/C2/C3 code paths.

Owner: Abhijay

Bug fixed 2026-09-01 (PROJECT_SPEC.md §14): this file used to assert `KEM_BACKEND ==
"kyber-py-fallback"` as a hardcoded fact about "this environment" -- true when written
(no liboqs available anywhere to test this project on), false the moment liboqs started
working in Docker, so those tests failed there for a reason that had nothing to do with
the guard or the ablation being wrong. Every test below now branches on the *live*
`KEM_BACKEND`/`SIG_BACKEND` instead, so the same file is correct whichever backend the
process it runs in actually has active -- the fallback-active host venv or the
liboqs-active Docker image.
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

_LIVE_IS_FALLBACK = "fallback" in KEM_BACKEND or "fallback" in SIG_BACKEND


def test_guard_behaviour_matches_live_backends():
    if _LIVE_IS_FALLBACK:
        try:
            guard_against_fallback_backend()
            raised = False
        except FallbackBackendActiveError:
            raised = True
        assert raised
    else:
        guard_against_fallback_backend()  # must not raise


def test_c0_runs_unconditionally_and_produces_a_real_number():
    result = run_c0(n_iterations=5)
    assert result["config"] == "C0"
    assert result["crypto"] == "none"
    assert result["ai"] == "none"
    assert result["latency"]["n"] == 5
    assert result["latency"]["mean_ms"] > 0.0


def test_overhead_ablation_matches_live_backend_state():
    result = run_overhead_ablation(n_iterations=5)
    assert not is_blocked(result["C0"])
    assert result["C0"]["latency"]["mean_ms"] > 0.0

    if _LIVE_IS_FALLBACK:
        assert is_blocked(result["C1"])
        assert is_blocked(result["C2"])
        assert is_blocked(result["C3"])
        assert is_blocked(result["pq_overhead_ms"])
        assert is_blocked(result["ai_overhead_ms"])
        assert is_blocked(result["ai_to_pq_overhead_ratio"])
    else:
        # liboqs active: the guard lets C1/C2/C3 through for real -- this is the
        # actual §8.3 ablation, not a stand-in for it.
        assert not is_blocked(result["C1"])
        assert not is_blocked(result["C2"])
        assert not is_blocked(result["C3"])
        assert result["C1"]["latency"]["mean_ms"] > 0.0
        assert result["C2"]["latency"]["mean_ms"] > 0.0
        assert result["C3"]["latency"]["mean_ms"] > 0.0
        assert not is_blocked(result["pq_overhead_ms"])
        assert not is_blocked(result["ai_overhead_ms"])
        assert "absolute_ms" in result["pq_overhead_ms"]
        assert "absolute_ms" in result["ai_overhead_ms"]


def test_c1_c2_crypto_binding_paths_are_correct_when_guard_bypassed():
    """Verifies the C1/C2 code itself works -- correctness, not a claim about what the
    numbers mean while the fallback is active. Bypassing the guard here exercises this
    code path unconditionally, independent of which backend happens to be live in the
    process running this test.
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
