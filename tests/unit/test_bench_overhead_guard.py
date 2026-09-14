"""Tests for the overhead-ablation fallback-backend guard (§8.3)."""

from __future__ import annotations

import pytest

from pqbio.bench import overhead


def test_guard_behaviour_matches_this_environments_live_backends() -> None:
    """Bug fixed 2026-09-01 (PROJECT_SPEC.md §14): this test used to hardcode "this dev
    environment runs on the kyber-py/dilithium-py fallback" as a fact — true when
    written (no liboqs available anywhere), false the moment liboqs started working in
    Docker, so it failed there for a reason that had nothing to do with the guard being
    wrong. `test_guard_passes_when_both_backends_report_liboqs` and the two
    `..._only_..._is_fallback` tests below already cover the guard's actual logic with
    `monkeypatch`, backend-independently; this test's only remaining job is to confirm
    the live `KEM_BACKEND`/`SIG_BACKEND` and the guard's live behaviour agree with each
    other, whatever they currently are — true on the fallback, true on liboqs, true on
    any future backend.
    """
    live_is_fallback = "fallback" in overhead.KEM_BACKEND or "fallback" in overhead.SIG_BACKEND
    if live_is_fallback:
        with pytest.raises(overhead.FallbackBackendActiveError) as exc_info:
            overhead.guard_against_fallback_backend()
        message = str(exc_info.value)
        assert overhead.KEM_BACKEND in message
        assert overhead.SIG_BACKEND in message
    else:
        overhead.guard_against_fallback_backend()  # must not raise


def test_guard_passes_when_both_backends_report_liboqs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(overhead, "KEM_BACKEND", "liboqs")
    monkeypatch.setattr(overhead, "SIG_BACKEND", "liboqs")
    overhead.guard_against_fallback_backend()  # must not raise


def test_guard_raises_when_only_kem_backend_is_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(overhead, "KEM_BACKEND", "kyber-py-fallback")
    monkeypatch.setattr(overhead, "SIG_BACKEND", "liboqs")
    with pytest.raises(overhead.FallbackBackendActiveError):
        overhead.guard_against_fallback_backend()


def test_guard_raises_when_only_sig_backend_is_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(overhead, "KEM_BACKEND", "liboqs")
    monkeypatch.setattr(overhead, "SIG_BACKEND", "dilithium-py-fallback")
    with pytest.raises(overhead.FallbackBackendActiveError):
        overhead.guard_against_fallback_backend()


class TestOverheadIntervals:
    """The PQ term is a sub-millisecond difference of two ~10 ms latencies. Across three
    committed bench runs it came out 0.88, 0.34 and -4.30 ms, sending the AI:PQ ratio from
    798x to 2327x to -191x. These tests pin the behaviour that stops the report publishing
    a ratio whose denominator is noise.
    """

    def test_identical_distributions_are_not_resolvable(self) -> None:
        from pqbio.bench.overhead import _difference_of_means

        rng = __import__("numpy").random.default_rng(2026)
        a = list(rng.normal(12.0, 4.0, 50))
        b = list(rng.normal(12.0, 4.0, 50))
        cell = _difference_of_means(a, b)
        low, high = cell["ci95_ms"]
        assert low < 0 < high
        assert cell["resolvable_from_noise"] is False

    def test_a_large_separation_is_resolvable(self) -> None:
        from pqbio.bench.overhead import _difference_of_means

        rng = __import__("numpy").random.default_rng(2026)
        c3 = list(rng.normal(830.0, 60.0, 50))
        c2 = list(rng.normal(11.0, 4.0, 50))
        cell = _difference_of_means(c3, c2)
        assert cell["resolvable_from_noise"] is True
        assert cell["ci95_ms"][0] > 700

    def test_interval_is_centred_on_the_mean_difference(self) -> None:
        from pqbio.bench.overhead import _difference_of_means

        cell = _difference_of_means([10.0, 12.0, 14.0], [1.0, 2.0, 3.0])
        assert cell["absolute_ms"] == 10.0
        low, high = cell["ci95_ms"]
        assert abs((low + high) / 2 - 10.0) < 1e-9
