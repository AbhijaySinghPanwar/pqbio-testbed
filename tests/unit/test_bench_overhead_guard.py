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
