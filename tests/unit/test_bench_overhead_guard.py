"""Tests for the overhead-ablation fallback-backend guard (§8.3)."""

from __future__ import annotations

import pytest

from pqbio.bench import overhead


def test_guard_raises_in_this_environment() -> None:
    """This dev environment runs on the kyber-py/dilithium-py fallback (no liboqs), so
    the guard must refuse to proceed and name both backends in the message.
    """
    with pytest.raises(overhead.FallbackBackendActiveError) as exc_info:
        overhead.guard_against_fallback_backend()
    message = str(exc_info.value)
    assert "kyber-py-fallback" in message
    assert "dilithium-py-fallback" in message


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
