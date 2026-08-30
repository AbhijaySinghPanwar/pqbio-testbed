"""Tests for the device key registry (§5.1)."""

from __future__ import annotations

import pytest

from pqbio.pqc.keystore import DuplicateEnrolmentError, KeyStore, UnknownDeviceError


def test_enroll_and_get() -> None:
    store = KeyStore()
    record = store.enroll("device-1", sig_pk=b"pk-bytes", sig_mode="pq")
    assert record.device_id == "device-1"
    assert store.get("device-1") == record


def test_duplicate_enrolment_rejected() -> None:
    store = KeyStore()
    store.enroll("device-1", sig_pk=b"pk", sig_mode="pq")
    with pytest.raises(DuplicateEnrolmentError):
        store.enroll("device-1", sig_pk=b"pk2", sig_mode="pq")


def test_unknown_device_lookup_rejected() -> None:
    store = KeyStore()
    with pytest.raises(UnknownDeviceError):
        store.get("no-such-device")


def test_counter_advances() -> None:
    store = KeyStore()
    store.enroll("device-1", sig_pk=b"pk", sig_mode="pq")
    store.update_counter("device-1", 1)
    store.update_counter("device-1", 2)
    assert store.get("device-1").counter == 2


def test_counter_regression_rejected() -> None:
    """This is what binding check B4 relies on: a replayed/rolled-back device counter
    must never be accepted once a higher counter has been seen.
    """
    store = KeyStore()
    store.enroll("device-1", sig_pk=b"pk", sig_mode="pq")
    store.update_counter("device-1", 5)
    with pytest.raises(ValueError):
        store.update_counter("device-1", 5)  # replay of the same counter
    with pytest.raises(ValueError):
        store.update_counter("device-1", 3)  # rollback


def test_counter_update_for_unknown_device_rejected() -> None:
    store = KeyStore()
    with pytest.raises(UnknownDeviceError):
        store.update_counter("ghost-device", 1)
