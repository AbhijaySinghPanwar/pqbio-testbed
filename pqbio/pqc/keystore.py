"""Device key registry and enrolment (PROJECT_SPEC.md §5.1).

In-memory and thread-safe for Module A's purposes (signature verification needs
somewhere to look up an enrolled device's public key). Module E's `server/store.py`
will back this with SQLite persistence once the server module is built; this
class's method signatures are the contract that backing store will need to satisfy.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass


class UnknownDeviceError(KeyError):
    """Raised when a lookup is attempted for a device_id that was never enrolled."""


class DuplicateEnrolmentError(ValueError):
    """Raised when a device_id is enrolled twice without an explicit re-enrol."""


@dataclass(frozen=True)
class DeviceRecord:
    device_id: str
    sig_pk: bytes  # device's Signer public key (classical | pq)
    sig_mode: str  # which Signer mode produced sig_pk — see pqbio.pqc.sign.SigMode
    counter: int = 0  # last-seen monotonic device counter, enforced by binding check B4


class KeyStore:
    """Thread-safe in-memory device key registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._devices: dict[str, DeviceRecord] = {}

    def enroll(self, device_id: str, sig_pk: bytes, sig_mode: str) -> DeviceRecord:
        with self._lock:
            if device_id in self._devices:
                raise DuplicateEnrolmentError(f"device already enrolled: {device_id}")
            record = DeviceRecord(device_id=device_id, sig_pk=sig_pk, sig_mode=sig_mode)
            self._devices[device_id] = record
            return record

    def get(self, device_id: str) -> DeviceRecord:
        with self._lock:
            try:
                return self._devices[device_id]
            except KeyError as exc:
                raise UnknownDeviceError(device_id) from exc

    def update_counter(self, device_id: str, counter: int) -> None:
        """Advance the last-seen monotonic counter (binding check B4). Fails closed:
        rejects any counter that does not strictly increase, which is exactly what B4
        needs to detect a replayed/rolled-back device counter.
        """
        with self._lock:
            record = self._devices.get(device_id)
            if record is None:
                raise UnknownDeviceError(device_id)
            if counter <= record.counter:
                raise ValueError(
                    f"counter regression for {device_id}: {counter} <= {record.counter}"
                )
            self._devices[device_id] = DeviceRecord(
                device_id=record.device_id,
                sig_pk=record.sig_pk,
                sig_mode=record.sig_mode,
                counter=counter,
            )
