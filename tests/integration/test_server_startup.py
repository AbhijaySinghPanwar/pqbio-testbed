"""Module E DoD: "Server refuses to start if a model in checksums.txt fails to load or
mismatches -- never silently skips a detector" (PROJECT_SPEC.md §5.5).

Owner: Abhijay

`_load_checksums` is monkeypatched in `pqbio.server.app`'s own namespace (where it was
imported, not `pqbio.detect.face`'s) so these tests never touch the real, committed
`models/checksums.txt`.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pqbio.server.app import ModelIntegrityStartupError, create_app


def test_server_refuses_to_start_when_a_checksummed_model_file_is_missing(monkeypatch):
    monkeypatch.setattr(
        "pqbio.server.app._load_checksums",
        lambda: {"this_model_does_not_exist.onnx": "deadbeef" * 8},
    )
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(data_dir=Path(tmp) / "data")
        with pytest.raises(ModelIntegrityStartupError, match="model file missing"), TestClient(app):
            pass


def test_server_refuses_to_start_when_a_model_checksum_mismatches(monkeypatch):
    from pqbio.detect.face import _load_checksums

    real_entries = _load_checksums()
    assert real_entries, "models/checksums.txt should have real entries in this environment"
    rel_path = next(iter(real_entries))

    monkeypatch.setattr(
        "pqbio.server.app._load_checksums",
        lambda: {rel_path: "0" * 64},
    )
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(data_dir=Path(tmp) / "data")
        with pytest.raises(ModelIntegrityStartupError, match="SHA-256 mismatch"), TestClient(app):
            pass


def test_server_refuses_to_start_when_checksums_file_is_empty(monkeypatch):
    monkeypatch.setattr("pqbio.server.app._load_checksums", dict)
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(data_dir=Path(tmp) / "data")
        with (
            pytest.raises(ModelIntegrityStartupError, match="no recorded checksums"),
            TestClient(app),
        ):
            pass


def test_server_starts_successfully_with_real_checksums():
    """Control: confirms the two failure tests above are testing the real gate, not a
    tautology -- with the actual committed checksums.txt (untouched), startup succeeds.
    """
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(data_dir=Path(tmp) / "data")
        with TestClient(app) as client:
            r = client.get("/v1/health")
            assert r.status_code == 200
            assert r.json() == {"status": "ok"}
