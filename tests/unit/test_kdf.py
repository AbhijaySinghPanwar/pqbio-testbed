"""Tests for HKDF-SHA256 transcript-bound key derivation (§5.1)."""

from __future__ import annotations

from pqbio.pqc.kdf import compute_transcript, derive_session_keys, hkdf_expand, hkdf_extract


def _sample_kwargs(**overrides: bytes) -> dict[str, bytes]:
    base = dict(
        ss=b"\x01" * 32,
        session_id=b"session-id-bytes",
        kem_ct=b"kem-ciphertext",
        server_sig_pk=b"server-sig-pk",
        device_sig_pk=b"device-sig-pk",
    )
    base.update(overrides)
    return base


def test_derive_session_keys_deterministic() -> None:
    keys_a = derive_session_keys(**_sample_kwargs())
    keys_b = derive_session_keys(**_sample_kwargs())
    assert keys_a == keys_b


def test_derived_keys_are_32_bytes_and_distinct() -> None:
    keys = derive_session_keys(**_sample_kwargs())
    assert len(keys.k_master) == 32
    assert len(keys.k_c2s) == 32
    assert len(keys.k_s2c) == 32
    assert keys.k_c2s != keys.k_s2c


def test_transcript_binds_every_component() -> None:
    """Changing any single transcript component must change K_master — a MITM that
    swaps the session, ciphertext, or either public key is detected via key mismatch,
    not trusted silently.
    """
    baseline = derive_session_keys(**_sample_kwargs()).k_master
    for field in ("session_id", "kem_ct", "server_sig_pk", "device_sig_pk"):
        mutated = derive_session_keys(**_sample_kwargs(**{field: b"tampered"}))
        assert mutated.k_master != baseline, f"tampering {field} did not change K_master"


def test_transcript_binds_shared_secret_too() -> None:
    baseline = derive_session_keys(**_sample_kwargs()).k_master
    mutated = derive_session_keys(**_sample_kwargs(ss=b"\x02" * 32))
    assert mutated.k_master != baseline


def test_hkdf_extract_matches_rfc5869_hmac_definition() -> None:
    import hashlib
    import hmac

    salt, ikm = b"salt-value", b"input-key-material"
    assert hkdf_extract(salt=salt, ikm=ikm) == hmac.new(salt, ikm, hashlib.sha256).digest()


def test_hkdf_expand_different_info_gives_different_output() -> None:
    prk = b"\x00" * 32
    a = hkdf_expand(prk, b"label-a")
    b = hkdf_expand(prk, b"label-b")
    assert a != b


def test_compute_transcript_is_sha256_length() -> None:
    transcript = compute_transcript(
        session_id=b"session-id-bytes",
        kem_ct=b"c",
        server_sig_pk=b"d",
        device_sig_pk=b"e",
    )
    assert len(transcript) == 32
