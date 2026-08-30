"""Hypothesis property tests for Module A (§5.1 DoD item 2): "encaps/decaps agree,
sign/verify agree, tampered ciphertext or signature always fails" — across both crypto
modes (classical, pq) behind the frozen KEM/Signer interfaces.

Tampering a KEM ciphertext does not raise: ML-KEM's implicit-rejection (Fujisaki-
Okamoto) construction means a corrupted ciphertext decapsulates to *some* shared secret
deterministically, not an error — so the property under test is that it never agrees
with the genuine one, not that it raises.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pqbio.pqc.kem import KemMode, get_kem
from pqbio.pqc.sign import SigMode, get_signer

MODES: list[KemMode] = ["classical", "pq"]

_settings = settings(max_examples=10, deadline=None)


@pytest.mark.parametrize("mode", MODES)
@_settings
@given(trial=st.integers(min_value=0, max_value=2**32 - 1))
def test_kem_encaps_decaps_agree(mode: KemMode, trial: int) -> None:
    kem = get_kem(mode)
    pk, sk = kem.keygen()
    ct, ss = kem.encapsulate(pk)
    assert kem.decapsulate(ct, sk) == ss


@pytest.mark.parametrize("mode", MODES)
@_settings
@given(data=st.data())
def test_kem_tampered_ciphertext_never_agrees(mode: KemMode, data: st.DataObject) -> None:
    kem = get_kem(mode)
    pk, sk = kem.keygen()
    ct, ss = kem.encapsulate(pk)

    idx = data.draw(st.integers(min_value=0, max_value=len(ct) - 1))
    flip = data.draw(st.integers(min_value=1, max_value=255))
    tampered = bytearray(ct)
    tampered[idx] ^= flip

    result_ss = kem.decapsulate(bytes(tampered), sk)
    assert result_ss != ss


@pytest.mark.parametrize("mode", MODES)
@_settings
@given(msg=st.binary(min_size=0, max_size=256))
def test_signer_sign_verify_agree(mode: SigMode, msg: bytes) -> None:
    signer = get_signer(mode)
    pk, sk = signer.keygen()
    sig = signer.sign(msg, sk)
    assert signer.verify(msg, sig, pk) is True


@pytest.mark.parametrize("mode", MODES)
@_settings
@given(data=st.data())
def test_signer_tampered_signature_always_fails(mode: SigMode, data: st.DataObject) -> None:
    signer = get_signer(mode)
    pk, sk = signer.keygen()
    msg = data.draw(st.binary(min_size=1, max_size=64))
    sig = signer.sign(msg, sk)

    idx = data.draw(st.integers(min_value=0, max_value=len(sig) - 1))
    flip = data.draw(st.integers(min_value=1, max_value=255))
    tampered = bytearray(sig)
    tampered[idx] ^= flip

    assert signer.verify(msg, bytes(tampered), pk) is False
