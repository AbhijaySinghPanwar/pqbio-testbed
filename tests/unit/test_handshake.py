"""Tests for the §5.1 handshake state machine, including the "replayed KEM ciphertext"
negative test from the Module A DoD: at the protocol layer, a replayed handshake
message is exactly a second attempt to transition an already-KEYED session to KEYED
again, which must be rejected (at-most-once KEYED, §5.1).
"""

from __future__ import annotations

import time

import pytest

from pqbio.pqc.handshake import (
    TERMINAL_STATES,
    HandshakeSession,
    HandshakeState,
    ProtocolStateError,
)


def _fresh_session(ttl_s: float = 30.0) -> HandshakeSession:
    return HandshakeSession(session_id="sess-1", expires_at_ns=time.time_ns() + int(ttl_s * 1e9))


def test_happy_path_reaches_verified() -> None:
    session = _fresh_session()
    session.transition(HandshakeState.CHALLENGED)
    session.transition(HandshakeState.KEYED)
    session.transition(HandshakeState.VERIFIED)
    assert session.current_state == HandshakeState.VERIFIED
    assert session.current_state in TERMINAL_STATES


def test_keyed_transition_at_most_once_replayed_handshake_rejected() -> None:
    """A replayed /handshake message is a second KEYED transition attempt — it must be
    rejected even though CHALLENGED -> KEYED is normally legal, and the session must be
    terminated (driven to REJECTED) rather than silently ignored.
    """
    session = _fresh_session()
    session.transition(HandshakeState.CHALLENGED)
    session.transition(HandshakeState.KEYED)

    with pytest.raises(ProtocolStateError) as exc_info:
        session.transition(HandshakeState.KEYED)  # replay

    assert exc_info.value.reason_code == "PROTO_STATE_ERROR"
    assert session.current_state == HandshakeState.REJECTED


@pytest.mark.parametrize(
    "start,target",
    [
        (HandshakeState.INIT, HandshakeState.KEYED),  # skips CHALLENGED
        (HandshakeState.INIT, HandshakeState.VERIFIED),  # skips two states
        (HandshakeState.CHALLENGED, HandshakeState.VERIFIED),  # skips KEYED
    ],
)
def test_out_of_order_transition_rejected(start: HandshakeState, target: HandshakeState) -> None:
    session = _fresh_session()
    if start != HandshakeState.INIT:
        # walk to `start` legitimately first
        for intermediate in (HandshakeState.CHALLENGED, HandshakeState.KEYED):
            if intermediate == start:
                break
            session.transition(intermediate)

    with pytest.raises(ProtocolStateError):
        session.transition(target)
    assert session.current_state == HandshakeState.REJECTED


def test_transition_after_terminal_state_rejected() -> None:
    session = _fresh_session()
    session.transition(HandshakeState.CHALLENGED)
    session.transition(HandshakeState.KEYED)
    session.transition(HandshakeState.VERIFIED)

    with pytest.raises(ProtocolStateError):
        session.transition(HandshakeState.CHALLENGED)
    # already-terminal VERIFIED must not be downgraded to REJECTED
    assert session.current_state == HandshakeState.VERIFIED


def test_expiry_is_lazy_on_access() -> None:
    session = _fresh_session(ttl_s=0)
    time.sleep(0.01)
    assert session.current_state == HandshakeState.EXPIRED


def test_expire_called_by_sweeper_is_idempotent_and_terminal() -> None:
    session = _fresh_session()
    session.expire()
    assert session.current_state == HandshakeState.EXPIRED
    session.expire()  # idempotent
    assert session.current_state == HandshakeState.EXPIRED

    with pytest.raises(ProtocolStateError):
        session.transition(HandshakeState.CHALLENGED)


def test_expired_session_cannot_reach_keyed() -> None:
    session = _fresh_session(ttl_s=0)
    time.sleep(0.01)
    with pytest.raises(ProtocolStateError):
        session.transition(HandshakeState.CHALLENGED)
