"""Handshake state machine (PROJECT_SPEC.md §5.1).

    INIT -> CHALLENGED -> KEYED -> VERIFIED | REJECTED | EXPIRED

- A session may transition to KEYED at most once (prevents key-reuse).
- EXPIRED is terminal and is reached lazily on access (`current_state`) as well as by a
  background sweeper calling `expire()`.
- Any protocol-order violation raises ProtocolStateError (reason code PROTO_STATE_ERROR)
  and terminates the session: an illegal transition drives the session to REJECTED
  before raising, so no operation on it can succeed afterwards either.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum


class HandshakeState(StrEnum):
    INIT = "INIT"
    CHALLENGED = "CHALLENGED"
    KEYED = "KEYED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


TERMINAL_STATES = frozenset(
    {HandshakeState.VERIFIED, HandshakeState.REJECTED, HandshakeState.EXPIRED}
)

# Allowed forward transitions from each state.
_ALLOWED: dict[HandshakeState, frozenset[HandshakeState]] = {
    HandshakeState.INIT: frozenset({HandshakeState.CHALLENGED}),
    HandshakeState.CHALLENGED: frozenset({HandshakeState.KEYED}),
    HandshakeState.KEYED: frozenset({HandshakeState.VERIFIED}),
    HandshakeState.VERIFIED: frozenset(),
    HandshakeState.REJECTED: frozenset(),
    HandshakeState.EXPIRED: frozenset(),
}


class ProtocolStateError(Exception):
    """Raised on any protocol-order violation (§5.1). reason_code == 'PROTO_STATE_ERROR'."""

    reason_code = "PROTO_STATE_ERROR"

    def __init__(
        self, session_id: str, from_state: HandshakeState, attempted: HandshakeState
    ) -> None:
        super().__init__(
            f"session {session_id}: illegal transition {from_state.value} -> {attempted.value}"
        )
        self.session_id = session_id
        self.from_state = from_state
        self.attempted = attempted


@dataclass
class HandshakeSession:
    session_id: str
    expires_at_ns: int
    state: HandshakeState = HandshakeState.INIT
    _keyed_once: bool = field(default=False, repr=False)

    @staticmethod
    def _now_ns() -> int:
        return time.time_ns()

    @property
    def current_state(self) -> HandshakeState:
        """Lazily expires the session on access if its TTL has elapsed."""
        if self.state not in TERMINAL_STATES and self._now_ns() > self.expires_at_ns:
            self.state = HandshakeState.EXPIRED
        return self.state

    def expire(self) -> None:
        """Called by the background sweeper. Idempotent on an already-terminal session."""
        if self.state not in TERMINAL_STATES:
            self.state = HandshakeState.EXPIRED

    def transition(self, target: HandshakeState) -> None:
        state = self.current_state
        already_keyed = target == HandshakeState.KEYED and self._keyed_once
        legal = (
            state not in TERMINAL_STATES
            and not already_keyed
            and target in _ALLOWED.get(state, frozenset())
        )
        if not legal:
            if state not in TERMINAL_STATES:
                self.state = HandshakeState.REJECTED
            raise ProtocolStateError(self.session_id, state, target)
        self.state = target
        if target == HandshakeState.KEYED:
            self._keyed_once = True
