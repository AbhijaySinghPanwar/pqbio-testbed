"""Internal helper: deterministic randomness injection for liboqs-backed KAT support
functions (`kem.py`'s `ml_kem_768_encapsulate_with_randomness`, `sign.py`'s
`ml_dsa_65_keygen_from_seed` / `ml_dsa_65_sign_deterministic`).

Owner: Abhijay

liboqs's C API only supports injecting explicit internal randomness via a global,
process-wide RNG override (`OQS_randombytes_custom_algorithm`) — there is no per-call
parameter for it, unlike ML-KEM's own `generate_keypair_seed(seed)` (a real per-call
seed argument liboqs-python exposes directly, used without this helper). Verified
empirically against the real ACVP vectors before writing this, not assumed: registering
a callback that always returns a fixed value reproduces the exact ct/ss, pk/sk, and
signature bytes NIST's vectors expect (see tests/unit/test_pqc_kat.py) — for ML-DSA,
this also confirms "deterministic" (non-hedged) signing is liboqs's normal hedged
`sign_with_ctx_str` with the internal 32-byte `rnd` draw fixed to all-zero, not a
separate code path.

**Why this needs its own context manager, not just a plain function call.** The
override is process-wide, not scoped to one `KeyEncapsulation`/`Signature` instance.
Forgetting to restore real randomness after a KAT call would leave *every subsequent*
liboqs operation in the same process — including real production keygen/encaps/sign
calls elsewhere in the same test run or, worse, a long-lived server process — silently
using fixed, predictable "randomness". That is a live cryptographic vulnerability, not
a test-hygiene nitpick, so restoration happens in a `finally`, and a failed restore
raises rather than continuing with an unknown RNG state.
"""

from __future__ import annotations

import ctypes as ct
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

_CALLBACK_TYPE = ct.CFUNCTYPE(None, ct.POINTER(ct.c_uint8), ct.c_size_t)


@contextmanager
def oqs_fixed_randomness(fixed_bytes: bytes) -> Iterator[None]:
    """Within this block, every liboqs call that draws "randomness" receives
    `fixed_bytes`, cycled to fill however many bytes are requested — matching
    `OQS_randombytes_custom_algorithm`'s actual C signature `(buffer, length)`, which
    has no length-checking of its own. Every current caller passes exactly the number
    of bytes its one internal draw needs, so the cycling never actually triggers in
    practice; it exists so a mismatched length fails predictably rather than reading
    out of bounds.

    Always restores liboqs to its default "system" RNG on exit, success or exception —
    see module docstring for why that restoration is a security property.
    """
    import oqs

    if not fixed_bytes:
        raise ValueError("oqs_fixed_randomness requires at least one byte")

    def _fill(buf: Any, n: int) -> None:
        for i in range(n):
            buf[i] = fixed_bytes[i % len(fixed_bytes)]

    callback = _CALLBACK_TYPE(_fill)
    oqs.native().OQS_randombytes_custom_algorithm(callback)
    try:
        yield
    finally:
        rv = oqs.native().OQS_randombytes_switch_algorithm(ct.create_string_buffer(b"system"))
        if rv != oqs.OQS_SUCCESS:
            raise RuntimeError(
                "failed to restore liboqs to system randomness after a KAT call — "
                "refusing to continue with a possibly-fixed global RNG still active"
            )
