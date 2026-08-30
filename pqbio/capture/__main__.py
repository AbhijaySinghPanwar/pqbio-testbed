"""CLI: python -m pqbio.capture --source {camera,replay} --clip PATH --out bundle.cbor

(PROJECT_SPEC.md §5.2 DoD.)

Standalone demo mode: Module C (challenge issuance) and Module E (the real
enroll/challenge/verify wire protocol) don't exist yet, so this generates an ephemeral
server + device keypair and a locally-signed Challenge instead of fetching one from a
real server — clearly not how a deployed client would get its challenge. Everything
downstream of that (capture, measurement, bundling, signing) is the real code path.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from uuid import UUID, uuid4

from pqbio.capture import FrameSource
from pqbio.capture.bundler import assemble_bundle, sign_bundle
from pqbio.capture.camera import CameraSource
from pqbio.capture.challenge import estimate_face_box_centre_crop, measure_chromaticity_trace
from pqbio.capture.replay_source import ReplaySource
from pqbio.config import settings
from pqbio.pqc.sign import get_signer
from pqbio.schemas import (
    Challenge,
    ChallengeSignal,
    Txn,
    canonical_cbor_encode,
    model_signing_payload,
    sha256,
)


def _issue_local_demo_challenge(session_id: UUID, txn: Txn) -> tuple[Challenge, bytes]:
    """Simulate what /v1/session/challenge will return once Module E exists. Returns
    (challenge, server_pk) — server_pk isn't otherwise used by this CLI but is what a
    real client would need to have pinned in order to trust the challenge.
    """
    signer = get_signer(settings.crypto.mode)
    server_pk, server_sk = signer.keygen()

    txn_payload = canonical_cbor_encode(txn.model_dump(mode="python"))
    now_ns = time.time_ns()
    challenge = Challenge(
        session_id=session_id,
        nonce=sha256(str(uuid4()).encode())[:32],
        txn=txn,
        txn_hash=sha256(txn_payload),
        issued_at=now_ns,
        expires_at=now_ns + settings.binding.challenge_ttl_s * 1_000_000_000,
    )
    payload = model_signing_payload(challenge, exclude={"server_sig"})
    server_sig = signer.sign(sha256(payload), server_sk)
    return challenge.model_copy(update={"server_sig": server_sig}), server_pk


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=["camera", "replay"], required=True)
    parser.add_argument("--clip", type=Path, help="clip path, required when --source=replay")
    parser.add_argument("--out", type=Path, default=Path("bundle.cbor"))
    parser.add_argument("--device-id", default="cli-demo-device")
    parser.add_argument("--device-index", type=int, default=0, help="camera device index")
    args = parser.parse_args()

    if args.source == "replay" and args.clip is None:
        parser.error("--clip is required when --source=replay")

    session_id = uuid4()
    txn = Txn(action="cli-demo", relying_party="pqbio-cli")
    challenge, _server_pk = _issue_local_demo_challenge(session_id, txn)

    signer = get_signer(settings.crypto.mode)
    _device_pk, device_sk = signer.keygen()

    source: FrameSource
    if args.source == "camera":
        resolution = (settings.capture.resolution[0], settings.capture.resolution[1])
        source = CameraSource(device_index=args.device_index, resolution=resolution)
    else:
        source = ReplaySource(args.clip)

    print(
        f"capturing {settings.capture.n_frames} frames @ {settings.capture.fps}fps "
        f"from {args.source}...",
        file=sys.stderr,
    )
    captured_frames, device_meta = source.capture(settings.capture.n_frames, settings.capture.fps)

    face_box = estimate_face_box_centre_crop(captured_frames[0].image.shape)
    illumination_trace = measure_chromaticity_trace([f.image for f in captured_frames], face_box)
    challenge_signal = ChallengeSignal(illumination_trace=illumination_trace)

    bundle = assemble_bundle(
        session_id=session_id,
        device_id=args.device_id,
        counter=1,
        challenge_echo=challenge,
        captured_frames=captured_frames,
        challenge_signal=challenge_signal,
        device_meta=device_meta,
    )
    signed_bundle = sign_bundle(bundle, signer, device_sk)

    encoded_bundle = model_signing_payload(
        signed_bundle
    )  # no exclude: full bundle, digest+signature included
    args.out.write_bytes(encoded_bundle)
    print(
        f"wrote {args.out} ({len(encoded_bundle)} bytes, {len(captured_frames)} frames)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
