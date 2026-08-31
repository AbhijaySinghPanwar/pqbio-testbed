"""Two-tier self-generated injection attack corpus (PROJECT_SPEC.md §7).

Owner: Abhijay

No public injection corpus exists (§6), and no real dataset clips are licensed yet, so
the "video files" here are small synthetic clips (an animated face-like pattern),
clearly labelled `"method": "synthetic"` throughout — swap in real clips once §6's
datasets land; nothing about this script's structure needs to change to do that.

**Tier 1 — direct API injection.** Skip the client entirely: frames come straight from
a video file with *no real-time capture pacing* (an attacker extracting frames from a
file and POSTing them doesn't bother re-simulating a camera's frame-interval jitter),
and the bundle is signed with a *compromised but genuinely enrolled* device key — per
the A6 threat model (§2.1: "assume a valid device key"), the signature itself is
completely valid. Only provenance signals (frame-timing jitter, device name, ...) can
catch this, which is exactly what D5 (injection.py) is for.

**Tier 2 — virtual camera.** Route a video file through a virtual camera
(v4l2loopback on Linux, OBS Virtual Camera on Windows) and run the *unmodified* client
against it. **Blocked in this environment** — see BLOCKED_TIER2_REASON below — so this
builds tier 1 only and reports tier 2 as blocked with the reason, rather than
simulating a virtual camera in software and mislabelling it tier 2.

**Genuine counterparts** come from `ReplaySource` over the same synthetic clips, run
through the *real* capture pacing loop, signed with the *same* device key as the tier-1
sample built from the same clip — so the signature and device identity are identical
between each genuine/injected pair, and only capture-provenance signals differ. That's
deliberate: it isolates exactly what D5 is supposed to detect, rather than confounding
it with "different device" or "different signature validity".

**Known limitation, not papered over:** `ReplaySource` always reports zeroed sensor
metadata (exposure/iso/focal) and a `"replay:<filename>"` device name (see
pqbio/capture/replay_source.py's own docstring) — a structural property of using it as
a stand-in for a live camera, not a corpus-generation bug. This means the "sensor
metadata plausibility" D5 signal, and part of "virtual camera enumeration", cannot
discriminate genuine from tier-1 *in this synthetic corpus* the way they would against
a real live-camera baseline. Recorded in the manifest, not hidden.

Usage:
    python scripts/make_injection_corpus.py [--n-pairs 20] [--n-frames 30]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import cv2
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pqbio.binding.nonce import NonceStore, issue_challenge  # noqa: E402
from pqbio.capture import CapturedFrame  # noqa: E402
from pqbio.capture.bundler import assemble_bundle, sign_bundle  # noqa: E402
from pqbio.capture.challenge import estimate_face_box, measure_chromaticity_trace  # noqa: E402
from pqbio.capture.replay_source import ReplaySource  # noqa: E402
from pqbio.config import settings  # noqa: E402
from pqbio.pqc.keystore import KeyStore  # noqa: E402
from pqbio.pqc.sign import get_signer  # noqa: E402
from pqbio.schemas import (  # noqa: E402
    ChallengeSignal,
    DeviceMeta,
    EvidenceBundle,
    FrameMeta,
    Txn,
    model_signing_payload,
)

BLOCKED_TIER2_REASON = (
    "No virtual camera driver is available: no OBS Studio / OBS Virtual Camera install "
    "found on this host (checked Program Files, Program Files (x86), and PATH for "
    "obs64.exe/obs32.exe), no v4l2loopback (this is Windows, not Linux), and the current "
    "session does not have Administrator rights (verified via "
    "WindowsPrincipal.IsInRole(Administrator) == False) — OBS's virtual camera driver is "
    "a signed kernel-mode DirectShow filter that requires elevated install, which this "
    "non-interactive session cannot grant or work around. Unblock: run this script on a "
    "machine with OBS Studio (with its Virtual Camera feature) installed, or on Linux "
    "with v4l2loopback loaded, then re-run with --tier2."
)

VIRTUAL_CAM_NAMES = [
    "OBS Virtual Camera",
    "v4l2loopback",
    "ManyCam Virtual Webcam",
    "Snap Camera",
]
PLAUSIBLE_REAL_CAM_NAMES = [
    "Logitech HD Webcam C920",
    "Integrated Webcam",
    "HP Wide Vision HD Camera",
    "Dell UltraSharp Webcam",
]


def _synthetic_clip(
    path: Path, seed: int, n_frames: int = 60, fps: float = 15.0, size: int = 160
) -> None:
    """A small animated face-like synthetic clip standing in for a real dataset clip
    (see module docstring). Slight per-frame motion so it isn't a frozen single image.
    """
    rng = np.random.default_rng(seed)
    skin = (int(rng.integers(140, 225)),) * 3
    face_w = int(rng.integers(size // 3 - 8, size // 3 + 8))
    face_h = int(rng.integers(size // 2 - 15, size // 2 + 5))
    eye_dx = int(rng.integers(15, 26))

    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    writer = cv2.VideoWriter(str(path), fourcc, fps, (size, size))
    try:
        for i in range(n_frames):
            img = np.full((size, size, 3), 205, dtype=np.uint8)
            wobble_x = int(2 * np.sin(i / 5.0))
            wobble_y = int(1 * np.cos(i / 7.0))
            cx, cy = size // 2 + wobble_x, size // 2 + wobble_y
            cv2.ellipse(img, (cx, cy), (face_w, face_h), 0, 0, 360, skin, -1)
            eye_y = cy - int(rng.integers(5, 15))
            cv2.circle(img, (cx - eye_dx, eye_y), 6, (30, 30, 30), -1)
            cv2.circle(img, (cx + eye_dx, eye_y), 6, (30, 30, 30), -1)
            mouth_y = cy + int(rng.integers(20, 32))
            cv2.ellipse(img, (cx, mouth_y), (16, 7), 0, 0, 180, (60, 30, 30), 2)
            writer.write(img)
    finally:
        writer.release()


def _manifest_path_str(path: Path) -> str:
    """Store paths relative to REPO_ROOT when possible (the normal case — default
    --out-dir lives under the repo), falling back to an absolute path string when
    --out-dir points elsewhere (e.g. a test's tmp_path) so the manifest is still
    correct, just not repo-relative.

    `.as_posix()`, not `str()`: on Windows, `str(Path(...))` uses backslash
    separators, which get written verbatim into the committed JSON manifest and then
    fail to resolve on Linux (a bare backslash isn't a path separator there — the
    whole string is read as one filename). Discovered running the test suite inside
    the liboqs Docker image (PROJECT_SPEC.md §14): every path this manifest was ever
    generated with came from a Windows host. `.as_posix()` produces forward-slash
    paths that resolve correctly on both.
    """
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return resolved.as_posix()


def _instant_read_all_frames(clip_path: Path, n_frames: int) -> list[CapturedFrame]:
    """Tier 1's capture: read every frame back-to-back with *no* real-time pacing —
    exactly what skipping the client's capture loop looks like. All capture_ts_ns
    values land within microseconds of each other, a stark "file-read artefact" signal
    (§5.4 D5's own rationale for the frame-timing-jitter feature).
    """
    cap = cv2.VideoCapture(str(clip_path))
    if not cap.isOpened():
        raise RuntimeError(f"could not open clip: {clip_path}")
    frames: list[CapturedFrame] = []
    try:
        for idx in range(n_frames):
            ok, image = cap.read()
            if not ok:
                raise RuntimeError(f"clip {clip_path} ran out of frames at index {idx}")
            frames.append(
                CapturedFrame(
                    image=image,
                    meta=FrameMeta(
                        capture_ts_ns=time.time_ns(),
                        exposure=0.0,
                        iso=0,
                        focal=0.0,
                        sequence_idx=idx,
                    ),
                )
            )
    finally:
        cap.release()
    return frames


def _build_bundle(
    *,
    frames: list[CapturedFrame],
    device_meta: DeviceMeta,
    device_id: str,
    device_sk: bytes,
    signer,
    nonce_store: NonceStore,
    server_sk: bytes,
    counter: int,
) -> EvidenceBundle:
    txn = Txn(action="injection-corpus-sample", relying_party="pqbio-corpus-gen")
    challenge = issue_challenge(
        session_id=uuid4(),
        txn=txn,
        signer=signer,
        server_sk=server_sk,
        nonce_store=nonce_store,
    )
    face_box = estimate_face_box(frames[0].image)
    trace = measure_chromaticity_trace([f.image for f in frames], face_box)
    bundle = assemble_bundle(
        session_id=challenge.session_id,
        device_id=device_id,
        counter=counter,
        challenge_echo=challenge,
        captured_frames=frames,
        challenge_signal=ChallengeSignal(illumination_trace=trace),
        device_meta=device_meta,
    )
    return sign_bundle(bundle, signer, device_sk)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-pairs", type=int, default=20)
    parser.add_argument("--n-frames", type=int, default=settings.capture.n_frames)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument(
        "--out-dir", type=Path, default=REPO_ROOT / "data" / "processed" / "injection_corpus"
    )
    parser.add_argument(
        "--manifest-out",
        type=Path,
        default=REPO_ROOT / "data" / "manifests" / "injection_corpus_manifest.json",
    )
    parser.add_argument(
        "--tier2", action="store_true", help="attempt tier 2 (see BLOCKED_TIER2_REASON)"
    )
    args = parser.parse_args()

    if args.tier2:
        print(f"--tier2 requested but blocked: {BLOCKED_TIER2_REASON}", file=sys.stderr)
        sys.exit(1)

    clips_dir = REPO_ROOT / "data" / "raw" / "synthetic_injection_clips"
    genuine_dir = args.out_dir / "genuine"
    tier1_dir = args.out_dir / "tier1_injection"
    for d in (clips_dir, genuine_dir, tier1_dir):
        d.mkdir(parents=True, exist_ok=True)

    signer = get_signer("pq")
    server_pk, server_sk = signer.keygen()
    keystore = KeyStore()

    rng = np.random.default_rng(args.seed)
    samples: list[dict] = []

    print(f"generating {args.n_pairs} genuine/tier1 pairs...", file=sys.stderr)
    for i in range(args.n_pairs):
        clip_path = clips_dir / f"clip_{i:03d}.mp4"
        _synthetic_clip(clip_path, seed=args.seed * 1000 + i, n_frames=args.n_frames + 5)

        device_id = f"corpus-device-{i:03d}"
        device_pk, device_sk = signer.keygen()
        keystore.enroll(device_id, sig_pk=device_pk, sig_mode="pq")

        nonce_store = NonceStore(args.out_dir / f"nonces_{i:03d}.db")

        # --- genuine counterpart: real client, real pacing, honest ReplaySource behaviour ---
        genuine_source = ReplaySource(clip_path)
        genuine_frames, genuine_device_meta = genuine_source.capture(
            args.n_frames, settings.capture.fps
        )
        genuine_bundle = _build_bundle(
            frames=genuine_frames,
            device_meta=genuine_device_meta,
            device_id=device_id,
            device_sk=device_sk,
            signer=signer,
            nonce_store=nonce_store,
            server_sk=server_sk,
            counter=1,
        )
        genuine_path = genuine_dir / f"sample_{i:03d}.cbor"
        genuine_path.write_bytes(model_signing_payload(genuine_bundle))

        # --- tier 1: skip the client, instant frame read, same compromised device key ---
        tier1_frames = _instant_read_all_frames(clip_path, args.n_frames)
        use_virtual_cam_name = bool(rng.integers(0, 2))  # half obvious, half a plausible fake
        fake_name = (
            VIRTUAL_CAM_NAMES[rng.integers(0, len(VIRTUAL_CAM_NAMES))]
            if use_virtual_cam_name
            else PLAUSIBLE_REAL_CAM_NAMES[rng.integers(0, len(PLAUSIBLE_REAL_CAM_NAMES))]
        )
        tier1_device_meta = DeviceMeta(
            os=genuine_device_meta.os,
            camera_device_name=fake_name,
            camera_driver_id="tier1-injected",
            resolution=genuine_device_meta.resolution,
            codec="tier1-injected",
            app_version=genuine_device_meta.app_version,
        )
        tier1_bundle = _build_bundle(
            frames=tier1_frames,
            device_meta=tier1_device_meta,
            device_id=device_id,
            device_sk=device_sk,
            signer=signer,
            nonce_store=nonce_store,
            server_sk=server_sk,
            counter=2,
        )
        tier1_path = tier1_dir / f"sample_{i:03d}.cbor"
        tier1_path.write_bytes(model_signing_payload(tier1_bundle))

        samples.append(
            {
                "pair_id": i,
                "clip": _manifest_path_str(clip_path),
                "device_id": device_id,
                "genuine": {
                    "label": "bona_fide",
                    "bundle_path": _manifest_path_str(genuine_path),
                    "device_name": genuine_device_meta.camera_device_name,
                },
                "tier1_injection": {
                    "label": "injection_tier1",
                    "bundle_path": _manifest_path_str(tier1_path),
                    "device_name": fake_name,
                    "device_name_is_known_virtual_cam": use_virtual_cam_name,
                },
            }
        )

    manifest = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "method": "synthetic",
        "caveat": (
            "No real dataset clips are licensed yet (PROJECT_SPEC.md §6); clips are "
            "synthetic animated face-like patterns, not real footage. Re-generate against "
            "real clips once datasets land."
        ),
        "tier2_status": "blocked",
        "tier2_blocked_reason": BLOCKED_TIER2_REASON,
        "known_limitation": (
            "ReplaySource always reports zeroed sensor metadata and a 'replay:<filename>' "
            "device name for genuine counterparts too, so the 'sensor metadata plausibility' "
            "D5 signal cannot discriminate genuine from tier-1 in this corpus the way it "
            "would against a real live-camera baseline. See this script's module docstring."
        ),
        "n_frames_per_sample": args.n_frames,
        "n_pairs": args.n_pairs,
        "samples": samples,
    }
    args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
    args.manifest_out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote manifest: {args.manifest_out}", file=sys.stderr)
    print(
        f"wrote {args.n_pairs} genuine + {args.n_pairs} tier1_injection bundles under {args.out_dir}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
