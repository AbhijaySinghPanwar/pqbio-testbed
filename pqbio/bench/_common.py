"""Shared infrastructure for pqbio/bench/*.py: run provenance, percentile/latency
statistics, the BLOCKED-cell convention, and one async client that drives the real
enroll -> challenge -> handshake -> verify flow over HTTP against an in-process
Module E app.

Owner: Abhijay

Not one of the six files PROJECT_SPEC.md §5.6 names (accuracy/latency/loadgen/
resources/overhead/report) — it exists so those six don't each reimplement "record git
commit + config hash + hardware" or "drive one real /verify call", the same reasoning
`tests/unit/_face_fixtures.py` and `_server_fixtures.py` exist for the test suite.
Leading underscore keeps it out of the module's public surface, not out of pytest
collection this time (there is nothing to collect here).
"""

from __future__ import annotations

import hashlib
import os
import platform
import statistics
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import cv2
import httpx
import numpy as np

from pqbio.config import DEFAULT_CONFIG_PATH, settings
from pqbio.pqc.kem import KEM_BACKEND, KemMode, get_kem
from pqbio.pqc.sign import SIG_BACKEND, SigMode, get_signer

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_DIR = REPO_ROOT / "results"

# ----------------------------------------------------------------------------------
# Run provenance -- every results/*.json this package writes carries this envelope
# (PROJECT_SPEC.md §5.6 DoD: "each run records git commit, config hash, hardware
# description, dataset versions, seeds").
# ----------------------------------------------------------------------------------


def git_commit() -> str:
    """The commit these results were produced from.

    `PQBIO_GIT_COMMIT` takes precedence over asking git: inside the Docker image (§4's
    reference environment) `/app` is assembled from explicit `COPY` steps and has no
    `.git`, so the subprocess call below can only ever answer "unknown" there — which
    would silently strip provenance from every containerised result, breaking §0's
    "every number is traceable" rule exactly where it matters most (the liboqs numbers
    can *only* be produced in a container). The caller passes the real commit in via
    `docker run -e PQBIO_GIT_COMMIT=$(git rev-parse HEAD)`.
    """
    from_env = os.environ.get("PQBIO_GIT_COMMIT", "").strip()
    if from_env:
        return from_env
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "unknown (not a git repository at run time)"


def config_hash() -> str:
    return hashlib.sha256(DEFAULT_CONFIG_PATH.read_bytes()).hexdigest()


def hardware_description() -> dict[str, str]:
    return {
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
    }


def crypto_backends() -> dict[str, str]:
    return {"KEM_BACKEND": KEM_BACKEND, "SIG_BACKEND": SIG_BACKEND}


def run_metadata(
    *,
    seed: int | None = None,
    dataset_versions: dict[str, str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The provenance envelope every bench result JSON embeds. `dataset_versions`
    defaults to naming the one dataset actually in use (the self-generated injection
    corpus) plus the three that are absent -- never silently omitted (§14: datasets are
    unlicensed, not untracked).
    """
    meta: dict[str, Any] = {
        "git_commit": git_commit(),
        "config_hash_sha256": config_hash(),
        "hardware": hardware_description(),
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "seed": seed,
        **crypto_backends(),
        "dataset_versions": (
            dataset_versions
            if dataset_versions is not None
            else {
                "injection_corpus": "self-generated, scripts/make_injection_corpus.py (see its manifest for its own git_commit)",
                "presentation": "BLOCKED -- unlicensed (CASIA-FASD/Replay-Attack/OULU-NPU/CelebA-Spoof, §6)",
                "morph": "BLOCKED -- unlicensed (FRLL-Morphs/SMDD, §6)",
                "deepfake": "BLOCKED -- unlicensed (FaceForensics++/Celeb-DF-v2, §6)",
            }
        ),
    }
    if extra:
        meta.update(extra)
    return meta


def write_json(path: Path, data: dict[str, Any]) -> None:
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ----------------------------------------------------------------------------------
# The BLOCKED-cell convention -- report.py looks for this exact shape everywhere.
# ----------------------------------------------------------------------------------


def blocked(reason: str, **extra: Any) -> dict[str, Any]:
    """The canonical shape for a metric/table cell that cannot be produced right now.
    Never write `None`, `0`, or omit the key instead -- PROJECT_SPEC.md's instruction is
    explicit: "mark absent components as BLOCKED in its output rather than omitting
    them or substituting a placeholder number." `report.py` renders any dict containing
    `"blocked": True` as an explicit BLOCKED row naming `reason`, never a blank cell.
    """
    return {"blocked": True, "blocker": reason, **extra}


def is_blocked(cell: Any) -> bool:
    return isinstance(cell, dict) and cell.get("blocked") is True


# ----------------------------------------------------------------------------------
# Percentile / latency statistics
# ----------------------------------------------------------------------------------


def percentile(values: Sequence[float], pct: float) -> float:
    values_sorted = sorted(values)
    if not values_sorted:
        raise ValueError("percentile() of an empty sequence is undefined")
    if len(values_sorted) == 1:
        return values_sorted[0]
    k = (len(values_sorted) - 1) * (pct / 100)
    f, c = int(k), min(int(k) + 1, len(values_sorted) - 1)
    if f == c:
        return values_sorted[f]
    return values_sorted[f] + (values_sorted[c] - values_sorted[f]) * (k - f)


def latency_stats(samples_ms: Sequence[float]) -> dict[str, float]:
    """p50/p95/p99/mean/min/max/n over a list of latency samples in milliseconds."""
    if not samples_ms:
        raise ValueError("latency_stats() of an empty sample set is undefined")
    return {
        "n": len(samples_ms),
        "mean_ms": statistics.mean(samples_ms),
        "p50_ms": percentile(samples_ms, 50),
        "p95_ms": percentile(samples_ms, 95),
        "p99_ms": percentile(samples_ms, 99),
        "min_ms": min(samples_ms),
        "max_ms": max(samples_ms),
    }


# ----------------------------------------------------------------------------------
# A representative, quality-gate-passing evidence bundle -- the one real photographed
# face available in this environment (skimage's astronaut image; no licensed biometric
# dataset exists yet, §6/§14). Coordinates mirror the crop validated in Module E's own
# test fixtures (tests/unit/_server_fixtures.py): a tighter crop detects at a det_score
# just above SCRFD's internal 0.5 filter, which collapses under any lossy round-trip;
# this wider-margin crop detects at ~0.77-0.99 and survives one. Duplicated rather than
# imported from tests/ -- production code (pqbio/bench/) must not depend on the test
# suite.
# ----------------------------------------------------------------------------------


def quality_pass_face_image() -> np.ndarray:
    from skimage import data

    img = cv2.cvtColor(data.astronaut(), cv2.COLOR_RGB2BGR)  # type: ignore[no-untyped-call]
    x, y, w, h = 140, 20, 180, 200
    crop = img[y : y + h, x : x + w]
    return cv2.resize(crop, (int(w * 1.5), int(h * 1.5)), interpolation=cv2.INTER_LANCZOS4)


def quality_pass_face_jpeg() -> bytes:
    ok, buf = cv2.imencode(".jpg", quality_pass_face_image(), [cv2.IMWRITE_JPEG_QUALITY, 95])
    assert ok
    return bytes(buf)


def shared_face_box() -> tuple[int, int, int, int]:
    """The face box for `quality_pass_face_image()`, detected once. Every bundle this
    module builds uses that same base crop, so callers building many bundles should
    compute this once and pass it to `build_signed_bundle(face_box=...)` rather than
    paying one SCRFD inference per bundle — see that function's docstring for why it
    matters at high concurrency.
    """
    from pqbio.capture.challenge import estimate_face_box

    return estimate_face_box(quality_pass_face_image())


def build_signed_bundle(
    device_signer: Any,
    device_sk: bytes,
    device_id: str,
    challenge_obj: Any,
    *,
    n_frames: int = 10,
    counter: int = 1,
    seed: int = 0,
    face_box: tuple[int, int, int, int] | None = None,
) -> Any:
    """A signed `EvidenceBundle` that satisfies every check (B1-B6, quality) against
    `challenge_obj` -- the same real face crop, palette-tinted per frame to correlate
    with the challenge's derived illumination sequence, jittered realistic timestamps.
    Used by `AsyncBenchClient.build_bundle` (HTTP-driven flows: latency.py, loadgen.py,
    C3) and directly by `overhead.py`'s C1/C2 (crypto+binding cost in isolation, no
    HTTP, no AI stages -- see overhead.py's module docstring for why).

    `face_box` skips this function's own `estimate_face_box` call, which is a full SCRFD
    inference. That call is *client-side harness cost*, not server cost, and it runs
    synchronously — so building N bundles concurrently serialises N SCRFD inferences on
    the event loop, inside the 30s window a challenge is already ticking through. At the
    top of the concurrency sweep that harness cost, not the server, was what exhausted
    the TTL (§14, 2026-09-01). Every bundle here is built from the same base crop, so
    the box is the same for all of them and hoisting it out is exact up to the per-frame
    palette tint, which shifts the detected box by a pixel or two at most — a documented
    approximation that affects only which pixels `measure_chromaticity_trace` averages,
    well inside B6's correlation tolerance.
    """
    import time

    from pqbio.capture import CapturedFrame
    from pqbio.capture.bundler import assemble_bundle, sign_bundle
    from pqbio.capture.challenge import (
        PALETTE_BGR,
        derive_illumination_sequence,
        estimate_face_box,
        measure_chromaticity_trace,
    )
    from pqbio.schemas import ChallengeSignal, DeviceMeta, FrameMeta

    rng = np.random.default_rng(seed)
    base = quality_pass_face_image()
    expected_indices = derive_illumination_sequence(
        challenge_obj.nonce, settings.binding.illumination_steps
    )
    fps = float(settings.capture.fps)
    nominal_dt_ns = int(1e9 / fps)

    images = []
    frames = []
    ts = time.time_ns()
    for i in range(n_frames):
        step = min(i * len(expected_indices) // n_frames, len(expected_indices) - 1)
        color = np.array(PALETTE_BGR[expected_indices[step]], dtype=np.float32)
        tinted = (base.astype(np.float32) * 0.75 + color * 0.25).astype(np.uint8)
        images.append(tinted)
        frames.append(
            CapturedFrame(
                image=tinted,
                meta=FrameMeta(capture_ts_ns=ts, exposure=0.01, iso=100, focal=4.0, sequence_idx=i),
            )
        )
        jitter_ns = int(rng.normal(0, nominal_dt_ns * 0.1))
        ts += nominal_dt_ns + jitter_ns

    resolved_face_box = face_box if face_box is not None else estimate_face_box(images[0])
    trace = measure_chromaticity_trace(images, resolved_face_box)
    bundle = assemble_bundle(
        session_id=challenge_obj.session_id,
        device_id=device_id,
        counter=counter,
        challenge_echo=challenge_obj,
        captured_frames=frames,
        challenge_signal=ChallengeSignal(illumination_trace=trace),
        device_meta=DeviceMeta(
            os="bench",
            camera_device_name="bench-cam",
            camera_driver_id="0",
            resolution=(base.shape[1], base.shape[0]),
            codec="raw",
            app_version="0.1.0",
        ),
    )
    return sign_bundle(bundle, device_signer, device_sk)


# ----------------------------------------------------------------------------------
# Async bench client -- drives the real HTTP surface (§8.2: "End-to-end latency |
# p50/p95/p99 on /verify"), not a direct pipeline function call.
# ----------------------------------------------------------------------------------


@dataclass
class VerifyOutcome:
    decision: dict[str, Any]  # decrypted Decision, as a plain dict (canonical_cbor_decode'd)
    client_latency_ms: float  # wall-clock time of the POST /v1/verify call itself


class AsyncBenchClient:
    """One simulated device: real ML-KEM/ML-DSA keys, real AES-256-GCM session keys,
    real signed evidence bundles -- driven over HTTP via `httpx.AsyncClient` against an
    in-process ASGI app (no real socket, but a real request/response cycle through
    FastAPI/Starlette routing, JSON (de)serialisation, and the full Module E pipeline).
    """

    def __init__(self, http: httpx.AsyncClient, device_id: str, *, mode: KemMode = "pq") -> None:
        self.http = http
        self.device_id = device_id
        self.mode: SigMode = mode
        self.device_signer = get_signer(mode)
        self.device_pk, self.device_sk = self.device_signer.keygen()
        self.server_kem_pk: bytes | None = None
        self.server_sig_pk: bytes | None = None

    async def enroll(self, face_jpeg: bytes | None = None) -> None:
        import base64

        face_jpeg = face_jpeg if face_jpeg is not None else quality_pass_face_jpeg()
        r = await self.http.post(
            "/v1/enroll",
            json={
                "device_id": self.device_id,
                "device_sig_pk_b64": base64.b64encode(self.device_pk).decode("ascii"),
                "sig_mode": self.mode,
                "face_image_b64": base64.b64encode(face_jpeg).decode("ascii"),
            },
        )
        r.raise_for_status()
        body = r.json()
        self.server_kem_pk = base64.b64decode(body["server_kem_pk_b64"])
        self.server_sig_pk = base64.b64decode(body["server_sig_pk_b64"])

    async def challenge(self, txn: dict[str, Any] | None = None) -> tuple[UUID, dict[str, Any]]:

        txn = txn or {"action": "login", "relying_party": "bench.example"}
        r = await self.http.post(
            "/v1/session/challenge", json={"device_id": self.device_id, "txn": txn}
        )
        r.raise_for_status()
        body = r.json()
        return UUID(body["session_id"]), body

    async def handshake(self, session_id: UUID) -> Any:
        import base64

        from pqbio.pqc.kdf import derive_session_keys

        assert self.server_kem_pk is not None, "enroll() first"
        assert self.server_sig_pk is not None, "enroll() first"
        client_kem = get_kem(self.mode)
        kem_ct, ss = client_kem.encapsulate(self.server_kem_pk)
        r = await self.http.post(
            "/v1/session/handshake",
            json={
                "session_id": str(session_id),
                "kem_ct_b64": base64.b64encode(kem_ct).decode("ascii"),
            },
        )
        r.raise_for_status()
        return derive_session_keys(
            ss=ss,
            session_id=session_id.bytes,
            kem_ct=kem_ct,
            server_sig_pk=self.server_sig_pk,
            device_sig_pk=self.device_pk,
        )

    def build_bundle(
        self,
        session_id: UUID,
        challenge_body: dict[str, Any],
        *,
        n_frames: int = 10,
        counter: int = 1,
        seed: int = 0,
        face_box: tuple[int, int, int, int] | None = None,
    ) -> Any:
        """A frame burst that satisfies every check (B1-B6, quality). Thin wrapper
        around `build_signed_bundle` -- this method exists for `AsyncBenchClient`
        callers that already have an HTTP-issued challenge response body; `overhead.py`
        (C1/C2, no HTTP round trip) calls `build_signed_bundle` directly instead.
        Pass `face_box` (see `shared_face_box()`) to skip a per-call SCRFD inference.
        """
        import base64

        from pqbio.schemas import Challenge, Txn

        nonce = base64.b64decode(challenge_body["nonce_b64"])
        challenge_obj = Challenge(
            session_id=session_id,
            nonce=nonce,
            txn=Txn.model_validate(challenge_body["txn"]),
            txn_hash=base64.b64decode(challenge_body["txn_hash_b64"]),
            issued_at=challenge_body["issued_at"],
            expires_at=challenge_body["expires_at"],
            server_sig=base64.b64decode(challenge_body["server_sig_b64"]),
        )
        return build_signed_bundle(
            self.device_signer,
            self.device_sk,
            self.device_id,
            challenge_obj,
            n_frames=n_frames,
            counter=counter,
            seed=seed,
            face_box=face_box,
        )

    async def verify(self, session_id: UUID, bundle: Any, keys: Any) -> VerifyOutcome:
        import base64
        import time

        from pqbio.pqc.aead import decrypt, encrypt
        from pqbio.schemas import canonical_cbor_decode, model_signing_payload

        plaintext = model_signing_payload(bundle)
        aead_nonce, ciphertext = encrypt(keys.k_c2s, plaintext, aad=b"")

        start = time.perf_counter()
        r = await self.http.post(
            "/v1/verify",
            json={
                "session_id": str(session_id),
                "aead_nonce_b64": base64.b64encode(aead_nonce).decode("ascii"),
                "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            },
        )
        client_latency_ms = (time.perf_counter() - start) * 1000.0
        r.raise_for_status()
        body = r.json()
        resp_nonce = base64.b64decode(body["aead_nonce_b64"])
        resp_ct = base64.b64decode(body["ciphertext_b64"])
        decision_bytes = decrypt(keys.k_s2c, resp_nonce, resp_ct, aad=b"")
        decision = canonical_cbor_decode(decision_bytes)
        return VerifyOutcome(decision=decision, client_latency_ms=client_latency_ms)

    async def full_flow(
        self, *, n_frames: int = 10, counter: int = 1, seed: int = 0
    ) -> VerifyOutcome:
        await self.enroll()
        session_id, challenge_body = await self.challenge()
        keys = await self.handshake(session_id)
        bundle = self.build_bundle(
            session_id, challenge_body, n_frames=n_frames, counter=counter, seed=seed
        )
        return await self.verify(session_id, bundle, keys)


def print_progress(msg: str) -> None:
    print(msg, file=sys.stderr)
