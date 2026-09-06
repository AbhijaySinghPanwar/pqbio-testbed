"""Module E integration tests: the ACCEPT-path happy flow, receipt verification, and
event-loop responsiveness under concurrency (PROJECT_SPEC.md §5.5 DoD).

Owner: Abhijay
"""

from __future__ import annotations

import statistics
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from _server_fixtures import ServerTestClient
from fastapi.testclient import TestClient

from pqbio.pqc.sign import get_signer
from pqbio.server.app import create_app
from pqbio.server.decision import verify_decision_signature


@pytest.fixture
def app_client():
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(data_dir=Path(tmp) / "data")
        with TestClient(app) as client:
            yield client


def test_happy_path_end_to_end_accepts_genuine_evidence(app_client):
    """enroll -> challenge -> handshake -> verify -> signed decision, through the real
    client and real crypto (ML-KEM-768/ML-DSA-65 fallback, AES-256-GCM). Evidence is
    built to actually satisfy every check, B6's illumination correlation included (see
    `ServerTestClient.build_live_genuine_bundle`) -- this is the genuine ACCEPT path,
    not just "reaches the pipeline without crashing".
    """
    stc = ServerTestClient(app_client)
    decision = stc.full_genuine_flow(n_frames=30)

    assert decision.decision == "ACCEPT"
    failed_binding_codes = [c for c in decision.reason_codes if c.startswith("BIND_")]
    assert failed_binding_codes == []
    assert "B6_OK" in decision.reason_codes
    assert "REUSE_OK" in decision.reason_codes
    # Three of six detectors still don't exist -- absent, never defaulted to benign.
    # MORPH left this list on 2026-09-06 when morph.py landed; the three that remain are
    # dataset-blocked (§6), not unimplemented by choice.
    for name in ("PAD", "DEEPFAKE", "REPLAY"):
        assert f"MISSING_SIGNAL_{name}" in decision.reason_codes
    assert "MISSING_SIGNAL_MORPH" not in decision.reason_codes
    for scored in ("match", "injection", "morph"):
        assert scored in decision.detector_scores
    assert decision.receipt_signature != b""


def test_happy_path_stage_latency_is_real_per_request_measurement(app_client):
    """Every pipeline stage's latency is instrumented (the data behind F2/§8.3), and
    varies between two independent requests -- proof it's a real measurement, not a
    constant/sampled placeholder.
    """
    stc1 = ServerTestClient(app_client, device_id="device-lat-1")
    stc2 = ServerTestClient(app_client, device_id="device-lat-2")
    d1 = stc1.full_genuine_flow(n_frames=30)
    d2 = stc2.full_genuine_flow(n_frames=30)

    expected_stages = {
        "crypto",
        "binding_fail_fast",
        "quality_face",
        "cheap_signals",
        "evidence_reuse",
        "heavy_models",
        "fusion",
    }
    assert expected_stages <= set(d1.stage_latency_ms.keys())
    assert all(v >= 0.0 for v in d1.stage_latency_ms.values())
    # not hardcoded/faked -- independent requests measure independently
    assert d1.stage_latency_ms != d2.stage_latency_ms


def test_receipt_signature_verifies_against_published_server_public_key(app_client):
    stc = ServerTestClient(app_client)
    decision = stc.full_genuine_flow(n_frames=30)

    server_signer = get_signer("pq")
    assert verify_decision_signature(decision, server_signer, stc.server_sig_pk)


def test_receipt_signature_rejected_against_wrong_public_key(app_client):
    stc = ServerTestClient(app_client)
    decision = stc.full_genuine_flow(n_frames=30)

    server_signer = get_signer("pq")
    wrong_pk, _wrong_sk = server_signer.keygen()
    assert not verify_decision_signature(decision, server_signer, wrong_pk)


def test_event_loop_stays_responsive_while_verify_is_in_flight(app_client):
    """The DoD's actual concern -- "event loop must never block on torch" -- is best
    shown directly: fire several slow /v1/verify requests (each several hundred ms of
    CPU-bound ONNX/PQC work) concurrently, and confirm /v1/health, which touches none
    of that work, keeps responding fast throughout. If the event loop were blocked
    synchronously inside a pipeline stage, health checks would queue up behind it.
    """
    n_concurrent = 3
    clients = [
        ServerTestClient(app_client, device_id=f"device-health-{i}") for i in range(n_concurrent)
    ]
    prepared = []
    for stc in clients:
        stc.enroll()
        session_id, challenge_obj = stc.challenge()
        keys = stc.handshake(session_id)
        bundle = stc.build_live_genuine_bundle(session_id, challenge_obj, n_frames=30)
        prepared.append((stc, session_id, bundle, keys))

    health_latencies_ms: list[float] = []
    stop = False

    def _poll_health() -> None:
        while not stop:
            start = time.perf_counter()
            r = app_client.get("/v1/health")
            health_latencies_ms.append((time.perf_counter() - start) * 1000.0)
            assert r.status_code == 200

    with ThreadPoolExecutor(max_workers=n_concurrent + 1) as pool:
        health_future = pool.submit(_poll_health)
        verify_futures = [
            pool.submit(stc.verify, session_id, bundle, keys)
            for stc, session_id, bundle, keys in prepared
        ]
        for f in verify_futures:
            f.result()
        stop = True
        health_future.result()

    assert len(health_latencies_ms) >= 3, "health endpoint should have been polled repeatedly"
    # a blocked event loop would show health checks stalling for hundreds of ms behind
    # the CPU-bound verify() calls; a live one keeps them fast throughout
    assert statistics.median(health_latencies_ms) < 100.0, health_latencies_ms


def test_verify_p99_does_not_scale_linearly_with_concurrency(app_client):
    """Compares per-request latency at low vs higher concurrency. A blocked event loop
    (or an executor that serialises everything) would make p99 grow roughly linearly
    with the number of concurrent requests; genuine off-loop concurrency keeps it much
    flatter than that.
    """

    def _prepare(n: int, prefix: str):
        prepared = []
        for i in range(n):
            stc = ServerTestClient(app_client, device_id=f"device-{prefix}-{i}")
            stc.enroll()
            session_id, challenge_obj = stc.challenge()
            keys = stc.handshake(session_id)
            bundle = stc.build_live_genuine_bundle(session_id, challenge_obj, n_frames=30)
            prepared.append((stc, session_id, bundle, keys))
        return prepared

    def _run_concurrent(prepared) -> list[float]:
        def _timed_verify(item):
            stc, session_id, bundle, keys = item
            start = time.perf_counter()
            stc.verify(session_id, bundle, keys)
            return (time.perf_counter() - start) * 1000.0

        with ThreadPoolExecutor(max_workers=len(prepared)) as pool:
            return list(pool.map(_timed_verify, prepared))

    low = _run_concurrent(_prepare(2, "conc-low"))
    high = _run_concurrent(_prepare(6, "conc-high"))

    p99_low = max(low)
    p99_high = max(high)
    # 3x the concurrency should not come anywhere near 3x the per-request latency;
    # generous bound (2x) to keep this robust against normal machine-load noise
    assert p99_high < p99_low * 2.0, (p99_low, p99_high, low, high)
