"""End-to-end and per-stage latency measurement on the real `/v1/verify` endpoint
(PROJECT_SPEC.md §8.2), plus the crypto micro-benchmark's fallback ML-DSA signing cost
reported as its own line.

Owner: Abhijay

Two latency numbers exist for a reason, not by oversight:

- **Client-observed latency** (`AsyncBenchClient.verify`'s `client_latency_ms`): wall
  time of the `POST /v1/verify` call itself, p50/p95/p99'd across N requests -- this is
  what §8.2's "End-to-end latency" row asks for.
- **Server-side stage breakdown**: read directly from the audit log's `decision_json`
  after the run, not from the client-visible `Decision.stage_latency_ms` -- the signed
  receipt cannot include `sign_audit`'s own duration (a signature can't cover the time
  spent computing itself; see `pqbio/server/pipeline.py`'s module docstring), but the
  unsigned audit record can and does. Reading it here is what makes the receipt-signing
  cost visible as its own stacked-breakdown segment (F2) instead of silently missing
  from every per-request number — which matters most when it is large: ~155 ms under
  the pure-Python fallback, ~5 ms under liboqs (§14, 2026-09-01).
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

import httpx

from pqbio.bench._common import (
    RESULTS_DIR,
    AsyncBenchClient,
    latency_stats,
    print_progress,
    run_metadata,
    write_json,
)
from pqbio.server.app import create_app

DEFAULT_N_REQUESTS = 200
DEFAULT_N_FRAMES = 10


def _read_audit_stage_latencies(data_dir: Path) -> list[dict[str, float]]:
    """Every `stage_latency_ms` dict recorded in the audit log during this run -- the
    full breakdown, `sign_audit` included (see module docstring). Read-only, direct
    SQLite -- `AuditLog` itself has no "read everything back" method (write-only from
    the app's own perspective is the right shape for it; bench code reading its own
    just-created database afterward is a different, legitimate use).
    """
    audit_db = data_dir / "audit.db"
    if not audit_db.is_file():
        return []
    conn = sqlite3.connect(str(audit_db))
    try:
        rows = conn.execute("SELECT decision_json FROM audit_log ORDER BY id").fetchall()
    finally:
        conn.close()
    breakdowns = []
    for (decision_json,) in rows:
        decision = json.loads(decision_json)
        stage_latency_ms = decision.get("stage_latency_ms")
        if stage_latency_ms:
            breakdowns.append(stage_latency_ms)
    return breakdowns


def _stage_breakdown_summary(breakdowns: list[dict[str, float]]) -> dict[str, dict[str, float]]:
    """Per-stage latency_stats() across every recorded request -- the stacked
    breakdown F2 plots."""
    if not breakdowns:
        return {}
    stage_names = sorted({name for b in breakdowns for name in b})
    summary: dict[str, dict[str, float]] = {}
    for name in stage_names:
        samples = [b[name] for b in breakdowns if name in b]
        if samples:
            summary[name] = latency_stats(samples)
    return summary


def _ml_dsa_signing_cost_ms() -> dict[str, Any]:
    """ML-DSA-65 signing cost for whichever backend produced `results/pqc_micro.json`
    (measured over >=1000 iterations there, far more precise than re-deriving it from
    N in-pipeline sign calls); otherwise timed fresh here. Always carries the `backend`
    field, because the number means two completely different things depending on it:
    ~79 ms under the pure-Python kyber-py/dilithium-py fallback, ~0.11 ms under liboqs
    (§14, 2026-09-01). Reported as its own line, separable from the per-stage
    breakdown, per the Module F build instruction.
    """
    pqc_micro_path = RESULTS_DIR / "pqc_micro.json"
    if pqc_micro_path.is_file():
        data = json.loads(pqc_micro_path.read_text(encoding="utf-8"))
        pq_sign = data.get("signer", {}).get("pq", {})
        if pq_sign.get("sign"):
            return {
                "source": "results/pqc_micro.json",
                "backend": pq_sign.get("backend"),
                **pq_sign["sign"],
            }

    from pqbio.pqc.sign import get_signer

    signer = get_signer("pq")
    pk, sk = signer.keygen()
    msg = b"pqbio bench ML-DSA signing cost probe"
    samples = []
    import time

    for _ in range(200):
        t0 = time.perf_counter()
        signer.sign(msg, sk)
        samples.append((time.perf_counter() - t0) * 1000.0)
    return {"source": "measured fresh (results/pqc_micro.json not found)", **latency_stats(samples)}


async def _run_requests(app: Any, n_requests: int, n_frames: int) -> tuple[list[float], list[str]]:
    client_latencies: list[float] = []
    outcomes: list[str] = []
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://bench") as http:
            for i in range(n_requests):
                device = AsyncBenchClient(http, device_id=f"latency-bench-{i}")
                outcome = await device.full_flow(n_frames=n_frames, seed=i)
                client_latencies.append(outcome.client_latency_ms)
                outcomes.append(str(outcome.decision["decision"]))
                if (i + 1) % 25 == 0:
                    print_progress(f"  latency: {i + 1}/{n_requests} requests done")
    return client_latencies, outcomes


def measure_latency(
    n_requests: int = DEFAULT_N_REQUESTS, n_frames: int = DEFAULT_N_FRAMES
) -> dict[str, Any]:
    """Runs `n_requests` independent, real enroll->challenge->handshake->verify flows
    against an in-process Module E app and reports client-observed p50/p95/p99 plus the
    server-side per-stage breakdown read back from its audit log.
    """
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(tmp) / "data"
        app = create_app(data_dir=data_dir)
        print_progress(f"latency: running {n_requests} requests ({n_frames} frames each)...")
        client_latencies, outcomes = asyncio.run(_run_requests(app, n_requests, n_frames))
        breakdowns = _read_audit_stage_latencies(data_dir)

    decision_counts: dict[str, int] = {}
    for outcome in outcomes:
        decision_counts[outcome] = decision_counts.get(outcome, 0) + 1

    result: dict[str, Any] = {
        **run_metadata(
            seed=None, extra={"n_requests": n_requests, "n_frames_per_bundle": n_frames}
        ),
        "end_to_end_client_observed": latency_stats(client_latencies),
        # Raw samples, so a caller can put an interval on a difference of means rather
        # than subtract two point estimates (overhead.py's C3-C2 term).
        "end_to_end_client_observed_samples_ms": list(client_latencies),
        "decision_outcomes": decision_counts,
        "stage_breakdown": _stage_breakdown_summary(breakdowns),
        "ml_dsa_signing_cost": _ml_dsa_signing_cost_ms(),
        "note": (
            "end_to_end_client_observed times the POST /v1/verify call only (§8.2); "
            "stage_breakdown is read from the audit log after the run, not the signed "
            "receipt, because the receipt cannot report its own signing duration -- see "
            "pqbio/server/pipeline.py's module docstring."
        ),
    }
    return result


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-requests", type=int, default=DEFAULT_N_REQUESTS)
    parser.add_argument("--n-frames", type=int, default=DEFAULT_N_FRAMES)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "latency.json")
    args = parser.parse_args()

    result = measure_latency(n_requests=args.n_requests, n_frames=args.n_frames)
    write_json(args.out, result)
    print_progress(f"wrote {args.out}")


if __name__ == "__main__":
    main()
