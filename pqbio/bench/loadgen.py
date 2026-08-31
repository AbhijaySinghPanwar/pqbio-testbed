"""Concurrency sweep and throughput load generator against the real `/v1/verify`
endpoint (PROJECT_SPEC.md §8.2 throughput row), via asyncio + httpx as specified.

Owner: Abhijay

This doubles as the real test of Module E's "event loop never blocked" claim: session
setup (enroll/challenge/handshake/bundle-build) for every request in a sweep level is
done up front, unmetered, so only the timed `POST /v1/verify` calls at that concurrency
level count toward throughput and latency. If the event loop were blocked anywhere in
the pipeline, p99 latency would grow roughly linearly with concurrency; `_degradation_finding`
computes and reports that ratio explicitly, in both directions -- a clean result is not
assumed, it is measured and stated (PROJECT_SPEC.md's instruction: "report that finding
explicitly either way").
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import httpx

from pqbio.bench._common import (
    RESULTS_DIR,
    AsyncBenchClient,
    latency_stats,
    print_progress,
    run_metadata,
    shared_face_box,
    write_json,
)
from pqbio.server.app import create_app

DEFAULT_CONCURRENCY_LEVELS = (1, 2, 4, 8, 16, 32, 64)
DEFAULT_REQUESTS_PER_WORKER = 1
DEFAULT_N_FRAMES = 6


async def _prepare_one(
    device: AsyncBenchClient,
    n_frames: int,
    seed: int,
    face_box: tuple[int, int, int, int] | None = None,
) -> tuple[AsyncBenchClient, Any, Any, Any] | None:
    try:
        await device.enroll()
        session_id, challenge_body = await device.challenge()
        keys = await device.handshake(session_id)
        bundle = device.build_bundle(
            session_id, challenge_body, n_frames=n_frames, seed=seed, face_box=face_box
        )
        return device, session_id, bundle, keys
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 409:
            # Even with setup parallelised (see this function's caller), at high
            # concurrency the setup calls themselves (enroll/challenge/handshake, each
            # its own executor-bound ML-DSA/ML-KEM operation) can queue up behind
            # server.workers' limited pool long enough that a session's 30s challenge
            # TTL expires before handshake() even completes -- a real, reportable
            # scalability limit of this environment's slow crypto backend, not a
            # harness bug. Counted as a setup failure, not raised.
            return None
        raise


async def _prepare_requests(
    http: httpx.AsyncClient, concurrency: int, requests_per_worker: int, n_frames: int
) -> tuple[list[tuple[AsyncBenchClient, Any, Any, Any]], int]:
    """Enroll, challenge, handshake, and build a signed bundle for every request this
    sweep level will send -- unmetered setup, since a session is single-use (at-most-once
    VERIFIED transition, §5.1) and cannot be reused across the timed calls below.
    Returns (successfully prepared requests, count that failed setup with a 409).

    Prepared **concurrently**, not one device at a time: a session's challenge has a
    30s TTL (`binding.challenge_ttl_s`), and at high concurrency a purely sequential
    setup loop can take long enough that the first devices prepared have their
    challenge expire before their (also queued-up) verify() call ever runs, surfacing
    as a spurious 409 that has nothing to do with the event-loop-blocking question this
    sweep actually exists to answer. Preparing everyone at roughly the same time is
    also the more realistic simulation of concurrent load in the first place -- though
    at the top of the sweep (concurrency=64) even parallel setup itself can still run
    into the same TTL wall; see `_prepare_one`.
    """
    total = concurrency * requests_per_worker
    devices = [
        AsyncBenchClient(http, device_id=f"loadgen-c{concurrency}-{i}") for i in range(total)
    ]
    # One SCRFD inference for the whole level instead of one per device: it is identical
    # for every device (same base crop) and running it per device serialises `total`
    # blocking inferences on the event loop *inside* the challenge TTL window.
    face_box = shared_face_box()
    results = await asyncio.gather(
        *[_prepare_one(d, n_frames, i, face_box) for i, d in enumerate(devices)]
    )
    prepared = [r for r in results if r is not None]
    setup_failed = len(results) - len(prepared)
    return prepared, setup_failed


async def _run_sweep_level(
    app: Any, concurrency: int, requests_per_worker: int, n_frames: int
) -> dict[str, Any]:
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://bench", timeout=60.0
        ) as http:
            prepared, setup_failed = await _prepare_requests(
                http, concurrency, requests_per_worker, n_frames
            )

            sem = asyncio.Semaphore(concurrency)
            latencies: list[float] = []
            decisions: dict[str, int] = {}
            expired_count = 0

            async def _one(item: tuple[Any, Any, Any, Any]) -> None:
                nonlocal expired_count
                device, session_id, bundle, keys = item
                async with sem:
                    try:
                        outcome = await device.verify(session_id, bundle, keys)
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 409:
                            # The session's 30s challenge TTL (binding.challenge_ttl_s)
                            # elapsed before this request's turn came up in a saturated
                            # queue -- a real outcome under sustained overload, not a
                            # harness bug (see loadgen.py's own module docstring on
                            # `_prepare_requests`). Recorded, not hidden.
                            expired_count += 1
                            return
                        raise
                latencies.append(outcome.client_latency_ms)
                d = str(outcome.decision["decision"])
                decisions[d] = decisions.get(d, 0) + 1

            start = time.perf_counter()
            await asyncio.gather(*[_one(item) for item in prepared])
            wall_s = time.perf_counter() - start

    requested = concurrency * requests_per_worker
    throughput = len(latencies) / wall_s if wall_s > 0 else 0.0
    result: dict[str, Any] = {
        "concurrency": concurrency,
        "requested": requested,
        "setup_failed_before_verify": setup_failed,
        "expired_before_verify": expired_count,
        "wall_time_s": wall_s,
        "throughput_per_s": throughput,
        "decision_outcomes": decisions,
    }
    if latencies:
        result["latency"] = latency_stats(latencies)
    else:
        result["latency"] = {
            "n": 0,
            "note": "no request at this concurrency level reached a completed verify() "
            "-- see setup_failed_before_verify/expired_before_verify",
        }
    return result


def _find_knee(
    levels: list[dict[str, Any]], marginal_gain_threshold: float = 0.10
) -> dict[str, Any]:
    """The smallest concurrency level after which throughput's marginal gain over the
    previous level drops below `marginal_gain_threshold` (default 10%) -- i.e. where
    adding more concurrent load stops paying off. If throughput keeps climbing right to
    the top of the sweep, that is reported honestly too (no knee found within range).
    """
    for i in range(1, len(levels)):
        prev_tp = levels[i - 1]["throughput_per_s"]
        cur_tp = levels[i]["throughput_per_s"]
        if prev_tp > 0 and (cur_tp - prev_tp) / prev_tp < marginal_gain_threshold:
            return {
                "concurrency": levels[i - 1]["concurrency"],
                "reason": (
                    f"throughput gain from concurrency={levels[i - 1]['concurrency']} to "
                    f"{levels[i]['concurrency']} was {(cur_tp - prev_tp) / prev_tp:.1%}, "
                    f"below the {marginal_gain_threshold:.0%} threshold"
                ),
            }
    return {
        "concurrency": None,
        "reason": (
            "throughput kept climbing by >= "
            f"{marginal_gain_threshold:.0%} at every step through the top of the sweep "
            f"(concurrency={levels[-1]['concurrency']}) -- no knee found in this range"
        ),
    }


def _degradation_finding(
    levels: list[dict[str, Any]], linear_threshold: float = 0.5
) -> dict[str, Any]:
    """Characterises how p99 latency grows with offered concurrency, split at the point
    where throughput peaks (i.e. where the server saturates).

    `linear_threshold` (default 0.5) is how much of "fully proportional" growth counts
    as notable -- p99 growing at >=50% of the concurrency growth rate, measured over the
    *unsaturated* region only. Past saturation, proportional growth is Little's law, not
    a defect, and reading it as one is a mistake this function used to make (§14,
    2026-09-01).

    Deliberately does **not** claim to answer "is the event loop blocked" by itself: on
    a CPU-bound pipeline, worker-pool and CPU contention produce the same curve. The
    returned `finding` says so explicitly and names the direct test that does answer it.
    """
    with_latency = [lvl for lvl in levels if "p99_ms" in lvl.get("latency", {})]
    zero_completion_levels = [
        lvl["concurrency"] for lvl in levels if "p99_ms" not in lvl.get("latency", {})
    ]
    collapse_note = (
        (
            f" Separately: concurrency level(s) {zero_completion_levels} completed *zero* "
            "requests before every session's 30s challenge TTL elapsed -- a real "
            "scalability ceiling of this environment's slow PQC fallback + AI pipeline "
            "under sustained load at that concurrency, not the event-loop-blocking "
            "question this comparison is about. See setup_failed_before_verify/"
            "expired_before_verify on those levels."
        )
        if zero_completion_levels
        else ""
    )

    if len(with_latency) < 2:
        return {
            "linear_degradation_detected": None,
            "zero_completion_levels": zero_completion_levels,
            "finding": (
                "fewer than two concurrency levels completed any request before its "
                "session's challenge TTL expired -- cannot compare p99 growth across "
                "the sweep (see each level's expired_before_verify/"
                "setup_failed_before_verify counts)."
            )
            + collapse_note,
        }
    # The event-loop question is only answerable *below saturation*. Once throughput
    # stops rising, the server is saturated and p99 growing in proportion to offered
    # concurrency is simply queueing (Little's law), not a blocked coroutine — reading
    # post-saturation growth as "the event loop is blocked" would be wrong, and this
    # function used to do exactly that (§14, 2026-09-01). So the verdict is computed
    # over the unsaturated region: from the lowest level up to peak throughput.
    peak_idx = max(range(len(with_latency)), key=lambda i: with_latency[i]["throughput_per_s"])
    unsaturated = with_latency[: peak_idx + 1]
    first, last = with_latency[0], with_latency[-1]
    p99_first = first["latency"]["p99_ms"]
    p99_last = last["latency"]["p99_ms"]

    if len(unsaturated) >= 2:
        u_first, u_last = unsaturated[0], unsaturated[-1]
        u_p99_ratio = (
            u_last["latency"]["p99_ms"] / u_first["latency"]["p99_ms"]
            if u_first["latency"]["p99_ms"] > 0
            else float("inf")
        )
        u_conc_ratio = u_last["concurrency"] / u_first["concurrency"]
        is_linear = u_p99_ratio >= u_conc_ratio * linear_threshold
        verdict = (
            "Below saturation, p99 grew "
            f"{u_p99_ratio:.2f}x while concurrency grew {u_conc_ratio:.0f}x "
            f"(concurrency={u_first['concurrency']}->{u_last['concurrency']}, peak "
            f"throughput {u_last['throughput_per_s']:.2f}/s). "
        )
        verdict += (
            "That is at or above proportional growth. "
            if is_linear
            else "That is well below proportional growth, i.e. per-request latency stays "
            "roughly flat while there is spare capacity. "
        )
    else:
        is_linear = None
        u_p99_ratio = None
        u_conc_ratio = None
        verdict = (
            "Peak throughput occurred at the lowest concurrency level, so there is no "
            "unsaturated region to read an event-loop verdict from."
        )

    saturation_note = (
        f" Past the peak, p99 rises to {p99_last:.0f}ms at concurrency="
        f"{last['concurrency']} (from {p99_first:.0f}ms at {first['concurrency']}) while "
        "throughput stays flat — expected queueing against a saturated worker pool "
        "(`server.workers` in config), not a separate defect."
    )

    # Stated rather than glossed over: this metric cannot answer the event-loop
    # question on its own. On a CPU-bound workload (this pipeline spends ~98% of a
    # request inside ONNX face inference, see results/overhead_ablation.json) latency
    # rising with concurrency is what worker-pool and CPU contention look like too, and
    # neither is a blocked coroutine. The discriminating test is a direct one.
    caveat = (
        " NOTE: latency growth alone cannot separate a blocked event loop from ordinary "
        "worker-pool/CPU saturation on a CPU-bound workload, so do not read the ratio "
        "above as a verdict on its own. The direct discriminator is "
        "tests/integration/test_server_happy_path.py::"
        "test_event_loop_stays_responsive_while_verify_is_in_flight, which polls "
        "GET /v1/health while concurrent /v1/verify calls are in flight and requires it "
        "to stay responsive — a blocked loop would stall those health checks behind the "
        "CPU-bound work, whatever the latency curve looks like."
    )

    return {
        "p99_ms_low_concurrency": p99_first,
        "p99_ms_high_concurrency": p99_last,
        "p99_growth_ratio_full_sweep": p99_last / p99_first if p99_first > 0 else float("inf"),
        "peak_throughput_concurrency": with_latency[peak_idx]["concurrency"],
        "peak_throughput_per_s": with_latency[peak_idx]["throughput_per_s"],
        "unsaturated_p99_growth_ratio": u_p99_ratio,
        "unsaturated_concurrency_growth_ratio": u_conc_ratio,
        "linear_degradation_detected": is_linear,
        "zero_completion_levels": zero_completion_levels,
        "finding": verdict + saturation_note + caveat + collapse_note,
    }


def sweep_concurrency(
    concurrency_levels: tuple[int, ...] = DEFAULT_CONCURRENCY_LEVELS,
    requests_per_worker: int = DEFAULT_REQUESTS_PER_WORKER,
    n_frames: int = DEFAULT_N_FRAMES,
) -> dict[str, Any]:
    import tempfile

    levels: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as tmp:
        for concurrency in concurrency_levels:
            print_progress(f"loadgen: concurrency={concurrency}...")
            app = create_app(data_dir=Path(tmp) / f"data-c{concurrency}")
            level_result = asyncio.run(
                _run_sweep_level(app, concurrency, requests_per_worker, n_frames)
            )
            levels.append(level_result)
            p99 = level_result["latency"].get("p99_ms")
            p99_str = f"{p99:.1f}ms" if p99 is not None else "n/a (no request completed verify())"
            print_progress(
                f"  -> {level_result['throughput_per_s']:.3f} verifications/sec, "
                f"p99={p99_str}, setup_failed={level_result['setup_failed_before_verify']}, "
                f"expired={level_result['expired_before_verify']}"
            )

    return {
        **run_metadata(
            extra={"n_frames_per_bundle": n_frames, "requests_per_worker": requests_per_worker}
        ),
        "concurrency_levels": levels,
        "knee": _find_knee(levels),
        "degradation_finding": _degradation_finding(levels),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--concurrency-levels", type=int, nargs="+", default=list(DEFAULT_CONCURRENCY_LEVELS)
    )
    parser.add_argument("--requests-per-worker", type=int, default=DEFAULT_REQUESTS_PER_WORKER)
    parser.add_argument("--n-frames", type=int, default=DEFAULT_N_FRAMES)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "loadgen.json")
    args = parser.parse_args()

    result = sweep_concurrency(
        concurrency_levels=tuple(args.concurrency_levels),
        requests_per_worker=args.requests_per_worker,
        n_frames=args.n_frames,
    )
    write_json(args.out, result)
    print_progress(f"wrote {args.out}")
    print_progress(f"knee: {result['knee']}")
    print_progress(f"degradation finding: {result['degradation_finding']['finding']}")


if __name__ == "__main__":
    main()
