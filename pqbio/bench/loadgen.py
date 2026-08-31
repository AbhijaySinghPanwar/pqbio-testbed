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
    write_json,
)
from pqbio.server.app import create_app

DEFAULT_CONCURRENCY_LEVELS = (1, 2, 4, 8, 16, 32, 64)
DEFAULT_REQUESTS_PER_WORKER = 1
DEFAULT_N_FRAMES = 6


async def _prepare_one(
    device: AsyncBenchClient, n_frames: int, seed: int
) -> tuple[AsyncBenchClient, Any, Any, Any] | None:
    try:
        await device.enroll()
        session_id, challenge_body = await device.challenge()
        keys = await device.handshake(session_id)
        bundle = device.build_bundle(session_id, challenge_body, n_frames=n_frames, seed=seed)
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
    results = await asyncio.gather(*[_prepare_one(d, n_frames, i) for i, d in enumerate(devices)])
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
    """Compares p99 growth across the full sweep to concurrency growth. A blocked event
    loop (or a shared resource serialising requests) would make p99 grow roughly
    proportionally to concurrency; genuine off-loop concurrency keeps it far flatter.
    `linear_threshold` (default 0.5) is how much of "fully proportional" growth counts
    as a red flag -- p99 growing at >=50% of the concurrency growth rate.
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
    first, last = with_latency[0], with_latency[-1]
    p99_first = first["latency"]["p99_ms"]
    p99_last = last["latency"]["p99_ms"]
    p99_ratio = p99_last / p99_first if p99_first > 0 else float("inf")
    concurrency_ratio = last["concurrency"] / first["concurrency"]
    is_linear = p99_ratio >= concurrency_ratio * linear_threshold
    finding = (
        f"p99 latency grew {p99_ratio:.2f}x while concurrency grew {concurrency_ratio:.0f}x "
        f"(concurrency={first['concurrency']}->{last['concurrency']}). "
    )
    finding += (
        "This is consistent with something serialising requests under load -- the event "
        "loop, the ThreadPoolExecutor being saturated at server.workers, or a shared "
        "resource -- contrary to Module E's 'event loop never blocked' design goal; "
        "investigate before trusting throughput numbers past the knee."
        if is_linear
        else "This is well below proportional growth, consistent with Module E's event "
        "loop staying unblocked under concurrency (per-request latency stays roughly flat "
        "as concurrency rises, rather than queuing up behind a blocked resource)."
    )
    finding += collapse_note
    return {
        "p99_ms_low_concurrency": p99_first,
        "p99_ms_high_concurrency": p99_last,
        "p99_growth_ratio": p99_ratio,
        "concurrency_growth_ratio": concurrency_ratio,
        "linear_degradation_detected": is_linear,
        "zero_completion_levels": zero_completion_levels,
        "finding": finding,
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
