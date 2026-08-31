"""CPU/RSS/GPU resource sampling during a load run (PROJECT_SPEC.md §8.2).

Owner: Abhijay

`ResourceSampler` runs in a background thread, polling `psutil` every 100ms — sampling
from inside the same coroutine being measured would perturb it; a separate OS thread
polling process-wide counters does not (`psutil.cpu_percent` and
`Process.memory_info()` are both cheap, non-blocking C-level calls, not something that
competes for the same asyncio event loop or GIL-heavy work the pipeline needs).

GPU sampling is `pynvml`, skipped cleanly (a `blocked()` cell, not an exception) if no
GPU is present or the NVML shared library can't be found -- true in this environment
(verified: `pynvml.nvmlInit()` raises `NVML Shared Library Not Found` here).
"""

from __future__ import annotations

import statistics
import threading
import time
from pathlib import Path
from typing import Any

import psutil

from pqbio.bench._common import RESULTS_DIR, print_progress, run_metadata, write_json

DEFAULT_SAMPLE_INTERVAL_S = 0.1


class ResourceSampler:
    """Samples this process's CPU% (per-core) and RSS every `interval_s` seconds on a
    background thread between `.start()` and `.stop()`.
    """

    def __init__(self, interval_s: float = DEFAULT_SAMPLE_INTERVAL_S) -> None:
        self._interval_s = interval_s
        self._process = psutil.Process()
        # Process.cpu_percent() (not the module-level, whole-system percpu variant) --
        # a single float that can exceed 100% on a multi-core process (e.g. 350% means
        # 3.5 cores' worth of this process's own CPU time), which is the number that
        # actually answers "how much of the machine is our workload using", not
        # per-core system-wide load from unrelated processes.
        self._cpu_samples: list[float] = []
        self._rss_samples: list[int] = []
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def _sample_loop(self) -> None:
        # A first call to cpu_percent() with no interval just primes the internal
        # counter and always returns 0.0 -- prime it once before the timed loop so the
        # first real sample is meaningful.
        self._process.cpu_percent()
        while not self._stop_event.is_set():
            time.sleep(self._interval_s)
            self._cpu_samples.append(self._process.cpu_percent())
            self._rss_samples.append(self._process.memory_info().rss)

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sample_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval_s * 5)

    def summary(self) -> dict[str, Any]:
        if not self._cpu_samples or not self._rss_samples:
            return {
                "n_samples": 0,
                "note": "no samples collected (sampled interval likely longer than the workload)",
            }
        # steady-state RSS: median of the later half of samples, once the workload has
        # ramped up past any one-off startup allocation spike.
        steady_start = len(self._rss_samples) // 2
        steady_state_rss = self._rss_samples[steady_start:] or self._rss_samples
        return {
            "n_samples": len(self._cpu_samples),
            "interval_s": self._interval_s,
            "cpu_percent_mean": statistics.mean(self._cpu_samples),
            "cpu_percent_peak": max(self._cpu_samples),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "rss_peak_bytes": max(self._rss_samples),
            "rss_steady_state_bytes": statistics.median(steady_state_rss),
        }


def gpu_summary() -> dict[str, Any]:
    try:
        import pynvml

        pynvml.nvmlInit()
        try:
            count = pynvml.nvmlDeviceGetCount()
            if count == 0:
                return {"blocked": True, "blocker": "pynvml reports zero GPU devices"}
            devices = []
            for i in range(count):
                handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                util = pynvml.nvmlDeviceGetUtilizationRates(handle)
                mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
                devices.append(
                    {
                        "name": pynvml.nvmlDeviceGetName(handle),
                        "utilization_percent": util.gpu,
                        "memory_used_bytes": mem.used,
                        "memory_total_bytes": mem.total,
                    }
                )
            return {"devices": devices}
        finally:
            pynvml.nvmlShutdown()
    except Exception as exc:
        return {
            "blocked": True,
            "blocker": f"no GPU / NVML unavailable in this environment: {exc}",
        }


def sample_during(fn: Any, *, interval_s: float = DEFAULT_SAMPLE_INTERVAL_S) -> dict[str, Any]:
    """Runs `fn()` (a synchronous callable — wrap an async workload in `asyncio.run`
    yourself before passing it here) while sampling CPU/RSS in the background, and
    returns the resource summary alongside whatever `fn()` returned.
    """
    sampler = ResourceSampler(interval_s=interval_s)
    sampler.start()
    try:
        fn_result = fn()
    finally:
        sampler.stop()
    return {
        **run_metadata(),
        "cpu_rss": sampler.summary(),
        "gpu": gpu_summary(),
        "workload_result": fn_result,
    }


def main() -> None:
    import argparse

    from pqbio.bench.latency import measure_latency

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-requests", type=int, default=50)
    parser.add_argument("--n-frames", type=int, default=6)
    parser.add_argument("--interval-s", type=float, default=DEFAULT_SAMPLE_INTERVAL_S)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "resources.json")
    args = parser.parse_args()

    print_progress(
        f"resources: sampling every {args.interval_s}s while running {args.n_requests} "
        "verify requests as the representative workload..."
    )
    result = sample_during(
        lambda: measure_latency(n_requests=args.n_requests, n_frames=args.n_frames),
        interval_s=args.interval_s,
    )
    write_json(args.out, result)
    print_progress(f"wrote {args.out}")


if __name__ == "__main__":
    main()
