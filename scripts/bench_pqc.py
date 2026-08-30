"""Module A crypto micro-benchmark (PROJECT_SPEC.md §5.1 DoD item 5).

Times keygen/encaps/decaps (KEM) and keygen/sign/verify (Signer) for both crypto modes
(classical, pq), mean and p95 over >=1000 iterations, plus artefact sizes in bytes.
Writes results/pqc_micro.json with the git commit, config hash, and hardware
description recorded alongside the numbers (PROJECT_SPEC.md §0: never fabricate
benchmark numbers — every number here comes from an actual timed call).

Usage:
    python scripts/bench_pqc.py [--iterations 1000] [--out results/pqc_micro.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pqbio.config import DEFAULT_CONFIG_PATH  # noqa: E402
from pqbio.pqc.kem import KemMode, get_kem  # noqa: E402
from pqbio.pqc.sign import SigMode, get_signer  # noqa: E402

MODES: list[KemMode] = ["classical", "pq"]
DEFAULT_ITERATIONS = 1000


def _percentile(values: list[float], pct: float) -> float:
    values_sorted = sorted(values)
    if len(values_sorted) == 1:
        return values_sorted[0]
    k = (len(values_sorted) - 1) * (pct / 100)
    f, c = int(k), min(int(k) + 1, len(values_sorted) - 1)
    if f == c:
        return values_sorted[f]
    return values_sorted[f] + (values_sorted[c] - values_sorted[f]) * (k - f)


def _time_ms(fn: Callable[[], Any], iterations: int) -> dict[str, float]:
    samples = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return {
        "mean_ms": statistics.mean(samples),
        "p95_ms": _percentile(samples, 95),
        "min_ms": min(samples),
        "max_ms": max(samples),
        "iterations": iterations,
    }


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "unknown (not a git repository at benchmark time)"


def _config_hash() -> str:
    return hashlib.sha256(DEFAULT_CONFIG_PATH.read_bytes()).hexdigest()


def _hardware_description() -> dict[str, str]:
    return {
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
    }


def bench_kem(mode: KemMode, iterations: int) -> dict[str, Any]:
    kem = get_kem(mode)
    keygen_stats = _time_ms(lambda: kem.keygen(), iterations)

    pk, sk = kem.keygen()
    encaps_stats = _time_ms(lambda: kem.encapsulate(pk), iterations)

    ct, ss = kem.encapsulate(pk)
    decaps_stats = _time_ms(lambda: kem.decapsulate(ct, sk), iterations)

    return {
        "backend": kem.backend,
        "artefact_sizes_bytes": {
            "pk": len(pk),
            "sk": len(sk),
            "ct": len(ct),
            "ss": len(ss),
        },
        "keygen": keygen_stats,
        "encaps": encaps_stats,
        "decaps": decaps_stats,
    }


def bench_signer(mode: SigMode, iterations: int) -> dict[str, Any]:
    signer = get_signer(mode)
    keygen_stats = _time_ms(lambda: signer.keygen(), iterations)

    pk, sk = signer.keygen()
    msg = b"pq-bio-auth benchmark message"
    sign_stats = _time_ms(lambda: signer.sign(msg, sk), iterations)

    sig = signer.sign(msg, sk)
    verify_stats = _time_ms(lambda: signer.verify(msg, sig, pk), iterations)

    return {
        "backend": signer.backend,
        "artefact_sizes_bytes": {"pk": len(pk), "sk": len(sk), "sig": len(sig)},
        "keygen": keygen_stats,
        "sign": sign_stats,
        "verify": verify_stats,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "results" / "pqc_micro.json")
    args = parser.parse_args()

    print(
        f"Running PQC micro-benchmark: {args.iterations} iterations per operation x "
        f"{len(MODES)} modes x (3 KEM ops + 3 signer ops)...",
        file=sys.stderr,
    )

    result = {
        "git_commit": _git_commit(),
        "config_hash_sha256": _config_hash(),
        "hardware": _hardware_description(),
        "iterations_per_operation": args.iterations,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "kem": {},
        "signer": {},
    }
    for mode in MODES:
        print(f"  kem/{mode}...", file=sys.stderr)
        result["kem"][mode] = bench_kem(mode, args.iterations)
    for mode in MODES:
        print(f"  signer/{mode}...", file=sys.stderr)
        result["signer"][mode] = bench_signer(mode, args.iterations)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
