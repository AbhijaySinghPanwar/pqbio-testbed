# pq-bio-auth

AI-based biometric evidence authentication for post-quantum digital identity systems.
See [`PROJECT_SPEC.md`](PROJECT_SPEC.md) for the full build specification — this file is
a quickstart, not a substitute for it.

## Status

Early scaffold. Only **Module A — the PQC layer** (`pqbio/pqc/`) is implemented; every
other package under `pqbio/` is a placeholder. See [`CLAUDE.md`](CLAUDE.md) "current
state" for the up-to-date module-by-module status.

## Setup

Requires Python 3.11.

```bash
python3.11 -m venv .venv
source .venv/bin/activate          # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

The primary PQC backend (`liboqs-python`) needs a C toolchain (CMake, Ninja, a C
compiler) and is an opt-in extra:

```bash
pip install -e ".[pqc-liboqs]"
```

Without it, `pqbio.pqc` transparently falls back to a pure-Python FIPS 203/204
reference implementation (`kyber-py` / `dilithium-py`) — see `pqbio/pqc/kem.py` and
`pqbio/pqc/sign.py` for exactly what that means and how to switch backends.

## Running things

```bash
make lint        # ruff + black --check
make typecheck    # mypy --strict on pqc/, binding/, server/
make test         # pytest
python scripts/bench_pqc.py   # Module A crypto micro-benchmark -> results/pqc_micro.json
```

`make bench`, `make report`, and `make demo` are stubs until Module F and Module E land
(see `PROJECT_SPEC.md` §5.6, §5.5).

## Docker

`docker-compose.yml` (server) and `docker/Dockerfile.server` are written per
spec but not build-verified in this environment (no Docker engine available when this
scaffold was created). Verify `docker compose up --build` on a machine with Docker
before relying on it.
