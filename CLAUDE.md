# CLAUDE.md

Working conventions for this repo. Read PROJECT_SPEC.md first — it is the single source
of truth; this file is the terse, imperative version of its §11 for day-to-day work.

## Current state (keep this updated as work lands)

- **Scaffolded, not implemented:** full directory tree (§3), `pyproject.toml`, `Makefile`,
  `config/default.yaml` + `pqbio/config.py`, `pqbio/schemas.py` (wire models + canonical
  CBOR helpers), `docker-compose.yml` + `docker/Dockerfile.server` (not build-verified —
  no Docker engine in the dev environment this was written in), `.github/workflows/ci.yml`.
- **Implemented: Module A — `pqbio/pqc/`** (kem.py, sign.py, kdf.py, aead.py,
  handshake.py, keystore.py). Two modes only — `classical` and `pq` — matching
  PROJECT_SPEC.md §5.1 exactly (an earlier draft of the spec also asked for a `hybrid`
  mode; that was built, then removed when the spec was trimmed down to
  "requirements-only" — don't reintroduce it without checking the spec again first).
  See "PQC backend" below — running on the documented `kyber-py`/`dilithium-py`
  fallback, not liboqs, in this environment.
- **Placeholder only (docstring naming owner + purpose, no logic):** `pqbio/capture/`,
  `pqbio/binding/`, `pqbio/detect/`, `pqbio/server/`, `pqbio/bench/`, and all of
  `scripts/` except `scripts/bench_pqc.py` (implemented, Module A's micro-benchmark).
- Do not start Module B/C/D/E/F without explicit instruction — see PROJECT_SPEC.md §0
  and §10 for the intended build order.

## PQC backend (read before touching pqbio/pqc/)

`liboqs-python` (the primary backend per §4) requires a C build: CMake, Ninja, and a C
compiler. This dev environment has none of those usable (no `cmake`/`ninja` on PATH, no
MSVC C++ workload, only a 32-bit MinGW.org gcc 6.3 from 2016), so `import oqs` fails.

Per an explicit, documented instruction, `pqbio/pqc/kem.py` and `pqbio/pqc/sign.py`
fall back at runtime to `kyber_py.ml_kem.ML_KEM_768` / `dilithium_py.ml_dsa.ML_DSA_65` —
pure-Python FIPS 203/204 reference implementations — never to a mock or a different
algorithm. Both modules expose `KEM_BACKEND` / `SIG_BACKEND` (`"liboqs"` or
`"...-fallback"`); every result that gets persisted (bench JSON, audit log, receipts)
should record which backend produced it. `results/pqc_micro.json` does this already.

The fallback's artefact sizes were verified against FIPS 203/204 exactly (pk/sk/ct/sig
byte lengths). It is **not** verified against liboqs' own KAT vectors (needs the liboqs
C source) and is **not constant-time** — treat any latency number produced under the
fallback as an upper bound on the fallback's cost, not as liboqs' cost, and do not use
it for a timing-side-channel argument.

**To switch to the real backend:** install a C++ toolchain (Visual Studio Build Tools
"Desktop development with C++" workload, or mingw-w64), then
`pip install -e ".[pqc-liboqs]"`. No code changes needed — both modules detect `oqs`
at import time and prefer it automatically.

## Code

- Python 3.11, `ruff` + `black` (line length 100), `mypy --strict` on `pqc/`, `binding/`,
  `server/`.
- Type hints everywhere. Pydantic models for anything crossing a boundary.
- No bare `except`. Errors carry reason codes.
- No magic numbers — everything in `config/default.yaml`, loaded via `pqbio/config.py`.
- Structured logging (`structlog`), JSON output, never log raw biometric data.

## Crypto

- Never roll your own primitive. Use liboqs / `cryptography` (or the documented
  kyber-py/dilithium-py fallback above — still someone else's audited-enough primitive,
  not a homebrew one).
- Constant-time comparison for all secrets and MACs: `pqbio.pqc.sign.constant_time_eq`
  (wraps `hmac.compare_digest`).
- Sign the canonical CBOR encoding (`pqbio.schemas.model_signing_payload`), never a JSON
  string — key ordering will bite you.
- Fail closed. If a check cannot be evaluated, it fails.

## ML

- Seed everything: `random`, `numpy`, `torch`, and `torch.backends.cudnn.deterministic = True`.
- One config file per experiment, committed alongside the result.
- Save model SHA-256 to `models/checksums.txt` and record it in every decision object.
- Never evaluate on the training split. Subject-disjoint splits, enforced by an assertion
  in the data loader.

## Git

- Conventional commits. Feature branches per module: `feat/pqc-kem`, `feat/detect-morph`.
- `results/` and `data/manifests/` are committed. `data/raw/`, `data/processed/`,
  `models/*.pt` are not (see `.gitignore`).

## Reporting

- Every number in the report is traceable to a JSON file in `results/`.
- If a result is bad, report it and explain it. Never tune a threshold on the test set.
- Never fabricate benchmark numbers (PROJECT_SPEC.md §0). If a number can't be produced
  by real code right now, say so instead of inventing one.
