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
  "requirements-only" — don't reintroduce it without checking the spec again first,
  see §14 Amendments). KATs verified against real NIST ACVP vectors
  (`tests/vectors/`), not just self-consistency. Running on the documented
  `kyber-py`/`dilithium-py` fallback, not liboqs, in this environment — see "PQC
  backend" below. `pqbio/bench/overhead.py` has only its fallback-backend guard
  implemented (`guard_against_fallback_backend()`); the C0-C3 ablation itself isn't
  built.
- **Implemented: Module B — `pqbio/capture/`** (camera.py, replay_source.py,
  challenge.py, bundler.py, `__main__.py` for the CLI). `CameraSource` is untested
  against a real webcam (none attached in this environment) — everything else
  (`ReplaySource`, the chromaticity-measurement half of the illumination challenge,
  bundling/signing/tamper-detection, the CLI) is tested, including one true
  subprocess end-to-end run. `render_challenge_fullscreen` needs a display and has
  never been run. `challenge.py`'s `estimate_face_box` now calls Module D's real SCRFD
  detector (the old fixed-centre-crop placeholder is deleted), falling back to a
  geometric centre crop only when detection finds nothing.
- **Implemented: Module C — `pqbio/binding/`** (nonce.py, phash_index.py, verify.py).
  All six B1-B6 checks plus the separate pHash reuse check, each with positive and
  negative tests; nonce single-use consumption verified atomic under a real 100-thread
  race (`tests/unit/test_nonce_store.py`); reuse check verified against exact,
  re-encoded, and rescaled resubmission, and to survive a process restart
  (BK-tree rebuilt from SQLite). Reuse now fires on **N-of-burst**, not any single
  frame: `phash_hamming_max: 10` (the floor that still catches every re-encode/rescale/
  crop case measured) and `phash_reuse_min_frames: 30` (require every frame of the
  burst — the least-bad point measured, not one that hits the original <1% FPR target;
  burst frames turned out to be highly correlated under phash, so N barely helps — see
  §14 Amendments, `results/phash_burst_calibration.json`, before touching either value
  or assuming N alone will fix the residual false-positive rate). B6's
  frame-to-challenge-step timing alignment is an even-split
  approximation (Module B doesn't interleave live render+capture yet) — see
  `verify.py`'s `_expand_expected_trace`.
- **Implemented: parts of Module D — `pqbio/detect/`** (base.py, face.py, match.py,
  injection.py, fusion.py) **and its injection corpus**
  (`scripts/make_injection_corpus.py`). `pad.py`/`morph.py`/`deepfake.py`/`replay.py`
  are dataset-blocked (§6) and were deliberately left **absent, not stubbed** — do not
  add placeholder files for them without checking datasets have actually landed.
  SCRFD + ArcFace `buffalo_l` fetched once (`scripts/fetch_face_models.py`) and
  verified end-to-end against a real photo (`skimage.data.astronaut()` — no licensed
  face dataset exists yet, see §14). `fusion.py`'s input is missing 4 of 6 spec'd
  detector slots (represented as `None`, never defaulted to benign) — see its module
  docstring before trusting any fused number. Injection detector hits 100%
  train/test accuracy on the synthetic corpus; §14 explains why that's expected and
  not a production claim. Tier 2 (virtual camera) injection is blocked in this
  environment (no OBS, no admin rights) — tier 1 only, reason recorded in every
  manifest.
- **Implemented: Module E — `pqbio/server/`** (app.py, routes.py, pipeline.py,
  decision.py, store.py). Real enroll → challenge → handshake → verify → signed-decision
  flow, end-to-end through real crypto, verified by a passing integration test — not
  just the pieces tested in isolation. All eight pipeline stages (not just §5.5's named
  3-6) run off the event loop via a `ThreadPoolExecutor`, since this environment's PQC
  fallback backend makes stages 1 and 8 (ML-DSA verify/sign) genuinely blocking too —
  see `pipeline.py`'s module docstring. SQLite for keystore/sessions/audit
  (`store.py`), reusing Module C's `NonceStore`/`PhashIndex` as-is. Server refuses to
  start if any `models/checksums.txt` entry is missing or mismatched
  (`app.py:verify_all_model_checksums`). A2/A3/A4 (presentation/morph/deepfake) remain
  **blocked** — no detector exists to score them, only to confirm the pipeline reaches a
  real decision reporting `MISSING_SIGNAL_*` rather than silently accepting. See §14's
  2026-08-31 Module E amendment for two real accept-path gaps found and fixed while
  building this (phash reuse recording and B4 counter advance were never wired up to
  the accept path in the first draft), a Windows SQLite connection leak found by the
  test suite (fixed across `nonce.py`/`phash_index.py`/`store.py`), and why the signed
  receipt cannot report its own signing latency (the audit log does instead).
- **Implemented: Module F — `pqbio/bench/`** (accuracy.py, latency.py, loadgen.py,
  resources.py, overhead.py, report.py) **and `scripts/run_full_eval.py`** (`make
  bench`/`make report`). Every §8 metric has a real implementation; most §8.1 accuracy
  cells are `pqbio.bench._common.blocked(...)` (four detectors, three datasets absent —
  never a blank or a zero, see `results/BLOCKERS.md`, regenerated every run). §8.2
  latency/throughput/CPU/RSS are real, measured against the actual Module E app
  in-process over HTTP (`pqbio.bench._common.AsyncBenchClient`), concurrency swept to
  64. §8.3's C0 runs for real; C1/C2/C3 sit behind `overhead.py`'s pre-existing
  fallback-backend guard (unchanged) and report BLOCKED, not a number, on this
  environment's pure-Python PQC. `report.py` renders `results/report.md` (T1-T8, F1-F4)
  and `results/BLOCKERS.md` from JSON only — never hand-assembled. See §14's Module F
  amendment for a real concurrency-related bug this found and fixed in the bench
  harness itself (not Module E): sequential per-device setup at high concurrency let
  early-prepared sessions' 30s challenge TTL expire before their `verify()` call ran,
  surfacing as a spurious 409; fixed by parallelising setup and reporting expiry as a
  named outcome rather than crashing the sweep.
- **Placeholder only (docstring naming owner + purpose, no logic):** the remaining
  scripts under `scripts/` — `download_datasets.py`, `prepare_datasets.py`,
  `train_detector.py` — pending the same dataset licensing §6 blocks everywhere else.
- All six modules (A-F) are now implemented. Do not start `pad.py`/`morph.py`/
  `deepfake.py`/`replay.py`, or any dataset-dependent work, without
  explicit instruction — see PROJECT_SPEC.md §0 and §10 for the intended build order.

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
