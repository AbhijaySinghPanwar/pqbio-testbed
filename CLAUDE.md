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
  challenge.py, bundler.py, `__main__.py` for the CLI). `ReplaySource`, the
  chromaticity-measurement half of the illumination challenge,
  bundling/signing/tamper-detection and the CLI are tested, including one true
  subprocess end-to-end run. `challenge.py`'s `estimate_face_box` now calls Module D's
  real SCRFD detector (the old fixed-centre-crop placeholder is deleted), falling back
  to a geometric centre crop only when detection finds nothing.
  **A camera and display are now attached, and the live check has been run once**
  (`scripts/live_challenge_check.py` → `results/live_challenge_check.json`): the
  challenge renders full-screen, and WB/exposure locking is verified to work and to be
  necessary (auto drifts 79→88 while correcting the cast; locked holds to σ=0.06).
  **It does not pass** — B6 correlation came out −0.47 against a 0.70 threshold. The
  colour cast *is* reaching the sensor (per-region B:R ratio moves 0.81→0.91 on blue
  steps in the central cells) but B6 cannot see it, because
  `measure_chromaticity_trace` returns absolute per-channel brightness rather than
  normalised chromaticity, so luminance drift swamps hue. Read §14's 2026-09-01 Module B
  amendment before touching B6 or `measure_chromaticity_trace` — the fix is known but
  changes a binding check's semantics and needs `illumination_corr_min` recalibrated.
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
  64. **§8.3's C0-C3 ablation is complete as of 2026-09-01** (run it with `make
  docker-bench`; on a fallback-only host `overhead.py`'s guard correctly re-blocks
  C1/C2/C3): PQ overhead = C2−C1 = 0.88 ms (+8.1%), AI overhead = C3−C2 = 703.8 ms,
  ratio 798x — provisional on the AI side only, since C3 runs one of six detectors.
  `report.py` renders `results/report.md` (T1-T8, F1-F4) and `results/BLOCKERS.md` from
  JSON only — never hand-assembled, including a generated backend-provenance table.
  See §14's Module F and liboqs amendments for two real bench-harness bugs found this
  way (neither in Module E): sequential per-device setup letting the 30s challenge TTL
  expire mid-sweep, and — the one that actually caused the concurrency=64 collapse — a
  per-device SCRFD inference inside `build_signed_bundle` serialising on the event loop
  while the TTL ran. With that hoisted out, concurrency=64 completes 64/64 on both
  backends and the real knee is ~8-16, set by `server.workers` against ONNX inference,
  not by crypto.
- **Placeholder only (docstring naming owner + purpose, no logic):** the remaining
  scripts under `scripts/` — `download_datasets.py`, `prepare_datasets.py`,
  `train_detector.py` — pending the same dataset licensing §6 blocks everywhere else.
- All six modules (A-F) are now implemented. Do not start `pad.py`/`morph.py`/
  `deepfake.py`/`replay.py`, or any dataset-dependent work, without
  explicit instruction — see PROJECT_SPEC.md §0 and §10 for the intended build order.

## PQC backend (read before touching pqbio/pqc/)

**Two live backends, and which one you get depends on where you run.**

- **In Docker (`docker/Dockerfile.server`) — liboqs 0.16.0.** This is §4's reference
  environment and the only place PQ *performance* numbers mean anything. The image
  build asserts `ML-KEM-768`/`ML-DSA-65` are both in liboqs' enabled-mechanism list and
  that `KEM_BACKEND`/`SIG_BACKEND` report `liboqs`, and **fails the build** otherwise —
  it can't silently ship the fallback. Use `make docker-build` / `docker-test` /
  `docker-bench` / `docker-cross-check`.
- **On a host without a C toolchain — the pure-Python fallback.** `pqbio/pqc/kem.py`
  and `sign.py` fall back to `kyber_py.ml_kem.ML_KEM_768` /
  `dilithium_py.ml_dsa.ML_DSA_65` — real FIPS 203/204 reference implementations, never
  a mock. This is what this Windows dev host uses (no usable `cmake`/`ninja`/MSVC).

Both modules expose `KEM_BACKEND` / `SIG_BACKEND`; every persisted result (bench JSON,
audit log, receipts) records which produced it, and `results/BLOCKERS.md` carries a
generated per-file provenance table. **Any crypto number measured on the fallback is
superseded** by the liboqs equivalent — the fallback is ~200-700x slower (ML-DSA-65
signing: 78.9 ms vs 0.114 ms) and is not constant-time, so never use a fallback timing
for a performance or side-channel claim.

**The two backends agree byte for byte** — 339 fields over 127 deterministic cases
(ACVP vectors + synthetic seeds), plus two-directional interop, via
`scripts/cross_check_backends.py` (`make docker-cross-check`,
`results/backend_cross_check.json`). That is what retroactively validates every result
produced during the period when only the fallback existed. Re-run it if you touch
either backend path.

Things that bite here, all learned the hard way (PROJECT_SPEC.md §14, 2026-09-01):

- **liboqs-python's ctypes wrappers silently zero-pad or truncate wrong-length input**
  instead of raising. `MLKEM768.encapsulate`/`decapsulate` and `MLDSA65.sign` therefore
  validate lengths themselves — do not remove those checks; the "fail closed" property
  is ours, not the backend's.
- **KAT determinism works differently per backend.** ML-KEM keygen takes a real per-call
  seed; everything else goes through liboqs' *process-global* RNG override in
  `pqbio/pqc/_oqs_kat.py`. Always use its context manager — leaving that override
  installed makes every later liboqs call in the process use predictable "randomness".
- **A test that only passes on one backend is a bug in the test.** Branch on the live
  `KEM_BACKEND`/`SIG_BACKEND` and assert behaviour *matches* it, rather than asserting
  which backend is present.

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
