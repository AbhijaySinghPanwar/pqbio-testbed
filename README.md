# pq-bio-auth

AI-based biometric evidence authentication for post-quantum digital identity systems.
See [`PROJECT_SPEC.md`](PROJECT_SPEC.md) for the full build specification — this file is
a quickstart, not a substitute for it.

## Status

Early scaffold. **Module A — the PQC layer** (`pqbio/pqc/`), **Module B — the capture
client** (`pqbio/capture/`), **Module C — transaction binding & freshness**
(`pqbio/binding/`), and the non-dataset-blocked parts of **Module D — attack detection**
(`pqbio/detect/base.py`, `face.py`, `match.py`, `injection.py`, `fusion.py`) are
implemented. `pqbio/detect/pad.py`/`morph.py`/`deepfake.py`/`replay.py` need licensed
datasets that haven't landed and are deliberately absent, not stubbed; `pqbio/server/`
and `pqbio/bench/` (besides one guard) remain placeholders. See [`CLAUDE.md`](CLAUDE.md)
"current state" for the up-to-date module-by-module status, including what's untested
(no webcam/display in this environment) versus fully verified.

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

Module D's face detection/matching needs the `insightface`/`onnxruntime`/`lightgbm`/
`scikit-learn`/`scipy` extras (currently in the optional `ml` group) and a one-time
model fetch:

```bash
pip install -e ".[dev,ml]"
python scripts/fetch_face_models.py   # fetches SCRFD + ArcFace buffalo_l, records checksums
```

## Running things

```bash
make lint        # ruff + black --check
make typecheck    # mypy --strict on pqc/, binding/, server/
make test         # pytest
python scripts/bench_pqc.py   # Module A crypto micro-benchmark -> results/pqc_micro.json
python -m pqbio.capture --source replay --clip PATH --out bundle.cbor   # Module B CLI
python scripts/measure_phash_fpr.py          # Module C reuse-check FPR -> results/binding_fpr.json
python scripts/measure_phash_robustness.py   # Module C reuse-check robustness sweep -> results/phash_robustness.json
python scripts/make_injection_corpus.py      # Module D injection corpus -> data/manifests/, data/processed/
python -m pqbio.detect.injection --train data/manifests/injection_corpus_manifest.json   # train + evaluate D5
python -m pqbio.detect.fusion                # train cascade + compare both D6 strategies on the corpus
```

`make bench`, `make report`, and `make demo` are stubs until Module F and Module E land
(see `PROJECT_SPEC.md` §5.6, §5.5).

## Docker

`docker-compose.yml` (server) and `docker/Dockerfile.server` are written per
spec but not build-verified in this environment (no Docker engine available when this
scaffold was created). Verify `docker compose up --build` on a machine with Docker
before relying on it.
