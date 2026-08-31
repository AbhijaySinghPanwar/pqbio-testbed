# AI-Based Biometric Evidence Authentication for Post-Quantum Digital Identity Systems

**Build specification — requirements scope only**
Team: Abhijay Singh Panwar (server, injection detection, fusion, benchmark harness) · Aviral Bhan (PQC + capture layer) · Krish Mehta (vision detection models)
Supervisors: Dr. Rajasekhara Reddy D, Dr. Aswani
Timeline: 8 weeks

> This document contains only what the project brief requires. Anything not traceable to a stated objective or deliverable has been left out deliberately. Do not add features. If something here proves unnecessary during implementation, raise it and cut it.

---

## 0. Using this document

Keep at repo root as `PROJECT_SPEC.md`. Generate `CLAUDE.md` from §11. Build modules in the order of §10; each has a Definition of Done that must pass before moving on.

Starting prompt:
> Read `PROJECT_SPEC.md`. Scaffold per §3, set up the environment per §4, generate `CLAUDE.md` from §11, then implement Module A (§5.1) only. Stop at its Definition of Done.

**Rule:** no number in the final report may be typed by hand. Every metric comes from `bench/` and is written to `results/` as JSON.

---

## 1. Requirements traceability

| Brief requirement | Where it is met |
|---|---|
| O1 Testbed combining PQC with AI biometric verification | §2 architecture, Modules A/B/E — A/B/C/E implemented; D3/D4 (morph/deepfake) absent, no detector to plug in (§14) |
| O2 Integrate ML-KEM and ML-DSA | Module A (§5.1) |
| O3 Detect presentation, morphing, deepfake, replay, injection | Module D (§5.4) |
| O4 Measure accuracy, latency, throughput, CPU, memory | Module F (§5.6), §8 — harness implemented and produces every metric via `make bench`; most §8.1 accuracy cells are BLOCKED (four detectors/three datasets absent, `results/BLOCKERS.md`), §8.2 performance numbers (latency, throughput, CPU/RSS) are real, measured |
| O5 Security–performance trade-off analysis | §8.3, §8.4 — C0 (framework floor) real; C1/C2/C3 (crypto/AI overhead) BLOCKED behind the fallback-backend guard until liboqs is installed; §8.4's T8 is latency/crypto-cost-only pending real ACER data |
| D1 Working reproducible prototype | §13 — real enroll→challenge→handshake→verify→signed-receipt flow now runs end-to-end through Module E (§13's `make demo`/`docker-compose` packaging still open, Module F) |
| D2 Attack-detection component on suitable datasets | §5.4, §6 |
| D3 Transaction binding and freshness mechanism | Module C (§5.3) |
| D4 Security + performance evaluation incl. PQ overhead | §8 — `make bench` produces the full evaluation; PQ overhead itself (C2-C1) is BLOCKED until liboqs replaces the pure-Python fallback (§14) |
| D5 Practical analysis and recommendation | §8.4 — provisional (latency/crypto-cost only); a real accuracy-informed recommendation needs the detector/dataset gaps in `results/BLOCKERS.md` closed first |

---

## 2. Problem and architecture

Cryptography proves a message arrived unmodified from a key holder. It does not prove the biometric sample inside came from a live person present at capture. An attacker with a valid device key can send a deepfake, morph, replay or injected stream through a perfectly secure channel.

Separately, biometrics are non-revocable, so a sample intercepted today under classical ECDH stays compromising for life once quantum attacks are practical. Hence ML-KEM (FIPS 203) and ML-DSA (FIPS 204).

The system composes both and measures the cost.

```
CLIENT                                    SERVER
  request challenge  ─────────────────►
                     ◄───────────────── signed challenge (nonce, txn, expiry)
  capture N frames
  respond to challenge
  bind nonce+txn into evidence
  sign bundle (ML-DSA)
  encapsulate (ML-KEM) → AES-GCM
  send bundle        ─────────────────►
                                          decrypt, verify signature
                                          binding + freshness checks
                                          5 attack detectors + face match
                                          fusion → decision
                     ◄───────────────── signed decision
```

### 2.1 Threat model

| Class | Adversary | Capability |
|---|---|---|
| A1 | Network | Read, drop, reorder, replay, modify. Records now for later quantum decryption. |
| A2 | Presentation | Print, mask, or screen artefact at the sensor. |
| A3 | Morph | Enrolment image blended from two identities. |
| A4 | Deepfake | Face swap or re-enactment video. |
| A5 | Replay | Re-submits previously captured genuine evidence. |
| A6 | Injection | Bypasses the sensor (virtual camera, direct API POST). Assume a valid device key. |

Out of scope: hardware attestation (simulated only), enrolment identity proofing, template protection, adversarial attacks on the models, quantum attacks on the models.

### 2.2 Security goals

| Goal | Mechanism |
|---|---|
| Confidentiality, PQ-secure | ML-KEM-768 → HKDF-SHA256 → AES-256-GCM |
| Evidence origin authenticity | ML-DSA-65 device signature |
| Freshness | Server nonce, expiry window, single-use nonce cache |
| Transaction binding | Nonce + transaction hash bound into the capture |
| Evidence authenticity / liveness | Five detectors + fusion |
| No reuse of prior evidence | Challenge response + perceptual-hash index of accepted evidence |
| Verifiable decision | Server-signed decision receipt |

---

## 3. Repository structure

```
pq-bio-auth/
├── PROJECT_SPEC.md
├── CLAUDE.md
├── README.md
├── Makefile                  # setup | test | bench | report | demo
├── pyproject.toml
├── docker-compose.yml
├── config/default.yaml
│
├── pqbio/
│   ├── config.py             # all thresholds, loaded from YAML
│   ├── schemas.py            # wire protocol models + canonical encoding
│   │
│   ├── pqc/                  # MODULE A — Aviral
│   │   ├── kem.py            # ML-KEM-768 + classical X25519 baseline
│   │   ├── sign.py           # ML-DSA-65 + classical Ed25519 baseline
│   │   ├── kdf.py            # HKDF-SHA256
│   │   ├── aead.py           # AES-256-GCM
│   │   ├── handshake.py      # session state machine
│   │   └── keystore.py       # device key registry
│   │
│   ├── capture/              # MODULE B — Aviral
│   │   ├── camera.py         # live webcam source
│   │   ├── replay_source.py  # dataset-as-camera source (for evaluation)
│   │   ├── challenge.py      # nonce-driven challenge + response measurement
│   │   └── bundler.py        # assemble, hash, sign evidence bundle
│   │
│   ├── binding/              # MODULE C — Abhijay
│   │   ├── nonce.py          # issue, cache, single-use enforcement
│   │   ├── phash_index.py    # seen-evidence store
│   │   └── verify.py         # binding checks B1–B6
│   │
│   ├── detect/               # MODULE D
│   │   ├── base.py           # Detector ABC
│   │   ├── face.py           # detect / align / quality gate  — Krish
│   │   ├── match.py          # ArcFace embedding + cosine     — Krish
│   │   ├── pad.py            # presentation attacks           — Krish
│   │   ├── morph.py          # morphing attacks               — Krish
│   │   ├── deepfake.py       # deepfakes                      — Krish
│   │   ├── replay.py         # screen replay                  — Krish
│   │   ├── injection.py      # injection                      — Abhijay
│   │   └── fusion.py         # score fusion + policy          — Abhijay
│   │
│   ├── server/               # MODULE E — Abhijay
│   │   ├── app.py  routes.py  pipeline.py  decision.py  store.py
│   │
│   └── bench/                # MODULE F — Abhijay
│       ├── accuracy.py  latency.py  loadgen.py  resources.py
│       ├── overhead.py       # 4-configuration ablation
│       └── report.py         # results/*.json → tables + plots
│
├── scripts/
│   ├── prepare_datasets.py
│   ├── make_injection_corpus.py
│   ├── train_detector.py
│   └── run_full_eval.py
│
├── data/{raw,processed,manifests}/     # raw + processed gitignored
├── models/                             # gitignored; checksums.txt committed
├── results/                            # committed
└── tests/{unit,integration,security}/
```

---

## 4. Stack

| Layer | Choice |
|---|---|
| Language | Python 3.11 |
| PQC | `liboqs-python` — `ML-KEM-768`, `ML-DSA-65`. Fallback: `kyber-py` / `dilithium-py`, documented if used. |
| Classical baseline | `cryptography` — X25519, Ed25519, AES-256-GCM |
| Server | FastAPI + Uvicorn |
| State | SQLite (nonce cache, keystore, pHash index, audit log) |
| DL | PyTorch 2.x + timm |
| Face | InsightFace (SCRFD detector, ArcFace `buffalo_l`) |
| CV | OpenCV, `imagehash` |
| Metrics | scikit-learn, NumPy, SciPy |
| Load gen | `asyncio` + `httpx` |
| Resources | `psutil` (+ `pynvml` if GPU) |
| Plots | Matplotlib |
| Config | `pydantic-settings` + YAML |
| Tests | pytest, pytest-asyncio |
| Packaging | Docker + docker-compose |

No network calls at inference time. Models load from `models/` with verified SHA-256.

---

## 5. Modules

### 5.1 Module A — Post-quantum cryptography (`pqbio/pqc/`) — Aviral

| Role | Algorithm | Sizes (bytes) |
|---|---|---|
| KEM | ML-KEM-768 (FIPS 203) | pk 1184, sk 2400, ct 1088, ss 32 |
| Signature | ML-DSA-65 (FIPS 204) | pk 1952, sk 4032, sig ~3309 |
| KDF | HKDF-SHA256 | 32-byte keys |
| AEAD | AES-256-GCM | 12-byte nonce, 16-byte tag |

Also implement classical X25519 + Ed25519 behind the same interface. This exists solely to measure PQ overhead in §8.3 — it is a requirement, not an extra.

**Frozen interfaces** (everything else depends on these):

```python
class KEM(Protocol):
    def keygen(self) -> tuple[bytes, bytes]: ...                 # (pk, sk)
    def encapsulate(self, pk: bytes) -> tuple[bytes, bytes]: ... # (ct, ss)
    def decapsulate(self, ct: bytes, sk: bytes) -> bytes: ...    # ss

class Signer(Protocol):
    def keygen(self) -> tuple[bytes, bytes]: ...
    def sign(self, msg: bytes, sk: bytes) -> bytes: ...
    def verify(self, msg: bytes, sig: bytes, pk: bytes) -> bool: ...
```

Factories `get_kem(mode)` / `get_signer(mode)` with `mode ∈ {"classical", "pq"}`.

**Key derivation** — bind the handshake transcript, not just the shared secret:

```
transcript = SHA256(session_id ‖ kem_ct ‖ server_sig_pk ‖ device_sig_pk)
K_master   = HKDF-Extract(salt=transcript, ikm=ss)
K_c2s      = HKDF-Expand(K_master, "pqbio/v1/c2s", 32)
K_s2c      = HKDF-Expand(K_master, "pqbio/v1/s2c", 32)
```

**Session state machine:** `INIT → CHALLENGED → KEYED → VERIFIED | REJECTED | EXPIRED`. `KEYED` reachable at most once. Any out-of-order message → `PROTO_STATE_ERROR`, session terminated.

**Definition of Done**
- [ ] Known-answer tests pass for ML-KEM-768 and ML-DSA-65.
- [ ] Round-trip tests: encaps/decaps agree, sign/verify agree, tampered ciphertext or signature always fails.
- [ ] Both modes behind one interface, selectable by config.
- [ ] Negative tests: replayed KEM ciphertext, malformed public key, wrong-length signature, truncated AEAD tag.
- [ ] `scripts/bench_pqc.py` → `results/pqc_micro.json`: keygen / encaps / decaps / sign / verify, mean and p95 over ≥1000 iterations, plus artefact sizes, for both modes.

---

### 5.2 Module B — Capture client (`pqbio/capture/`) — Aviral

Two interchangeable sources producing identical bundle structures:
- `CameraSource` — live webcam.
- `ReplaySource` — reads a dataset clip and presents it as a camera. This is how labelled attack data goes through the real pipeline rather than being tested on the detectors in isolation.

**Challenge.** The server nonce drives a physical challenge a pre-recorded stream cannot satisfy. Derive a colour sequence from the nonce (`PRF(nonce)` → 4 steps from {red, green, blue, white}, ~200 ms each), display full-screen, and record the per-frame mean chromaticity of the face region. The verifier correlates the measured trace against the expected sequence. This is the mechanism behind deliverable D3 and the strongest signal for replay and injection.

**Evidence bundle:**

```
session_id, device_id, counter
challenge_echo    : the server challenge, verbatim
frames[]          : N frames (default 30 @ 15 fps)
frame_meta[]      : per-frame capture_ts_ns, exposure, iso, sequence_idx
challenge_signal  : measured illumination response trace
device_meta       : os, camera device name, resolution, codec, app version
capture_binding   : SHA256(nonce ‖ txn_hash ‖ SHA256(concat frame hashes))
bundle_digest     : SHA256(canonical CBOR of all the above)
signature         : ML-DSA-65(bundle_digest, device_sk)
```

**Definition of Done**
- [ ] Both sources produce byte-identical bundle structures.
- [ ] Canonical CBOR: re-serialising yields an identical digest.
- [ ] Challenge renders and its response trace is measurable on a real webcam.
- [ ] CLI: `python -m pqbio.capture --source {camera,replay} --clip PATH --out bundle.cbor`
- [ ] Changing any single byte invalidates the signature (test).

---

### 5.3 Module C — Transaction binding and freshness (`pqbio/binding/`) — Abhijay

This is deliverable D3.

**Challenge issued by the server:**

```
session_id, nonce (32 random bytes), txn (descriptor), txn_hash,
issued_at, expires_at (default +30 s), server_sig (ML-DSA-65)
```

**Six checks, all must pass, each with a reason code:**

| # | Check | Failure code |
|---|---|---|
| B1 | Server signature on the echoed challenge is valid | `BIND_CHALLENGE_FORGED` |
| B2 | Within expiry, allowing ±2 s clock skew | `BIND_EXPIRED` |
| B3 | Nonce was issued and not yet consumed; consumption is atomic | `BIND_NONCE_REPLAY` |
| B4 | Device counter strictly greater than last seen | `BIND_COUNTER_REGRESSION` |
| B5 | `capture_binding` recomputes from nonce, txn_hash and frame hashes | `BIND_DIGEST_MISMATCH` |
| B6 | Challenge signal correlates with expectation (default r ≥ 0.7) | `BIND_CHALLENGE_UNMET` |

**Seen-evidence index.** Perceptual hashes of every accepted bundle's frames, in SQLite with a BK-tree for Hamming lookup. Reject if any frame is within distance 6 of a stored hash (`BIND_EVIDENCE_REUSE`). B1–B5 stop resubmission of the same *message*; this stops resubmission of the same *media* under a fresh, correctly signed session — which is what "prevent reuse of previously captured biometric evidence" actually requires.

**Definition of Done**
- [ ] Positive and negative test for each of B1–B6 and the reuse check.
- [ ] Nonce consumption atomic under 100 concurrent requests with the same nonce — exactly one succeeds.
- [ ] Reuse check catches exact resubmission and re-encoded/rescaled resubmission; false-positive rate on genuine distinct captures of the same subject is measured and reported.
- [ ] Every failure returns a structured reason code, never a generic error.

---

### 5.4 Module D — Attack detection (`pqbio/detect/`)

**Common contract:**

```python
@dataclass
class DetectorResult:
    name: str
    score: float          # 0.0 benign … 1.0 attack
    decision: bool
    threshold: float
    latency_ms: float
    reasons: list[str]
    features: dict        # for fusion training
```

`face.py` produces `PreparedEvidence` (detect → align → crops → quality score) once per request; all detectors share it.

**D0 Face processing and match** — Krish. SCRFD detection, 5-point alignment, quality gate (blur, pose, face size) returning `QUALITY_INSUFFICIENT` rather than an attack score, ArcFace 512-D embedding, cosine match against the enrolled template.

**D1 Presentation** — Krish. DeepPixBiS (pixel-wise binary supervision) on aligned crops; EfficientNet-B0 binary classifier as the baseline. Auxiliary features for fusion: LBP histogram, HSV/YCbCr colour statistics. Datasets: CASIA-FASD, Replay-Attack, OULU-NPU, CelebA-Spoof.

**D2 Morphing** — Krish. Two settings: S-MAD (single image, texture + CNN) and D-MAD (differential — classifier over the ArcFace embedding difference between the suspect image and a trusted live capture). D-MAD matches our threat model since a live capture is always available at verification. Datasets: FRLL-Morphs, SMDD. Report MMPMR alongside APCER/BPCER.

**D3 Deepfake** — Krish. EfficientNet-B4 or XceptionNet on face crops, with temporal aggregation over the frame burst (mean vs top-k mean — report which wins). Datasets: FaceForensics++ (c23, c40), Celeb-DF-v2.

**D4 Replay** — Krish. Moiré energy in the 2D FFT of the face region, screen-edge detection, specular reflection profile, temporal flicker, plus the challenge–illumination correlation shared with B6. Datasets: Replay-Attack, MSU-MFSD, plus self-recorded replays.

**D5 Injection** — Abhijay. Injection pixels can be a perfect genuine recording, so this attacks provenance, not appearance:

| Signal | Rationale |
|---|---|
| Virtual camera enumeration | Device name matches a known virtual-cam driver |
| Frame timing jitter | Real sensors have characteristic inter-frame Δt noise; injected streams are metronomic or show file-read artefacts. Features: mean, σ, skew, kurtosis of Δt |
| Compression provenance | Double-JPEG detection, quantisation-table fingerprint |
| Sensor metadata plausibility | Do exposure/ISO vary naturally and agree with observed brightness |
| Challenge–illumination correlation | A pre-recorded injected stream cannot satisfy a fresh challenge |
| Attestation token | Simulated; document the production path |

Combine with gradient boosting over the feature vector (low-dimensional and heterogeneous — trees beat a network here).

**D6 Fusion and policy** — Abhijay.

Input: `[match, pad, morph, deepfake, replay, injection, quality, binding_flags, n_frames]`.

Implement and compare two strategies:
1. **Rule baseline** — reject if any detector exceeds its threshold.
2. **Cascade** — cheap checks first (binding, injection heuristics, quality), short-circuit on confident rejection, run the CNNs only on survivors, then a logistic regression over the resulting scores. This is the latency-optimised path.

Outcomes: `ACCEPT` / `REJECT` / `CHALLENGE` (step up with a fresh nonce). Thresholds set at a stated operating point — default BPCER at APCER = 5%, with a table at 1% and 10%.

**Definition of Done**
- [ ] Every detector implements the ABC and returns latency and reasons.
- [ ] `PreparedEvidence` computed once per request.
- [ ] Per-detector CLI: `python -m pqbio.detect.pad --input PATH --out scores.json`.
- [ ] Fixed seeds; one config file per experiment; results in `results/detectors/<name>/`.
- [ ] Cross-dataset result reported for D1 and D3 (train one dataset, test another).
- [ ] Both fusion strategies implemented and compared.
- [ ] CPU-only inference path works.

---

### 5.5 Module E — Verification server (`pqbio/server/`) — Abhijay

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/enroll` | Register device ML-DSA pk, enrol face template |
| POST | `/v1/session/challenge` | Issue signed challenge |
| POST | `/v1/session/handshake` | ML-KEM encapsulation, session keys |
| POST | `/v1/verify` | Submit encrypted bundle → decision |
| GET | `/v1/health` | Liveness |

**Pipeline order — cheapest first, short-circuit early:**

```
1. AEAD decrypt + ML-DSA verify              → fail fast
2. Binding checks B1–B5                      → fail fast
3. Quality gate + face detect/align
4. Cheap signals: injection heuristics,
   replay artefacts, challenge correlation   → short-circuit if confident
5. Evidence-reuse pHash check
6. Heavy models: PAD, deepfake, morph, match (parallel)
7. Fusion + policy
8. Sign decision, write audit log
```

Stages 3–6 run in a thread/process pool; the event loop is never blocked by torch.

**Decision object:**

```json
{
  "session_id": "...",
  "decision": "ACCEPT | REJECT | CHALLENGE",
  "fused_score": 0.037,
  "reason_codes": ["BIND_OK", "PAD_OK", "DF_OK"],
  "detector_scores": {"pad": 0.02, "deepfake": 0.11},
  "stage_latency_ms": {"crypto": 1.2, "binding": 0.9, "detect": 84.3},
  "model_versions": {"pad": "sha256:..."},
  "receipt_signature": "<ML-DSA-65 over canonical(decision)>"
}
```

Audit log stores scores, reason codes and frame hashes — never raw frames, except behind an explicit `--research-retain` flag.

**Definition of Done**
- [ ] Happy path passes end-to-end in an integration test.
- [ ] Each adversary class A1–A6 has a test producing the correct rejection reason code.
- [ ] Event loop never blocked (verified via p99 under concurrency).
- [ ] Receipt signature verifies against the published server public key.
- [ ] If a model fails to load, the server refuses to start rather than silently skipping a detector.

---

### 5.6 Module F — Benchmark harness (`pqbio/bench/`) — Abhijay

Produces everything in §8. Single command: `make bench`.

**Definition of Done**
- [ ] Every metric in §8 produced automatically, no manual steps.
- [ ] JSON first; tables and plots rendered from JSON.
- [ ] Each run records git commit, config hash, hardware description, dataset versions, seeds.
- [ ] Same seed reproduces accuracy metrics exactly; timing within a stated variance.

---

## 6. Datasets

> Every dataset requires a signed academic EULA and several need institutional sign-off. `scripts/prepare_datasets.py` must not auto-download restricted data — it prints the request steps and verifies checksums for data already placed in `data/raw/`. Record licence status in `data/LICENCES.md`. Any team recording of human subjects needs written consent and supervisor approval.

| Attack | Datasets |
|---|---|
| Presentation | CASIA-FASD, Replay-Attack, OULU-NPU (4 official protocols), CelebA-Spoof |
| Morphing | FRLL-Morphs (AMSL, FaceMorpher, OpenCV, StyleGAN2), SMDD |
| Deepfake | FaceForensics++ (c23, c40), Celeb-DF-v2 |
| Replay | Replay-Attack, MSU-MFSD, team-recorded replays |
| Injection | Self-generated (§7) — no standard public corpus exists |
| Bona fide | Genuine splits of the above + team-recorded live captures |

**If licences are delayed**, proceed with CelebA-Spoof, SMDD, FF++ and the self-recorded replay/injection sets, and state clearly which datasets were unavailable.

**Splits are subject-disjoint.** No identity in both train and test, enforced by an assertion in the data loader. Fix and commit splits in `data/manifests/`.

---

## 7. Attack simulation

Each adversary class generates labelled traffic through the real client and server, asserting an expected reason code. This doubles as the security regression suite.

| Class | Simulation |
|---|---|
| A1 | Proxy that replays, reorders, truncates and bit-flips messages |
| A2 | PAD attack clips via `ReplaySource` |
| A3 | Enrol with a morph, attempt verification as both contributing identities |
| A4 | FF++ / Celeb-DF clips via `ReplaySource` |
| A5 | (a) resubmit a bundle verbatim; (b) resubmit the same media under a fresh nonce and re-signature; (c) screen-replay recapture |
| A6 | Two tiers, below |

**Injection corpus** (`scripts/make_injection_corpus.py`), two tiers, report detection rate per tier:
- **Tier 1 — direct API injection.** Skip the client; POST a bundle signed with a compromised key, frames taken from a video file.
- **Tier 2 — virtual camera.** Route a video file through `v4l2loopback` or OBS Virtual Camera and run the unmodified client against it.

---

## 8. Evaluation

### 8.1 Accuracy (ISO/IEC 30107-3 where applicable)

| Metric | Reported per |
|---|---|
| APCER — attacks accepted | attack type, dataset |
| BPCER — genuine rejected | dataset |
| ACER = (APCER + BPCER) / 2 | dataset |
| EER | detector |
| AUC-ROC | detector |
| TDR @ FAR = 1% | detector, system |
| MMPMR | morph only |
| Per-attack detection rate at the deployed operating point | each of the 5 attack types |
| 6-class confusion matrix (bona fide + 5 attacks) | system |
| DET curve | detectors + fused system |

Intra-dataset **and** cross-dataset for D1 and D3.

### 8.2 Performance

| Metric | Method |
|---|---|
| End-to-end latency | p50 / p95 / p99 on `/verify` |
| Stage-level latency | Instrument every stage; stacked breakdown |
| Crypto micro-latency | keygen, encaps, decaps, sign, verify — ≥1000 iterations |
| Throughput | verifications/sec at concurrency {1, 2, 4, 8, 16, 32, 64}; find the knee |
| CPU | mean and peak % across cores, sampled at 100 ms |
| Memory | peak RSS, steady-state RSS |
| GPU | utilisation and VRAM if present |
| Payload size | handshake and signature bytes, PQ vs classical |

### 8.3 Overhead ablation

Identical workload under four configurations:

| Config | Crypto | AI | Isolates |
|---|---|---|---|
| C0 | none | none | Framework/transport floor |
| C1 | X25519 + Ed25519 | none | Conventional crypto cost |
| C2 | ML-KEM-768 + ML-DSA-65 | none | **Marginal PQ cost** |
| C3 | ML-KEM-768 + ML-DSA-65 | full | **Total system cost** |

State explicitly: PQ overhead = C2 − C1 (absolute ms and %); AI overhead = C3 − C2; the ratio between them. Do not write the conclusion before the harness prints it.

### 8.4 Trade-off analysis

- ACER vs p95 latency for both fusion strategies.
- Marginal ACER improvement per millisecond added, per detector. Some detectors may not earn their latency — say so.
- Deployment recommendation for three scenarios: high-security low-volume (bank onboarding), balanced (mobile login), high-volume low-latency (access control).

### 8.5 Required outputs

`results/` must contain, generated:

1. T1 per-detector accuracy, intra-dataset
2. T2 per-detector accuracy, cross-dataset
3. T3 fusion strategy comparison
4. T4 per-attack detection rate at the operating point
5. T5 crypto micro-benchmarks and artefact sizes
6. T6 four-configuration overhead ablation
7. T7 throughput vs concurrency
8. T8 deployment recommendation matrix
9. F1 DET curves
10. F2 stage-level latency breakdown per config
11. F3 ACER vs p95 latency
12. F4 6-class confusion matrix

---

## 9. Configuration

All tunables in `config/default.yaml`. No magic numbers in code.

```yaml
crypto:
  mode: pq                  # classical | pq
  kem: ML-KEM-768
  sig: ML-DSA-65

binding:
  nonce_bytes: 32
  challenge_ttl_s: 30
  clock_skew_s: 2
  illumination_steps: 4
  illumination_corr_min: 0.70
  phash_hamming_max: 6

capture:
  n_frames: 30
  fps: 15
  resolution: [1280, 720]

detect:
  quality: {min_face_px: 112, min_blur_var: 60.0, max_yaw_deg: 25}
  thresholds:               # set by calibration, not by hand
    pad: 0.50
    morph: 0.50
    deepfake: 0.50
    replay: 0.50
    injection: 0.40
    match_cosine_min: 0.38
  fusion:
    strategy: cascade       # rule | cascade
    operating_point: bpcer_at_apcer_5

server:
  workers: 4
  max_concurrency: 64
  request_timeout_s: 10
```

---

## 10. Milestones

| Week | Abhijay | Aviral | Krish | Gate |
|---|---|---|---|---|
| 1 | Scaffold, schemas, config, CI | liboqs, KEM/DSA wrappers + KATs | Dataset licence requests, env setup | PQC round-trips |
| 2 | Server skeleton, endpoints, store | Handshake, AEAD, classical mode | Face detect/align/embed + quality gate | Signed empty bundle traverses the channel |
| 3 | Binding B1–B5, nonce cache | Capture client, bundler, canonical CBOR | PAD trained, intra-dataset result | End-to-end genuine verification passes |
| 4 | Injection features + GBM, pHash index | Challenge render + measure (B6) | Deepfake trained | All binding checks pass |
| 5 | Pipeline orchestration, cascade fusion | Injection corpus tiers 1–2 | Morph (S-MAD + D-MAD), replay | All 5 detectors score through the server |
| 6 | Fusion comparison, threshold calibration | Attack simulation A1–A6 | Cross-dataset runs | Security suite green |
| 7 | Benchmark harness, ablation, load gen | Docker, reproducibility, README | DET curves, confusion matrix | `make bench` produces T1–T8, F1–F4 |
| 8 | Trade-off analysis, recommendations | Demo script | Report figures and write-up | Final report + reproducible artefact |

Friday integration demo every week. The system must be demoable end-to-end from week 3, however weak the detectors are then.

**Load risk:** five detection models on one owner is the most likely thing to slip. If week 4 runs late, move replay detection to the challenge owner (it shares the illumination signal) and morph D-MAD to the fusion owner (it is an embedding-difference classifier).

---

## 11. Conventions (source for `CLAUDE.md`)

**Code** — Python 3.11, ruff + black (line 100), type hints throughout, pydantic at boundaries. No bare `except`; errors carry reason codes. No magic numbers. Structured logging, never log raw biometric data.

**Crypto** — never roll your own primitive. `hmac.compare_digest` for secret comparison. Sign canonical CBOR, never a JSON string. Fail closed: an unevaluable check fails.

**ML** — seed `random`, `numpy`, `torch`, and set `cudnn.deterministic`. One config per experiment, committed with its result. Model SHA-256 in `models/checksums.txt` and in every decision object. Never evaluate on the training split; never tune a threshold on the test set.

**Git** — feature branches per module (`feat/pqc-kem`). Commit `results/` and `data/manifests/`; gitignore `data/raw/`, `data/processed/`, `models/*.pt`.

**Reporting** — every number traceable to a JSON file in `results/`. Bad results get reported and explained.

---

## 12. Limitations to state in the report

1. **Cross-dataset generalisation.** PAD and deepfake detectors degrade sharply on unseen generators and capture conditions. Quantify the gap; do not present intra-dataset numbers as system performance.
2. **Simulated attestation.** Without a TEE, injection detection rests on heuristics an attacker with client control can forge. State which signals survive and which do not.
3. **Self-generated injection corpus.** No standard benchmark, so results are not directly comparable to other work.
4. **No template protection.** Enrolled embeddings are stored recoverably; production needs cancellable biometrics.
5. **Demographic fairness.** Error rates likely vary by skin tone, age and gender. Report per-group BPCER if dataset metadata allows; if not, state that it was not measurable.
6. **Single-machine benchmarks.** Throughput reflects one host. Report the hardware precisely.
7. **Illumination challenge assumes a screen.** Kiosk capture devices without a controllable display need a different freshness primitive.

---

## 13. Project Definition of Done

- [ ] `docker-compose up` gives a working system on a clean machine.
- [ ] `make demo` runs a live end-to-end verification against a webcam.
- [ ] `make bench` regenerates every table and figure from scratch.
- [ ] All six adversary classes have passing security tests with correct reason codes.
- [ ] Four-configuration ablation completed with a stated PQ-vs-AI cost split.
- [ ] Trade-off analysis with a recommendation per deployment scenario.
- [ ] Limitations written honestly (§12).
- [ ] README lets a third party reproduce every result, including dataset acquisition.

---

## 14. Amendments

Deviations from this spec discovered during implementation, recorded here rather than
silently worked around, so they survive into the final report (§0: "if something here
proves unnecessary during implementation, raise it and cut it" — this section is the
paper trail for that).

### 2026-08-30 — liboqs unavailable; kyber-py/dilithium-py is the live backend

§4 names `liboqs-python` as the primary PQC backend. The development host had no usable
C++ toolchain (no `cmake`/`ninja` on PATH, no MSVC "Desktop development with C++"
workload, only a 32-bit MinGW.org gcc 6.3 from 2016), and `liboqs-python`'s installer
builds liboqs from source via CMake — so `import oqs` failed. `pqbio/pqc/kem.py` and
`pqbio/pqc/sign.py` fall back at runtime to `kyber-py`/`dilithium-py` (pure-Python FIPS
203/204 reference implementations) as the **live** backend, not a mock: `KEM_BACKEND` /
`SIG_BACKEND` record which is active, a `RuntimeWarning` fires on import, and every
persisted result (`results/pqc_micro.json`, this file's own amendments) names the
backend. Correctness was verified against real NIST ACVP vectors, not just artefact
sizes (see the 2026-08-30 KAT amendment below). **Reversal:** install a C++ toolchain
(or use `docker/Dockerfile.server`, which builds liboqs from a clean Debian base) and
`pip install -e ".[pqc-liboqs]"` — both modules detect `oqs` at import time and prefer
it automatically, no code changes needed.

### 2026-08-30 — hybrid crypto mode built, then removed

An earlier draft of this spec specified three crypto modes (`classical`, `pq`,
`hybrid` — X25519‖ML-KEM-768 and Ed25519‖ML-DSA-65 dual-signing). `HybridKEM` and
`HybridSigner` were implemented and tested against that draft. The spec was then
trimmed to "requirements-only" scope and now specifies exactly two modes (§5.1:
`mode ∈ {"classical", "pq"}`); the hybrid classes and their tests were deleted to match.
Do not reintroduce a hybrid mode without checking this spec is current first — it was
deliberately cut, not forgotten.

### 2026-08-30 — KAT requirement: self-KAT substituted, then resolved with real vectors

§5.1's DoD asks for known-answer tests against ML-KEM-768/ML-DSA-65. Neither liboqs's
own KAT suite (needs the liboqs C source, unavailable per the amendment above) nor a
manual fetch of NIST's ACVP vectors was available on the first pass, so
`tests/unit/test_pqc_kat.py` initially pinned SHA-256 hashes of the fallback backend's
own deterministic output — a *self*-KAT, which proves output stability, not
correctness; a bug shared by kyber-py/dilithium-py would have locked itself in and
reported green forever. **Resolved:** real vectors were fetched from
[usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server) and vendored into
`tests/vectors/` (source URLs and SHA-256 of both the original and vendored files in
`tests/vectors/README.md`); `test_pqc_kat.py` now verifies keyGen, encapsulation,
decapsulation, sigGen, and verify against them, and passes. DoD item 1 is PASS.

### 2026-08-30 — overhead ablation (§8.3) blocked while a fallback backend is active

`results/pqc_micro.json` shows ML-DSA-65 `sign` at ~52ms mean under the
dilithium-py fallback — pure-Python rejection-sampling cost, not a property of
ML-DSA-65 (liboqs is expected to be roughly two orders of magnitude faster).
Running the C1/C2/C3 configurations on the fallback would misattribute that cost to
"PQ overhead" and invert §8.3's PQ-vs-AI split. `pqbio/bench/overhead.py` now guards
against this: `guard_against_fallback_backend()` raises `FallbackBackendActiveError`
naming the active backend whenever `KEM_BACKEND`/`SIG_BACKEND` is a `*-fallback` value.
**Unblock condition:** both backends report `"liboqs"` (see the first amendment above)
— the guard is a pure function of those two globals and needs no other change once
that's true.

### 2026-08-30 — Module B's "live webcam" DoD item verified on synthetic frames only

§5.2's DoD asks for the illumination challenge's response trace to be "measurable on a
real webcam"; no camera or display is attached in this environment. `CameraSource` and
`render_challenge_fullscreen` are implemented but have never run against real hardware.
`measure_chromaticity_trace` was instead verified on synthetic frames with a known,
injected colour sequence (exact recovery — see `tests/unit/test_capture_challenge.py`).
**Unblock condition:** run `python -m pqbio.capture --source camera` on a machine with a
webcam and confirm frames arrive and the trace looks sane; ideally also exercise
`render_challenge_fullscreen` against a real display at the same time, since that half
has no coverage at all yet (needs a display, not just a camera).

### 2026-08-30 — pHash reuse threshold (§5.3): measured tension, default kept

`scripts/measure_phash_fpr.py` generated 30 synthetic subjects × 10 jittered captures
each (1350 within-subject pairs) and measured, per Hamming-distance threshold:

| Threshold | Within-subject FPR (synthetic) | Cross-subject flag rate |
|---|---|---|
| 2 | 2.2% | 0.0% |
| 4 | 6.2% | 0.2% |
| **6 (spec default)** | **12.7%** | **0.2%** |
| 8 | 18.0% | 1.6% |

Separately, `tests/unit/test_phash_index.py::test_reuse_check_catches_reencoded_and_rescaled_resubmission`
measured the actual Hamming distance for a re-encode (quality 95→35) at **4** and a
rescale round-trip (0.7×, back up) at **0**. So threshold 4 would still catch both cases
measured here, at roughly half the synthetic FPR of threshold 6 — but with *zero*
margin on the re-encode case (a slightly more aggressive real re-encode could exceed 4
and slip through undetected).

**Decision: keep the spec default of 6, not 4.** Two reasons: (a) missing a re-encoded
replay is a false negative on an anti-evidence-reuse control — the more costly failure
mode versus a usability false positive, which routes to `CHALLENGE` (step up with a
fresh nonce) rather than an outright reject once Module D's policy engine exists, not a
hard failure; (b) the synthetic within-subject FPR almost certainly *overstates* the
real one — "captures" here are a geometric+photometric jitter of one identical base
image (rotation, translation, brightness, noise), not independent real capture sessions
with genuinely different expression, pose, and lighting, so real distinct captures of
the same person are expected to differ more than this model produces, not less.

This is a plausibility check, not a validated FPR — `config/default.yaml` is
**unchanged**. Re-run `scripts/measure_phash_fpr.py` once real datasets land (§6) and
revisit both the threshold and this reasoning against real numbers.

### 2026-08-30 — pHash robustness sweep widened: threshold 6 does not have uniform margin

`scripts/measure_phash_robustness.py` widened the sweep beyond the two cases spot-checked
during Module C (one re-encode, one rescale): JPEG quality 95→20 in steps of 5, rescale
round-trips at 0.5x/0.7x/1.3x, and a 5% centre crop, across 5 synthetic base images (105
cases total). Result, by transform:

| Transform | Max distance | All within threshold 6? |
|---|---|---|
| Rescale round-trip (0.5x/0.7x/1.3x) | 4 | Yes |
| 5% centre crop | 4 | Yes |
| **JPEG re-quality (95→20)** | **10** | **No — 5 of 80 cases exceed 6** |

**Threshold 6 does not have uniform margin.** Rescaling and centre-cropping stay well
within it (max distance 4 across both), but aggressive JPEG re-compression — quality
≤30, a visibly degraded but plausible attacker choice — pushed distance to 8–10 in 5 of
80 cases, exceeding the threshold. Full data: `results/phash_robustness.json`.

This does not itself change the threshold decision above (raising it further would
worsen the already non-trivial FPR without addressing why quality ≤30 drifts unevenly;
see the mitigation noted immediately below), but it means the reuse check has a real,
demonstrated gap against a sufficiently aggressive re-encode, not just a theoretical one.

### 2026-08-30 — known mitigation for both findings above, not implemented

Both the FPR and robustness findings share a root cause: pHash is computed on a face
*crop*, so it is partly measuring identity/structure, not purely media provenance — two
distinct captures of the same person share enough low-frequency structure to sometimes
collide, while one adversarially-recompressed frame can drift enough to escape. Neither
is fixable by moving the single Hamming threshold alone (tightening it worsens the
robustness gap above; loosening it worsens the FPR already measured).

**Mitigation, recorded here as a known direction, deliberately not implemented this
session:** require **N of the burst's frames** (e.g. a majority of the default 30) to
each land within the threshold against the same accepted bundle, rather than flagging
reuse on *any single frame* match. A resubmission of genuinely reused media should trip
this on most/all of its frames; a genuinely distinct capture of the same person
colliding on one or two frames by chance should not. This changes `PhashIndex.check_reuse`
and `check_evidence_reuse`'s pass/fail aggregation, not the per-frame Hamming distance
or the threshold itself — do not implement without also re-running both measurement
scripts against the new aggregation rule to confirm it actually improves the trade-off.

### 2026-08-31 — Module D: face/match/injection/fusion built, pad/morph/deepfake/replay deliberately absent

Per explicit instruction, this session implements only the parts of Module D (§5.4) that
are not dataset-blocked: `base.py`, `face.py` (D0 detection/alignment/quality),
`match.py` (D0 identity match), `injection.py` (D5), `fusion.py` (D6), plus the injection
corpus (§7) they depend on. `pad.py`, `morph.py`, `deepfake.py`, `replay.py` need
licensed datasets (§6, none obtained) and were **not stubbed — left entirely absent**,
as instructed, not merely deferred with a placeholder file.

**Face models.** SCRFD + ArcFace `buffalo_l` fetched once via `scripts/fetch_face_models.py`
into `models/insightface/` (real network fetch, ~280MB); the pack's other three
components (landmark_3d68, 2d106det, genderage — gender/age/2D-landmark models this
project doesn't use) were deleted after download rather than kept unused, so
`models/checksums.txt` only records the two files actually loaded. `face.py` verifies
both against that checksum file before every load and never touches the network itself.
Verified end-to-end against a real photographed face (see the next amendment) — this is
not a mock integration.

**No licensed face dataset exists yet (§6), so `tests/unit/_face_fixtures.py` uses
`skimage.data.astronaut()`** — a single well-known, public-domain-status NASA photo
bundled with scikit-image specifically as a standard CV test image — as the one real
photographed face available to verify SCRFD/ArcFace actually work, rather than mocking
the model calls. This is a smoke-test fixture (one image, hand-picked crop/scale
coordinates to exercise both the quality-pass and quality-fail paths), not a dataset;
it proves the integration works, not detector accuracy. Real accuracy numbers need §6's
licensed datasets.

**Yaw estimation is a documented geometric approximation**, not a calibrated pose
estimator (see `face.py`'s `_estimate_yaw_deg` docstring for the exact reasoning): a
real 3D pose solve would need another model download (insightface's `landmark_3d68`,
143MB) not judged worth it for a coarse quality-gate threshold. Recalibrate or replace
once real face data is available to check it against.

**pHash's face-detection seam is now wired, not a placeholder.**
`pqbio/capture/challenge.py`'s `estimate_face_box_centre_crop` (a permanent fixed-crop
placeholder, §5.2) is deleted; `estimate_face_box` now calls `pqbio.detect.face`'s real
SCRFD detector, falling back to the same geometric centre-crop *only* when detection
finds nothing (a frame with no face, or this project's own synthetic test/corpus clips,
which are stylised ellipse patterns SCRFD was never going to recognise as a face). The
fallback is graceful degradation, not the primary path, and is exercised by real failed
detection attempts in tests, not skipped.

**Fusion (D6) is scoped to the signals that exist.** §5.4's full fusion input is
`[match, pad, morph, deepfake, replay, injection, quality, binding_flags, n_frames]`;
this session only has match/injection/quality/binding. `fusion.py`'s `FusionInput`
represents every missing detector as `None` ("not run"), never `0.0` ("verified
benign"), and every `FusionResult` carries `missing_signals` naming exactly what's
absent. Both strategies (rule, cascade) are implemented and compared, but only against
the one labelled dataset available — the injection corpus — so the numbers in
`results/detectors/fusion/results.json` describe provenance-attack separation, not
system-wide ACER. See `fusion.py`'s module docstring for the full scope note; it is not
hidden in this file alone.

**Injection detector reaches 100% train/test accuracy on the synthetic corpus** (25
genuine/tier-1 pairs, subject-disjoint 70/30 split — see
`results/detectors/injection/results.json`). This is expected, not a sign the detector
is production-ready: tier-1's defining trait (frames read back-to-back with no capture
pacing) produces inter-frame timing on the order of 0.3ms versus genuine's ~66ms-paced
capture — a huge, unambiguous gap for `timing_std_dt_ns` alone to separate, before the
other five signals even contribute. §7's two-tier corpus has no "sophisticated attacker
who fakes realistic timing" case (that would be a tier 3, which an earlier draft of this
spec had and the current one deliberately trimmed — see the hybrid-mode amendment above
for the same kind of trim) — so this 100% figure bounds how well D5 separates *this*
corpus, not how it would fare against a more careful real attacker. Re-evaluate once
real injection attempts (or a harder synthetic construction) are available.

**Tier 2 (virtual camera) is blocked in this environment**, per instruction: no OBS
Studio / OBS Virtual Camera install found, no v4l2loopback (this is Windows), and the
session lacks Administrator rights (verified via `WindowsPrincipal.IsInRole`) needed to
install one — OBS's virtual camera is a signed kernel-mode DirectShow filter requiring
elevated install. `scripts/make_injection_corpus.py` builds tier 1 only and records
`tier2_status: "blocked"` with this reason in every manifest it writes (see
`BLOCKED_TIER2_REASON`), rather than simulating a virtual camera in software and
mislabelling it tier 2. **Unblock condition:** run on a machine with OBS Studio (Virtual
Camera feature enabled) or Linux with v4l2loopback loaded, then re-run with `--tier2`.

### 2026-08-31 — N-of-burst evidence reuse implemented; mitigation weaker than hoped

Promotes the "known mitigation, deliberately not implemented" amendment above from
proposal to implementation, via `scripts/measure_phash_burst_calibration.py`
(→ `results/phash_burst_calibration.json`), and reports an honest, unwelcome finding
along the way.

**Phase A (D floor).** Re-ran the robustness sweep (JPEG requality 95→20, rescale
0.5x/0.7x/1.3x, 5% centre crop, 5 base images): worst-case distance is **10**, matching
the earlier robustness-sweep amendment exactly. `phash_hamming_max` raised from 6 to
**10** — the floor that still catches every case measured, not a number picked by feel.

**Phase B (N sweep).** Simulated 30 synthetic subjects × 5 capture sessions each × a
30-frame burst per session (a session-level jitter — same magnitude as
`measure_phash_fpr.py`'s single-frame jitter — plus a much smaller per-frame jitter on
top, modelling natural intra-burst video variation), then measured, for every N from 1
to 30, the fraction of same-subject session-pairs where ≥N frames of one session land
within D=10 of the other:

| N | 1 | 5 | 10 | 15 | 20 | 25 | 29 | 30 |
|---|---|---|---|---|---|---|---|---|
| Within-subject FPR | 33.7% | 31.3% | 30.0% | 29.0% | 26.3% | 26.0% | 25.0% | 24.0% |

**No N in [1, 30] gets anywhere near the "comfortably below 1%" target** — not even
N=30 (require every single frame to match). The instruction anticipated N might need
*raising* if real collisions ran higher than synthetic ones; what this run actually
found is structural, not a matter of degree: **burst frames are not independent
trials.** Within one capture, all 30 frames share the same coarse pose/lighting (only
small intra-burst jitter on top of one session-level draw), so under phash's coarse,
low-frequency hashing a false-positive collision tends to hit *all* frames of a burst
or *none* — the match-count distribution across the 300 session-pairs measured is
sharply bimodal (median 0, p95 = 30 of 30, mean 8.6), not a smooth curve N could ride
down. Raising N barely helps because the thing that determines a collision (whether two
sessions' overall pose/lighting happened to land close) is already decided before N is
ever evaluated.

**Implemented anyway, with the values the data actually supports:** `phash_hamming_max:
10`, new `phash_reuse_min_frames: 30` (require *every* frame of the burst to match —
the least-bad point measured, not a point that meets the original target).
`pqbio.binding.phash_index.PhashIndex.is_burst_reused(frame_jpegs, max_distance,
min_matching_frames)` implements the rule; `pqbio.binding.verify.check_evidence_reuse`
calls it instead of flagging on any single `check_reuse` hit (the low-level primitive
is unchanged and still used directly by `is_burst_reused`, so nothing about hash
computation or the BK-tree/SQLite consistency property changed — the restart test
still passes unmodified logic, just through the new method too).

**What this means for a real deployment, stated plainly:** at these values, the check
still reliably catches genuine reuse (identical or lightly modified media matches on
effectively all frames, trivially clearing N=30) but the false-positive rate against a
*second genuine session of the same person* remains high — the burst aggregation did
not fix that, contrary to the original hope. A production system should not treat a
lone `BIND_EVIDENCE_REUSE` as an automatic hard reject; routing it to `CHALLENGE`
(step up with a fresh nonce) once Module D's policy engine exists is the honest
mitigation for the residual FPR, not a further N/D tuning pass. A structurally
different signal — one that doesn't inherit phash's per-burst correlation — is the
real fix, and is out of scope here.

**This remains a synthetic measurement** (§6: no licensed dataset yet). Re-run
`scripts/measure_phash_burst_calibration.py` once real multi-session captures of the
same subjects are available — both the bimodal shape and the specific FPR numbers need
checking against real data, not just the headline percentages.

### 2026-08-31 — Module E: verification server implemented (`pqbio/server/`)

`app.py` (startup/model-integrity gate), `routes.py` (the five §5.5 endpoints),
`pipeline.py` (eight-stage orchestration), `decision.py` (receipt construction/signing),
`store.py` (SQLite keystore/sessions/audit). Real enroll → challenge → handshake →
verify → signed-decision flow now runs end-to-end through real ML-KEM-768/ML-DSA-65
(fallback backend) and AES-256-GCM, verified by an actual passing test, not just
component-level tests of the pieces.

**Deliberate extension beyond the literal spec text:** all eight stages run off the
event loop via a `ThreadPoolExecutor`, not just stages 3-6 as §5.5 names — under the
kyber-py/dilithium-py fallback, stage 1's ML-DSA verify and stage 8's ML-DSA sign alone
cost tens of milliseconds each (`results/pqc_micro.json`), so offloading only 3-6 would
not actually have delivered "event loop never blocked" on this backend. Documented in
`pipeline.py`'s module docstring, not silently done.

**Two real gaps found and fixed while building this, not anticipated in the instruction:**
both binding checks B4 (device counter) and the evidence-reuse pHash index are
deliberately *read-only* during verification (§5.3's own design — a check must not
mutate state for a bundle some *later* check might still reject). Module C's own
docstrings correctly named the accept path as the place that should advance them
(`PhashIndex.record_accepted_bundle`, `KeyStore.update_counter`) — but nothing in this
session's first pipeline.py draft ever called either one. Caught by writing the A5(b)
reuse regression test and finding it didn't fire. Both are now called from
`run_verify_pipeline`, gated on `decision_outcome == "ACCEPT"`, after fusion. The
counter advance has a known, undefended TOCTOU race against a second concurrent
accepted request for the same device (B4's check and this advance are two separate
statements, unlike `nonce.py`'s single atomic `UPDATE`); `SqliteKeyStore.update_counter`
raises `ValueError` on a regression rather than corrupting state, so the race fails
loud, not silently, but doesn't yet resolve to a clean reason code. Flagged for
whoever picks up server concurrency hardening next, not fixed here.

**Receipt self-reporting is logically impossible, so the signed receipt doesn't try:**
`stage_latency_ms["sign_audit"]` (the ~52ms fallback ML-DSA signing cost the build
instruction asked to be recorded) cannot appear inside the *signed* `Decision` object,
because a signature cannot cover the duration of computing itself — by the time signing
finishes, the payload it signed is already fixed. It's recorded in the (unsigned) audit
log instead, which has no such constraint; `pipeline.py`'s docstring and
`_decision_to_audit_json`'s call site explain why.

**Windows SQLite connection leak, found by the test suite itself, not anticipated:**
every store (`nonce.py`, `phash_index.py`, `server/store.py`) opened connections via
`with _connect(path) as conn:` — but `with` on a raw `sqlite3.Connection` only
commits/rolls back a transaction; it never closes the connection. Under this project's
`isolation_level=None` autocommit convention there's no transaction for that to matter,
so the connection was simply never closed, relying on GC. POSIX tolerates deleting an
open file; Windows doesn't, and the very first Module E integration test
(`tests/integration/test_server_happy_path.py`) hit `PermissionError: [WinError 32]`
tearing down its `tempfile.TemporaryDirectory`. Fixed by turning all three `_connect`
helpers into `@contextmanager` generators that `close()` in a `finally`, with zero
changes needed at any of the ~20 call sites. Real bug, not a test-only artefact — would
have leaked file handles in a long-running server too.

**A face-detection/video-codec interaction, found while building realistic test
fixtures:** the astronaut crop used elsewhere in this project detects at a borderline
SCRFD confidence (~0.52, just above the model's internal 0.5 filter) in memory, but a
`cv2.VideoWriter` → `cv2.VideoCapture` round-trip (tested across mp4v/XVID/MJPG,
identical result on all three) degrades it just enough to drop to zero detections —
not a codec bug, a margin problem. A wider-crop version with more background margin
detects at ~0.77-0.99 and survives the round-trip cleanly. `tests/unit/_server_fixtures.py`
uses the wider crop; `ReplaySource`-backed bundles (`build_genuine_bundle`) now correctly
exercise codec-driven pacing, and a separate `build_live_genuine_bundle` (paced,
jittered timestamps; palette-tinted frames that actually satisfy B6's illumination
correlation) is the ACCEPT-path happy-path fixture, since a static pre-recorded clip
can never react to a fresh per-session nonce by construction — that's B6 working
correctly, not a fixture bug.

**A2/A3/A4 remain BLOCKED, as anticipated going in:** `pad.py`/`morph.py`/`deepfake.py`
are still absent (Module D amendment above). Their tests confirm the DoD's actual
ask — the pipeline reaches a real decision and reports `MISSING_SIGNAL_PAD` /
`_MORPH` / `_DEEPFAKE`, never silently defaulting to benign — not that the attacks are
caught. A5(c) (screen-replay recapture) is `pytest.mark.skip`, not faked: it needs a
real display+webcam capture loop that doesn't exist in this headless environment (§5.2
amendment above).

**Result:** 18 new tests (`tests/integration/test_server_happy_path.py`,
`tests/integration/test_server_startup.py`, `tests/security/test_server_adversary_classes.py`),
204 passed / 1 documented skip project-wide, `ruff`/`black`/`mypy --strict` clean on
`pqc/`, `binding/`, `server/`. Concurrency and receipt-verification DoD items measured
directly (see those test files), not asserted from documentation.

### 2026-08-31 — Module F: benchmark harness implemented (`pqbio/bench/`)

`accuracy.py`, `latency.py`, `loadgen.py`, `resources.py`, `overhead.py`, `report.py`,
plus `scripts/run_full_eval.py` and working `make bench`/`make report` targets. Every
§8 metric has a real implementation; `make bench` runs to completion in one command
and produces `results/report.md` (T1-T8, F1-F4) and `results/BLOCKERS.md` entirely from
`results/*.json`, never hand-assembled.

**Accuracy metrics (accuracy.py) were unit-tested against synthetic, analytically-known
score distributions before touching any real detector's output** — 25 tests
(`tests/unit/test_bench_accuracy.py`), each with a hand-computed expected value (e.g.
90 genuine at score 0.0 / 10 at 1.0 against 99 attack at 1.0 / 1 at 0.0 gives an exact
TDR@FAR=1% of 0.90 by construction). All 25 passed on the first run. Real numbers exist
only for the injection detector (the one detector that exists) on its synthetic corpus
— APCER/BPCER/ACER all 0.0, AUC 1.0, EER 0.0 on the 7-genuine/7-attack held-out split;
every other T1/T2/T4 cell, MMPMR, and the 6-class confusion matrix's four non-injection
rows/columns are `pqbio.bench._common.blocked(...)`, not a blank or a zero, per the
build instruction.

**Two real bugs found and fixed while building this, both in the bench harness itself,
not in Module E:**

1. `psutil.Process.cpu_percent(percpu=True)` doesn't exist — `percpu` is a module-level
   `psutil.cpu_percent()` argument (whole-system, per-core), not a per-process one.
   `resources.py`'s `ResourceSampler` now uses the plain per-process `cpu_percent()`
   (a single float that can exceed 100% on a multi-core process, e.g. 350% = 3.5
   cores), which is the number that actually answers "how much of the machine is our
   workload using."
2. **A genuine concurrency race in `loadgen.py`, not Module E**, caught by running the
   real sweep, not by inspection. First symptom: intermittent `409` on `/v1/verify` at
   concurrency=8+. Root cause: a session's challenge has a 30s TTL
   (`binding.challenge_ttl_s`); the first draft of `_prepare_requests` set up every
   device (enroll → challenge → handshake → build bundle) **sequentially**, so at high
   concurrency the earliest-prepared sessions could age past their TTL before their
   (also queued-up) `verify()` call ever ran — a spurious expiry with nothing to do
   with event-loop blocking. Fixed by parallelising setup (`asyncio.gather` instead of
   a `for` loop). At concurrency=64 even *parallel* setup can still lose the race —
   64 simultaneous ML-DSA-bearing HTTP calls queuing behind `server.workers`'s 4
   executor threads can themselves take long enough that a session expires during
   handshake. Rather than papering over this, `_prepare_one`/the verify loop now catch
   the `409` explicitly, count it (`setup_failed_before_verify` /
   `expired_before_verify`), and let the sweep complete — turning a crash into a
   reported finding.

**The real concurrency sweep (`results/loadgen.json`, concurrency 1→64, 6-frame
bundles) produced two distinct, honest findings, not one:**

- **Event loop: not blocked.** p99 latency grew 11.26x (1232ms → 13878ms) while
  concurrency grew 32x (1→32) — far below proportional. Throughput rose from 0.81 to
  2.29 verifications/sec over the same range, with a knee at concurrency=8 (the
  marginal throughput gain from 8→16 drops to 4.2%, below the 10% threshold) —
  consistent with Module E's event loop staying responsive under load and
  `server.workers=4` (config) being the real limiting resource past the knee, not a
  blocked coroutine.
- **A separate, real scalability ceiling at concurrency=64**, under this environment's
  pure-Python PQC fallback specifically: every one of the 64 simultaneous sessions
  either failed setup (29) or expired before its `verify()` call ran (35) — **zero**
  completions. This is not the event-loop-blocking question §8.2 asks about; it is
  this environment's crypto backend being too slow, relative to the 30s challenge TTL,
  to sustain 64-way concurrent session establishment at all. Expected to close
  substantially once liboqs replaces the fallback (ML-DSA sign alone is ~52ms fallback
  vs. an expected ~2 orders of magnitude faster under liboqs — `results/pqc_micro.json`).

**Overhead ablation (§8.3): C0 real, C1/C2/C3 correctly BLOCKED.** C0 (bare
`GET /v1/health`, no crypto, no AI) measures ~1.2ms mean — the ASGI/FastAPI dispatch
floor. C1/C2/C3 all refuse via `overhead.py`'s pre-existing fallback-backend guard
(unchanged this session) and report `blocked(...)`, not a number; `pq_overhead_ms`,
`ai_overhead_ms`, and their ratio are likewise blocked, derived quantities that can't
exist without their inputs. **All four paths are fully implemented** — C1/C2 measure
crypto+binding cost directly via Module A/C function calls (deliberately skipping real
face detection so "AI: none" is actually AI-free, not just unscored — see
`overhead.py`'s module docstring), C3 reuses `latency.py`'s real HTTP driver — verified
correct by bypassing the guard in a test (`tests/integration/test_bench_overhead.py`);
installing liboqs is the only remaining step, no code changes needed.

**Reproducibility (§5.6 DoD) verified directly, not assumed:** the injection
detector's `train_and_evaluate` with a fixed seed produces bit-identical
`test_accuracy`/`test_auc`/per-sample `test_scores` across two independent runs
(`tests/integration/test_bench_reproducibility.py`), and that reproducibility survives
`accuracy.py`'s own EER/AUC/TDR sweeps too, not just the raw detector output. Timing
variance is bounded, not eliminated: two independent 5-request latency runs must stay
within 3x of each other's mean — generous on purpose, since wall-clock latency in a
shared/virtualised environment is never bit-reproducible the way accuracy numbers are.

**Result:** 61 new tests across `tests/unit/` and `tests/integration/`
(`test_bench_accuracy.py`, `test_bench_common.py`, `test_bench_report.py`,
`test_bench_loadgen.py`, `test_bench_overhead.py`, `test_bench_reproducibility.py`),
265 passed / 1 documented skip project-wide, `ruff`/`black` clean repo-wide, `mypy`
clean on `pqbio/bench/` and `mypy --strict` clean on `pqc/`/`binding/`/`server/`.
`results/BLOCKERS.md` (32 blocked entries) is the honest scope statement for weeks 6-8.
