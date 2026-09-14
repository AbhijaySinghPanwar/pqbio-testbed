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
| O3 Detect presentation, morphing, deepfake, replay, injection | Module D (§5.4) — **two of five implemented**: injection (self-generated corpus, §7) and morphing (S-MAD + D-MAD, self-generated LFW-derived corpus, §5.4 D2). Presentation, deepfake and replay remain absent, not stubbed — no licensed dataset and, for replay, no consented recording (§6, `results/BLOCKERS.md`) |
| O4 Measure accuracy, latency, throughput, CPU, memory | Module F (§5.6), §8 — harness implemented and produces every metric via `make bench`; most §8.1 accuracy cells are BLOCKED (four detectors/three datasets absent, `results/BLOCKERS.md`), §8.2 performance numbers (latency, throughput, CPU/RSS) are real, measured |
| O5 Security–performance trade-off analysis | §8.3, §8.4 — C0 (framework floor) real; C1/C2/C3 (crypto/AI overhead) BLOCKED behind the fallback-backend guard until liboqs is installed; §8.4's T8 is latency/crypto-cost-only pending real ACER data |
| D1 Working reproducible prototype | §13 — real enroll→challenge→handshake→verify→signed-receipt flow now runs end-to-end through Module E (§13's `make demo`/`docker-compose` packaging still open, Module F) |
| D2 Attack-detection component on suitable datasets | §5.4, §6 — **two of five attack types covered**. "Suitable datasets" is where this is weakest and the wording should not paper over it: both covered corpora are *self-generated*, not suitable public benchmarks, so the numbers are not comparable to published results (§12 items 3 and 9). The three uncovered types are blocked on licences and consent, not on implementation |
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

**Challenge.** The server nonce drives a physical challenge a pre-recorded stream cannot satisfy. Derive a colour sequence from the nonce (`PRF(nonce)` → `binding.illumination_steps` steps from {red, green, blue, white}, `binding.illumination_step_ms` each — 12 × 200 ms, revised from 4 on 2026-09-03, see below), display full-screen, and record the per-frame mean chromaticity of the face region. The verifier correlates the measured trace against the expected sequence. This is the mechanism behind deliverable D3 and the strongest signal for replay and injection.

**What "mean chromaticity" means here, precisely** (tightened 2026-09-02 — the original wording was too loose to implement correctly, and was implemented incorrectly; see §14):

- The per-frame measurement is **luminance-normalised**: `r = R/(R+G+B)`, `g = G/(R+G+B)`, `b = B/(R+G+B)`, so a frame's three values sum to 1. Absolute per-channel brightness is *not* chromaticity, and correlating it makes B6 track scene illumination instead of hue.
- The denominator is **guarded**. Below `capture.illumination_min_channel_sum` a region has no recoverable hue, and the measurement returns the neutral point (1/3, 1/3, 1/3) rather than amplifying sensor noise. Neutral is constant, so it contributes nothing to the correlation — the fail-closed direction.
- The **expected** trace is built in the same normalised space (`pqbio.binding.verify.palette_chromaticity`). White is therefore the neutral point, not a maximum in all three channels.
- The correlation is **channel-centred**: each of the three channels has its own mean across frames removed before Pearson. Without this the score is dominated by the static colour of the room rather than by the modulation the challenge induces.
- The measurement region may be weighted (`capture.illumination_region_weighting`: `uniform` or `centre`). Which one separates better is an empirical question, re-derived by `scripts/calibrate_illumination_corr.py`, not a fixed choice.

**Why 12 steps, and the frame budget that follows.** The correlation's effective sample size is the number of challenge *steps*, not the number of frames — frames captured within one step are near-identical, so capturing more of them narrows nothing. At the 4 steps originally specified, the genuine and wrong-nonce classes **overlap by 0.100** on real sensor data: no threshold separates them, and the choice is not a tuning question. Swept over {4, 8, 12, 16} steps (§14, 2026-09-03 → `results/b6_operating_point.json`), separation appears at 8 and is comfortable at 12.

The capture budget must cover the challenge: `capture.n_frames / capture.fps ≥ illumination_steps × illumination_step_ms`. At 12 × 200 ms that is 2.4 s, met by 48 frames at 20 fps (4 frames per step, ~2 of them usable after the ~60 ms panel-and-sensor settle at each step). This is asserted by a test, not left to a reader — see `tests/unit/test_spec_config_agreement.py`.

**Capture protocol.** Lock white balance; leave exposure automatic. Auto WB spends the capture correcting the very cast the challenge induces. Auto exposure does the opposite job — it is what reaches an operating point bright enough for the cast to register — and on the reference sensor manual exposure cannot reach one. Locking both, and locking at a setpoint chosen while the challenge renders, were each measured and each scored worse (§14, 2026-09-03). `CameraSource._apply_capture_protocol` implements this.

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
| B6 | Challenge signal correlates with expectation (`binding.illumination_corr_min`) | `BIND_CHALLENGE_UNMET` |
| B6-pre | **Evaluability:** the capture can measure the challenge at all — trace spread ≥ `binding.illumination_min_trace_spread`. Runs *before* B6's correlation; a capture failing it never reaches the correlation | `BIND_CHALLENGE_UNEVALUABLE` |

**B6 has three outcomes, not two.** Pass, failed, and *could not be evaluated* — modelled on Module D's `QUALITY_INSUFFICIENT` (§5.4). An unmeasurable capture is not an attack, and calling it one both wrongs the user and corrupts §8.1's per-attack rates, which are computed from these outcomes. `BIND_CHALLENGE_UNEVALUABLE` propagates as `None` in the tristate binding flags Module D consumes (never benign, never an attack — the same contract as a missing detector score) and maps to `CHALLENGE` in §5.5's policy, never `REJECT`. A *missing or malformed* trace is a different thing again: that is a protocol violation and stays `BIND_CHALLENGE_UNMET`, so an attacker cannot buy a retry loop by omitting the field.

B1–B5 are deterministic predicates and are always evaluable on a well-formed bundle; B6 is the only statistical check, which is also why it carries the whole BPCER budget (§14, 2026-09-03).

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

**D2 Morphing** — Krish. Two settings: S-MAD (single image, texture + CNN) and D-MAD (differential — classifier over the ArcFace embedding difference between the suspect image and a trusted live capture). Datasets: FRLL-Morphs, SMDD. Report MMPMR alongside APCER/BPCER.

*Where each setting runs — an architectural fact, not a gap.* D-MAD needs two images: a suspect **document** image and a trusted live capture. That pair exists at **enrolment**, where a document photo is submitted and checked against the person presenting it; it is the moment a morph is actually introduced into the system, and it is where D-MAD belongs. `/v1/verify` receives a live capture bundle and nothing else, so there is no suspect document to difference against — running D-MAD there would compare an image with itself. The verification pipeline therefore runs **S-MAD** (stage 6), which can score the one image it has, e.g. an injected morphed frame. The earlier wording here ("D-MAD matches our threat model since a live capture is always available at verification") conflated the two moments: a live capture is available at verification, but the suspect image is not. The enrolment route does not yet run D-MAD — `/v1/enroll` accepts a face image without a separate document image — and that is recorded as a limitation of the enrolment flow, not of the detector.

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

**Reading the 6-class matrix when a decision carries several reason codes.** Since
2026-09-06 a rejected decision carries *every* code determined up to the rejection point,
not only the one that triggered it (§14) — a sample can be both an injection and a
counter-replay. The matrix is single-label, so the collapse is defined rather than left to
whichever code happened to be first:

1. **A documented precedence order** (`pqbio.bench.accuracy.ATTACK_CODE_PRECEDENCE`), applied
   in this order: `PAD_DETECTED` → presentation, `MORPH_DETECTED` → morph,
   `DEEPFAKE_DETECTED` → deepfake, `REPLAY_DETECTED` → replay, `INJECTION_DETECTED` →
   injection, then `BIND_EVIDENCE_REUSE` → replay, `BIND_CHALLENGE_UNMET` → replay. The
   ordering principle is **specificity of attribution, not severity**: a detector that
   examined the media and named an attack outranks a binding check that inferred one from
   protocol evidence, because the detector's answer is about what the sample *is* while the
   binding check's is about what it *failed to do*.
2. **Rejections that name no attack type are excluded, not folded in.** A forged signature,
   an expired challenge, a nonce replay, a counter regression, a quality failure — these are
   real rejections, but none of them is one of the six classes, and assigning them to the
   nearest-looking one would invent an attribution the system never made. They are counted
   in `non_attributing_rejections` and reported alongside the matrix.
   `BIND_CHALLENGE_UNEVALUABLE` is likewise excluded; it is not a rejection at all.
3. **The collapse is auditable.** `classify_decisions` returns `multi_attribution_count`
   and the discarded competing labels, so it is visible how often the single-label view
   hid a second finding. A precedence order applied silently is indistinguishable from a
   bug; if that count is large, the matrix is hiding most of what the system found and the
   per-attack rates should be read instead.

Every cell of the matrix therefore counts samples whose predicted class is not `None`, and
the matrix's total is **not** the sample count — the difference is
`non_attributing_rejections`, which must be reported with it.

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

This block and `config/default.yaml` are compared by `tests/unit/test_spec_config_agreement.py`
— they had silently drifted (`phash_hamming_max` still read 6 here long after §14 moved it
to 10), so the agreement is now enforced rather than trusted.

```yaml
crypto:
  mode: pq                  # classical | pq
  kem: ML-KEM-768
  sig: ML-DSA-65

binding:
  nonce_bytes: 32
  challenge_ttl_s: 30
  clock_skew_s: 2
  illumination_steps: 12          # 4 gave overlapping classes; see §5.2 and §14
  illumination_step_ms: 200
  illumination_corr_min: 0.60     # strict on TPR, permissive on FAR -- §14, 2026-09-03
  illumination_min_trace_spread: 0.0015  # evaluability floor -- §14, 2026-09-04
  phash_hamming_max: 10           # calibrated, §14
  phash_reuse_min_frames: 30

capture:
  n_frames: 48                    # 48/20 = 2.4 s, covers 12 x 200 ms
  fps: 20
  resolution: [1280, 720]
  illumination_region_weighting: uniform
  illumination_min_channel_sum: 12.0
  illumination_centre_grid: 4

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
  morph:
    min_verifying_attacks_reported: 30   # below this, verifying-subset cells BLOCK with the count

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
8. **Most generated morphs do not work, so morph detection performance on real attacks rests on a small subset.** This is the stronger morph limitation and is stated first. MMPMR — the fraction of morphs that verify as *both* contributing identities at `match_cosine_min` = 0.38, the attack's actual success condition — is **0.096: 160 of 1,666 morphs** (`landmark_alpha` 144/833 = 0.173; `spliced_jpeg` 16/833 = 0.019). Everything else in the morph rows is measured on a corpus that is ~90% failed attacks.
    - **The pool was scaled to its ceiling and it moved MMPMR only from 0.064 to 0.096.** The corpus now uses every LFW identity with ≥2 images — 1,672 usable of LFW's 5,749; the other 4,069 have a single image and cannot supply an enrolment image distinct from the one their morph is built from. Best-pair ArcFace cosine rose 0.365 → 0.562, but the bulk barely moved (median 0.163 → 0.197). The limit is not compute.
    - **Low MMPMR has two different causes, one per method** (`results/detectors/morph/results.json`, `mmpmr.by_pair_cosine_quintile`, T4b):

      | contributing-pair cosine | `landmark_alpha` MMPMR | `spliced_jpeg` MMPMR |
      |---|---|---|
      | 0.046–0.159 | 0.042 (7/167) | 0.000 (0/167) |
      | 0.159–0.187 | 0.084 (14/167) | 0.012 (2/167) |
      | 0.187–0.206 | 0.211 (35/166) | 0.012 (2/166) |
      | 0.206–0.233 | 0.216 (36/167) | 0.018 (3/167) |
      | 0.233–0.562 | 0.313 (52/166) | 0.054 (9/166) |
      | top decile (≥0.253) | **0.333 (28/84)** | **0.071 (6/84)** |

      **`landmark_alpha` is pool-limited, then method-capped.** MMPMR climbs 7.5× from the least to the most similar quintile, so the scarcity of look-alikes in LFW matters — but it plateaus at a third even for the closest decile, which is a ceiling of the method itself: a 5-point landmark morph at 250×250 does not land close enough to both identities. **`spliced_jpeg` is method-limited outright.** Even its closest decile verifies 7% of the time. The asymmetric 0.6 blend spliced back into the first contributor's own photograph produces an image that is mostly that contributor, and no pool changes that. Neither a bigger pool nor a better pairing rule would fix either result; a higher-fidelity morphing method (68/81-point landmarks, or a generative morph) is what the data points to.
    - **Detection on the verifying subset** — same model, same subject-disjoint test split, attack class narrowed to morphs that verify, genuine class unchanged — is the real number, and it carries far fewer attacks:

      | setting | all test morphs | verifying test morphs only |
      |---|---|---|
      | **S-MAD** ACER / AUC / APCER | 0.175 / 0.905 / 0.176 (n = 666 attacks, 669 bona fide) | 0.153 / 0.920 / 0.133, APCER 95% CI [0.059, 0.246] (**n = 60 attacks**, 669 bona fide) |
      | **D-MAD** ACER / AUC / APCER | 0.119 / 0.952 / 0.117 (n = 520 attacks, 354 bona fide) | 0.114 / 0.967 / 0.106, APCER 95% CI [0.035, 0.231] (**n = 47 attacks**, 354 bona fide) |

      Both verifying cells clear the 30-attack reporting floor (`detect.morph.min_verifying_attacks_reported`), but only just, and the intervals are wide enough to contain the all-morph figures: **no measurable difference between detecting working and failed morphs is supported at this n**, and "better on verifying morphs" should not be read into the point estimates. Two further constraints on what these cells can carry. First, **composition**: the 60 S-MAD attacks are 54 `landmark_alpha` and 6 `spliced_jpeg`; the 47 D-MAD attacks are 43 and 4. The verifying subset is effectively a `landmark_alpha` subset, so **detection of *working* spliced morphs — the hard case — is unmeasured**; 6 and 4 attacks cannot support a figure. Second, D-MAD's genuine class is 354 not 669, and 1,145 of its rows are dropped, because only 893 identities have a third LFW image to serve as the live reference.
9. **Self-generated morph corpus — not comparable to published numbers.** The corpus is generated by `scripts/make_morph_corpus.py` from LFW, because FRLL-Morphs and SMDD both need agreements this project does not have (`data/LICENCES.md`, whose LFW entry is itself **unverified from the primary source**). Every morph ACER/EER/AUC here describes this corpus and these two generators; published FRLL-Morphs and SMDD figures are not a baseline for them and must not be quoted alongside them. The morphs use 5-point SCRFD landmarks rather than the 68/81 points of published corpora, and item 8 shows that matters.
10. **Morph detection has only ever seen two generators, and S-MAD does not survive the change of generator.** Cross-method generalisation — train on one morph method, test on the other — is the closest available proxy for cross-dataset evaluation (`results/detectors/morph/results.json`, T4c):

    | setting | within-corpus | train `landmark_alpha` → test `spliced_jpeg` | train `spliced_jpeg` → test `landmark_alpha` |
    |---|---|---|---|
    | **S-MAD** ACER / AUC | 0.175 / 0.905 | **0.480 / 0.603** (APCER 0.907) | 0.381 / 0.791 |
    | **D-MAD** ACER / AUC | 0.119 / 0.952 | 0.223 / 0.912 | 0.087 / 0.977 |

    **S-MAD trained on plain landmark morphs is worth almost nothing on spliced ones** — AUC 0.603 against a 0.5 floor, missing 91% of them — and a 4× larger pool did not change that (it was 0.586 at 399 identities). `spliced_jpeg` blends only the face interior inside one untouched photograph, removing the global texture and compression cues S-MAD leans on. **D-MAD degrades far less** (0.952 → 0.912) because an embedding difference does not care which pixels were re-compressed. Training on the harder generator transfers down to the easier one; the reverse does not. These are all-morph figures, so item 8's caveat applies to them in full: they are dominated by morphs that do not verify.
11. **The illumination challenge has an operating envelope, and it is narrower than it looks.** The mechanism requires the display to be a *material fraction of the scene's illumination*. Measured on the reference sensor: in a dimly lit room the challenge was recoverable and B6 scored +0.775 ± 0.035; in the same room an hour later with the lights on, the display contributed **~1.5%** of scene brightness, the measured chromaticity trace flattened to a per-channel spread of 0.0002 against 0.0116, and the same capture condition scored **+0.077 ± 0.455** (§14, 2026-09-03). No threshold, step count or exposure setting recovers a signal that is not there. **Implication:** bright ambient light, outdoor capture, and small-screen-at-arm's-length capture may all sit outside the envelope, and the population that falls outside it is not random — it correlates with where and how people verify. A deployment must therefore *detect* the condition rather than fail the user: B6's evaluability precondition (§5.3) returns `BIND_CHALLENGE_UNEVALUABLE`, which maps to `CHALLENGE`, not `REJECT`. The envelope's boundary has been measured on **one sensor in one room** and is not characterised; a deployment on other hardware must re-derive it.

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

> **RESOLVED 2026-09-01.** liboqs 0.16.0 now builds and runs in
> `docker/Dockerfile.server`; `KEM_BACKEND`/`SIG_BACKEND` both report `liboqs` there,
> enforced by a build-time assertion that fails the image rather than shipping the
> fallback. The reversal path above turned out to be exactly right — no code changes
> were needed to *select* liboqs — but four things had to be fixed before it worked
> end to end, and the two backends were then cross-checked against each other rather
> than merely assumed equivalent. See the 2026-09-01 amendment at the end of this
> section for the full account, the measured speedups (ML-DSA-65 signing 78.9 ms →
> 0.114 ms), and what it unblocked. **The fallback remains the live backend on a host
> without a C toolchain** — this is a resolution for the reference environment (§4),
> not a removal of the fallback.

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

  > **CORRECTED 2026-09-01 — this attribution was wrong.** The ceiling was not the
  > crypto backend. Installing liboqs (crypto ~600x faster) did **not** move it: a
  > controlled A/B in one container, same host, same sweep, only the backend differing,
  > hit zero completions at concurrency=64 on *both* backends. The actual cause was in
  > the benchmark harness, not the server or the crypto: `_common.build_signed_bundle`
  > ran a full SCRFD face-detection inference per device, synchronously, so preparing N
  > sessions concurrently serialised N inferences on the event loop *while each
  > session's 30s challenge TTL was already ticking*. Hoisting that one inference out
  > (it is identical for every device — same base crop) cleared the ceiling completely:
  > concurrency=64 now completes 64/64, 0 expired, 0 setup failures. See the 2026-09-01
  > amendment at the end of this section for the corrected sweep and the real knee.

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
`results/BLOCKERS.md` (23 blocked entries) is the honest scope statement for weeks 6-8.

### 2026-09-01 — liboqs working in Docker; fallback results retroactively validated

Closes the 2026-08-30 liboqs amendment at the top of this section. liboqs 0.16.0 now
builds and runs in `docker/Dockerfile.server`, `KEM_BACKEND`/`SIG_BACKEND` both report
`liboqs` there, and the image refuses to build otherwise. The fallback remains the live
backend on a host without a C toolchain — this resolves the reference environment (§4),
it does not remove the fallback.

**Four things had to be fixed before the image worked; none were guessed at.**

1. **`libssl-dev` was missing.** liboqs's CMake build fails at configure time with
   "Could NOT find OpenSSL" without it. Added to the apt layer.
2. **`opencv-python` needs X11/GL shared libraries** that `python:3.11-slim` doesn't
   ship — `import cv2` failed with `libxcb.so.1: cannot open shared object file`, which
   surfaced only when the *test suite* ran in the image, not at build time. Added
   `libgl1 libglib2.0-0 libxcb1 libxrender1 libxext6 libsm6`.
3. **`pip install liboqs-python` does not build liboqs.** It installs a thin ctypes
   wrapper; the C library is cloned from GitHub and CMake-built *lazily on first
   `import oqs`*. The expensive ~6-minute build was therefore silently deferred into
   whichever layer first imported it — the last one — so it re-ran on every retry of an
   unrelated, flakier step. The Dockerfile now forces the build immediately after the
   `pqc-liboqs` install, in its own cacheable layer.
4. **`torch` and `timm` were dead weight.** §4's stack table names PyTorch for the DL
   layer, but Module D was built on insightface+onnxruntime and lightgbm+scikit-learn,
   and neither `torch` nor `timm` is imported anywhere (`grep -rn` finds zero hits, and
   every test already passed on a host where neither is installed). Their only effect
   was pulling multi-GB CUDA wheels into a CPU-only image, which repeatedly timed out
   the build. Removed from the `ml` extra.

**The backends agree, byte for byte** (`scripts/cross_check_backends.py`,
`results/backend_cross_check.json`, `make docker-cross-check`). This is the check that
retroactively validates every result produced while the fallback was the only option,
and it is a positive result: **339 fields identical across 127 deterministic cases** —
ML-KEM keygen from (d,z), encapsulation from explicit `m`, decapsulation, ML-DSA keygen
from seed, deterministic signing, and verification, over the vendored NIST ACVP vectors
plus fixed synthetic seeds. Interop was checked separately and in both directions: each
backend accepts the other's signatures and agrees on the other's decapsulated shared
secret. The 7 ACVP KAT tests pass unchanged on liboqs.

**Getting the KATs to run on liboqs required implementing the deterministic hooks the
fallback had for free.** `ml_kem_768_keygen_from_seed`, `..._encapsulate_with_randomness`,
`ml_dsa_65_keygen_from_seed`, `..._sign_deterministic` and `..._verify_with_context` all
raised `NotImplementedError` on the liboqs path — deliberately, with a note that the hook
still needed writing. It now exists (`pqbio/pqc/_oqs_kat.py`). liboqs-python exposes a
real per-call seed for ML-KEM keygen (`generate_keypair_seed`), but nothing equivalent
for encapsulation or for ML-DSA, so those go through liboqs's global
`OQS_randombytes_custom_algorithm` override. Two things about that were verified
empirically rather than assumed: that fixing the RNG to the ACVP `m`/seed reproduces the
published vectors exactly, and that ML-DSA "deterministic" signing is simply hedged
signing with the internal 32-byte `rnd` fixed to zero. The override is **process-global**,
so it is wrapped in a context manager that restores the system RNG in a `finally` and
raises if the restore fails — leaving it installed would give every subsequent liboqs
call in the process fixed, predictable "randomness", which is a live vulnerability rather
than a test-hygiene problem.

**A real fail-closed gap, found by cross-checking and fixed.** Two negative tests
(`test_kem_encapsulate_rejects_malformed_public_key`,
`test_kem_decapsulate_rejects_wrong_length_ciphertext`) passed on the fallback and failed
on liboqs. The tests were right and the production code was wrong: `kyber-py` happens to
raise on malformed-length input as a side effect of its own array slicing, so
`MLKEM768`'s "fail closed" behaviour was never a contract this project provided — it was
borrowed from one backend. liboqs-python builds its C buffers with
`ctypes.create_string_buffer(data, expected_length)`, which *silently zero-pads or
truncates* instead: a 10-byte garbage "public key" encapsulates without error, and a
10-byte "secret key" produces a well-formed 3309-byte signature. `MLKEM768.encapsulate`,
`MLKEM768.decapsulate` and `MLDSA65.sign` now validate input lengths against the FIPS
203/204 sizes explicitly, before either backend sees a byte. `MLDSA65.verify` needs no
guard — a wrong-length signature must return `False`, not raise, and both backends
already agree on that.

**Measured speedups** (`results/pqc_micro.json` vs the labelled
`results/pqc_micro_fallback.json`, 1000 iterations each, same machine):

| Operation | fallback | liboqs | speedup |
|---|---|---|---|
| ML-KEM-768 keygen | 4.734 ms | 0.0246 ms | 193x |
| ML-KEM-768 encaps | 6.302 ms | 0.0216 ms | 291x |
| ML-KEM-768 decaps | 8.388 ms | 0.0249 ms | 337x |
| ML-DSA-65 keygen | 12.842 ms | 0.0472 ms | 272x |
| **ML-DSA-65 sign** | **78.886 ms** | **0.1144 ms** | **689x** |
| ML-DSA-65 verify | 14.653 ms | 0.0498 ms | 294x |

The 2026-08-30 amendment predicted "roughly two orders of magnitude"; measured is closer
to three. Worth noting against the classical baseline from the same run: ML-KEM-768
encapsulation (0.0216 ms) is now *faster* than X25519 (0.0669 ms), while ML-DSA-65
signing (0.1144 ms) is about 1.9x Ed25519 (0.0607 ms).

**§8.3 overhead ablation, now real** (`results/overhead_ablation.json`, 50 iterations):

| Config | Crypto | AI | Mean |
|---|---|---|---|
| C0 | none | none | 1.675 ms |
| C1 | X25519 + Ed25519 | none | 10.839 ms |
| C2 | ML-KEM-768 + ML-DSA-65 | none | 11.721 ms |
| C3 | ML-KEM-768 + ML-DSA-65 | full | 715.513 ms |

- **PQ overhead = C2 − C1 = 0.88 ms (+8.1% over C1).**
- **AI overhead = C3 − C2 = 703.79 ms (+6005% over C2).**
- **AI:PQ ratio = 798x.**

The numbers do say PQ is cheap next to inference — but the ratio is a **lower bound on
the AI side and therefore provisional**: only one of six detectors exists (injection), so
C3 is missing pad/morph/deepfake/replay entirely. Adding them can only increase the AI
term, pushing the ratio further in the same direction; nothing about the missing
detectors could shrink it. The PQ term is the one that is now solid.

**The concurrency ceiling was not what the previous amendment said it was.** The
prediction was that ~52 ms signs exhausting the 30s challenge TTL caused the
concurrency=64 collapse, and that liboqs would clear it. A controlled A/B — one
container, one host, one sweep, only the backend differing — showed **both** backends
still completing zero requests at concurrency=64. The cause was in the benchmark harness:
`_common.build_signed_bundle` ran a full SCRFD face-detection inference *per device*,
synchronously, so preparing N sessions concurrently serialised N inferences on the event
loop while each session's TTL was already running. That inference is identical for every
device (same base crop); hoisting it out cleared the ceiling completely — concurrency=64
now completes 64/64 with zero expiries on both backends.

**Corrected sweep** (`results/loadgen.json` on liboqs;
`results/loadgen_fallback_controlled.json` is the same sweep with `import oqs` blocked,
for a like-for-like backend comparison): throughput rises to a peak of ~3.6
verifications/sec at concurrency 8–16 and is flat or slightly declining beyond it, on
**both** backends; p50 latency grows roughly proportionally past that point (479 ms at
c=1 to ~20 s at c=64 under liboqs). The real knee is concurrency ≈ 8–16, and it is set by
`server.workers=4` against ~700 ms of ONNX inference per request — not by the crypto,
which is ~1.6% of a request under liboqs. liboqs is clearly faster per request at low
concurrency (p50 479 ms vs 775 ms at c=1) but does **not** move the saturation point,
because it was never the bottleneck.

**A correctness fix to the finding itself:** `_degradation_finding` used to compare p99
growth across the *whole* sweep and call proportional growth evidence of a blocked event
loop. Past saturation that is just Little's law, so the verdict is now computed over the
unsaturated region only. More importantly, the finding now states plainly that a latency
curve **cannot** distinguish a blocked event loop from ordinary worker/CPU saturation on
a CPU-bound workload, and points at the test that actually can:
`test_event_loop_stays_responsive_while_verify_is_in_flight`, which polls `/v1/health`
during concurrent verifies. That test passes.

**Three unrelated bugs surfaced by running the suite on Linux for the first time**, all
pre-existing and all real:

- `scripts/make_injection_corpus.py` wrote manifest paths with `str(Path)`, i.e. Windows
  backslashes, into a committed JSON file. On Linux `data\processed\...` is one filename,
  not a path, so five tests failed with `FileNotFoundError`. Now `.as_posix()`; the
  manifest and corpus were regenerated.
- `tests/integration/test_bench_reproducibility.py` retrained the injection detector into
  the **shared** `models/injection_gbm.txt` as a side effect of testing reproducibility,
  silently mutating a verified production artefact on every test run — which is how an
  unrelated corpus regeneration shifted the model's decision boundary and broke an A6
  security-regression test in another module. `train_and_evaluate` grew a
  `record_checksum=False` flag; the test now writes to a temp path. This also made the
  test runnable against a read-only `models/` mount, which is how the container runs it.
- `tests/unit/_server_fixtures.py::build_instant_bundle` drew a fresh `time.time_ns()`
  per frame, making the A6 injection test's outcome depend on real interpreter jitter
  landing on one side of a trained model's decision boundary. It now uses a seeded,
  deterministic "file-read with occasional stutter" timing pattern, verified to score
  ~0.997 against the model rather than sitting on the boundary. (A literal shared
  timestamp was tried first and rejected: zero-variance deltas force
  `timing_skew_dt`/`timing_kurtosis_dt` to exactly 0.0, which is *out* of the training
  distribution and scored as bona fide.)

**Two tests were coupled to the backend rather than to the behaviour they claimed to
test**, exactly as anticipated — reported and fixed rather than special-cased.
`test_guard_raises_in_this_environment` and
`test_guard_raises_when_fallback_backend_is_active` both asserted "this environment runs
the fallback" as a fact. True when written, false in the image. Both now branch on the
live `KEM_BACKEND`/`SIG_BACKEND` and assert the guard's behaviour *matches* whichever
backend is active, so they are correct on either. `test_overhead_ablation_...` likewise
now asserts C1/C2/C3 are blocked on the fallback and real on liboqs.

**Result:** 265 passed / 1 documented skip **in the container on liboqs**, identical to
the host on the fallback; `ruff`/`black` clean, `mypy --strict` clean on
`pqc/`/`binding/`/`server/`. New make targets: `docker-build`, `docker-test`,
`docker-bench`, `docker-cross-check`. Because the image has no `.git`, provenance is
passed in via `PQBIO_GIT_COMMIT` rather than silently degrading to "unknown" — every
containerised result file carries the real commit.

### 2026-09-01 — two corrections: the assembled system behaved unlike its tested parts

Both of the following were wrong in this document, and both are the same *class* of
error, which is worth naming rather than filing as two unrelated bugs. In each case
every component was individually correct and individually tested, the integration was
also tested, and the assembled system still behaved differently from what the parts
implied — because the property that mattered lived in the *composition*, where nothing
was looking. Component tests cannot see these. Only a differential (A/B) or
cross-implementation check can.

**Correction 1 — the concurrency-64 ceiling was not crypto TTL exhaustion.**

The Module F amendment attributed the concurrency=64 collapse to three ~52 ms ML-DSA
signs per transaction exhausting the 30 s challenge TTL, and predicted liboqs would
clear it. Both halves were wrong.

The A/B: one container, one host, one sweep, `import oqs` blocked for the second arm so
that *only* the backend differed. Both arms still completed **zero** requests at
concurrency=64 — liboqs, whose crypto is ~600x faster, moved the ceiling not at all.

The real cause was in the benchmark harness, not the server and not the crypto:
`pqbio/bench/_common.py::build_signed_bundle` ran a full SCRFD face-detection inference
*per device*, synchronously, inside an `async` setup path. Preparing N sessions
concurrently therefore serialised N inferences on the event loop **while each session's
30 s challenge TTL was already running**. The sessions timed out waiting for the
harness, never for the server. That inference is identical for every device (all bundles
are built from the same base crop), so hoisting it out of the per-device path removed it
entirely: concurrency=64 now completes 64/64 with zero expiries on *both* backends.

With the ceiling gone, the corrected sweep gives the real shape: throughput peaks at
~3.6 verifications/sec around concurrency 8–16 and is flat or slightly declining beyond,
on both backends. **The knee is set by `server.workers` (4) against ~700 ms of ONNX
inference per request. Crypto is ~1.6% of a request under liboqs** (C2−C0 ≈ 10 ms of a
715 ms C3), which is why replacing it changed nothing about where the system saturates.
liboqs is still clearly faster per request at low concurrency (p50 479 ms vs 775 ms at
concurrency=1) — it just was never the constraint.

The secondary lesson: the metric itself was miscalibrated. `_degradation_finding` read
proportional p99 growth *past saturation* as evidence of a blocked event loop, when past
saturation that is Little's law. It now judges the unsaturated region only, and states
outright that a latency curve cannot separate a blocked event loop from ordinary
worker/CPU saturation on a CPU-bound workload — naming
`test_event_loop_stays_responsive_while_verify_is_in_flight` (which polls `/v1/health`
under load) as the test that actually discriminates.

**Correction 2 — `MLKEM768`'s "fail closed" was inherited, never implemented.**

`tests/unit/test_pqc_negative.py` asserted that malformed-length input is rejected, and
it passed for weeks. It was passing on a property this project never wrote:
`kyber-py` happens to raise on wrong-length input as a side effect of its own array
slicing. `MLKEM768` and `MLDSA65` simply forwarded the bytes and inherited that
behaviour. CLAUDE.md §11 says "fail closed" is a project-wide invariant; in fact it was a
property of one backend, and the test could not tell the difference.

liboqs does not raise. liboqs-python builds its C buffers with
`ctypes.create_string_buffer(data, expected_length)`, which **silently zero-pads or
truncates** to the expected size. Measured, not inferred: a 10-byte garbage "public key"
encapsulates without error, and **a 10-byte "secret key" produces a well-formed
3309-byte ML-DSA-65 signature**. Under liboqs the negative tests failed — correctly.
The tests were right; the production code had never had the property.

`MLKEM768.encapsulate`, `MLKEM768.decapsulate` and `MLDSA65.sign` now validate input
lengths against the FIPS 203/204 sizes explicitly, before either backend sees a byte, so
the guarantee is ours rather than borrowed. (`MLDSA65.verify` needs no guard: a
wrong-length signature must return `False`, not raise, and both backends already agree.)

**Only the cross-backend check surfaced this.** Not the unit tests (green on the
fallback for weeks), not the ACVP KATs (each backend agrees with NIST independently on
*well-formed* input — malformed input is outside their scope), not code review across
several sessions. Swapping one dependency for another and demanding identical behaviour
is what exposed it. That is a general argument for keeping both backends alive and for
`make docker-cross-check` staying in the loop: the fallback's value is no longer
performance or availability, it is being a second implementation to disagree with.

### 2026-09-01 — Module B live sensor check: run, and it did not pass

§5.2's DoD item "verified against a real webcam" has been outstanding since Module B was
built, because no camera was attached. One now is (HP Wide Vision HD, 640x480), and there
is a display, so the check was run for the first time:
`scripts/live_challenge_check.py` → `results/live_challenge_check.json`. It renders the
nonce-derived colour sequence full-screen while capturing from the sensor, tagging every
frame with the step that was actually on screen — the render/capture interleaving Module
B's CLI never did.

**What passed.**

- The challenge renders full-screen on a real display.
- **White balance and exposure locking works, and it matters.** Left on auto, the sensor
  drifted 79 → 88 mean brightness while settling — auto-exposure actively correcting the
  very cast the challenge induces. Locked (`CAP_PROP_AUTO_WB` 1.0 → 0.0, manual exposure
  pinned at the value auto had converged to), frame-to-frame brightness holds to a
  standard deviation of 0.06 on a mean of 38.4. A no-render control confirms the lock is
  what is doing it: locks on, nothing displayed, brightness drifts −0.14 over two seconds.
  So `CameraSource` must lock both at capture start, and this is now demonstrated rather
  than argued.
- The even-split timing approximation cost nothing measurable here: correlation under
  B6's `_expand_expected_trace` and under exact per-frame step alignment agreed to four
  decimal places (−0.4667 both), because frames arrived uniformly across steps. That is
  one favourable case, not a general result, but it is the first evidence either way.

**What did not pass: B6 would reject this capture.** Pearson r came out **−0.47**
(threshold 0.70). The check does **not** close the DoD item.

**Why it failed is the useful part, and it is not "the mechanism doesn't work".** A
per-region diagnostic (B:R ratio per challenge step, 4x4 grid — a ratio isolates hue from
brightness in a way B6's absolute per-channel means do not) shows the colour cast is
physically present and reaching the sensor. In the four central cells the B:R ratio rises
on blue steps exactly as it should — cell r2c2 goes 0.812 (white) → 0.911 (blue), spread
0.099 — while peripheral cells sit flat at 0.001–0.005 spread. Reproduced across two
independent runs. The screen is casting colour on the scene; B6 is not seeing it.

Three contributing causes, in order of how actionable they are:

1. **`measure_chromaticity_trace` measures brightness-per-channel, not chromaticity.**
   It returns each channel's absolute mean normalised to [0,1], so any change in total
   illumination moves all three channels together and swamps the hue signal B6 is
   trying to correlate. That is exactly what the data shows: the per-step means rose
   monotonically (0.380 → 0.403 → 0.444 → 0.452) with the channel *ratios* essentially
   fixed. A normalised formulation (r = R/(R+G+B), etc.) would isolate the signal the
   challenge actually induces. **This is a real design finding about a security check,
   surfaced only by running on a sensor — but changing B6's formulation changes a
   binding check's semantics and would need `illumination_corr_min` recalibrated and
   Module C's suite re-run, so it is recorded here rather than changed in passing.**
2. **No subject at capture distance.** The challenge assumes a face at roughly selfie
   distance reflecting the screen. With nobody present, the only surfaces in frame are
   background, metres away, and the reflected signal is correspondingly weak. The
   regions that did respond are exactly the central ones nearest the screen.
3. **Probable panel auto-brightness.** Total scene illumination rose steadily *across*
   the sequence rather than tracking the displayed colour's luminance (white, the
   brightest panel, produced the *dimmest* scene). Consistent with the display's own
   automatic brightness limiting reacting to a full-screen white field. Worth
   controlling for in any real capture protocol.

**Status:** §5.2's live-webcam DoD item stays open, now with a measured reason and a
reproducible script rather than "never run". Closing it needs a subject (or a diffuse
surface) at capture distance, and probably the chromaticity fix in (1).

### 2026-09-01 — replay corpus (§5.4 D4): blocked on subjects, not hardware

Recorded because the blocker changed shape and `results/BLOCKERS.md` said something now
misleading. Replay was filed as "dataset-blocked" alongside pad/morph/deepfake. For the
licensed corpora (Replay-Attack, MSU-MFSD) that is still true. But §5.4 D4 also names a
self-recorded route, and that route is **not** blocked by equipment: the camera, the
display, and WB/exposure locking are all verified working (previous amendment).

It is blocked by people:

- §6 requires **written consent and supervisor approval** to record any human subject.
  A replay corpus is, definitionally, recordings of someone's face.
- A **subject-disjoint split needs at least two consenting subjects** — with one person
  the split the DoD asks for cannot exist at all.
- The protocol needs someone to physically run it: capture genuine clips, replay them on
  a phone and on a laptop screen, at two distances each, re-capturing throughout.

So `pqbio/detect/replay.py` remains deliberately absent rather than stubbed, consistent
with how pad/morph/deepfake are handled — and consistent with the standing rule that a
software-simulated screen replay is not a screen replay and must not be substituted for
one. The blocker text in `BLOCKERS.md` now states the subject/consent requirement
explicitly, because "dataset-blocked" would send someone looking for a licence when what
is actually needed is two consenting people and an afternoon.

Consequence for §8.3: C3 still runs **one of six detectors** (injection), so the AI
overhead term and the 798x AI:PQ ratio remain the provisional lower bound described in
the liboqs amendment above. Nothing about this session changed them.
*(Superseded 2026-09-06: morph landed, so C3 now runs **two of six detectors** and the
ratio moved to 2327x — see that date's amendment.)*


### 2026-09-02 — B6's measurement was a spec defect, and fixing it exposed a second one

**This is a defect in §5.2's wording, not a coding mistake against it.** §5.2 said "record
the per-frame mean chromaticity of the face region". `measure_chromaticity_trace` returned
each channel's absolute mean brightness. Those are different quantities — chromaticity is
luminance-normalised by definition — and nothing in the spec said so explicitly, so the
implementation matched the sentence while missing the meaning. Both have now been
corrected: §5.2 above states the formulation precisely, and the code implements it.

**Why it survived so long.** Every headless test passed, because the test fixtures were
solid palette-colour frames: when the frame *is* the challenge colour, brightness-per-
channel and chromaticity carry the same information and B6 scores 1.0 either way. The
defect only appears when the scene has its own colour and the challenge adds a small
amount of light on top — which is every real capture and no synthetic one. There is no
substitute for a sensor here.

**The fix, and the second defect it exposed.** Normalising the measurement was necessary
and not sufficient. With normalised chromaticity on both sides, a capture where the
challenge visibly worked *still* scored −0.17: measured `b` climbed 0.150 → 0.213 → 0.241
across the blue steps and `g` spiked to 0.457 on the green step, and flattened Pearson
read it as anti-correlated. The reason is that both traces are laid out
[r,g,b, r,g,b, ...] and a real room has a large static chromaticity offset — r=0.42,
g=0.39, b=0.19 on every frame — which dominates the variance and gets correlated against
an expected sequence demanding b=1 on blue steps. **Removing each channel's own mean
across frames before correlating** deletes the room and leaves the modulation. The same
capture then reads +0.79.

That second defect was invisible until the first was fixed. It also tightens the check
rather than loosening it: a bundle can no longer score on the static colour of its scene,
only on whether its trace moves the way its nonce demands.

**Recalibration** (`scripts/calibrate_illumination_corr.py` →
`results/illumination_corr_calibration.json`). The old 0.70 was set against the old
formulation and carried no information about the new one. Re-derived from 24 real captures
(6 repeats × 4 conditions, `results/live_challenge_check.json`) against three negative
classes: 6 real no-render controls taken on the same sensor seconds apart, 192 wrong-nonce
scorings of real traces (the attack B6 exists to stop), and 200 synthetic no-cast traces.

| weighting | positives | negatives | Cohen's d | AUC |
|---|---|---|---|---|
| `uniform` | +0.509 ± 0.275 | +0.016 ± 0.259 | 1.85 | 0.911 |
| `centre` | +0.481 ± 0.325 | +0.003 ± 0.275 | 1.59 | 0.869 |

**`uniform` wins, and that is the opposite of what the 4×4 regional diagnostic suggested.**
That diagnostic showed central cells swinging 0.05–0.10 in B:R while the periphery sat at
0.001–0.005, which looked like a clear case for down-weighting the periphery. It is not: a
larger swing in the signal is not better separation once the periphery's noise is dropped
along with its signal. Picked on the measured number, not on the earlier reasoning.

**The threshold is 0.70 again, and the coincidence is worth stating so nobody reads it as
"unchanged".** It is now the lowest round value above the measured zero-false-accept floor
of 0.688; the worst wrong-nonce negative scored 0.673, giving a margin of +0.027 below.
**There is no comparable margin above.** Measured TPR at 0.70 is 0.33 across all capture
conditions and 0.67 in the best one — B6 will false-reject genuine captures at this
setting. Set on false-accept rate because B6 is one of six ANDed checks: a false reject
costs a retry, a false accept is the failure the check exists to prevent. Flagged
**interim**: one session, one room, one sensor, no subject at capture distance.

**The real problem is the step count, not the threshold.** B6's correlation has roughly
`illumination_steps` effective samples per channel — frames within a step are
near-identical, so capturing 30 or 300 of them narrows nothing. At the spec'd 4 steps the
null distribution is far too wide for any threshold to work. Measured directly by re-running
the live check at 16 steps (`results/live_challenge_check_16step.json`):

| steps | wrong-nonce p95 | wrong-nonce max | control max | zero-FPR threshold |
|---|---|---|---|---|
| 4 | 0.577 | 0.673 | 0.498 | 0.688 |
| 16 | 0.213 | 0.360 | 0.289 | 0.400 |

Four times the steps cuts the false-accept tail roughly in half and would support a
threshold near 0.40 with far better TPR. **Raise `illumination_steps` before lowering
`illumination_corr_min`.** Left at 4 here because changing it is a §5.2 protocol change
that should be made together with the consented recording session, not in passing.

**§5.2's live-webcam DoD item: still not closed, and now for a different reason.** The
formulation is right — a synthetic scene with only a 5% cast scores r=0.9998, so the
measurement is not the limitation. On the sensor, `unlocked_render` cleared 0.70 on
individual runs (+0.79, +0.81 centre) but averaged +0.687 ± 0.269 over 6 repeats, which
straddles the threshold rather than clearing it. Reporting that as a pass would be picking
the favourable run.

**What the four-pass design settled about the two locks.** The 2026-09-01 entry said "WB
and exposure must be locked". That was half right, and the halves point in opposite
directions:

| condition | uniform r (6 repeats) |
|---|---|
| WB+AE locked, rendered | +0.368 ± 0.192 |
| WB locked, AE auto, rendered | +0.472 ± 0.291 |
| auto WB+AE, rendered | +0.687 ± 0.269 |
| WB+AE locked, **not** rendered (control) | +0.058 ± 0.346 |

Auto WB does fight the cast, as argued. But **auto exposure is what reaches an operating
point where the cast is measurable at all**, and on this sensor that dominates. Locking
exposure via DirectShow pins a short exposure no `CAP_PROP_EXPOSURE` value lifts: 0, −1 and
−2 all land at 33/255 in this room, while auto reaches 112–169/255 during rendering. Gain
is the only remaining lever (0 → 128 buys 33 → 69/255) and it is not enough. So the capture
protocol needs to lock white balance, lock exposure *at a setpoint chosen while the
challenge is rendering* rather than at ambient, and verify the resulting operating point —
not simply "lock both at capture start".

**Of the two contributors flagged on 2026-09-01, one is now distinguished and one is not.**
Panel auto-brightness is no longer a candidate: the luminance ramp it would cause is exactly
what normalisation removes, and the control pass isolates sensor drift from screen effects
directly. **No subject at capture distance remains untested and is now the leading
explanation** — the screen lights whatever is in front of it, and with nobody there the
reflecting surfaces are background metres away. Testing it needs the same §6 consent that
blocks the replay corpus.

**What remains unexplained:** why per-run variance stays as high as it does even at 16
steps (σ ≈ 0.2–0.45 on the positives). Effective sample size accounts for the 4-step case;
it does not fully account for the residual spread at 16. Not resolved here, and not papered
over by moving the threshold.


### 2026-09-03 — B6 was calibrated backwards for a link in an AND chain

**The error.** The 2026-09-02 recalibration drove B6's false-accept rate to zero and
accepted whatever true-positive rate fell out — 0.33. That is the right reasoning for a
check standing alone and the wrong reasoning for one of six ANDed checks. An AND chain
**compounds false rejects** (a genuine capture must clear all six) and **suppresses false
accepts** (an attacker must clear all six). So each link should be calibrated *strict on
TPR and permissive on FAR* — the inverse of what was done. At TPR 0.33, B6 alone rejected
two thirds of genuine verifications and would have been the dominant term in system BPCER
(§8.1), while its contribution to system FAR was being optimised at that cost.

**How the BPCER budget actually divides.** Naively, six independent statistical checks
each need TPR = 0.95^(1/6) = 0.9915 for a 5% system BPCER. That is not this chain: B1–B5
are *deterministic* predicates on a genuine bundle — valid server signature, within expiry,
unconsumed nonce, advancing counter, recomputing digest — and reject genuine traffic only
when something is really wrong. They carry no BPCER budget. So B6 absorbs all of it and
its required TPR is the system target itself, 0.95, not the sixth root of it. The
distinction barely moves the number here (0.95 vs 0.9915) but it decides who pays, and it
will matter the moment a second statistical check joins the chain.

**No threshold fixes this at 4 steps; the step count does.** Swept {4, 8, 12, 16} steps at
200 ms, 8 repeats × 5 capture conditions, with the same three negative classes as before
(real no-render controls, wrong-nonce scorings of real traces, synthetic no-cast) —
`scripts/b6_operating_point.py` → `results/b6_operating_point.json`. For the deployed
protocol (WB locked, AE auto) under `uniform` weighting:

| steps | wall | lowest genuine | worst negative | gap | threshold | TPR | FAR |
|---|---|---|---|---|---|---|---|
| 4 | 0.8 s | 0.544 | 0.644 | **−0.100 (overlap)** | none exists | — | — |
| 8 | 1.6 s | 0.726 | 0.620 | +0.105 | 0.68 | 1.00 | 0.000 |
| 12 | 2.4 s | 0.748 | 0.472 | +0.276 | **0.60** | 1.00 | 0.000 |
| 16 | 3.2 s | 0.653 | 0.368 | +0.285 | 0.52 | 1.00 | 0.000 |

At 4 steps the classes **overlap**: there is no threshold, and that closes the question of
whether 0.70 or any other value was ever going to work. **12 steps is chosen over 16**
because their minimum two-sided margins (+0.133 vs +0.143) differ by less than the standard
error of the estimate (~0.02 on 8 captures) while 16 costs another 0.8 s of capture on
every verification. The selection rule is in the JSON, not just in this paragraph.

**A methodological correction inside the correction.** The first pass at this sweep pooled
all four rendered conditions into one positive class and concluded no operating point
existed at any step count. That was an artefact: most of the apparent variance was
*between* protocols, not within them (pooled σ ≈ 0.24, per-condition σ ≈ 0.03–0.12).
A deployment runs one capture protocol, so the positive class is one protocol's captures.
The first version of the script had also persisted summaries only, so this could not be
re-derived without the room and the hardware back — it now persists every raw correlation
and per-frame trace, and `--reanalyse` recomputes from them.

**Frame budget** (`scripts/measure_frame_budget.py` → `results/frame_budget.json`, measured
against the production JPEG-q90 path, not estimated). 12 × 200 ms needs 2.4 s:

| option | wall | bundle | server per-frame cost | note |
|---|---|---|---|---|
| 30 @ 15 (old) | 2.0 s | 6.79 MiB | 190 ms | too short for 12 steps |
| 36 @ 15 | 2.4 s | 8.15 MiB | +20 ms | 3 frames/step, zero slack |
| **48 @ 20** | **2.4 s** | **10.86 MiB** | **+92 ms** | 4 frames/step — chosen |
| 64 @ 20 | 3.2 s | 14.48 MiB | +189 ms | only needed for 16 steps |

48 @ 20 is chosen: after the ~60 ms panel-and-sensor settle at each step, 3 frames/step
leaves only ~2 usable, and under-sampling steps is precisely what put B6 in this state.
The +92 ms is server-side per-frame work (pHash dominates) against the ~700 ms of ONNX
inference already in a request, and 2.4 s of capture against a 30 s challenge TTL — neither
is close to binding. Shortening the step below 200 ms was rejected for the same
under-sampling reason.

**§14's own proposed exposure fix was tested and lost.** The 2026-09-02 entry proposed
locking exposure "at a setpoint chosen while the challenge renders" rather than at ambient.
Implemented (`_lock_at_challenge_setpoint`) and measured as a fifth condition, it scored
*worse* than simply leaving AE automatic at every step count — 0.372 vs 0.551 at 4 steps,
0.615 vs 0.769 at 8, 0.632 vs 0.777 at 12, 0.429 vs 0.750 at 16. It is therefore **not
implemented in the capture path**, and the condition is kept in the diagnostic script
because a rejected hypothesis with data behind it is worth more than one quietly dropped.

`CameraSource._apply_capture_protocol` therefore **locks white balance and leaves exposure
automatic**. The white-balance half is well supported — auto WB spends the capture
correcting the cast, and locking it beat leaving it in every session. **The exposure half
is not settled**, and the paragraph below is why.

### 2026-09-03 (later the same evening) — the operating point does not reproduce

Everything above was measured in one sitting. Re-running the live check an hour later, in
the same room with the lights now on, did not reproduce it: at 12 steps `wb_locked_ae_auto`
scored **+0.077 ± 0.455** where the sweep had given **+0.775 ± 0.035**, and the no-render
control (+0.174) scored *higher* than three of the four rendered conditions. That is not a
small discrepancy and it is not noise around the same mean.

Two things were then measured directly (`scripts/measure_operating_window.py` →
`results/b6_operating_window.json`), sweeping exposure under a rendered challenge:

1. **Saturation flattens the trace.** At auto-exposure in the brighter room the sensor sat
   at ~196/255 with **9–10% of pixels clipped**, and in the worst capture the chromaticity
   trace went flat — per-channel spread **0.00024**, against 0.0116 for a locked capture at
   138/255 in the same room minutes apart. Once a channel clips, the ratios stop moving and
   there is nothing left for B6 to correlate.
2. **The screen contributes ~1.5% of the scene's light here.** Rendering full white versus
   full black at fixed exposure moves mean brightness from 197.2 to 198.6 —
   `screen_fraction_of_scene` = 0.012–0.018 across every exposure tested. The challenge is
   a small perturbation on a large ambient constant, and *that ratio* is the physical
   quantity B6 depends on. No threshold, step count or lock setting controls it.

**And the measurement is not stably reproducible even within the evening.** Two runs of the
same sweep, same config, minutes apart: exposure −1 gave **+0.659** and then **−0.304**;
exposure −6 gave **−0.501** and then **+0.503**. A third run was internally consistent
(+0.707 / +0.709 at −1, ten of fourteen points clearing 0.60). The difference between the
erratic and the consistent runs has **not** been isolated — the plausible candidates are
scene motion in front of the camera and sensor adaptation state between passes, and neither
was controlled for.

**What this does and does not invalidate.**

- **The 4-step overlap stands.** It was measured with 8 repeats across 5 conditions and the
  classes overlapped by 0.100. Whatever the run-to-run variance, 4 steps has less signal
  than 12, and the step-count change is the robust part of this session.
- **The AND-chain calibration reasoning stands** — it is an argument about how to set a
  threshold, not a measurement.
- **The threshold 0.60 does not have the two-sided margin claimed above.** Those margins
  (+0.128 / +0.148) came from one sitting whose positives had σ ≈ 0.035; the later evening
  produced σ ≈ 0.455 for the same condition. 0.60 is retained as the best available
  estimate and is **now on weaker evidence than the tables above imply** — read them as one
  session's operating point, not as a characterisation.
- **§5.2's live-webcam DoD item stays open.** The mechanism is demonstrated (the trace is
  recoverable, and at 12 steps the classes separate in a controlled sitting). Reproducibility
  across ambient conditions is not, and that is what a deployable threshold would need.

**What B6 is missing, and the recommended next step:** a precondition. Right now a capture
that is saturated, or one where the screen contributes almost none of the scene's light,
still produces a correlation — a meaningless number that B6 then thresholds as though it
meant something, rejecting a genuine user with `BIND_CHALLENGE_UNMET` as if an attack had
been detected. B6 should first ask *can this capture evaluate the challenge at all* —
clipped-pixel fraction below a bound, chromaticity spread above a floor, screen contribution
above a floor — and fail with a distinct reason code when it cannot. That is a check the
capture client can also evaluate before submitting, and it is the difference between
"the challenge was not satisfied" and "the challenge could not be measured". Not implemented
here; recorded as the next piece of work rather than started at the end of a session.

**What the evidence does and does not support.** TPR 1.00 at threshold 0.60 is measured on
**8 captures**. That does not demonstrate a 5% BPCER: the one-sided 95% Clopper–Pearson
upper bound on BPCER from 8/8 successes is **0.312**. Demonstrating ≤5% at 95% confidence
needs ~59 consecutive clean captures. The threshold is *derived* to meet the target; the
evidence *bounds* it only loosely, and still from one room, one sensor, no subject at
capture distance. §5.2's live-webcam DoD item is closed on the mechanism — the trace is
recoverable and B6 clears its threshold with margin on both sides — and remains open on
population: it has never been run against a human face, which needs the same §6 consent
that blocks the replay corpus.

**Also fixed here, found while doing it:** §9's config block had silently drifted from
`config/default.yaml` — `phash_hamming_max` still read 6 there long after an earlier
amendment moved it to 10, and four `capture.illumination_*` keys added on 2026-09-02 were
never mirrored in at all. Nothing was comparing them.
`tests/unit/test_spec_config_agreement.py` now does, including an assertion that the
capture budget covers the challenge. Separately, the challenge step duration was a
hardcoded `0.2` default in `render_challenge_fullscreen` — a magic number in the one
parameter the frame budget turns on — and is now `binding.illumination_step_ms`.


### 2026-09-04 — B6 could not tell whether it was inside its own operating envelope

The previous two entries left B6 with a threshold and no way to know when the threshold
was meaningless. That is the gap this closes, and it is a different gap from the one that
kept being re-litigated: **the problem was never the threshold.**

**What was actually wrong.** The sweep and the live check disagreed (+0.775 ± 0.035 versus
+0.077 ± 0.455 for the same capture condition) because they sampled different physics, not
because either was mismeasured. In the second room the display contributed ~1.5% of scene
illumination and the chromaticity trace flattened to sensor noise. B6 computed a
correlation from that noise, thresholded it, and returned `BIND_CHALLENGE_UNMET` — an
attack reason code — for a genuine user in a brightly lit room.

**The precondition, derived from held captures rather than intuition.** Three candidates
were named; **one survived**, measured on 166 rendered captures and 38 no-render controls
already on disk (`scripts/derive_b6_evaluability.py` → `results/b6_evaluability.json`; no
new capture was taken).

| candidate | verdict | evidence |
|---|---|---|
| **chromaticity trace spread** | **shipped**, floor 0.0015 | gates **0 of 97** captures that passed the correlation; lowest of them 0.00226, a margin of +0.00076 (51% of the floor); reclassifies 33% of failing rendered captures from "attack" to "retry"; gates 74% of no-render controls |
| clipped-pixel fraction | **dropped** | does not discriminate, and points the *wrong way*: the only two clipped captures held (9.29% and 10.02%, at 196–199/255) both **passed**, at r = +0.785 and +0.753, while every capture that failed had zero clipping |
| screen-contribution fraction | **dropped** | classes overlap and are inverted — passing 0.0122–0.0171, failing 0.0163–0.0183 — and it costs an extra white/black probe at capture start |

The clipping result **corrects the 2026-09-03 entry above**, which attributed the flat
trace to saturation. High brightness and a flat trace do co-occur, but clipping fraction is
not what separates them; trace spread measures the thing directly. Shipping either dropped
candidate would have been a gate firing at random, which is worse than no gate.

**The floor was chosen to protect the true positives, not to maximise reclassification.**
Higher floors reclassify more (0.0022 → 46%) but crowd the lowest passing capture; 0.0025
starts gating genuine captures outright. The rule is: highest floor that gates none of the
passing captures while keeping a margin of at least half the floor beneath the lowest of
them. That is in the JSON, not only here.

**A distinction that took a test failure to find.** A *present but static* trace is
unevaluable — a real sensor looked at a real scene and the cast did not register. A
*missing or malformed* trace is a protocol violation and stays `BIND_CHALLENGE_UNMET`. If
absence routed to unevaluable, an attacker could omit the field and get an endless
`CHALLENGE` retry loop instead of a `REJECT`. An attacker can still reach `CHALLENGE` by
submitting a flat trace, but that is a loop they can never convert into an `ACCEPT`; it
costs them attempts rather than buying them anything.

**Evidence weight for the threshold itself, restated because it keeps mattering.**
`illumination_corr_min = 0.60` rests on **one sitting**. Measured TPR was 1.00 on **8
captures**, whose one-sided 95% Clopper–Pearson upper bound on BPCER is **0.312** — the
data is consistent with a true BPCER of 31%. Demonstrating ≤5% at 95% confidence needs
**~59 consecutive clean captures**. **§5.2's live-webcam DoD item closes on that
measurement and not before**, and that measurement needs the consented multi-capture
session that §6 currently blocks — the same blocker as the replay corpus. Until then the
number stands as the best available estimate, not as a characterised operating point.

**The third outcome had to be stopped from masking the second.** The first version routed
any unevaluable check straight to `CHALLENGE`, everywhere. A security test caught what that
costs: a **statically-injected stream also has a flat illumination trace**, so B6 goes
unevaluable at precisely the moment the injection detector fires, and A6 (tier-1 injection,
instant capture) turned from `REJECT` into a polite retry. An attacker could have laundered
a detected injection by making B6 unmeasurable — exactly backwards.

The rule is now: unevaluable routes to `CHALLENGE` **only when nothing else indicted the
capture**. In the cascade it is evaluated after the quality, binding and injection
short-circuits rather than before them; in `decision.binding_outcome` it guards `ACCEPT`
and deliberately leaves `REJECT` alone, because a `REJECT` that survived fusion was driven
by evidence that *was* read. The general shape is worth stating: **a "cannot measure"
outcome must never outrank a positive detection**, only an absence of one.

**Also updated:** `TestB6Semantics`'s negative fixture used flat grey frames, which since
this change are correctly *unevaluable* rather than *unmet* — it was a fixture for the
wrong outcome and now builds a capture lit by a different nonce's sequence, which is
measurable and genuinely fails the challenge.


### 2026-09-05 — the masking rule, and two more places it was already broken

**The rule, stated as a design principle rather than an incident note:**

> **An outcome meaning "cannot evaluate" may outrank an *absence* of detection, but never
> a *positive* detection. Any gate that returns early must not skip a detector that would
> have fired.**

The asymmetry is the whole content. "Cannot evaluate" is a statement about the *evidence*,
not about the subject: it says the system failed to look, so it is entitled to override a
conclusion drawn from not-looking (an ACCEPT by default) and entitled to nothing else. A
detector that *did* look and *did* fire has strictly more information, and no gate may
discard that. The failure mode is quiet by construction — the gate returns a plausible
outcome, the skipped detector leaves no trace, and only a test that trips the gate *and*
the detector together can see it.

**The worked example** is B6 (§14, 2026-09-04). Routing `BIND_CHALLENGE_UNEVALUABLE`
straight to `CHALLENGE` everywhere looked obviously right — an unmeasurable capture is not
an attack. But a statically-injected stream also has a flat illumination trace, so B6 went
unevaluable at exactly the moment the injection detector fired, and A6 (tier-1 injection,
instant capture) turned from `REJECT` into a polite retry. An attacker could have laundered
a detected injection by making B6 unmeasurable.

**The audit.** Every short-circuit in §5.5's pipeline was then checked — by instrumenting
the real pipeline and recording which detectors executed, not by reading the code's
intent, because the original bug was a wiring bug that the code's stated intent did not
describe.

| # | Short-circuit | Skips | Verdict |
|---|---|---|---|
| 1 | Stage 1 crypto: AEAD failure, malformed bundle, bad device signature | everything | **Safe.** Nothing can run before the bundle is decrypted and validated; there is no detector to mask. The failure is itself a positive detection. |
| 2 | Stage 2 binding B1–B5 fail-fast | quality, B6, injection, reuse, match | **Safe.** B1–B5 are deterministic positive detections (forged signature, expiry, nonce replay, counter regression, digest mismatch), not "cannot evaluate" outcomes, so they are entitled to outrank. *Caveat below.* |
| 3 | Stage 3 quality gate | — | **Safe in the pipeline.** `prepare_evidence` does not short-circuit: stage 4 runs regardless, and `injection.py` reads the bundle rather than the face crops, so it scores normally on a quality-failed capture. Measured, not assumed. |
| 4 | Stage 4 `confident_reject` → skips stage 6 heavy models | `match` | **UNSAFE — fixed.** |
| 5 | Stage 5 evidence-reuse fail-fast | match, fusion | **Safe.** A pHash reuse hit is a positive detection. *Caveat below.* |
| 6 | `fuse_cascade` quality short-circuit | binding-flag and injection checks | **UNSAFE — fixed.** |
| 7 | `fuse_cascade` binding / injection short-circuits | later cascade stages | **Safe.** Both are positive detections, and the unevaluable case was already ordered after them (§14, 2026-09-04). |

**Unsafe #4 — stage 4 skipped the identity match on an unevaluable B6.**
`confident_reject` was `(not b6.passed) or injection_result.decision`. An unevaluable B6
reports `passed=False` — the two-state view is deliberately fail-closed — so it satisfied
that predicate and stage 6 was skipped. Measured end to end: a capture with a flat
illumination trace produced `CHALLENGE` with `MISSING_SIGNAL_MATCH`, having never scored
the face against the enrolled template. An impostor whose capture happened to be
unmeasurable was never checked for being an impostor. Now
`b6.evaluable and not b6.passed`: a *genuine* B6 failure still short-circuits (the outcome
is already REJECT, so the match score cannot change it), an unevaluable one does not.

**Unsafe #6 — the quality gate masked injection attribution.** `fuse_cascade` returned on
`not x.quality_passed` before consulting the binding flags or the injection score. A
degraded capture that was *also* a tier-1 injection reported only
`QUALITY_INSUFFICIENT (short-circuit)`. Both paths end in `REJECT`, so this was not an
accept-path hole — but §8.1's per-attack detection rates and the 6-class confusion matrix
are computed from exactly these reason codes, so the injection detector was being silently
understated whenever an attacker also degraded the capture. The quality check now runs
after the binding and injection short-circuits, which are cheap comparisons that had
already been computed.

**A caveat that applies to #2 and #5, recorded rather than fixed.** Both raise
`PipelineRejection` carrying only their own reason code, so when an injected bundle *also*
fails B4 or hits the reuse index, the injection attribution is lost the same way #6 lost
it. This does not violate the rule — a positive detection is outranking another positive
detection, not being masked by a "cannot evaluate" — and the decision is `REJECT` either
way. It is the same §8.1 attribution weakness in a place where the rule does not forbid
it, and it is worth closing when the remaining detectors exist and per-attack rates start
carrying weight.

**Latency.** Cheapest-first ordering is unchanged; nothing new runs on the happy path. The
one real cost is that fix #4 now runs the heavy-models stage in the case it used to skip —
B6 unevaluable with nothing else firing — which is **p50 251.6 ms** on the current
in-process benchmark (`results/latency.json`). That is the price of not silently skipping
the identity check on a capture heading for `CHALLENGE`, and it is paid only in that case.
The #6 reorder moves only in-memory comparisons inside a stage whose total is p50 0.33 ms,
so it is not measurable.

**What would have caught these earlier.** Not review — all three read as obviously correct.
The shape that works is the one that caught the original: **a capture that trips the gate
AND would trip a detector, asserting the detection survives**
(`tests/unit/test_shortcircuit_masking.py`). One such test per gate, asserting on observed
detector execution rather than on the predicate's expression, since a predicate test passes
happily while the wiring is wrong.


### 2026-09-06 — rejections were discarding results they had already computed

The 2026-09-05 audit recorded stages 2 and 5 as rule-compliant-but-lossy: they raise
`PipelineRejection` carrying only their own code, so an injected bundle that also fails B4
or hits the reuse index loses the injection attribution. The decision is `REJECT` either
way, so it was never a security hole. It was a **measurement** hole, and §8.1's numbers are
the deliverable — so it is fixed before the evaluation runs rather than discovered in the
matrix afterwards.

**What was lost.** The handler did `reason_codes = rejection.reason_codes` and
`detector_scores = {}` — a wholesale replacement. A reuse rejection at stage 5 therefore
threw away B1–B6's outcomes *and* the injection score, all of which stage 4 had already
computed and paid for. Measured before the fix, a resubmitted-media rejection reported
exactly `['BIND_EVIDENCE_REUSE']` with no detector scores at all.

**What it carries now.** Every code determined up to the rejection point, in stage order,
with the triggering codes additionally repeated under a `REJECTED_BY:` prefix so "what
ended this request" stays recoverable now that "what was known about it" is also present.
The bare code stays in the list, so existing membership checks and metric consumers are
unaffected. The same reuse rejection now reports `BIND_EVIDENCE_REUSE`, `B1_OK`…`B6_OK`,
`REJECTED_BY:BIND_EVIDENCE_REUSE`, and an injection score.

**Cheapest-first ordering is untouched, and this is worth being precise about**: nothing
extra is computed and no stage moved. The change is that results already in hand are not
thrown away on the way out. Happy-path latency is unchanged — the accumulation is a handful
of list appends inside stages that already existed.

**Consequence for §8.1, resolved there rather than left implicit.** Multi-code decisions
make a single-label matrix ambiguous. §8.1 now documents the precedence order, the
exclusion of rejections that name no attack class, and a `multi_attribution_count` so the
collapse is auditable rather than silent. The ordering principle is specificity of
attribution, not severity.

**One more discarded result, found by the same audit.** The accept path wrapped
`update_counter` in `contextlib.suppress(ValueError)` to tolerate the documented TOCTOU
race against a concurrent accepted request for the same device. Suppressing it kept the
decision honest — the request really was accepted — but left the failed advance invisible
to the audit log: a determined outcome dropped before reaching the decision object, the
same defect class as the discarded reason codes. It now appends `COUNTER_ADVANCE_RACE`.
The race itself is still not resolved; it is merely no longer silent.

**Paths audited for discarded results** (same instrumented approach as 2026-09-05 —
observing what reached the decision object, not reading intent):

| Path | Verdict |
|---|---|
| Stage 1 crypto rejection | **Safe.** Nothing has been computed yet; there is no result to discard. |
| Stage 2 B1–B5 rejection | **Was unsafe — fixed.** Passing B1–B5 outcomes now survive. |
| Stage 5 reuse rejection | **Was unsafe — fixed.** B1–B6 and the injection score now survive. |
| Success path reason codes | **Safe.** B1–B6, reuse, missing signals and fusion reasons were already assembled in full. |
| Success path detector scores | **Safe.** Injection and match both reach the decision; a skipped match is reported as `MISSING_SIGNAL_MATCH` rather than omitted. |
| Quality verdict on a later rejection | **Was unsafe — fixed.** `QUALITY_INSUFFICIENT` is now recorded when determined, not only when fusion happens to reach it. |
| `advance_counter` ValueError suppression | **Was unsafe — fixed.** Now `COUNTER_ADVANCE_RACE`. |
| `frame_hashes` Exception suppression | **Safe.** Guards hashing a bundle that stage 1 never decoded; no computed result is dropped. |
| Audit log persistence | **Safe, verified by test.** `store.py` serialises the decision whole; it never truncated the list, so the fix propagates without a storage change. |

**A note on fix #4 from 2026-09-05, which deserves stating more sharply than it was.** The
unevaluable-B6 path that skipped the identity match was not merely an accidental
reachability. `BIND_CHALLENGE_UNEVALUABLE` is **not randomly distributed**: it correlates
with bright ambient light and low screen contribution (§12 item 11), which are conditions an
attacker can simply arrange — verify next to a window, or at arm's length from a small
screen. The skipped match was therefore *deliberately* reachable by an impostor, not just
theoretically reachable. It terminated in `CHALLENGE` rather than `ACCEPT`, so it was never
an authentication bypass and no identity was ever wrongly confirmed; but "an attacker can
choose the lighting that makes a detector not run" is the part worth stating plainly,
because it generalises: **any evaluability gate is an attacker-influenceable input, and
anything conditioned on one inherits that.**


### 2026-09-06 — morph detection (D2): built, and the corpus is the weak part

FRLL-Morphs and SMDD both need agreements that have not arrived and are not expected to.
Morph is the one attack corpus that can be *generated* rather than collected — SMDD's own
premise — so it was generated. `data/LICENCES.md` now records every dataset's status,
including the two things about LFW that decided how this was done.

**Licence, and what could not be verified.** LFW requires no EULA, no fee and no request
form, so nothing about it blocked this work. But its images are press photographs whose
copyright sits with the original outlets, and **the canonical LFW page could not be read
from this environment** — that specific host does not resolve here while the rest of the
network does, so the terms come from the distributing ecosystem rather than quoted from
the primary source. "No licence" is not "permissively licensed": nothing grants
redistribution, so nothing derived is committed. Script and manifest only, matching
`data/`'s existing convention. Anyone who can reach the primary page should replace that
paragraph with the verbatim notice.

**Corpus.** 399 identities, 390 morphs across two methods, 399 bona fide and 399 held-out
live references. Pairs are chosen by **highest ArcFace cosine within a split** rather than
by matching apparent sex and face shape: the demographic labels that criterion needs do not
exist here and would have to come from a classifier we cannot validate, whereas embedding
similarity is measurable, needs no protected attribute, and is what an attacker actually
optimises when choosing an accomplice. Identities are partitioned *before* pairing and the
disjointness is asserted at generation time, not documented and hoped for.

**Two methods, and the second is the one that matters.** `landmark_alpha` is the plain
case: Delaunay warp to the mean shape, blend 0.5, every pixel a mixture.
`spliced_jpeg` blends 0.6 and then **splices the morphed face interior back into one
contributor's untouched photograph** before re-compressing — so hair, ears, neck,
background and the original compression history all belong to one real person. That is what
real morph attacks do, and it is what makes the cross-method number meaningful rather than
decorative.

**S-MAD and D-MAD, and D-MAD wins as §5.4 predicted.** Within-corpus ACER 0.246 → 0.140,
AUC 0.837 → 0.930. The prediction was that a trusted live capture would help substantially;
it does. Under a change of generator the gap widens into a difference in kind: S-MAD falls
to AUC **0.586** (near chance, APCER 0.909) while D-MAD holds at 0.884. §12 items 8 and 10
carry the tables.

**The backbone is ArcFace ResNet-50, not EfficientNet-B0**, because `torch` is not
installed and adding it for one detector was not in scope. The ArcFace weights were already
present and checksum-verified. This helps D-MAD, whose whole feature *is* an embedding
difference, and handicaps S-MAD, which would rather have a texture-pretrained backbone — so
the S-MAD figures are a floor rather than a fair reading of what S-MAD can do.

**The corpus's real weakness is MMPMR, and it is stated first in §12 for a reason.** Only
6.4% of these morphs verify as both contributors. Most of them would not have fooled the
matcher, so the detection numbers substantially describe the detection of failed attacks.
This is not fixable by tuning: the most similar pairing available among 399 LFW identities
reaches cosine 0.365, and a blend of two people who look that different resembles neither.
Raising it needs a source with deliberate look-alike pairs, which is what the licensed
corpora provide and what makes them worth the paperwork.

**§8.3's overhead ratio moved, and the detector count belongs next to it.** With morph in
stage 6, C3 now runs **two of six detectors** (injection + morph S-MAD):

| term | one detector (2026-09-01) | two detectors (2026-09-06) |
|---|---|---|
| PQ overhead C2−C1 | 0.88 ms (+8.1%) | 0.34 ms (+3.8%) |
| AI overhead C3−C2 | 703.8 ms | **784.5 ms** |
| **AI:PQ ratio** | **798x** *(one of six detectors)* | **2327x** *(two of six detectors)* |

Two cautions on reading that jump. The AI term rose by 81 ms, which is the morph
detector's real cost and the only part of the change attributable to this session. The
ratio nearly tripled largely because the **PQ** term fell to 0.34 ms — run-to-run variation
on a sub-millisecond measurement, not a crypto improvement. Quoting "2327x" without the
detector count attached is exactly the misreading the count is there to prevent: it is
still a **lower bound**, and it will keep rising as the remaining four detectors land.

**Integration.** `morph.py` runs in pipeline stage 6 in the **S-MAD** setting. D-MAD is the
better detector and is deliberately *not* wired into `/v1/verify`: that endpoint receives a
live capture and no document image, so there is no suspect/reference pair to differentiate,
and using it there would mean comparing an image with itself and calling the result a
differential. A morph reaches this system at enrolment, or as an injected frame; only the
second is in this pipeline's reach. `test_a3_morph_reaches_pipeline_as_missing_signal` was
inverted into `test_a3_morph_is_scored_not_reported_missing` — it existed to mark that D2
had no detector, and its replacement marks that it has one.


### 2026-09-14 — morph: the pool was not the whole problem, and the PQ ratio was noise

**Pool scaled to its ceiling.** MMPMR was 0.064 on 399 identities, so the reported morph
ACER/AUC largely described detecting failed attacks. The corpus now uses every LFW identity
with ≥2 images: 1,680, of which 1,672 had a detectable face on two images. That is LFW's
ceiling, not a compute choice — 4,069 of its 5,749 identities have a single image, and a
one-image identity cannot supply an enrolment image distinct from its morph's source, so
MMPMR on it would self-match. Best-pair cosine rose 0.365 → 0.562; the median only
0.163 → 0.197. **MMPMR rose to 0.096 (160 of 1,666).**

**Why it stayed low was then measured rather than argued.** MMPMR per quintile of
contributing-pair cosine separates a pool limit from a method limit (§12 item 8, T4b).
`landmark_alpha` climbs 0.042 → 0.313 across quintiles and **0.333 in the top decile**:
pool-limited, then capped by the method. `spliced_jpeg` reaches **0.071 in its top decile**:
method-limited outright, because the asymmetric blend spliced into one contributor's own
photograph leaves an image that is mostly that contributor. The lever for a corpus of
working attacks is a higher-fidelity morph (68/81-point landmarks or a generative morph),
not more identities.

**Verifying-subset detection is now reported beside all-morph detection**, with the count
inline and a 30-attack floor below which the cell BLOCKS with its count
(`detect.morph.min_verifying_attacks_reported`). S-MAD: 60 verifying attacks, APCER 0.133
[0.059, 0.246]; D-MAD: 47, APCER 0.106 [0.035, 0.231]. Both intervals contain the all-morph
figures, and both subsets are ~90% `landmark_alpha` (54/60, 43/47) — so detection of
*working* spliced morphs, the hard case, is effectively unmeasured.

**The AI:PQ overhead ratio was tracking noise, and the report had just published −191x.**
The PQ term C2−C1 is a sub-millisecond difference of two ~10–15 ms latencies; across four
runs it was 0.88, 0.34, −4.30 and 0.10 ms, while the C1 baseline mean alone drifted by
~7 ms between runs. The point ratio (798x → 2327x → −191x) was following the noise in its
denominator. `overhead.py` now puts a Welch 95% interval on both terms and publishes a
point ratio only when the PQ interval excludes zero. This run: PQ 0.10 ms [−0.70, 0.90] —
not resolvable — so the ratio is BLOCKED and the claim is the **lower bound, 802x** (AI
lower limit 718 ms over PQ upper limit 0.90 ms). The intervals cover within-run noise only;
between-run drift is larger, so "not resolvable" is if anything understated. Measuring the
PQ term properly would need C1/C2 interleaved within one run and far more iterations; not
done here.

**Also fixed while regenerating:** T4 rendered morph rows as raw Python dicts in the
committed report; T6 said C3 runs one detector (it runs two); T2's morph rows carried a
blocker naming the injection corpus; `make_morph_corpus.py` loaded the whole pool into
memory as float32 (~6.9 GB), now read from sklearn's cache per file (~470 MB); the manifest
described pairing as "identity mean embeddings" when the code has always paired on the
contributing images' embeddings. §5.4 now places D-MAD at enrolment, where a document image
exists — checked against `routes.py`, `/v1/enroll` does not yet take one — and
`data/LICENCES.md` carries LFW's terms as outstanding, unverified from the primary source.
