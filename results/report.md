# Evaluation report (PROJECT_SPEC.md §8)

*git `5772950b57b6` · config `66991fa0bd3e` · Linux-6.6.87.2-microsoft-standard-WSL2-x86_64-with-glibc2.41 / x86_64 · KEM=liboqs SIG=liboqs · seed=2026 · generated 2026-09-14T16:31:21.773255+00:00*

---

### T1 — Per-detector accuracy, intra-dataset

| Detector | APCER | BPCER | ACER | EER | AUC-ROC | TDR@FAR=1% | n_genuine | n_attack |
|---|---|---|---|---|---|---|---|---|
| deepfake | BLOCKED — no deepfake detector implemented -- pqbio/detect/deepfake.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |  |  |  |  |  |  |  |
| injection | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 1.0000 | 6 | 6 |
| match | BLOCKED — no labelled genuine/impostor pair dataset exists to compute match FAR/FRR (§6) |  |  |  |  |  |  |  |
| morph_dmad (all morphs) | 0.1173 | 0.1215 | 0.1194 | 0.1173 | 0.9523 | 0.3418 | 354 | 520 |
| morph_dmad (verifying morphs only) | 0.1064 | 0.1215 | 0.1139 | 0.1073 | 0.9666 | 0.6808 | 354 | 47 |
| morph_smad (all morphs) | 0.1757 | 0.1734 | 0.1745 | 0.1749 | 0.9049 | 0.3423 | 669 | 666 |
| morph_smad (verifying morphs only) | 0.1333 | 0.1734 | 0.1534 | 0.1333 | 0.9202 | 0.3423 | 669 | 60 |
| pad | BLOCKED — no pad detector implemented -- pqbio/detect/pad.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |  |  |  |  |  |  |  |
| replay | BLOCKED — no replay detector implemented -- pqbio/detect/replay.py is deliberately absent, not stubbed. Replay-Attack/MSU-MFSD are unlicensed (§6), and the self-recorded alternative is blocked on human subjects rather than hardware: §6 requires written consent and supervisor approval to record anyone, and a subject-disjoint split needs at least two consenting subjects. The capture rig itself is verified working (camera, display, WB/exposure lock -- PROJECT_SPEC.md §14, 2026-09-01) |  |  |  |  |  |  |  |

### T2 — Per-detector accuracy, cross-dataset

| Detector | APCER | BPCER | ACER | EER | AUC-ROC | TDR@FAR=1% | n_genuine | n_attack |
|---|---|---|---|---|---|---|---|---|
| deepfake | BLOCKED — only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6) |  |  |  |  |  |  |  |
| injection | BLOCKED — only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6) |  |  |  |  |  |  |  |
| match | BLOCKED — only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6) |  |  |  |  |  |  |  |
| morph_dmad | BLOCKED — only one morph corpus exists (self-generated from LFW, scripts/make_morph_corpus.py) -- cross-dataset evaluation needs an independent morph dataset such as FRLL-Morphs or SMDD, neither licensed (§6, data/LICENCES.md). Cross-METHOD generalisation within the one corpus is the available proxy: T4c |  |  |  |  |  |  |  |
| morph_smad | BLOCKED — only one morph corpus exists (self-generated from LFW, scripts/make_morph_corpus.py) -- cross-dataset evaluation needs an independent morph dataset such as FRLL-Morphs or SMDD, neither licensed (§6, data/LICENCES.md). Cross-METHOD generalisation within the one corpus is the available proxy: T4c |  |  |  |  |  |  |  |
| pad | BLOCKED — only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6) |  |  |  |  |  |  |  |
| replay | BLOCKED — only one dataset exists in this environment (the self-generated injection corpus) -- cross-dataset evaluation needs a second, independent dataset (§6) |  |  |  |  |  |  |  |

### T3 — Fusion strategy comparison

| Strategy | Accuracy |
|---|---|
| rule | 1.0000 |
| cascade | 1.0000 |

_n=40 — Only match/injection/binding/quality signals exist this session — pad/morph/deepfake/replay are dataset-blocked and not built. Both strategies are compared on the injection corpus only (provenance detection), not full system ACER. See pqbio/detect/fusion.py's module docstring._

### T4 — Per-attack detection rate at the deployed operating point

| Attack type | Detection rate |
|---|---|
| deepfake | BLOCKED — no deepfake detector implemented -- pqbio/detect/deepfake.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |
| injection_tier1 | 1.0000 |
| morph_dmad (all morphs) | 0.8827 |
| morph_dmad (verifying morphs only) | 0.8936 |
| morph_smad (all morphs) | 0.8243 |
| morph_smad (verifying morphs only) | 0.8667 |
| presentation | BLOCKED — no presentation detector implemented -- pqbio/detect/pad.py is deliberately absent, not stubbed (dataset-blocked, see CLAUDE.md 'Current state' / PROJECT_SPEC.md §14) |
| replay | BLOCKED — no replay detector implemented -- pqbio/detect/replay.py is deliberately absent, not stubbed. Replay-Attack/MSU-MFSD are unlicensed (§6), and the self-recorded alternative is blocked on human subjects rather than hardware: §6 requires written consent and supervisor approval to record anyone, and a subject-disjoint split needs at least two consenting subjects. The capture rig itself is verified working (camera, display, WB/exposure lock -- PROJECT_SPEC.md §14, 2026-09-01) |

### T4b — MMPMR (morph only)

_Threshold: `match_cosine_min` = 0.38._

| Morph method | n | n verifying | MMPMR (verifies as ALL contributors) | Verifies as ANY contributor | Mean min similarity |
|---|---|---|---|---|---|
| landmark_alpha | 833 | 144 | 0.1729 | 0.5918 | 0.2661 |
| spliced_jpeg | 833 | 16 | 0.0192 | 0.7647 | 0.1861 |
| **all methods** | 1666 | **160** | **0.0960** | 0.6783 |  |

**Read this before the morph rows of T1/T4.** MMPMR is 0.0960 at `match_cosine_min` = 0.38: most of these morphs do not verify as both contributors, so they would not have fooled the matcher in the first place and the detection metrics largely describe the detection of failed attacks. Cause and consequences in §12 item 8.

**MMPMR by contributing-pair ArcFace cosine (quintiles).** Separates a pool limit (MMPMR climbs with pair similarity) from a method limit (it stays low even for the closest pairs). Read with §12 item 8.

| Pair cosine | landmark_alpha | spliced_jpeg |
|---|---|---|
| 0.046–0.159 | 0.0419 (7/167) | 0.0000 (0/167) |
| 0.159–0.187 | 0.0838 (14/167) | 0.0120 (2/167) |
| 0.187–0.206 | 0.2108 (35/166) | 0.0120 (2/166) |
| 0.206–0.233 | 0.2156 (36/167) | 0.0180 (3/167) |
| 0.233–0.562 | 0.3133 (52/166) | 0.0542 (9/166) |
| top decile (≥0.253) | **0.3333** (28/84) | **0.0714** (6/84) |

### T4c — Morph cross-method generalisation

AUC near 0.5 means the detector learned the *generator*, not morphing. Compare against the within-corpus rows of T1: the gap is the honest number (§12 item 10).

| Setting | Train → test | ACER | EER | AUC-ROC | APCER |
|---|---|---|---|---|---|
| DMAD | train landmark_alpha → test spliced_jpeg | 0.2225 | 0.1695 | 0.9123 | 0.3885 |
| DMAD | train spliced_jpeg → test landmark_alpha | 0.0873 | 0.0808 | 0.9766 | 0.0615 |
| SMAD | train landmark_alpha → test spliced_jpeg | 0.4796 | 0.4264 | 0.6028 | 0.9069 |
| SMAD | train spliced_jpeg → test landmark_alpha | 0.3813 | 0.2913 | 0.7913 | 0.7297 |

### T5 — Crypto micro-benchmarks and artefact sizes

| Operation | Backend | Mean (ms) | p95 (ms) | Iterations |
|---|---|---|---|---|
| kem/classical/keygen | x25519 | 0.0544 | 0.0696 | 1000 |
| kem/classical/encaps | x25519 | 0.1347 | 0.2170 | 1000 |
| kem/classical/decaps | x25519 | 0.1206 | 0.1826 | 1000 |
| kem/classical/artefact_sizes_bytes | x25519 | {"ct": 32, "pk": 32, "sk": 32, "ss": 32} |  |  |
| kem/pq/keygen | liboqs | 0.0345 | 0.0607 | 1000 |
| kem/pq/encaps | liboqs | 0.0290 | 0.0500 | 1000 |
| kem/pq/decaps | liboqs | 0.0289 | 0.0348 | 1000 |
| kem/pq/artefact_sizes_bytes | liboqs | {"ct": 1088, "pk": 1184, "sk": 2400, "ss": 32} |  |  |
| signer/classical/keygen | ed25519 | 0.0457 | 0.0618 | 1000 |
| signer/classical/sign | ed25519 | 0.0677 | 0.0923 | 1000 |
| signer/classical/verify | ed25519 | 0.1040 | 0.1402 | 1000 |
| signer/classical/artefact_sizes_bytes | ed25519 | {"pk": 32, "sig": 64, "sk": 32} |  |  |
| signer/pq/keygen | liboqs | 0.0510 | 0.0649 | 1000 |
| signer/pq/sign | liboqs | 0.1326 | 0.2930 | 1000 |
| signer/pq/verify | liboqs | 0.0472 | 0.0557 | 1000 |
| signer/pq/artefact_sizes_bytes | liboqs | {"pk": 1952, "sig": 3309, "sk": 4032} |  |  |

### T6 — Four-configuration overhead ablation

| Config | Crypto | AI | Isolates | Mean latency (ms) |
|---|---|---|---|---|
| C0 | none | none | framework/transport floor | 1.5650 |
| C1 | X25519 + Ed25519 | none | conventional crypto cost | 12.9404 |
| C2 | ML-KEM-768 + ML-DSA-65 | none | marginal PQ cost | 13.0389 |
| C3 | ML-KEM-768 + ML-DSA-65 | full | total system cost | 797.4182 |

**PQ overhead (C2−C1):** 0.0985 ms (0.8%), 95% CI [-0.6986, 0.8956] ms — **spans zero: not resolvable from run noise**

**AI overhead (C3−C2):** 784.3794 ms (6015.7%), 95% CI [717.9744, 850.7844] ms

**AI:PQ overhead ratio:** BLOCKED — the PQ overhead is not resolvable from run noise: C2-C1 = 0.10 ms with a 95% interval of [-0.70, 0.90] ms, which spans zero, so a point ratio would be dividing by noise (the three committed runs gave 798x, 2327x and -191x). The defensible statement is the lower bound in ai_to_pq_overhead_ratio_lower_bound

**AI:PQ ratio, 95% lower bound:** 802x (AI overhead's lower limit over PQ overhead's upper limit — the smallest ratio consistent with both intervals, and the figure that survives rerunning)

_The AI side is **a lower bound**: C3 runs two of the five attack detectors — injection, and morph in its S-MAD setting (§5.4, pipeline stage 6). pad, deepfake and replay are absent (§6/§14). Adding them can only increase C3. The intervals cover within-run sampling noise only; the C1 baseline mean has moved by ~7 ms between committed runs, so between-run drift is larger still._

### T7 — Throughput vs concurrency

| Concurrency | Throughput (verif/s) | p50 (ms) | p95 (ms) | p99 (ms) | Setup failed (409) | Expired before verify (409) |
|---|---|---|---|---|---|---|
| 1 | 1.792 | 557.5937 | 557.5937 | 557.5937 | 0 | 0 |
| 2 | 1.535 | 1082.6140 | 1268.5933 | 1285.1248 | 0 | 0 |
| 4 | 2.371 | 1320.5818 | 1633.8737 | 1652.4563 | 0 | 0 |
| 8 | 2.896 | 2237.5174 | 2700.1728 | 2720.9356 | 0 | 0 |
| 16 | 2.768 | 5405.2950 | 5534.5793 | 5722.1241 | 0 | 0 |
| 32 | 2.842 | 10873.3290 | 11143.7021 | 11147.8264 | 0 | 0 |
| 64 | 2.614 | 23891.1394 | 24237.5109 | 24326.9790 | 0 | 0 |

**Knee:** concurrency=1 — throughput gain from concurrency=1 to 2 was -14.3%, below the 10% threshold

**Event-loop-blocking finding:** Below saturation, p99 grew 4.88x while concurrency grew 8x (concurrency=1->8, peak throughput 2.90/s). That is at or above proportional growth.  Past the peak, p99 rises to 24327ms at concurrency=64 (from 558ms at 1) while throughput stays flat — expected queueing against a saturated worker pool (`server.workers` in config), not a separate defect. NOTE: latency growth alone cannot separate a blocked event loop from ordinary worker-pool/CPU saturation on a CPU-bound workload, so do not read the ratio above as a verdict on its own. The direct discriminator is tests/integration/test_server_happy_path.py::test_event_loop_stays_responsive_while_verify_is_in_flight, which polls GET /v1/health while concurrent /v1/verify calls are in flight and requires it to stay responsive — a blocked loop would stall those health checks behind the CPU-bound work, whatever the latency curve looks like.

### T8 — Deployment recommendation matrix

**Provisional — based on measured latency/throughput/PQ-overhead numbers only.** A real ACER-vs-scenario recommendation (§8.4) needs the four missing detectors and real datasets (§6/§14); this matrix cannot yet weigh accuracy against latency per scenario, only latency and crypto cost, which are real.

| Scenario | Recommendation (latency/crypto-only) |
|---|---|
| High-security, low-volume (bank onboarding) | Maximise detection strength once available; the system's own p95 (1062.1391 ms) is not the binding constraint at low volume. Crypto choice is not the trade-off axis here at all. |
| Balanced (mobile login) | PQ is affordable on these numbers: the measured PQ overhead is 0.10 ms per session (T6), 0.01% of end-to-end p95. The cost that matters for this scenario is inference, not crypto. |
| High-volume, low-latency (access control) | T7's knee bounds this scenario. Throughput saturates against `server.workers` running per-request ONNX inference, so scale that (or move inference to a GPU) — dropping PQ for classical crypto would buy back only 0.10 ms per session and is not the lever. |

---

### F1 — DET curves

![DET curves](figures/f1_det_curves.png)

### F2 — Stage-level latency breakdown

![Stage latency](figures/f2_stage_latency.png)

### F3 — ACER vs p95 latency

![ACER vs latency](figures/f3_acer_vs_latency.png)

_Only one real (ACER, p95) pair exists (injection); this plot cannot yet show the trade-off curve §8.4 asks for across strategies/detectors._

### F4 — 6-class confusion matrix

![Confusion matrix](figures/f4_confusion_matrix.png)

Samples counted in the matrix: **40**

Rejections excluded (named no attack class): **0** — forged signature, expiry, nonce replay, counter regression, quality failure, unevaluable challenge. Excluded rather than folded into the nearest class, which would invent an attribution the system never made (§8.1).

Total decisions: **40**

Decisions carrying more than one attack attribution: **0** — collapsed to a single label by ATTACK_CODE_PRECEDENCE. A large count here means this matrix is hiding most of what the system found, and the per-attack rates (T4) should be read instead.

_Only bona_fide and injection have real labelled samples in this environment; presentation/morph/deepfake/replay rows and columns are structurally zero, not measured-and-found-zero (§14)._

---

See `results/BLOCKERS.md` for the complete list of blocked metrics and what unblocks each one.
