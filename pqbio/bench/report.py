"""Renders `results/*.json` into `results/report.md` (tables T1-T8, PROJECT_SPEC.md
§8.5) and `results/figures/*.png` (F1-F4), plus `results/BLOCKERS.md`.

Owner: Abhijay

JSON first, always: every function here reads a results/*.json file and formats it --
none compute a number of their own. A BLOCKED cell (`pqbio.bench._common.is_blocked`)
renders as an explicit "BLOCKED — <reason>" table row, never a blank cell or a zero
(§5.6's build instruction, restated because it is the one rule every render function
below must not violate).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pqbio.bench._common import RESULTS_DIR, is_blocked, run_metadata

FIGURES_DIR = RESULTS_DIR / "figures"


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def _fmt(value: Any, digits: int = 4) -> str:
    if is_blocked(value):
        return f"BLOCKED — {value['blocker']}"
    if value is None:
        return "n/a"
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _metadata_line(data: dict[str, Any] | None) -> str:
    if not data:
        return "_no data available for this run_"
    hw = data.get("hardware", {})
    return (
        f"*git `{data.get('git_commit', '?')[:12]}` · config `{data.get('config_hash_sha256', '?')[:12]}` · "
        f"{hw.get('platform', '?')} / {hw.get('processor', '?')} · "
        f"KEM={data.get('KEM_BACKEND', '?')} SIG={data.get('SIG_BACKEND', '?')} · "
        f"seed={data.get('seed')} · generated {data.get('generated_at_utc', '?')}*"
    )


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


# ----------------------------------------------------------------------------------
# T1 / T2: per-detector accuracy, intra- and cross-dataset
# ----------------------------------------------------------------------------------


def _render_accuracy_table(section: dict[str, Any] | None, title: str) -> str:
    if section is None:
        return (
            f"### {title}\n\nBLOCKED — results/accuracy.json not found; run `make bench` first.\n"
        )
    lines = [f"### {title}\n"]
    headers = [
        "Detector",
        "APCER",
        "BPCER",
        "ACER",
        "EER",
        "AUC-ROC",
        "TDR@FAR=1%",
        "n_genuine",
        "n_attack",
    ]
    rows = []
    for name, cell in section.items():
        if is_blocked(cell):
            rows.append([name, f"BLOCKED — {cell['blocker']}", "", "", "", "", "", "", ""])
        else:
            rows.append(
                [
                    name,
                    _fmt(cell.get("apcer")),
                    _fmt(cell.get("bpcer")),
                    _fmt(cell.get("acer")),
                    _fmt(cell.get("eer")),
                    _fmt(cell.get("auc_roc")),
                    _fmt(cell.get("tdr_at_far_1pct")),
                    _fmt(cell.get("n_genuine"), 0),
                    _fmt(cell.get("n_attack"), 0),
                ]
            )
    lines.append(_markdown_table(headers, rows))
    return "\n".join(lines) + "\n"


def render_t1(accuracy: dict[str, Any] | None) -> str:
    section = accuracy.get("T1_per_detector_accuracy_intra_dataset") if accuracy else None
    return _render_accuracy_table(section, "T1 — Per-detector accuracy, intra-dataset")


def render_t2(accuracy: dict[str, Any] | None) -> str:
    section = accuracy.get("T2_per_detector_accuracy_cross_dataset") if accuracy else None
    return _render_accuracy_table(section, "T2 — Per-detector accuracy, cross-dataset")


def render_t3(accuracy: dict[str, Any] | None) -> str:
    title = "### T3 — Fusion strategy comparison\n"
    section = accuracy.get("T3_fusion_strategy_comparison") if accuracy else None
    if section is None or is_blocked(section):
        blocker = section["blocker"] if section else "results/accuracy.json not found"
        return f"{title}\nBLOCKED — {blocker}\n"
    rows = [
        ["rule", _fmt(section.get("rule_accuracy"))],
        ["cascade", _fmt(section.get("cascade_accuracy"))],
    ]
    body = _markdown_table(["Strategy", "Accuracy"], rows)
    note = f"\n\n_n={section.get('n_samples')} — {section.get('scope_note', '')}_"
    return f"{title}\n{body}{note}\n"


def render_t4(accuracy: dict[str, Any] | None) -> str:
    title = "### T4 — Per-attack detection rate at the deployed operating point\n"
    section = accuracy.get("T4_per_attack_detection_rate") if accuracy else None
    if section is None:
        return f"{title}\nBLOCKED — results/accuracy.json not found\n"
    rows = [
        [name, _fmt(rate) if not is_blocked(rate) else f"BLOCKED — {rate['blocker']}"]
        for name, rate in section.items()
    ]
    return f"{title}\n{_markdown_table(['Attack type', 'Detection rate'], rows)}\n"


def render_t4b_mmpmr(accuracy: dict[str, Any] | None) -> str:
    """MMPMR — §8.1's morph-only metric, and the one to read before any morph ACER.

    MMPMR asks whether the *attack works*: does a morph verify as **every** contributing
    identity against the enrolled template? A corpus whose MMPMR is low is a corpus of
    morphs the matcher would have rejected anyway, and its detection numbers describe the
    detection of failed attacks. That is why this renders immediately after T4 and carries
    the warning inline rather than in a footnote.
    """
    title = "### T4b — MMPMR (morph only)\n"
    section = accuracy.get("mmpmr") if accuracy else None
    if section is None:
        return f"{title}\nBLOCKED — results/accuracy.json not found\n"
    if is_blocked(section):
        return f"{title}\nBLOCKED — {section['blocker']}\n"

    threshold = section.get("match_cosine_min")
    rows = []
    for method, stats in section.get("by_method", {}).items():
        rows.append(
            [
                method,
                str(stats.get("n_morphs", "")),
                str(stats.get("n_verifying", "")),
                _fmt(stats.get("mmpmr")),
                _fmt(stats.get("any_contributor_match_rate")),
                _fmt(stats.get("min_similarity_mean")),
            ]
        )
    overall = section.get("overall")
    if overall:
        rows.append(
            [
                "**all methods**",
                str(overall.get("n_morphs", "")),
                f"**{overall.get('n_verifying', '')}**",
                f"**{_fmt(overall.get('mmpmr'))}**",
                _fmt(overall.get("any_contributor_match_rate")),
                "",
            ]
        )

    table = _markdown_table(
        [
            "Morph method",
            "n",
            "n verifying",
            "MMPMR (verifies as ALL contributors)",
            "Verifies as ANY contributor",
            "Mean min similarity",
        ],
        rows,
    )
    caveat = ""
    if overall and isinstance(overall.get("mmpmr"), (int, float)) and overall["mmpmr"] < 0.5:
        caveat = (
            f"\n**Read this before the morph rows of T1/T4.** MMPMR is "
            f"{_fmt(overall['mmpmr'])} at `match_cosine_min` = {threshold}: most of these "
            "morphs do not verify as both contributors, so they would not have fooled the "
            "matcher in the first place and the detection metrics largely describe the "
            "detection of failed attacks. Cause and consequences in §12 item 8.\n"
        )
    banding = ""
    by_band = section.get("by_pair_cosine_quintile")
    if isinstance(by_band, dict) and not is_blocked(by_band):
        methods = [m for m in by_band if isinstance(by_band[m], dict) and "bands" in by_band[m]]
        edges = by_band["band_edges"]
        band_rows = []
        for i in range(len(edges) - 1):
            row = [f"{_fmt(edges[i], 3)}–{_fmt(edges[i + 1], 3)}"]
            for m in methods:
                b = by_band[m]["bands"][i]
                row.append(f"{_fmt(b['mmpmr'])} ({b['n_verifying']}/{b['n_morphs']})")
            band_rows.append(row)
        top_row = [f"top decile (≥{_fmt(by_band['top_decile_pair_cosine_min'], 3)})"]
        for m in methods:
            t = by_band[m]["top_decile"]
            top_row.append(f"**{_fmt(t['mmpmr'])}** ({t['n_verifying']}/{t['n_morphs']})")
        band_rows.append(top_row)
        banding = (
            "\n**MMPMR by contributing-pair ArcFace cosine (quintiles).** Separates a pool "
            "limit (MMPMR climbs with pair similarity) from a method limit (it stays low even "
            "for the closest pairs). Read with §12 item 8.\n\n"
            + _markdown_table(["Pair cosine", *methods], band_rows)
            + "\n"
        )
    return (
        f"{title}\n_Threshold: `match_cosine_min` = {threshold}._\n\n{table}\n{caveat}" f"{banding}"
    )


def render_morph_cross_method(accuracy: dict[str, Any] | None) -> str:
    """Train on one morph generator, test on the other — the §12 generalisation number.

    Cross-*dataset* evaluation is impossible with one self-generated corpus; this is the
    closest available proxy, and it is where a morph detector's honest number lives.
    """
    title = "### T4c — Morph cross-method generalisation\n"
    section = accuracy.get("morph_cross_method_generalisation") if accuracy else None
    if section is None:
        return f"{title}\nBLOCKED — results/accuracy.json not found\n"
    if is_blocked(section):
        return f"{title}\nBLOCKED — {section['blocker']}\n"

    rows = []
    for setting, pairings in section.items():
        if not isinstance(pairings, dict):
            continue
        for pairing, metrics in pairings.items():
            if is_blocked(metrics):
                rows.append([setting.upper(), pairing, "BLOCKED", "", "", ""])
                continue
            rows.append(
                [
                    setting.upper(),
                    pairing.replace("train_", "train ").replace("__test_", " → test "),
                    _fmt(metrics.get("acer")),
                    _fmt(metrics.get("eer")),
                    _fmt(metrics.get("auc_roc")),
                    _fmt(metrics.get("apcer")),
                ]
            )
    table = _markdown_table(["Setting", "Train → test", "ACER", "EER", "AUC-ROC", "APCER"], rows)
    return (
        f"{title}\nAUC near 0.5 means the detector learned the *generator*, not morphing. "
        "Compare against the within-corpus rows of T1: the gap is the honest number "
        "(§12 item 10).\n\n"
        f"{table}\n"
    )


def render_t5(pqc_micro: dict[str, Any] | None) -> str:
    title = "### T5 — Crypto micro-benchmarks and artefact sizes\n"
    if pqc_micro is None:
        return f"{title}\nBLOCKED — results/pqc_micro.json not found\n"
    rows = []
    for family, ops in (
        ("kem", ("keygen", "encaps", "decaps")),
        ("signer", ("keygen", "sign", "verify")),
    ):
        for mode, block in pqc_micro.get(family, {}).items():
            for op in ops:
                stats = block.get(op, {})
                rows.append(
                    [
                        f"{family}/{mode}/{op}",
                        block.get("backend", "?"),
                        _fmt(stats.get("mean_ms")),
                        _fmt(stats.get("p95_ms")),
                        _fmt(stats.get("iterations"), 0),
                    ]
                )
            sizes = block.get("artefact_sizes_bytes", {})
            rows.append(
                [
                    f"{family}/{mode}/artefact_sizes_bytes",
                    block.get("backend", "?"),
                    json.dumps(sizes),
                    "",
                    "",
                ]
            )
    body = _markdown_table(["Operation", "Backend", "Mean (ms)", "p95 (ms)", "Iterations"], rows)
    return f"{title}\n{body}\n"


def render_t6(overhead: dict[str, Any] | None) -> str:
    title = "### T6 — Four-configuration overhead ablation\n"
    if overhead is None:
        return f"{title}\nBLOCKED — results/overhead_ablation.json not found\n"
    rows = []
    for cfg_name in ("C0", "C1", "C2", "C3"):
        cfg = overhead.get(cfg_name, {})
        if is_blocked(cfg):
            rows.append([cfg_name, "", "", f"BLOCKED — {cfg['blocker']}", ""])
        else:
            latency = cfg.get("latency", {})
            rows.append(
                [
                    cfg_name,
                    cfg.get("crypto", "?"),
                    cfg.get("ai", "?"),
                    cfg.get("isolates", "?"),
                    _fmt(latency.get("mean_ms")),
                ]
            )
    body = _markdown_table(["Config", "Crypto", "AI", "Isolates", "Mean latency (ms)"], rows)
    pq = overhead.get("pq_overhead_ms", {})
    ai = overhead.get("ai_overhead_ms", {})
    ratio = overhead.get("ai_to_pq_overhead_ratio")
    bound = overhead.get("ai_to_pq_overhead_ratio_lower_bound")

    def term(cell: Any, pct_key: str) -> str:
        if is_blocked(cell):
            return f"BLOCKED — {cell['blocker']}"
        text = f"{_fmt(cell.get('absolute_ms'))} ms ({_fmt(cell.get(pct_key), 1)}%)"
        ci = cell.get("ci95_ms")
        if ci:
            text += f", 95% CI [{_fmt(ci[0])}, {_fmt(ci[1])}] ms"
            if not cell.get("resolvable_from_noise", True):
                text += " — **spans zero: not resolvable from run noise**"
        return text

    derived = (
        f"\n\n**PQ overhead (C2−C1):** {term(pq, 'percent_of_c1')}\n\n"
        f"**AI overhead (C3−C2):** {term(ai, 'percent_of_c2')}\n\n"
        f"**AI:PQ overhead ratio:** "
        f"{('BLOCKED — ' + str(ratio['blocker'])) if is_blocked(ratio) and ratio else _fmt(ratio, 2)}"
    )
    if bound is not None:
        derived += (
            f"\n\n**AI:PQ ratio, 95% lower bound:** "
            f"{('BLOCKED — ' + bound['blocker']) if is_blocked(bound) else _fmt(bound, 0) + 'x'} "
            "(AI overhead's lower limit over PQ overhead's upper limit — the smallest ratio "
            "consistent with both intervals, and the figure that survives rerunning)"
        )
    if not is_blocked(ai):
        derived += (
            "\n\n_The AI side is **a lower bound**: C3 runs two of the five attack detectors "
            "— injection, and morph in its S-MAD setting (§5.4, pipeline stage 6). pad, "
            "deepfake and replay are absent (§6/§14). Adding them can only increase C3. The "
            "intervals cover within-run sampling noise only; the C1 baseline mean has moved "
            "by ~7 ms between committed runs, so between-run drift is larger still._"
        )
    return f"{title}\n{body}{derived}\n"


def render_t7(loadgen: dict[str, Any] | None) -> str:
    title = "### T7 — Throughput vs concurrency\n"
    if loadgen is None:
        return f"{title}\nBLOCKED — results/loadgen.json not found\n"
    rows = []
    for level in loadgen.get("concurrency_levels", []):
        rows.append(
            [
                _fmt(level.get("concurrency"), 0),
                _fmt(level.get("throughput_per_s"), 3),
                _fmt(level.get("latency", {}).get("p50_ms")),
                _fmt(level.get("latency", {}).get("p95_ms")),
                _fmt(level.get("latency", {}).get("p99_ms")),
                _fmt(level.get("setup_failed_before_verify"), 0),
                _fmt(level.get("expired_before_verify"), 0),
            ]
        )
    body = _markdown_table(
        [
            "Concurrency",
            "Throughput (verif/s)",
            "p50 (ms)",
            "p95 (ms)",
            "p99 (ms)",
            "Setup failed (409)",
            "Expired before verify (409)",
        ],
        rows,
    )
    knee = loadgen.get("knee", {})
    degradation = loadgen.get("degradation_finding", {})
    extra = (
        f"\n\n**Knee:** concurrency={knee.get('concurrency')} — {knee.get('reason', '')}\n\n"
        f"**Event-loop-blocking finding:** {degradation.get('finding', 'n/a')}"
    )
    return f"{title}\n{body}{extra}\n"


def render_t8(
    accuracy: dict[str, Any] | None, latency: dict[str, Any] | None, overhead: dict[str, Any] | None
) -> str:
    title = "### T8 — Deployment recommendation matrix\n"
    lines = [
        title,
        "**Provisional — based on measured latency/throughput/PQ-overhead numbers only.** "
        "A real ACER-vs-scenario recommendation (§8.4) needs the four missing detectors "
        "and real datasets (§6/§14); this matrix cannot yet weigh accuracy against "
        "latency per scenario, only latency and crypto cost, which are real.\n",
    ]
    e2e = latency.get("end_to_end_client_observed", {}) if latency else {}
    p95 = e2e.get("p95_ms")
    pq = (overhead or {}).get("pq_overhead_ms", {})
    pq_ms = None if is_blocked(pq) else (pq or {}).get("absolute_ms")
    pq_phrase = (
        f"the measured PQ overhead is {_fmt(pq_ms, 2)} ms per session (T6), "
        f"{_fmt((pq_ms / p95 * 100) if (pq_ms and p95) else None, 2)}% of end-to-end p95"
        if pq_ms is not None
        else "PQ overhead is BLOCKED (see T6) — measure it before deciding here"
    )
    rows = [
        [
            "High-security, low-volume (bank onboarding)",
            "Maximise detection strength once available; the system's own p95 "
            f"({_fmt(p95)} ms) is not the binding constraint at low volume. Crypto choice "
            "is not the trade-off axis here at all.",
        ],
        [
            "Balanced (mobile login)",
            f"PQ is affordable on these numbers: {pq_phrase}. The cost that matters for "
            "this scenario is inference, not crypto.",
        ],
        [
            "High-volume, low-latency (access control)",
            "T7's knee bounds this scenario. Throughput saturates against "
            "`server.workers` running per-request ONNX inference, so scale that (or move "
            "inference to a GPU) — dropping PQ for classical crypto would buy back only "
            f"{_fmt(pq_ms, 2) if pq_ms is not None else '(unmeasured)'} ms per session "
            "and is not the lever.",
        ],
    ]
    lines.append(_markdown_table(["Scenario", "Recommendation (latency/crypto-only)"], rows))
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------------
# Figures F1-F4
# ----------------------------------------------------------------------------------


def render_f1_det_curves(accuracy: dict[str, Any] | None) -> str:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out_path = FIGURES_DIR / "f1_det_curves.png"
    det_curves = (accuracy or {}).get("det_curve", {})
    real_curves = {name: c for name, c in det_curves.items() if not is_blocked(c)}
    if not real_curves:
        return "### F1 — DET curves\n\nBLOCKED — no detector has a real DET curve yet (§14)\n"

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(6, 5))
    for name, curve in real_curves.items():
        ax.plot(curve["far"], curve["frr"], label=name)
    ax.set_xlabel("FAR (APCER)")
    ax.set_ylabel("FRR (BPCER)")
    ax.set_title("DET curve(s)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return f"### F1 — DET curves\n\n![DET curves]({out_path.relative_to(RESULTS_DIR).as_posix()})\n"


def render_f2_stage_latency(latency: dict[str, Any] | None) -> str:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out_path = FIGURES_DIR / "f2_stage_latency.png"
    breakdown = (latency or {}).get("stage_breakdown", {})
    if not breakdown:
        return "### F2 — Stage-level latency breakdown\n\nBLOCKED — results/latency.json not found or empty\n"

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    stages = sorted(breakdown, key=lambda name: breakdown[name]["mean_ms"], reverse=True)
    means = [breakdown[s]["mean_ms"] for s in stages]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh(stages, means)
    ax.set_xlabel("Mean latency (ms)")
    ax.set_title("Per-stage latency breakdown (mean, one config)")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return f"### F2 — Stage-level latency breakdown\n\n![Stage latency]({out_path.relative_to(RESULTS_DIR).as_posix()})\n"


def render_f3_acer_vs_latency(
    accuracy: dict[str, Any] | None, latency: dict[str, Any] | None
) -> str:
    section = (accuracy or {}).get("T1_per_detector_accuracy_intra_dataset", {})
    real_points = {name: cell for name, cell in section.items() if not is_blocked(cell)}
    if not real_points or not latency:
        return "### F3 — ACER vs p95 latency\n\nBLOCKED — fewer than one real (detector, latency) pair exists yet (§14)\n"

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out_path = FIGURES_DIR / "f3_acer_vs_latency.png"
    p95 = latency.get("end_to_end_client_observed", {}).get("p95_ms")

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(6, 5))
    for name, cell in real_points.items():
        ax.scatter([p95], [cell["acer"]], label=name)
        ax.annotate(name, (p95, cell["acer"]))
    ax.set_xlabel("System p95 latency (ms)")
    ax.set_ylabel("ACER")
    ax.set_title("ACER vs p95 latency (one point per detector with real data)")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    note = (
        "\n\n_Only one real (ACER, p95) pair exists (injection); this plot cannot yet "
        "show the trade-off curve §8.4 asks for across strategies/detectors._"
    )
    return f"### F3 — ACER vs p95 latency\n\n![ACER vs latency]({out_path.relative_to(RESULTS_DIR).as_posix()}){note}\n"


def render_f4_confusion_matrix(accuracy: dict[str, Any] | None) -> str:
    section = (accuracy or {}).get("confusion_matrix_6class")
    if not section or is_blocked(section):
        blocker = (
            section["blocker"]
            if section and is_blocked(section)
            else "results/accuracy.json not found"
        )
        return f"### F4 — 6-class confusion matrix\n\nBLOCKED — {blocker}\n"

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    out_path = FIGURES_DIR / "f4_confusion_matrix.png"

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    labels = section["labels"]
    matrix = np.array(section["matrix"])
    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(matrix, cmap="Blues")
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_yticklabels(labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, str(matrix[i, j]), ha="center", va="center")
    fig.colorbar(im)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    caveat = section.get("caveat", "")

    # Reconciliation, printed WITH the matrix rather than as a field somewhere else.
    # Since 2026-09-06 a rejected decision carries every code determined up to the
    # rejection point, so the single-label collapse (§8.1) drops rejections that name no
    # attack class -- which makes the matrix total smaller than the sample count. A
    # matrix that does not sum to the number of samples reads as an arithmetic error
    # unless the missing rows are accounted for immediately beside it.
    total = int(np.asarray(matrix).sum())
    non_attributing = section.get("non_attributing_rejections")
    multi = section.get("multi_attribution_count")
    lines = [f"Samples counted in the matrix: **{total}**"]
    if non_attributing is not None:
        lines.append(
            f"Rejections excluded (named no attack class): **{non_attributing}** — "
            "forged signature, expiry, nonce replay, counter regression, quality "
            "failure, unevaluable challenge. Excluded rather than folded into the "
            "nearest class, which would invent an attribution the system never made "
            "(§8.1)."
        )
        lines.append(f"Total decisions: **{total + int(non_attributing)}**")
    if multi is not None:
        lines.append(
            f"Decisions carrying more than one attack attribution: **{multi}** — "
            "collapsed to a single label by ATTACK_CODE_PRECEDENCE. A large count here "
            "means this matrix is hiding most of what the system found, and the "
            "per-attack rates (T4) should be read instead."
        )
    reconciliation = "\n\n".join(lines)

    return (
        f"### F4 — 6-class confusion matrix\n\n"
        f"![Confusion matrix]({out_path.relative_to(RESULTS_DIR).as_posix()})\n\n"
        f"{reconciliation}\n\n_{caveat}_\n"
    )


# ----------------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------------


def generate_report(out_path: Path = RESULTS_DIR / "report.md") -> Path:
    accuracy = _load_json(RESULTS_DIR / "accuracy.json")
    latency = _load_json(RESULTS_DIR / "latency.json")
    loadgen = _load_json(RESULTS_DIR / "loadgen.json")
    overhead = _load_json(RESULTS_DIR / "overhead_ablation.json")
    pqc_micro = _load_json(RESULTS_DIR / "pqc_micro.json")

    top_metadata = accuracy or latency or run_metadata()

    sections = [
        "# Evaluation report (PROJECT_SPEC.md §8)\n",
        _metadata_line(top_metadata),
        "\n---\n",
        render_t1(accuracy),
        render_t2(accuracy),
        render_t3(accuracy),
        render_t4(accuracy),
        render_t4b_mmpmr(accuracy),
        render_morph_cross_method(accuracy),
        render_t5(pqc_micro),
        render_t6(overhead),
        render_t7(loadgen),
        render_t8(accuracy, latency, overhead),
        "---\n",
        render_f1_det_curves(accuracy),
        render_f2_stage_latency(latency),
        render_f3_acer_vs_latency(accuracy, latency),
        render_f4_confusion_matrix(accuracy),
        "---\n",
        "See `results/BLOCKERS.md` for the complete list of blocked metrics and what unblocks each one.\n",
    ]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(sections), encoding="utf-8")
    return out_path


def _collect_blocked(node: Any, path: str, results_file: str, sink: list[dict[str, str]]) -> None:
    if is_blocked(node):
        sink.append({"file": results_file, "path": path, "blocker": node["blocker"]})
        return
    if isinstance(node, dict):
        for key, value in node.items():
            _collect_blocked(value, f"{path}.{key}" if path else key, results_file, sink)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            _collect_blocked(value, f"{path}[{i}]", results_file, sink)


def write_blockers_document(out_path: Path = RESULTS_DIR / "BLOCKERS.md") -> Path:
    """Scans every results/*.json for the BLOCKED convention and writes one document
    naming every blocked metric, where it lives, and its blocker verbatim -- the honest
    scope statement for the report (§5.6's final deliverable this session).
    """
    entries: list[dict[str, str]] = []
    for path in sorted(RESULTS_DIR.glob("*.json")):
        data = _load_json(path)
        if data is not None:
            _collect_blocked(data, "", path.name, entries)

    lines = [
        "# BLOCKERS\n",
        "Every metric this evaluation could not produce, where it would have appeared, "
        "and what would need to change to unblock it. Generated from the `blocked` "
        "markers in `results/*.json` -- not maintained by hand.\n",
        f"_Generated {run_metadata()['generated_at_utc']}_\n",
        "\n---\n",
    ]
    if not entries:
        lines.append("No blocked entries found.\n")
    else:
        lines.append(f"**{len(entries)} blocked entries.**\n")
        for entry in entries:
            lines.append(f"- **`{entry['file']}` → `{entry['path']}`**\n  {entry['blocker']}\n")

    # Backend provenance: which PQC backend each result file was actually produced on.
    # Derived from the files themselves, not maintained by hand — a table measured on
    # the pure-Python fallback and one measured on liboqs differ by ~3 orders of
    # magnitude in every crypto number, so "which backend produced this" is not a
    # footnote, it decides whether the number means anything (§14, 2026-09-01).
    lines.append("\n---\n\n## Backend provenance of each result file\n")
    lines.append(
        "Crypto figures produced on the `kyber-py`/`dilithium-py` fallback are **superseded** "
        "by any liboqs-backed file below — the fallback is a reference implementation for "
        "correctness, never a performance measurement of ML-KEM-768/ML-DSA-65. "
        "`pqc_micro_fallback.json`, if present, is retained deliberately as the labelled "
        "comparison arm.\n"
    )
    lines.append("| Result file | KEM backend | SIG backend | Generated |")
    lines.append("|---|---|---|---|")
    for path in sorted(RESULTS_DIR.glob("*.json")):
        data = _load_json(path)
        if not data:
            continue
        kem = data.get("KEM_BACKEND") or data.get("kem", {}).get("pq", {}).get("backend") or "—"
        sig = data.get("SIG_BACKEND") or data.get("signer", {}).get("pq", {}).get("backend") or "—"
        generated = str(data.get("generated_at_utc", "—"))[:19]
        lines.append(f"| `{path.name}` | {kem} | {sig} | {generated} |")
    lines.append("")

    lines.append("\n---\n\n## What unblocks each category\n")
    lines.append(
        "\n".join(
            [
                "- **pad/morph/deepfake/replay detectors** — implement "
                "`pqbio/detect/{pad,morph,deepfake,replay}.py` once their datasets are "
                "licensed (§6); currently deliberately absent, not stubbed.",
                "- **Cross-dataset accuracy (T2)** — needs a second, independent "
                "labelled dataset per attack type; only the self-generated injection "
                "corpus exists today.",
                "- **MMPMR** — needs the morph detector above, plus a morph dataset "
                "(FRLL-Morphs/SMDD).",
                "- **match FAR/FRR** — needs a labelled genuine/impostor pair dataset; "
                "none exists (§6).",
                "- **C1/C2/C3 overhead ablation** — UNBLOCKED 2026-09-01. Needs liboqs, "
                "which now builds in `docker/Dockerfile.server`; run it there via "
                "`make docker-bench`. On a host without a C toolchain the fallback is "
                "still selected and `pqbio/bench/overhead.py`'s "
                "`guard_against_fallback_backend` will (correctly) re-block C1/C2/C3, "
                "so check the backend provenance table above before reading T6.",
                "- **GPU utilisation/VRAM** — needs a machine with an NVIDIA GPU and "
                "NVML available; this environment has neither.",
                "- **T8 real ACER-based recommendation** — depends on the detector and "
                "dataset gaps above; today's T8 is latency/crypto-cost-only.",
            ]
        )
    )
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


def main() -> None:
    report_path = generate_report()
    blockers_path = write_blockers_document()
    print(f"wrote {report_path}")
    print(f"wrote {blockers_path}")


if __name__ == "__main__":
    main()
