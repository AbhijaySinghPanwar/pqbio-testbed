"""Tests for scripts/make_injection_corpus.py: the genuine/tier1 structural contrast
(§5.4 D5, §7) — small scale, isolated from the real corpus under data/.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "make_injection_corpus.py"

spec = importlib.util.spec_from_file_location("make_injection_corpus", SCRIPT_PATH)
assert spec is not None and spec.loader is not None
corpus_module = importlib.util.module_from_spec(spec)
sys.modules["make_injection_corpus"] = corpus_module
spec.loader.exec_module(corpus_module)


def test_blocked_tier2_reason_names_concrete_evidence() -> None:
    reason = corpus_module.BLOCKED_TIER2_REASON
    assert "OBS" in reason
    assert "Administrator" in reason
    assert "v4l2loopback" in reason


def test_instant_read_has_near_zero_jitter(tmp_path: Path) -> None:
    clip_path = tmp_path / "clip.mp4"
    corpus_module._synthetic_clip(clip_path, seed=1, n_frames=20)

    frames = corpus_module._instant_read_all_frames(clip_path, n_frames=10)
    ts = np.array([f.meta.capture_ts_ns for f in frames], dtype=np.float64)
    dt = np.diff(ts)
    # instant back-to-back reads: not paced to any fps interval
    assert np.mean(dt) < 5_000_000  # well under 5ms, nowhere near a 15fps ~66ms interval


def test_genuine_and_tier1_pair_have_different_timing_signatures(tmp_path: Path) -> None:
    from pqbio.binding.nonce import NonceStore
    from pqbio.capture.replay_source import ReplaySource
    from pqbio.pqc.keystore import KeyStore
    from pqbio.pqc.sign import get_signer

    clip_path = tmp_path / "clip.mp4"
    corpus_module._synthetic_clip(clip_path, seed=2, n_frames=20)

    signer = get_signer("pq")
    _server_pk, server_sk = signer.keygen()
    device_pk, device_sk = signer.keygen()
    keystore = KeyStore()
    keystore.enroll("dev", sig_pk=device_pk, sig_mode="pq")
    nonce_store = NonceStore(tmp_path / "nonces.db")

    genuine_frames, genuine_meta = ReplaySource(clip_path).capture(10, fps=15)
    genuine_bundle = corpus_module._build_bundle(
        frames=genuine_frames,
        device_meta=genuine_meta,
        device_id="dev",
        device_sk=device_sk,
        signer=signer,
        nonce_store=nonce_store,
        server_sk=server_sk,
        counter=1,
    )

    tier1_frames = corpus_module._instant_read_all_frames(clip_path, 10)
    tier1_bundle = corpus_module._build_bundle(
        frames=tier1_frames,
        device_meta=genuine_meta,
        device_id="dev",
        device_sk=device_sk,
        signer=signer,
        nonce_store=nonce_store,
        server_sk=server_sk,
        counter=2,
    )

    g_dt = np.diff([m.capture_ts_ns for m in genuine_bundle.frame_meta])
    t_dt = np.diff([m.capture_ts_ns for m in tier1_bundle.frame_meta])
    assert np.mean(g_dt) > 10 * np.mean(t_dt)  # genuine is paced; tier1 is near-instant
    # both signed with the SAME compromised device key, matching the A6 threat model
    assert genuine_bundle.device_id == tier1_bundle.device_id


def test_full_corpus_generation_small_scale(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    out_dir = tmp_path / "corpus"

    import subprocess

    result = subprocess.run(
        [
            sys.executable,
            "-W",
            "ignore",
            str(SCRIPT_PATH),
            "--n-pairs",
            "2",
            "--n-frames",
            "8",
            "--out-dir",
            str(out_dir),
            "--manifest-out",
            str(manifest_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["tier2_status"] == "blocked"
    assert len(manifest["samples"]) == 2
    for sample in manifest["samples"]:
        assert (REPO_ROOT / sample["genuine"]["bundle_path"]).is_file()
        assert (REPO_ROOT / sample["tier1_injection"]["bundle_path"]).is_file()


def test_tier2_flag_exits_nonzero_with_reason(tmp_path: Path) -> None:
    import subprocess

    result = subprocess.run(
        [sys.executable, "-W", "ignore", str(SCRIPT_PATH), "--tier2"],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=REPO_ROOT,
    )
    assert result.returncode != 0
    assert "blocked" in result.stderr
