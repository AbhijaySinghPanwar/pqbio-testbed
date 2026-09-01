"""Confirms the Module A DoD claim "both modes behind one interface, selectable by
config": pqbio.config.CryptoConfig.mode and pqbio.pqc's KemMode/SigMode share the same
two literal values, so `get_kem(settings.crypto.mode)` / `get_signer(...)` just work.
"""

from __future__ import annotations

import pytest

from pqbio.config import load_settings
from pqbio.pqc.kem import get_kem
from pqbio.pqc.sign import get_signer


@pytest.mark.parametrize("mode", ["classical", "pq"])
def test_config_crypto_mode_selects_matching_kem_and_signer(mode: str, tmp_path) -> None:  # type: ignore[no-untyped-def]
    yaml_text = f"""
crypto:
  mode: {mode}
  kem: ML-KEM-768
  sig: ML-DSA-65
binding:
  nonce_bytes: 32
  challenge_ttl_s: 30
  clock_skew_s: 2
  illumination_steps: 4
  illumination_corr_min: 0.70
  phash_hamming_max: 10
  phash_reuse_min_frames: 30
capture:
  n_frames: 30
  fps: 15
  resolution: [1280, 720]
  illumination_region_weighting: uniform
  illumination_min_channel_sum: 12.0
  illumination_centre_grid: 4
detect:
  quality:
    min_face_px: 112
    min_blur_var: 60.0
    max_yaw_deg: 25
  thresholds:
    pad: 0.50
    morph: 0.50
    deepfake: 0.50
    replay: 0.50
    injection: 0.40
    match_cosine_min: 0.38
  fusion:
    strategy: cascade
    operating_point: bpcer_at_apcer_5
server:
  workers: 4
  max_concurrency: 64
  request_timeout_s: 10
"""
    config_path = tmp_path / "test_config.yaml"
    config_path.write_text(yaml_text, encoding="utf-8")

    settings = load_settings(config_path)
    assert settings.crypto.mode == mode

    kem = get_kem(settings.crypto.mode)
    pk, sk = kem.keygen()
    ct, ss = kem.encapsulate(pk)
    assert kem.decapsulate(ct, sk) == ss

    signer = get_signer(settings.crypto.mode)
    spk, ssk = signer.keygen()
    sig = signer.sign(b"msg", ssk)
    assert signer.verify(b"msg", sig, spk) is True
