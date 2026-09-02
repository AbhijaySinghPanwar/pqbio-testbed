"""PROJECT_SPEC.md §9's config block must match `config/default.yaml`.

§9 is where a reader looks to find out what the system is tuned to, and it had silently
drifted: `phash_hamming_max` still read 6 there after §14's calibration moved it to 10,
and four `capture.illumination_*` keys added on 2026-09-02 were never mirrored into it at
all. Nothing caught that, because nothing was comparing them.

This test compares them. It exists because "update the spec, not just the config" is only
enforceable if something checks.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT / "PROJECT_SPEC.md"
CONFIG_PATH = REPO_ROOT / "config" / "default.yaml"


def _flatten(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in d.items():
        if isinstance(value, dict):
            out.update(_flatten(value, f"{prefix}{key}."))
        else:
            out[f"{prefix}{key}"] = value
    return out


def _spec_config_block() -> dict[str, Any]:
    text = SPEC_PATH.read_text(encoding="utf-8")
    match = re.search(r"## 9\. Configuration.*?```yaml\n(.*?)```", text, re.S)
    assert match is not None, "§9's ```yaml config block is missing from PROJECT_SPEC.md"
    parsed = yaml.safe_load(match.group(1))
    assert isinstance(parsed, dict)
    return _flatten(parsed)


def _actual_config() -> dict[str, Any]:
    parsed = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    return _flatten(parsed)


def test_spec_section_9_values_match_config() -> None:
    spec, actual = _spec_config_block(), _actual_config()
    mismatched = {
        key: (value, actual[key])
        for key, value in spec.items()
        if key in actual and actual[key] != value
    }
    assert not mismatched, "PROJECT_SPEC.md §9 disagrees with config/default.yaml on " + ", ".join(
        f"{k} (spec={s!r}, config={c!r})" for k, (s, c) in mismatched.items()
    )


def test_spec_section_9_documents_every_config_key() -> None:
    spec, actual = _spec_config_block(), _actual_config()
    missing = sorted(set(actual) - set(spec))
    assert not missing, (
        "config/default.yaml has keys PROJECT_SPEC.md §9 never mentions: "
        + ", ".join(missing)
        + ". A tunable nobody can find in the spec is a tunable nobody will maintain."
    )


def test_spec_section_9_invents_no_keys() -> None:
    spec, actual = _spec_config_block(), _actual_config()
    extra = sorted(set(spec) - set(actual))
    assert (
        not extra
    ), "PROJECT_SPEC.md §9 documents keys that do not exist in config/default.yaml: " + ", ".join(
        extra
    )


@pytest.mark.parametrize(
    "key",
    [
        "binding.illumination_steps",
        "binding.illumination_corr_min",
        "capture.n_frames",
        "capture.fps",
    ],
)
def test_challenge_tunables_are_present_on_both_sides(key: str) -> None:
    """The four B6 sweeps and recalibrations of 2026-09-02/03 all turned on these, so a
    drift here is the most expensive kind. Named explicitly so the failure says which.
    """
    assert key in _spec_config_block(), f"§9 does not document {key}"
    assert key in _actual_config(), f"config/default.yaml does not define {key}"


def test_capture_wall_time_covers_the_challenge() -> None:
    """`n_frames / fps` must leave room for `illumination_steps` steps.

    This is the frame-budget constraint of §14 (2026-09-03) as an assertion: if someone
    raises the step count without raising the capture budget, the last steps of the
    challenge are never captured and B6 silently degrades rather than failing loudly.
    """
    actual = _actual_config()
    wall_time_s = actual["capture.n_frames"] / actual["capture.fps"]
    step_ms = actual["binding.illumination_step_ms"]
    needed_s = actual["binding.illumination_steps"] * step_ms / 1000.0
    assert wall_time_s >= needed_s, (
        f"capture budget is {wall_time_s:.2f}s (n_frames/fps) but "
        f"{actual['binding.illumination_steps']} steps at {step_ms}ms need {needed_s:.2f}s"
    )
