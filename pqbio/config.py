"""Central configuration.

Every tunable in the system lives here or in config/default.yaml — never as a magic
number in code (PROJECT_SPEC.md §11). YAML supplies the defaults; environment
variables (`PQBIO_` prefix, `__` nested delimiter, see .env.example) override them.

All fields below are required with no Python-level defaults, so a missing key in
config/default.yaml raises `pydantic.ValidationError` at import time — configuration
fails closed rather than silently falling back to an implicit value.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, cast

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "default.yaml"


class CryptoConfig(BaseModel):
    mode: Literal["classical", "pq"]
    kem: str
    sig: str


class BindingConfig(BaseModel):
    nonce_bytes: int
    challenge_ttl_s: int
    clock_skew_s: int
    illumination_steps: int
    illumination_step_ms: int
    illumination_corr_min: float
    illumination_min_trace_spread: float
    phash_hamming_max: int
    phash_reuse_min_frames: int


class CaptureConfig(BaseModel):
    n_frames: int
    fps: int
    resolution: tuple[int, int]
    illumination_region_weighting: Literal["uniform", "centre"]
    illumination_min_channel_sum: float
    illumination_centre_grid: int


class QualityConfig(BaseModel):
    min_face_px: int
    min_blur_var: float
    max_yaw_deg: int


class DetectThresholds(BaseModel):
    pad: float
    morph: float
    deepfake: float
    replay: float
    injection: float
    match_cosine_min: float


class FusionConfig(BaseModel):
    strategy: Literal["rule", "cascade"]
    operating_point: str


class DetectConfig(BaseModel):
    quality: QualityConfig
    thresholds: DetectThresholds
    fusion: FusionConfig


class ServerConfig(BaseModel):
    workers: int
    max_concurrency: int
    request_timeout_s: int


class YamlConfigSource(PydanticBaseSettingsSource):
    """Loads the base config dict from a YAML file (config/default.yaml)."""

    def __init__(self, settings_cls: type[BaseSettings], yaml_path: Path) -> None:
        super().__init__(settings_cls)
        self._yaml_path = yaml_path

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        # Required by the abstract base; actual values come from __call__.
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        if not self._yaml_path.is_file():
            raise FileNotFoundError(f"config file not found: {self._yaml_path}")
        with self._yaml_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not data:
            raise ValueError(f"config file is empty or invalid: {self._yaml_path}")
        return cast(dict[str, Any], data)


class Settings(BaseSettings):
    """Root settings object, assembled from config/default.yaml with env-var overrides."""

    model_config = SettingsConfigDict(
        env_prefix="PQBIO_",
        env_nested_delimiter="__",
        extra="forbid",
    )

    crypto: CryptoConfig
    binding: BindingConfig
    capture: CaptureConfig
    detect: DetectConfig
    server: ServerConfig

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Precedence, highest first: explicit init kwargs > env vars > .env file >
        # config/default.yaml > secret files.
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSource(settings_cls, DEFAULT_CONFIG_PATH),
            file_secret_settings,
        )


def load_settings(yaml_path: Path = DEFAULT_CONFIG_PATH) -> Settings:
    """Load and validate settings. Raises if any required key is missing or malformed."""
    if yaml_path == DEFAULT_CONFIG_PATH:
        return Settings()

    class _Settings(Settings):
        @classmethod
        def settings_customise_sources(
            cls,
            settings_cls: type[BaseSettings],
            init_settings: PydanticBaseSettingsSource,
            env_settings: PydanticBaseSettingsSource,
            dotenv_settings: PydanticBaseSettingsSource,
            file_secret_settings: PydanticBaseSettingsSource,
        ) -> tuple[PydanticBaseSettingsSource, ...]:
            return (
                init_settings,
                env_settings,
                dotenv_settings,
                YamlConfigSource(settings_cls, yaml_path),
                file_secret_settings,
            )

    return _Settings()


settings = load_settings()
