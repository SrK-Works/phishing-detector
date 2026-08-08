from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "app" / "data"
ARTIFACTS_DIR = BACKEND_DIR / "app" / "model" / "artifacts"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PHISH_", env_file=".env")

    database_url: str = f"sqlite:///{BACKEND_DIR / 'phishing.db'}"

    # overall time budget for a single /api/check call, in seconds
    check_timeout_seconds: float = 6.0

    # per-outbound-request timeout for whois/dns/content fetch.
    # Real-world WHOIS round-trips regularly take 1.5-2.0s, so anything at or
    # below 2.0s here flakily times out and silently drops domain-age signal.
    network_timeout_seconds: float = 3.5

    # cache a repeated URL lookup for this many hours before recomputing
    cache_ttl_hours: int = 24

    max_content_bytes: int = 2_000_000
    max_redirects: int = 3

    tranco_list_path: Path = DATA_DIR / "tranco.csv"
    # A domain ranked at or below this in Tranco's top-1M is treated as
    # well-established enough to override a shaky/borderline model verdict.
    # Not the full 1M -- the tail of that list is thin/low-quality traffic,
    # so a tighter cutoff keeps this an actually-strong signal.
    popularity_override_rank: int = 200_000
    model_artifact_path: Path = ARTIFACTS_DIR / "model.joblib"
    model_metadata_path: Path = ARTIFACTS_DIR / "metadata.json"

    # Optional: enables the Google Safe Browsing ground-truth check.
    # Free tier, self-service -- get one at
    # https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com
    # Left unset, that check is simply skipped (feature degrades gracefully).
    safe_browsing_api_key: str | None = None


settings = Settings()
