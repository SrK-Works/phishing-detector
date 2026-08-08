from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "app" / "data"
ARTIFACTS_DIR = BACKEND_DIR / "app" / "model" / "artifacts"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PHISH_", env_file=".env")

    database_url: str = f"sqlite:///{BACKEND_DIR / 'phishing.db'}"

    # overall time budget for a single /api/check call, in seconds
    check_timeout_seconds: float = 4.0

    # per-outbound-request timeout for whois/dns/content fetch
    network_timeout_seconds: float = 2.0

    # cache a repeated URL lookup for this many hours before recomputing
    cache_ttl_hours: int = 24

    max_content_bytes: int = 2_000_000
    max_redirects: int = 3

    tranco_list_path: Path = DATA_DIR / "tranco.csv"
    model_artifact_path: Path = ARTIFACTS_DIR / "model.joblib"
    model_metadata_path: Path = ARTIFACTS_DIR / "metadata.json"


settings = Settings()
