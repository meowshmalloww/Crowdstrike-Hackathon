from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./counterflow.db")
    api_token: str | None = os.getenv("CONTROL_API_TOKEN")
    gateway_api_token: str | None = os.getenv("GATEWAY_API_TOKEN")
    policy_signing_key: str | None = os.getenv("POLICY_SIGNING_KEY")
    source_hash_salt: str = os.getenv("SOURCE_HASH_SALT", "")
    site_id: str = os.getenv("COUNTERFLOW_SITE_ID", "lab-site")
    lab_mode: str = os.getenv("LAB_MODE", "observe-only")
    origin_url: str = os.getenv("ORIGIN_URL", "http://127.0.0.1:8000")
    local_model_api_base: str = os.getenv("LOCAL_MODEL_API_BASE", "")
    local_model_name: str = os.getenv("LOCAL_MODEL_NAME", "")
    local_model_api_key: str = os.getenv("LOCAL_MODEL_API_KEY", "")
    local_model_timeout_seconds: float = float(os.getenv("LOCAL_MODEL_TIMEOUT_SECONDS", "120"))
    repair_artifact_dir: str = os.getenv("REPAIR_ARTIFACT_DIR", "./repair-artifacts")


settings = Settings()
