from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # SQLite by default (single-process broker, one host). Postgres remains
    # supported: postgresql+asyncpg://user:pw@host:5432/agent_auth
    database_url: str = "sqlite+aiosqlite:///agent-auth.db"
    policy_file: str = "policy.yaml"
    listen_host: str = "0.0.0.0"
    listen_port: int = 8400

    admin_token: str = ""
    # Fernet key for encrypting cached credentials at rest (generate: agent-auth admin gen-key)
    encryption_key: str = ""

    discord_token: str = ""
    discord_channel_id: int = 0
    discord_owner_id: int = 0

    openrouter_api_key: str = ""
    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    github_app_id: str = ""
    github_installation_id: str = ""
    github_app_private_key_file: str = ""
    github_api_url: str = "https://api.github.com"

    lldap_url: str = ""
    lldap_admin_user: str = ""
    lldap_admin_password: str = ""

    # "in-cluster" for the pod's own credentials, or an API server URL
    kubernetes_api_url: str = ""
    kubernetes_token: str = ""
    kubernetes_token_file: str = ""
    kubernetes_ca_file: str = ""
    kubernetes_insecure_skip_verify: bool = False

    a2a_relay_enabled: bool = True
    # If set, a2a webhook deliveries are signed: X-Agent-Auth-Signature carries
    # an HMAC-SHA256 of the raw body. Recipients verify with the same secret.
    webhook_signing_secret: str = ""

    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
