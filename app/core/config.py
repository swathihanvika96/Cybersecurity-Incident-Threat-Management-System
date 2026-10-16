"""Environment-based application configuration (12-factor style)."""
from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_DEFAULT_SECRET = "change-me-in-production-use-a-long-random-string"
INSECURE_DEFAULT_ADMIN_PASSWORD = "Admin@12345"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- general -----------------------------------------------------------
    PROJECT_NAME: str = "Security Incident Management API"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"  # development | testing | production
    API_V1_PREFIX: str = "/api/v1"
    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = True

    # --- database ----------------------------------------------------------
    DATABASE_URL: str = "sqlite:///./security_incident.db"
    AUTO_CREATE_TABLES: bool = False  # dev convenience only; production uses Alembic
    SEED_ON_STARTUP: bool = True  # idempotent: roles, permissions, SLA policies, first admin

    # --- auth --------------------------------------------------------------
    SECRET_KEY: str = INSECURE_DEFAULT_SECRET
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    RESET_TOKEN_EXPIRE_MINUTES: int = 30
    BCRYPT_ROUNDS: int = 12
    CORS_ORIGINS: list[str] = []
    REGISTRATION_AUTO_ACTIVATE: bool = False  # self-registered accounts need admin activation
    EXPOSE_RESET_TOKEN: bool = False  # simulated e-mail: return reset token in API response (dev only)
    FIRST_SUPERADMIN_EMAIL: str = "admin@example.com"
    FIRST_SUPERADMIN_PASSWORD: str = INSECURE_DEFAULT_ADMIN_PASSWORD
    FIRST_SUPERADMIN_NAME: str = "System Administrator"

    # --- business rules ----------------------------------------------------
    DUPLICATE_ALERT_WINDOW_MINUTES: int = 60
    CORRELATION_WINDOW_MINUTES: int = 120
    CORRELATION_MIN_ALERTS: int = 3
    CORRELATION_LOOKBACK_HOURS: int = 168
    DUPLICATE_INCIDENT_WINDOW_HOURS: int = 24
    SLA_APPROACHING_FRACTION: float = 0.25  # "approaching" = last 25% of an SLA window remains
    REMEDIATION_DUE_SOON_HOURS: int = 24

    # --- background workers ------------------------------------------------
    ENABLE_BACKGROUND_WORKERS: bool = False
    WORKER_INTERVAL_SECONDS: int = 60

    # --- redis (optional) --------------------------------------------------
    REDIS_URL: str | None = None
    DASHBOARD_CACHE_TTL_SECONDS: int = 30

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")

    @model_validator(mode="after")
    def _reject_insecure_production_defaults(self) -> "Settings":
        if self.is_production:
            if self.SECRET_KEY == INSECURE_DEFAULT_SECRET or len(self.SECRET_KEY) < 32:
                raise ValueError("SECRET_KEY must be set to a random value of at least 32 characters in production")
            if self.FIRST_SUPERADMIN_PASSWORD == INSECURE_DEFAULT_ADMIN_PASSWORD:
                raise ValueError("FIRST_SUPERADMIN_PASSWORD must be changed in production")
            if self.EXPOSE_RESET_TOKEN:
                raise ValueError("EXPOSE_RESET_TOKEN must be false in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
