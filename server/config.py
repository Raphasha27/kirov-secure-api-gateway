from pydantic import Field, field_validator
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    app_name: str = "Kirov Secure API Gateway"
    app_version: str = "1.0.0"
    debug: bool = False
    jwt_secret: str = Field(
        default="",
        description="JWT signing secret. Must be set in production via env var KG_JWT_SECRET.",
    )
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    database_url: str = Field(
        default="postgresql://kirov:kirov@localhost:5432/kirov_gateway",
        description="Database connection string. Must be set in production via env var KG_DATABASE_URL.",
    )
    rate_limit_per_minute: int = 100
    rate_limit_burst: int = 200
    cors_origins: list[str] = ["*"]
    openai_api_key: Optional[str] = None
    model_config = {"env_prefix": "KG_", "env_file": ".env"}

    @field_validator("jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        stripped = v.strip() if v else ""
        if (
            not stripped
            or "placeholder" in stripped.lower()
            or "change" in stripped.lower()
        ):
            raise ValueError(
                "JWT_SECRET must be set and must not be a placeholder. "
                "Set the KG_JWT_SECRET environment variable or add it to your .env file."
            )
        return stripped

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        stripped = v.strip() if v else ""
        if not stripped:
            raise ValueError("DATABASE_URL must be set.")
        return stripped


settings = Settings()
