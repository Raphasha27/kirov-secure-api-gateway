from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    app_name: str = "Kirov Secure API Gateway"
    app_version: str = "1.0.0"
    debug: bool = False
    jwt_secret: str = "change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    rate_limit_per_minute: int = 100
    rate_limit_burst: int = 200
    cors_origins: list[str] = ["*"]
    openai_api_key: Optional[str] = None
    model_config = {"env_prefix": "KG_", "env_file": ".env"}

settings = Settings()
