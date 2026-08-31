from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
import os

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "PromptGuard AI Firewall Gateway"
    VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Gateway Server Config
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # LLM Provider Configuration
    MOCK_LLM_MODE: bool = Field(default=True)
    UPSTREAM_LLM_URL: str = Field(default="https://api.openai.com/v1/chat/completions")
    OPENAI_API_KEY: str = Field(default="")

    # Logging & Audit Configuration
    LOGS_DIR: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
    AUDIT_DB_PATH: str = os.path.join(LOGS_DIR, "audit.db")
    AUDIT_LOG_FILE: str = os.path.join(LOGS_DIR, "audit.log")

    # Detection Pipeline Toggles
    ENABLE_STAGE_1_PII: bool = True
    ENABLE_STAGE_2_CREDENTIALS: bool = True
    ENABLE_STAGE_3_FINANCIAL: bool = True
    ENABLE_STAGE_4_INTENT: bool = True

    # Default Policy Actions
    DEFAULT_CREDENTIAL_ACTION: str = "BLOCK"
    DEFAULT_INTENT_ACTION: str = "BLOCK"
    DEFAULT_FINANCIAL_ACTION: str = "REDACT"
    DEFAULT_PII_ACTION: str = "REDACT"

settings = Settings()
