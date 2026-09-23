from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from enum import Enum
import os


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    GROQ = "groq"
    MISTRAL = "mistral"
    COHERE = "cohere"
    CUSTOM = "custom"


# Default upstream URLs per provider
PROVIDER_URLS = {
    LLMProvider.OPENAI: "https://api.openai.com/v1/chat/completions",
    LLMProvider.ANTHROPIC: "https://api.anthropic.com/v1/messages",
    LLMProvider.GEMINI: "https://generativelanguage.googleapis.com/v1beta",
    LLMProvider.GROQ: "https://api.groq.com/openai/v1/chat/completions",
    LLMProvider.MISTRAL: "https://api.mistral.ai/v1/chat/completions",
    LLMProvider.COHERE: "https://api.cohere.com/v2/chat",
}

# Default models per provider
PROVIDER_DEFAULT_MODELS = {
    LLMProvider.OPENAI: "gpt-4o",
    LLMProvider.ANTHROPIC: "claude-sonnet-4-20250514",
    LLMProvider.GEMINI: "gemini-2.0-flash",
    LLMProvider.GROQ: "llama-3.3-70b-versatile",
    LLMProvider.MISTRAL: "mistral-large-latest",
    LLMProvider.COHERE: "command-r-plus",
    LLMProvider.CUSTOM: "default",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "PromptGuard AI Firewall Gateway"
    VERSION: str = "2.0.0"
    DEBUG: bool = True

    # Gateway Server Config
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # LLM Provider Selection
    LLM_PROVIDER: LLMProvider = Field(default=LLMProvider.OPENAI)
    MOCK_LLM_MODE: bool = Field(default=True)

    # Per-Provider API Keys
    OPENAI_API_KEY: str = Field(default="")
    ANTHROPIC_API_KEY: str = Field(default="")
    GEMINI_API_KEY: str = Field(default="")
    GROQ_API_KEY: str = Field(default="")
    MISTRAL_API_KEY: str = Field(default="")
    COHERE_API_KEY: str = Field(default="")

    # Custom / OpenAI-Compatible Endpoint (for Ollama, vLLM, LM Studio, etc.)
    CUSTOM_LLM_URL: str = Field(default="http://localhost:11434/v1/chat/completions")
    CUSTOM_API_KEY: str = Field(default="")

    # Override: if set, this takes priority over the auto-resolved provider URL
    UPSTREAM_LLM_URL: str = Field(default="")

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

    # Intent Classifier Model Configuration (Option B: Transformer Model)
    INTENT_CLASSIFIER_BACKEND: str = "transformer"
    INTENT_TRANSFORMER_MODEL: str = "ProtectAI/deberta-v3-base-prompt-injection-v2"
    INTENT_MODEL_CONFIDENCE_THRESHOLD: float = 0.65
    INTENT_MODEL_DEVICE: str = "cpu"

    # Media Scanning Configuration
    ENABLE_MEDIA_SCANNING: bool = True
    MAX_ATTACHMENT_SIZE_MB: int = 10
    SUPPORTED_IMAGE_EXTENSIONS: str = ".png,.jpg,.jpeg,.gif,.bmp,.tiff,.webp"
    SUPPORTED_FILE_EXTENSIONS: str = ".pdf,.docx,.xlsx,.csv,.txt,.log,.env,.json,.xml,.yaml,.yml,.md,.py,.js,.ts,.java,.go,.rs,.rb,.sh,.sql,.html,.css,.ini,.conf,.cfg"

    def get_upstream_url(self, provider: LLMProvider | None = None) -> str:
        """Resolve the upstream LLM URL for a given provider."""
        p = provider or self.LLM_PROVIDER
        # Explicit override takes priority
        if self.UPSTREAM_LLM_URL:
            return self.UPSTREAM_LLM_URL
        if p == LLMProvider.CUSTOM:
            return self.CUSTOM_LLM_URL
        return PROVIDER_URLS.get(p, PROVIDER_URLS[LLMProvider.OPENAI])

    def get_api_key(self, provider: LLMProvider | None = None) -> str:
        """Resolve the API key for a given provider."""
        p = provider or self.LLM_PROVIDER
        key_map = {
            LLMProvider.OPENAI: self.OPENAI_API_KEY,
            LLMProvider.ANTHROPIC: self.ANTHROPIC_API_KEY,
            LLMProvider.GEMINI: self.GEMINI_API_KEY,
            LLMProvider.GROQ: self.GROQ_API_KEY,
            LLMProvider.MISTRAL: self.MISTRAL_API_KEY,
            LLMProvider.COHERE: self.COHERE_API_KEY,
            LLMProvider.CUSTOM: self.CUSTOM_API_KEY,
        }
        return key_map.get(p, "")

    def get_default_model(self, provider: LLMProvider | None = None) -> str:
        """Get the default model name for a given provider."""
        p = provider or self.LLM_PROVIDER
        return PROVIDER_DEFAULT_MODELS.get(p, "default")


settings = Settings()
