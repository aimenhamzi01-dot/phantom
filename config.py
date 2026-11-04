import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", 8000))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    ALLOWED_ORIGINS: list = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:5500").split(",")
    AI_MODEL: str = os.getenv("META_MODEL", "muse-spark-1.3").split(",")[0].strip()
    AI_MAX_TOKENS: int = 3000
    HTTP_TIMEOUT: int = 15
    AI_TIMEOUT: int = 120
    PHANTOM_API_TOKEN: str = os.getenv("PHANTOM_API_TOKEN", "")
    MIZAN_PHANTOM_SIGNING_KEY: str = os.getenv("MIZAN_PHANTOM_SIGNING_KEY", "")
    ALLOW_DIRECT_SCANS: bool = os.getenv("PHANTOM_ALLOW_DIRECT_SCANS", "false").lower() == "true"
    MAX_SOURCE_BYTES: int = 2 * 1024 * 1024

    @classmethod
    def validate(cls):
        if not (os.getenv("MODEL_API_KEY") or os.getenv("META_API_KEY") or os.getenv("META_MODEL_API_KEY")):
            raise ValueError("MODEL_API_KEY or META_API_KEY is required in .env file")
        if not cls.PHANTOM_API_TOKEN:
            raise ValueError("PHANTOM_API_TOKEN is required in .env file")
        if len(cls.MIZAN_PHANTOM_SIGNING_KEY) < 32:
            raise ValueError("MIZAN_PHANTOM_SIGNING_KEY must be at least 32 characters")
        return True


config = Config()
