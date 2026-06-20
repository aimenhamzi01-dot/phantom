import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", 8000))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    ALLOWED_ORIGINS: list = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:5500").split(",")
    AI_MODEL: str = "claude-sonnet-4-6"
    AI_MAX_TOKENS: int = 4096
    HTTP_TIMEOUT: int = 15
    AI_TIMEOUT: int = 60

    @classmethod
    def validate(cls):
        if not cls.ANTHROPIC_API_KEY or cls.ANTHROPIC_API_KEY == "sk-ant-your-key-here":
            raise ValueError("ANTHROPIC_API_KEY is required in .env file")
        return True

config = Config()
