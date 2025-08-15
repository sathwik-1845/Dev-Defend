from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    OPENAI_API_KEY: str | None = None
    DATABASE_URL: str = "sqlite+aiosqlite:///./scanner.db"
    MAX_FILE_SIZE_BYTES: int = 2_000_000  # 2 MB per file
    ALLOWED_LANGS: list[str] = ["python", "javascript", "java", "go", "csharp", "ruby", "php"]
    ENABLE_FIXES: bool = True  # set False to skip GPT calls
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
