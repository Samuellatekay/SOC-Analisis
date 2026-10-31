"""
Application Configuration.
"""

import os
from typing import List


class Settings:
    PROJECT_NAME: str = "SOC Analisis & Priority Awareness API"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"
    
    # Server settings
    HOST: str = os.getenv("API_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("API_PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "true").lower() in ("true", "1", "yes")

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "*",
    ]

    # Database & Storage
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./soc_analisis.db")
    ELASTICSEARCH_URL: str = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")

    # Ollama LLM
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3:latest")
    OLLAMA_ENABLED: bool = os.getenv("OLLAMA_ENABLED", "false").lower() in ("true", "1", "yes")


settings = Settings()
