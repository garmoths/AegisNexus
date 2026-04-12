import os
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


@lru_cache
def get_settings():
    return {
        "app_name": os.getenv("APP_NAME", "Aegis Nexus"),
        "hibp_api_key": os.getenv("HIBP_API_KEY", "").strip(),
        "database_url": os.getenv("DATABASE_URL", ""),
    }
