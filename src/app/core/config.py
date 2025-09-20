"""
Configuration management for the application.
This file loads environment variables and provides a centralized config object.
"""

from pydantic_settings import BaseSettings
from pydantic import EmailStr
from typing import Optional
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Pydantic automatically validates types and provides defaults.
    """
    
    # MongoDB Atlas Configuration
    mongodb_url: str = os.getenv("MONGODB_URL", "mongodb://localhost:27017/buildvilds_db")
    
    # JWT Configuration
    jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "fallback-secret-key")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    jwt_access_token_expire_minutes: int = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 15))
    jwt_refresh_token_expire_days: int = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 30))
    
    # Email Configuration  
    smtp_host: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port: int = int(os.getenv("SMTP_PORT", 587))
    smtp_username: str = os.getenv("SMTP_USERNAME", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    from_email: EmailStr = os.getenv("FROM_EMAIL", "noreply@example.com")
    from_name: str = os.getenv("FROM_NAME", "Buildvilds")
    
    # Redis Configuration
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # Application Configuration
    app_name: str = os.getenv("APP_NAME", "Buildvilds")
    api_url: str = os.getenv("API_URL", "http://localhost:8000")
    
    # Security Configuration
    bcrypt_rounds: int = int(os.getenv("BCRYPT_ROUNDS", 12))
    otp_expire_minutes: int = int(os.getenv("OTP_EXPIRE_MINUTES", 10))
    max_login_attempts: int = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", 60))

# Create global settings instance that can be imported throughout the app
settings = Settings()