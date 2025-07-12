"""
Configuration settings for the Sav Demo application.
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class DatabaseConfig:
    """Database configuration."""
    host: str = "localhost"
    port: int = 5432
    database: str = "sav_demo"
    username: str = "demo_user"
    password: str = "demo_password"
    pool_size: int = 10
    max_overflow: int = 20
    
    @classmethod
    def from_env(cls) -> 'DatabaseConfig':
        """Load database config from environment variables."""
        return cls(
            host=os.getenv('DB_HOST', 'localhost'),
            port=int(os.getenv('DB_PORT', '5432')),
            database=os.getenv('DB_NAME', 'sav_demo'),
            username=os.getenv('DB_USER', 'demo_user'),
            password=os.getenv('DB_PASSWORD', 'demo_password'),
            pool_size=int(os.getenv('DB_POOL_SIZE', '10')),
            max_overflow=int(os.getenv('DB_MAX_OVERFLOW', '20'))
        )


@dataclass
class SecurityConfig:
    """Security configuration."""
    secret_key: str = "your-secret-key-here"
    jwt_expiration_hours: int = 24
    password_min_length: int = 8
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    
    @classmethod
    def from_env(cls) -> 'SecurityConfig':
        """Load security config from environment variables."""
        return cls(
            secret_key=os.getenv('SECRET_KEY', 'your-secret-key-here'),
            jwt_expiration_hours=int(os.getenv('JWT_EXPIRATION_HOURS', '24')),
            password_min_length=int(os.getenv('PASSWORD_MIN_LENGTH', '8')),
            max_login_attempts=int(os.getenv('MAX_LOGIN_ATTEMPTS', '5')),
            lockout_duration_minutes=int(os.getenv('LOCKOUT_DURATION_MINUTES', '15'))
        )


@dataclass
class AppConfig:
    """Main application configuration."""
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"
    database: DatabaseConfig = None
    security: SecurityConfig = None
    
    def __post_init__(self):
        if self.database is None:
            self.database = DatabaseConfig.from_env()
        if self.security is None:
            self.security = SecurityConfig.from_env()
    
    @classmethod
    def from_env(cls) -> 'AppConfig':
        """Load application config from environment variables."""
        return cls(
            debug=os.getenv('DEBUG', 'False').lower() == 'true',
            host=os.getenv('HOST', '0.0.0.0'),
            port=int(os.getenv('PORT', '8000')),
            log_level=os.getenv('LOG_LEVEL', 'INFO').upper(),
            database=DatabaseConfig.from_env(),
            security=SecurityConfig.from_env()
        )


# Global configuration instance
config = AppConfig.from_env()
