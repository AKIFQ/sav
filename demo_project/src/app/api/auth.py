"""Authentication API endpoints."""

from datetime import datetime, timedelta
from typing import Optional
import jwt
from src.app.models import User, DatabaseManager
from src.app.config import config


class AuthenticationError(Exception):
    """Authentication related errors."""
    pass


class AuthService:
    """Authentication service."""
    
    def __init__(self):
        self.db = DatabaseManager()
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password."""
        user = self.db.get_user_by_username(username)
        if user and user.check_password(password):
            return user
        return None
    
    def generate_token(self, user: User) -> str:
        """Generate JWT token for authenticated user."""
        payload = {
            'user_id': user.id,
            'username': user.username,
            'exp': datetime.utcnow() + timedelta(hours=config.security.jwt_expiration_hours)
        }
        
        return jwt.encode(payload, config.security.secret_key, algorithm='HS256')
    
    def verify_token(self, token: str) -> Optional[dict]:
        """Verify JWT token and return payload."""
        try:
            payload = jwt.decode(token, config.security.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid token")
    
    def register_user(self, username: str, email: str, password: str) -> User:
        """Register a new user."""
        # Check if user already exists
        existing_user = self.db.get_user_by_username(username)
        if existing_user:
            raise AuthenticationError("Username already exists")
        
        # Validate password strength
        if len(password) < config.security.password_min_length:
            raise AuthenticationError(f"Password must be at least {config.security.password_min_length} characters")
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        user_id = self.db.create_user(user)
        user.id = user_id
        
        return user
