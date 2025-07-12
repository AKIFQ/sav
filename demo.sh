#!/bin/bash

# Zed Shadow VCS Demo Script
# Simplified version for sequential execution with 1-2 screenshots

set -e

echo "Setting up Zed Shadow VCS Demo Environment..."
echo "=============================================="

# Create demo directory
DEMO_DIR="zed_demo_project"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

echo "Created demo directory: $DEMO_DIR"

# Initialize Zed repository
echo ""
echo "Initializing Zed repository..."
zed init

echo ""
echo "Zed repository initialized in .zed/"

# Create a realistic project structure
echo ""
echo "Creating realistic project structure..."

# Create directories
mkdir -p src/auth src/api src/utils docs tests

# Create main application files
cat > src/__init__.py << 'EOF'
"""
Main application package for Zed Demo Project.
A realistic web application with authentication and API endpoints.
"""
__version__ = "1.0.0"
EOF

cat > src/auth/__init__.py << 'EOF'
"""Authentication module for the web application."""
EOF

cat > src/auth/authenticator.py << 'EOF'
"""
Authentication service for user management.
Handles login, registration, and session management.
"""
import hashlib
import os
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

class Authenticator:
    """Main authentication service."""
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or os.environ.get('JWT_SECRET', 'default-secret-key')
        self.users = {}
    
    def hash_password(self, password: str) -> str:
        """Hash a password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register_user(self, username: str, password: str, email: str) -> bool:
        """Register a new user."""
        if username in self.users:
            return False
        
        self.users[username] = {
            'password_hash': self.hash_password(password),
            'email': email,
            'created_at': datetime.now(),
            'is_active': True
        }
        return True
    
    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate a user and return JWT token."""
        user = self.users.get(username)
        if not user or not user['is_active']:
            return None
        
        if user['password_hash'] == self.hash_password(password):
            return self._generate_token(username)
        return None
    
    def _generate_token(self, username: str) -> str:
        """Generate JWT token for user."""
        payload = {
            'username': username,
            'exp': datetime.utcnow() + timedelta(hours=24),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return payload."""
        try:
            return jwt.decode(token, self.secret_key, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            return None
EOF

cat > src/api/__init__.py << 'EOF'
"""API endpoints for the web application."""
EOF

cat > src/api/routes.py << 'EOF'
"""
API route definitions for the web application.
Handles HTTP endpoints and request processing.
"""
from flask import Flask, request, jsonify
from src.auth.authenticator import Authenticator
import logging

app = Flask(__name__)
auth_service = Authenticator()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'service': 'zed-demo-api'})

@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration endpoint."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    if not all([username, password, email]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if auth_service.register_user(username, password, email):
        return jsonify({'message': 'User registered successfully'}), 201
    else:
        return jsonify({'error': 'Username already exists'}), 409

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not all([username, password]):
        return jsonify({'error': 'Missing credentials'}), 400
    
    token = auth_service.authenticate(username, password)
    if token:
        return jsonify({'token': token, 'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/user/profile', methods=['GET'])
def get_profile():
    """Get user profile (requires authentication)."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid authorization header'}), 401
    
    token = auth_header.split(' ')[1]
    payload = auth_service.verify_token(token)
    
    if not payload:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    username = payload['username']
    user = auth_service.users.get(username)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'username': username,
        'email': user['email'],
        'created_at': user['created_at'].isoformat(),
        'is_active': user['is_active']
    }), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
EOF

cat > src/utils/__init__.py << 'EOF'
"""Utility functions for the application."""
EOF

cat > src/utils/helpers.py << 'EOF'
"""
Helper utilities for the web application.
Common functions used across the application.
"""
import re
import hashlib
from typing import List, Dict, Any
from datetime import datetime

def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def sanitize_input(text: str) -> str:
    """Sanitize user input to prevent XSS."""
    return text.replace('<', '&lt;').replace('>', '&gt;')

def generate_api_key() -> str:
    """Generate a secure API key."""
    timestamp = str(datetime.now().timestamp())
    random_data = f"{timestamp}-{hashlib.md5(timestamp.encode()).hexdigest()}"
    return hashlib.sha256(random_data.encode()).hexdigest()[:32]

def format_response(data: Any, success: bool = True, message: str = "") -> Dict[str, Any]:
    """Format API response consistently."""
    return {
        'success': success,
        'message': message,
        'data': data,
        'timestamp': datetime.now().isoformat()
    }

def log_activity(user: str, action: str, details: Dict[str, Any] = None):
    """Log user activity for audit purposes."""
    log_entry = {
        'user': user,
        'action': action,
        'timestamp': datetime.now().isoformat(),
        'details': details or {}
    }
    # In a real application, this would write to a proper logging system
    print(f"ACTIVITY_LOG: {log_entry}")
EOF

cat > config.py << 'EOF'
"""
Configuration settings for the Zed Demo application.
"""
import os
from typing import Dict, Any

class Config:
    """Application configuration."""
    
    # Database settings
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
    
    # Security settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    JWT_SECRET = os.environ.get('JWT_SECRET', 'jwt-secret-key-change-in-production')
    
    # API settings
    API_HOST = os.environ.get('API_HOST', '0.0.0.0')
    API_PORT = int(os.environ.get('API_PORT', 5000))
    DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'
    
    # Logging settings
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'app.log')
    
    # Rate limiting
    RATE_LIMIT_PER_MINUTE = int(os.environ.get('RATE_LIMIT_PER_MINUTE', 100))
    
    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'database_url': cls.DATABASE_URL,
            'api_host': cls.API_HOST,
            'api_port': cls.API_PORT,
            'debug': cls.DEBUG,
            'log_level': cls.LOG_LEVEL,
            'rate_limit': cls.RATE_LIMIT_PER_MINUTE
        }
EOF

cat > requirements.txt << 'EOF'
Flask==2.3.3
PyJWT==2.8.0
Werkzeug==2.3.7
python-dotenv==1.0.0
requests==2.31.0
pytest==7.4.2
black==23.9.1
flake8==6.1.0
EOF

cat > README.md << 'EOF'
# Zed Demo Project

A realistic web application demonstrating Zed Shadow VCS capabilities.

## Features

- User authentication with JWT tokens
- RESTful API endpoints
- Input validation and sanitization
- Activity logging
- Configuration management

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   python src/api/routes.py
   ```

3. Test endpoints:
   ```bash
   curl http://localhost:5000/api/health
   ```

## API Endpoints

- `GET /api/health` - Health check
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `GET /api/user/profile` - Get user profile (authenticated)

## Development

This project uses Zed Shadow VCS for secure code management.
EOF

cat > tests/__init__.py << 'EOF'
"""Test suite for the Zed Demo application."""
EOF

cat > tests/test_auth.py << 'EOF'
"""
Tests for authentication functionality.
"""
import pytest
from src.auth.authenticator import Authenticator

class TestAuthenticator:
    """Test cases for Authenticator class."""
    
    def test_register_user(self):
        """Test user registration."""
        auth = Authenticator()
        assert auth.register_user("testuser", "password123", "test@example.com")
        assert "testuser" in auth.users
    
    def test_duplicate_registration(self):
        """Test duplicate user registration."""
        auth = Authenticator()
        auth.register_user("testuser", "password123", "test@example.com")
        assert not auth.register_user("testuser", "password456", "test2@example.com")
    
    def test_authentication(self):
        """Test user authentication."""
        auth = Authenticator()
        auth.register_user("testuser", "password123", "test@example.com")
        token = auth.authenticate("testuser", "password123")
        assert token is not None
    
    def test_invalid_credentials(self):
        """Test authentication with invalid credentials."""
        auth = Authenticator()
        auth.register_user("testuser", "password123", "test@example.com")
        token = auth.authenticate("testuser", "wrongpassword")
        assert token is None
EOF

cat > tests/test_api.py << 'EOF'
"""
Tests for API endpoints.
"""
import pytest
from src.api.routes import app
from src.auth.authenticator import Authenticator

@pytest.fixture
def client():
    """Create test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

class TestAPIEndpoints:
    """Test cases for API endpoints."""
    
    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get('/api/health')
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'
    
    def test_register_user(self, client):
        """Test user registration endpoint."""
        data = {
            'username': 'testuser',
            'password': 'password123',
            'email': 'test@example.com'
        }
        response = client.post('/api/auth/register', json=data)
        assert response.status_code == 201
    
    def test_login_user(self, client):
        """Test user login endpoint."""
        # First register a user
        register_data = {
            'username': 'testuser',
            'password': 'password123',
            'email': 'test@example.com'
        }
        client.post('/api/auth/register', json=register_data)
        
        # Then try to login
        login_data = {
            'username': 'testuser',
            'password': 'password123'
        }
        response = client.post('/api/auth/login', json=login_data)
        assert response.status_code == 200
        data = response.get_json()
        assert 'token' in data
EOF

echo ""
echo "Created realistic project structure with:"
echo "   - Python web application with authentication"
echo "   - API endpoints and utilities"
echo "   - Configuration management"
echo "   - Test suite"
echo "   - Documentation"

echo ""
echo "Starting Zed Demo Commands..."
echo "============================="

# Create risky AI-generated code
echo ""
echo "Creating risky AI-generated code..."

cat > src/debug_utils.py << 'EOF'
import os
import logging

def debug_environment():
    """Debug function that logs sensitive environment variables."""
    logging.info(f"Database URL: {os.environ.get('DATABASE_URL')}")
    logging.info(f"Secret Key: {os.environ.get('SECRET_KEY')}")
    logging.info(f"JWT Secret: {os.environ.get('JWT_SECRET')}")
    return True

def get_all_env_vars():
    """Get all environment variables for debugging."""
    return dict(os.environ)

def log_user_credentials(username, password):
    """Log user credentials for debugging (DANGEROUS!)."""
    logging.warning(f"User login attempt: {username}")
    logging.warning(f"Password hash: {hash(password)}")
    return True
EOF

echo ""
echo "Demo setup complete!"
echo "==================="
echo ""
echo "Commands to run for screenshots:"
echo ""
echo "1. Safe documentation commit (auto-approved):"
echo "   zed commit -m \"Add project documentation\" README.md"
echo ""
echo "2. AI-generated risky code (requires review):"
echo "   zed commit -m \"AI: Add debug logging with sensitive data\" -a \"gpt-4\" src/debug_utils.py"
echo ""
echo "3. Status dashboard:"
echo "   zed status --all"
echo ""
echo "4. Review risky commit (replace [HASH] with actual commit hash):"
echo "   zed review [HASH]"
echo ""
echo "5. Reject risky commit:"
echo "   zed reject [HASH] -r \"Security concern: logging sensitive environment variables\""
echo ""
echo "6. Final status:"
echo "   zed status --all"
echo ""
echo "Take screenshots of commands 2 and 5 for the best demonstration."
echo ""
echo "To clean up: cd .. && rm -rf $DEMO_DIR" 