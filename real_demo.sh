#!/bin/bash
# Real Sav Demo with Ollama Integration

set -e

echo "🚀 REAL SAV DEMO WITH OLLAMA INTEGRATION"
echo "Setting up Real Sav Demo with Ollama Integration..."

# Clean up any existing demo
if [ -d "real_demo_project" ]; then
    echo "Cleaning up existing demo..."
    rm -rf real_demo_project
fi

# Create demo project
mkdir -p real_demo_project
cd real_demo_project

# Initialize Sav repository
echo ""
echo "Initializing Sav repository..."
sav init

echo ""
echo "Sav repository initialized in .sav/"

# Create complex project structure
echo ""
echo "Creating complex project structure..."

# Create directories
mkdir -p src/{auth,api,utils,database,services,models} docs/{api,deployment} tests/{unit,integration} scripts config

# Create complex main application files
cat > src/__init__.py << 'EOF'
"""
Main application package for Zed Real Demo Project.
A complex microservices architecture with authentication, API gateway, and database layers.
"""
__version__ = "2.1.0"
__author__ = "Zed Demo Team"
__license__ = "MIT"

import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Application configuration
APP_CONFIG = {
    'debug': True,
    'host': '0.0.0.0',
    'port': 8000,
    'database_url': 'postgresql://user:pass@localhost:5432/zed_demo',
    'redis_url': 'redis://localhost:6379',
    'jwt_secret': 'your-super-secret-jwt-key-change-in-production',
    'api_rate_limit': 100,
    'session_timeout': 3600,
    'max_file_size': 10485760,  # 10MB
    'allowed_file_types': ['.py', '.js', '.ts', '.json', '.yaml', '.md'],
    'cors_origins': ['http://localhost:3000', 'https://zed-demo.com'],
    'log_level': 'INFO',
    'environment': 'development'
}

# Initialize application paths
BASE_DIR = Path(__file__).parent.parent
STATIC_DIR = BASE_DIR / 'static'
UPLOAD_DIR = BASE_DIR / 'uploads'
TEMP_DIR = BASE_DIR / 'temp'

# Create necessary directories
for directory in [STATIC_DIR, UPLOAD_DIR, TEMP_DIR]:
    directory.mkdir(exist_ok=True)

def get_config(key, default=None):
    """Get configuration value."""
    return APP_CONFIG.get(key, default)

def set_config(key, value):
    """Set configuration value."""
    APP_CONFIG[key] = value

def validate_config():
    """Validate application configuration."""
    required_keys = ['database_url', 'jwt_secret', 'host', 'port']
    missing_keys = [key for key in required_keys if not APP_CONFIG.get(key)]
    
    if missing_keys:
        raise ValueError(f"Missing required configuration keys: {missing_keys}")
    
    logger.info("Configuration validation passed")

# Validate configuration on import
try:
    validate_config()
except Exception as e:
    logger.error(f"Configuration validation failed: {e}")
    raise
EOF

cat > src/auth/__init__.py << 'EOF'
"""Authentication and authorization module for the Zed Demo application."""
EOF

cat > src/auth/authenticator.py << 'EOF'
"""
Advanced authentication service with JWT tokens, role-based access control,
and multi-factor authentication support.
"""
import hashlib
import os
import jwt
import bcrypt
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum

class UserRole(Enum):
    """User roles enumeration."""
    ADMIN = "admin"
    DEVELOPER = "developer"
    REVIEWER = "reviewer"
    VIEWER = "viewer"
    GUEST = "guest"

class AuthStatus(Enum):
    """Authentication status enumeration."""
    SUCCESS = "success"
    FAILED = "failed"
    LOCKED = "locked"
    EXPIRED = "expired"
    REQUIRES_MFA = "requires_mfa"

@dataclass
class User:
    """User data class."""
    id: str
    username: str
    email: str
    password_hash: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    failed_attempts: int
    locked_until: Optional[datetime]
    mfa_enabled: bool
    mfa_secret: Optional[str]
    api_keys: List[str]

class Authenticator:
    """Advanced authentication service."""
    
    def __init__(self, secret_key: str = None, bcrypt_rounds: int = 12):
        self.secret_key = secret_key or os.environ.get('JWT_SECRET', 'default-secret-key')
        self.bcrypt_rounds = bcrypt_rounds
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Dict] = {}
        self.rate_limits: Dict[str, List[float]] = {}
        self.max_failed_attempts = 5
        self.lockout_duration = 300  # 5 minutes
        self.session_timeout = 3600  # 1 hour
        
        # Initialize with some demo users
        self._create_demo_users()
    
    def _create_demo_users(self):
        """Create demo users for testing."""
        admin_password = self._hash_password("admin123")
        dev_password = self._hash_password("dev123")
        
        self.users["admin"] = User(
            id="admin-001",
            username="admin",
            email="admin@zed-demo.com",
            password_hash=admin_password,
            role=UserRole.ADMIN,
            is_active=True,
            created_at=datetime.now(),
            last_login=None,
            failed_attempts=0,
            locked_until=None,
            mfa_enabled=False,
            mfa_secret=None,
            api_keys=[]
        )
        
        self.users["developer"] = User(
            id="dev-001",
            username="developer",
            email="dev@zed-demo.com",
            password_hash=dev_password,
            role=UserRole.DEVELOPER,
            is_active=True,
            created_at=datetime.now(),
            last_login=None,
            failed_attempts=0,
            locked_until=None,
            mfa_enabled=False,
            mfa_secret=None,
            api_keys=[]
        )
    
    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt."""
        salt = bcrypt.gensalt(rounds=self.bcrypt_rounds)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash."""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    def _generate_token(self, user: User, expires_in: int = 3600) -> str:
        """Generate JWT token for user."""
        payload = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role.value,
            'exp': datetime.utcnow() + timedelta(seconds=expires_in),
            'iat': datetime.utcnow(),
            'jti': secrets.token_urlsafe(32)
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def _is_rate_limited(self, username: str) -> bool:
        """Check if user is rate limited."""
        now = time.time()
        if username not in self.rate_limits:
            self.rate_limits[username] = []
        
        # Remove old attempts
        self.rate_limits[username] = [t for t in self.rate_limits[username] if now - t < 60]
        
        # Check if too many attempts
        if len(self.rate_limits[username]) >= 10:
            return True
        
        self.rate_limits[username].append(now)
        return False
    
    def register_user(self, username: str, password: str, email: str, role: UserRole = UserRole.DEVELOPER) -> bool:
        """Register a new user."""
        if username in self.users:
            return False
        
        if self._is_rate_limited(username):
            return False
        
        user_id = f"{role.value}-{secrets.token_urlsafe(8)}"
        password_hash = self._hash_password(password)
        
        self.users[username] = User(
            id=user_id,
            username=username,
            email=email,
            password_hash=password_hash,
            role=role,
            is_active=True,
            created_at=datetime.now(),
            last_login=None,
            failed_attempts=0,
            locked_until=None,
            mfa_enabled=False,
            mfa_secret=None,
            api_keys=[]
        )
        return True
    
    def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate a user and return result."""
        if self._is_rate_limited(username):
            return {
                'status': AuthStatus.FAILED,
                'message': 'Rate limited. Too many attempts.',
                'token': None
            }
        
        user = self.users.get(username)
        if not user or not user.is_active:
            return {
                'status': AuthStatus.FAILED,
                'message': 'Invalid credentials or inactive account.',
                'token': None
            }
        
        # Check if account is locked
        if user.locked_until and datetime.now() < user.locked_until:
            return {
                'status': AuthStatus.LOCKED,
                'message': f'Account locked until {user.locked_until}.',
                'token': None
            }
        
        # Verify password
        if not self._verify_password(password, user.password_hash):
            user.failed_attempts += 1
            
            # Lock account if too many failed attempts
            if user.failed_attempts >= self.max_failed_attempts:
                user.locked_until = datetime.now() + timedelta(seconds=self.lockout_duration)
                return {
                    'status': AuthStatus.LOCKED,
                    'message': f'Account locked for {self.lockout_duration} seconds due to too many failed attempts.',
                    'token': None
                }
            
            return {
                'status': AuthStatus.FAILED,
                'message': f'Invalid credentials. {self.max_failed_attempts - user.failed_attempts} attempts remaining.',
                'token': None
            }
        
        # Reset failed attempts on successful login
        user.failed_attempts = 0
        user.locked_until = None
        user.last_login = datetime.now()
        
        # Generate token
        token = self._generate_token(user)
        
        # Check if MFA is required
        if user.mfa_enabled:
            return {
                'status': AuthStatus.REQUIRES_MFA,
                'message': 'Multi-factor authentication required.',
                'token': None,
                'mfa_required': True
            }
        
        return {
            'status': AuthStatus.SUCCESS,
            'message': 'Authentication successful.',
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role.value
            }
        }
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return payload."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            
            # Check if user still exists and is active
            username = payload.get('username')
            user = self.users.get(username)
            
            if not user or not user.is_active:
                return None
            
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def has_permission(self, user_role: str, required_role: UserRole) -> bool:
        """Check if user has required role permission."""
        role_hierarchy = {
            UserRole.ADMIN: 5,
            UserRole.DEVELOPER: 4,
            UserRole.REVIEWER: 3,
            UserRole.VIEWER: 2,
            UserRole.GUEST: 1
        }
        
        user_level = role_hierarchy.get(UserRole(user_role), 0)
        required_level = role_hierarchy.get(required_role, 0)
        
        return user_level >= required_level
    
    def generate_api_key(self, username: str) -> Optional[str]:
        """Generate API key for user."""
        user = self.users.get(username)
        if not user:
            return None
        
        api_key = f"zed_{secrets.token_urlsafe(32)}"
        user.api_keys.append(api_key)
        return api_key
    
    def revoke_api_key(self, username: str, api_key: str) -> bool:
        """Revoke API key for user."""
        user = self.users.get(username)
        if not user or api_key not in user.api_keys:
            return False
        
        user.api_keys.remove(api_key)
        return True
EOF

cat > src/api/__init__.py << 'EOF'
"""API endpoints and routing for the Zed Demo application."""
EOF

cat > src/api/routes.py << 'EOF'
"""
Advanced API route definitions with authentication, rate limiting,
and comprehensive error handling.
"""
from flask import Flask, request, jsonify, g, abort
from flask_cors import CORS
from src.auth.authenticator import Authenticator, UserRole, AuthStatus
import logging
import time
import functools
from datetime import datetime
from typing import Dict, Any, Optional

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize services
auth_service = Authenticator()

# Rate limiting storage
rate_limit_storage: Dict[str, list] = {}

def rate_limit(max_requests: int = 100, window: int = 60):
    """Rate limiting decorator."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            now = time.time()
            
            if client_ip not in rate_limit_storage:
                rate_limit_storage[client_ip] = []
            
            # Remove old requests
            rate_limit_storage[client_ip] = [
                req_time for req_time in rate_limit_storage[client_ip]
                if now - req_time < window
            ]
            
            # Check if limit exceeded
            if len(rate_limit_storage[client_ip]) >= max_requests:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'Too many requests. Limit: {max_requests} per {window} seconds'
                }), 429
            
            # Add current request
            rate_limit_storage[client_ip].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_auth(required_role: UserRole = UserRole.GUEST):
    """Authentication decorator."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                abort(401, description='Missing or invalid authorization header')
            
            token = auth_header.split(' ')[1]
            payload = auth_service.verify_token(token)
            
            if not payload:
                abort(401, description='Invalid or expired token')
            
            # Check role permissions
            if not auth_service.has_permission(payload['role'], required_role):
                abort(403, description='Insufficient permissions')
            
            # Add user info to request context
            g.user = payload
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.errorhandler(400)
def bad_request(error):
    """Handle bad request errors."""
    return jsonify({
        'error': 'Bad Request',
        'message': str(error.description),
        'timestamp': datetime.now().isoformat()
    }), 400

@app.errorhandler(401)
def unauthorized(error):
    """Handle unauthorized errors."""
    return jsonify({
        'error': 'Unauthorized',
        'message': str(error.description),
        'timestamp': datetime.now().isoformat()
    }), 401

@app.errorhandler(403)
def forbidden(error):
    """Handle forbidden errors."""
    return jsonify({
        'error': 'Forbidden',
        'message': str(error.description),
        'timestamp': datetime.now().isoformat()
    }), 403

@app.errorhandler(404)
def not_found(error):
    """Handle not found errors."""
    return jsonify({
        'error': 'Not Found',
        'message': 'The requested resource was not found',
        'timestamp': datetime.now().isoformat()
    }), 404

@app.errorhandler(429)
def too_many_requests(error):
    """Handle rate limit errors."""
    return jsonify({
        'error': 'Too Many Requests',
        'message': 'Rate limit exceeded',
        'timestamp': datetime.now().isoformat()
    }), 429

@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors."""
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred',
        'timestamp': datetime.now().isoformat()
    }), 500

@app.route('/api/health', methods=['GET'])
@rate_limit(max_requests=1000, window=60)
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'zed-demo-api',
        'version': '2.1.0',
        'timestamp': datetime.now().isoformat(),
        'uptime': time.time(),
        'environment': 'development'
    })

@app.route('/api/auth/register', methods=['POST'])
@rate_limit(max_requests=10, window=300)
def register():
    """User registration endpoint."""
    data = request.get_json()
    
    if not data:
        abort(400, description='Request body is required')
    
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role', 'developer')
    
    if not all([username, password, email]):
        abort(400, description='Missing required fields: username, password, email')
    
    # Validate role
    try:
        user_role = UserRole(role)
    except ValueError:
        abort(400, description=f'Invalid role. Allowed roles: {[r.value for r in UserRole]}')
    
    # Validate password strength
    if len(password) < 8:
        abort(400, description='Password must be at least 8 characters long')
    
    if auth_service.register_user(username, password, email, user_role):
        return jsonify({
            'message': 'User registered successfully',
            'username': username,
            'role': role
        }), 201
    else:
        abort(409, description='Username already exists or rate limited')

@app.route('/api/auth/login', methods=['POST'])
@rate_limit(max_requests=5, window=300)
def login():
    """User login endpoint."""
    data = request.get_json()
    
    if not data:
        abort(400, description='Request body is required')
    
    username = data.get('username')
    password = data.get('password')
    
    if not all([username, password]):
        abort(400, description='Missing required fields: username, password')
    
    result = auth_service.authenticate(username, password)
    
    if result['status'] == AuthStatus.SUCCESS:
        return jsonify({
            'message': 'Login successful',
            'token': result['token'],
            'user': result['user']
        }), 200
    elif result['status'] == AuthStatus.REQUIRES_MFA:
        return jsonify({
            'message': 'Multi-factor authentication required',
            'mfa_required': True
        }), 200
    else:
        return jsonify({
            'error': 'Authentication failed',
            'message': result['message']
        }), 401

@app.route('/api/user/profile', methods=['GET'])
@require_auth(UserRole.GUEST)
def get_profile():
    """Get user profile (requires authentication)."""
    username = g.user['username']
    
    # In a real application, you would fetch user data from database
    user_data = {
        'id': g.user['user_id'],
        'username': username,
        'email': f'{username}@zed-demo.com',
        'role': g.user['role'],
        'created_at': datetime.now().isoformat(),
        'last_login': datetime.now().isoformat(),
        'is_active': True
    }
    
    return jsonify(user_data), 200

@app.route('/api/user/api-keys', methods=['GET'])
@require_auth(UserRole.DEVELOPER)
def get_api_keys():
    """Get user's API keys."""
    username = g.user['username']
    api_keys = auth_service.users.get(username, {}).get('api_keys', [])
    
    return jsonify({
        'api_keys': api_keys,
        'count': len(api_keys)
    }), 200

@app.route('/api/user/api-keys', methods=['POST'])
@require_auth(UserRole.DEVELOPER)
def generate_api_key():
    """Generate new API key for user."""
    username = g.user['username']
    api_key = auth_service.generate_api_key(username)
    
    if api_key:
        return jsonify({
            'message': 'API key generated successfully',
            'api_key': api_key
        }), 201
    else:
        abort(400, description='Failed to generate API key')

@app.route('/api/admin/users', methods=['GET'])
@require_auth(UserRole.ADMIN)
def list_users():
    """List all users (admin only)."""
    users = []
    for username, user in auth_service.users.items():
        users.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role.value,
            'is_active': user.is_active,
            'created_at': user.created_at.isoformat(),
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'failed_attempts': user.failed_attempts,
            'locked_until': user.locked_until.isoformat() if user.locked_until else None
        })
    
    return jsonify({
        'users': users,
        'count': len(users)
    }), 200

@app.route('/api/admin/users/<username>/lock', methods=['POST'])
@require_auth(UserRole.ADMIN)
def lock_user(username):
    """Lock/unlock user account (admin only)."""
    user = auth_service.users.get(username)
    if not user:
        abort(404, description='User not found')
    
    data = request.get_json() or {}
    lock = data.get('lock', True)
    
    if lock:
        user.locked_until = datetime.now() + timedelta(hours=24)
        message = f'User {username} locked for 24 hours'
    else:
        user.locked_until = None
        user.failed_attempts = 0
        message = f'User {username} unlocked'
    
    return jsonify({
        'message': message,
        'username': username,
        'locked': lock
    }), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
EOF

cat > requirements.txt << 'EOF'
Flask==2.3.3
Flask-CORS==4.0.0
PyJWT==2.8.0
bcrypt==4.0.1
Werkzeug==2.3.7
python-dotenv==1.0.0
requests==2.31.0
pytest==7.4.2
black==23.9.1
flake8==6.1.0
psycopg2-binary==2.9.7
redis==4.6.0
celery==5.3.1
gunicorn==21.2.0
EOF

cat > README.md << 'EOF'
# Zed Real Demo Project

A complex microservices application demonstrating Zed Shadow VCS capabilities with real AI integration.

## Architecture

- **Authentication Service**: JWT-based auth with role-based access control
- **API Gateway**: Rate-limited REST API with comprehensive error handling
- **Database Layer**: PostgreSQL with Redis caching
- **Background Tasks**: Celery for async processing
- **Security**: Multi-factor authentication, API keys, rate limiting

## Features

- Advanced user authentication with bcrypt password hashing
- Role-based access control (Admin, Developer, Reviewer, Viewer, Guest)
- Rate limiting and account lockout protection
- Multi-factor authentication support
- API key management
- Comprehensive error handling and logging
- CORS support for frontend integration
- Health monitoring and metrics

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set environment variables:
   ```bash
   export DATABASE_URL="postgresql://user:pass@localhost:5432/zed_demo"
   export REDIS_URL="redis://localhost:6379"
   export JWT_SECRET="your-super-secret-jwt-key"
   ```

3. Run the application:
   ```bash
   python src/api/routes.py
   ```

4. Test endpoints:
   ```bash
   curl http://localhost:8000/api/health
   ```

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login

### User Management
- `GET /api/user/profile` - Get user profile (authenticated)
- `GET /api/user/api-keys` - Get user's API keys
- `POST /api/user/api-keys` - Generate new API key

### Admin (Admin role required)
- `GET /api/admin/users` - List all users
- `POST /api/admin/users/{username}/lock` - Lock/unlock user

## Development

This project uses Zed Shadow VCS for secure code management and AI agent integration.

## Security

- Passwords hashed with bcrypt (12 rounds)
- JWT tokens with configurable expiration
- Rate limiting on sensitive endpoints
- Account lockout after failed attempts
- Role-based access control
- API key authentication
- CORS protection
EOF

echo ""
echo "Created complex project structure with:"
echo "   - Advanced authentication system with bcrypt"
echo "   - Role-based access control"
echo "   - Rate limiting and security features"
echo "   - Comprehensive API with error handling"
echo "   - Real-world complexity for AI testing"

echo ""
echo "Setting up Ollama integration..."
echo "==============================="

# Check if Ollama is available
if command -v ollama &> /dev/null; then
    echo "Ollama found. Available models:"
    ollama list
    echo ""
    echo "To generate real AI code, run:"
    echo "ollama run codellama 'Create a Python function that logs sensitive environment variables for debugging'"
    echo ""
    echo "Then commit the AI-generated code to Sav:"
    echo "sav commit -m \"AI: Add debug logging function\" -a \"codellama\" [generated_file.py]"
else
    echo "Ollama not found. Install from https://ollama.ai"
    echo ""
    echo "After installation, run:"
    echo "ollama pull codellama"
    echo "ollama run codellama 'Create a Python function that logs sensitive environment variables'"
fi

echo ""
echo "Demo setup complete!"
echo "==================="
echo ""
echo "Commands to run for real AI integration:"
echo ""
echo "1. Generate AI code with Ollama:"
echo "   ollama run codellama 'Create a Python function that logs sensitive environment variables for debugging' > ai_generated_debug.py"
echo ""
echo "2. Commit AI-generated code to Sav:"
echo "   sav commit -m \"AI: Add debug logging function\" -a \"codellama\" ai_generated_debug.py"
echo ""
echo "3. Check status:"
echo "   sav status --all"
echo ""
echo "4. Review AI-generated code:"
echo "   sav review [COMMIT_HASH]"
echo ""
echo "5. Reject if risky:"
echo "   sav reject [COMMIT_HASH] -r \"Security concern: AI generated code logs sensitive data\""
echo ""
echo "This will demonstrate real AI code generation and Sav's risk assessment."
echo ""
echo "To clean up: cd .. && rm -rf $DEMO_DIR" 