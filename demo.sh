#!/bin/bash
# Sav Shadow VCS Demo Script

set -e

echo "🚀 SAV SHADOW VCS DEMO"
echo "Setting up Sav Shadow VCS Demo Environment..."

# Clean up any existing demo
if [ -d "demo_project" ]; then
    echo "Cleaning up existing demo..."
    rm -rf demo_project
fi

# Create demo project
mkdir -p demo_project
cd demo_project

# Initialize Sav repository
echo ""
echo "Initializing Sav repository..."
sav init

echo ""
echo "Sav repository initialized in .sav/"

# Create project structure
echo ""
echo "Creating realistic project structure..."

# Main application package
mkdir -p src/app
cat > src/app/__init__.py << 'EOF'
"""
Main application package for Sav Demo Project.
"""

__version__ = "1.0.0"
__author__ = "Sav Demo Team"
EOF

# Database models
cat > src/app/models.py << 'EOF'
"""Database models for the Sav Demo application."""

from dataclasses import dataclass
from typing import Optional, List
from datetime import datetime
import sqlite3
import hashlib
import secrets


@dataclass
class User:
    """User model with authentication capabilities."""
    id: Optional[int] = None
    username: str = ""
    email: str = ""
    password_hash: str = ""
    created_at: Optional[datetime] = None
    is_active: bool = True
    
    def set_password(self, password: str) -> None:
        """Hash and set the user's password."""
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', 
                                          password.encode('utf-8'), 
                                          salt.encode('utf-8'), 
                                          100000)
        self.password_hash = salt + password_hash.hex()
    
    def check_password(self, password: str) -> bool:
        """Verify the user's password."""
        if not self.password_hash:
            return False
        
        salt = self.password_hash[:32]
        stored_hash = self.password_hash[32:]
        
        password_hash = hashlib.pbkdf2_hmac('sha256',
                                          password.encode('utf-8'),
                                          salt.encode('utf-8'),
                                          100000)
        return stored_hash == password_hash.hex()


@dataclass
class Task:
    """Task model for project management."""
    id: Optional[int] = None
    title: str = ""
    description: str = ""
    assignee_id: Optional[int] = None
    priority: str = "medium"  # low, medium, high, critical
    status: str = "todo"  # todo, in_progress, done, blocked
    created_at: Optional[datetime] = None
    due_date: Optional[datetime] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class DatabaseManager:
    """Database operations manager."""
    
    def __init__(self, db_path: str = "demo.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT,
                    assignee_id INTEGER,
                    priority TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'todo',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    due_date TIMESTAMP,
                    tags TEXT,
                    FOREIGN KEY (assignee_id) REFERENCES users (id)
                )
            ''')
            
            conn.commit()
    
    def create_user(self, user: User) -> int:
        """Create a new user and return the ID."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, is_active)
                VALUES (?, ?, ?, ?)
            ''', (user.username, user.email, user.password_hash, user.is_active))
            
            conn.commit()
            return cursor.lastrowid
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Retrieve a user by username."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM users WHERE username = ? AND is_active = TRUE
            ''', (username,))
            
            row = cursor.fetchone()
            if row:
                return User(
                    id=row['id'],
                    username=row['username'],
                    email=row['email'],
                    password_hash=row['password_hash'],
                    created_at=datetime.fromisoformat(row['created_at']),
                    is_active=bool(row['is_active'])
                )
            return None
    
    def create_task(self, task: Task) -> int:
        """Create a new task and return the ID."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO tasks (title, description, assignee_id, priority, status, due_date, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (task.title, task.description, task.assignee_id, 
                  task.priority, task.status, task.due_date, 
                  ','.join(task.tags) if task.tags else ''))
            
            conn.commit()
            return cursor.lastrowid
    
    def get_tasks_by_user(self, user_id: int) -> List[Task]:
        """Get all tasks assigned to a user."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM tasks WHERE assignee_id = ? ORDER BY created_at DESC
            ''', (user_id,))
            
            tasks = []
            for row in cursor.fetchall():
                task = Task(
                    id=row['id'],
                    title=row['title'],
                    description=row['description'],
                    assignee_id=row['assignee_id'],
                    priority=row['priority'],
                    status=row['status'],
                    created_at=datetime.fromisoformat(row['created_at']),
                    due_date=datetime.fromisoformat(row['due_date']) if row['due_date'] else None,
                    tags=row['tags'].split(',') if row['tags'] else []
                )
                tasks.append(task)
            
            return tasks
EOF

# Configuration settings
cat > src/app/config.py << 'EOF'
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
EOF

# Create README
cat > README.md << 'EOF'
# Sav Demo Project

A realistic web application demonstrating Sav Shadow VCS capabilities.

## Features

- User authentication and authorization
- Task management system
- RESTful API endpoints
- Database integration with SQLite
- Configuration management
- Comprehensive error handling
- Security best practices

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Initialize the database:
   ```bash
   python -m src.app.models
   ```

3. Run the application:
   ```bash
   python -m src.app.main
   ```

## API Endpoints

- `POST /api/auth/login` - User authentication
- `POST /api/auth/register` - User registration
- `GET /api/tasks` - List user tasks
- `POST /api/tasks` - Create new task
- `PUT /api/tasks/{id}` - Update task
- `DELETE /api/tasks/{id}` - Delete task

## Configuration

This project uses Sav Shadow VCS for secure code management.

Set environment variables in `.env` file for configuration.
EOF

# Create test file
mkdir -p tests
cat > tests/test_models.py << 'EOF'
"""Test suite for the Sav Demo application."""

import unittest
import tempfile
import os
from datetime import datetime
from src.app.models import User, Task, DatabaseManager


class TestUser(unittest.TestCase):
    """Test cases for User model."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.user = User(username="testuser", email="test@example.com")
    
    def test_set_password(self):
        """Test password hashing."""
        password = "secure_password123"
        self.user.set_password(password)
        
        self.assertIsNotNone(self.user.password_hash)
        self.assertNotEqual(self.user.password_hash, password)
        self.assertTrue(len(self.user.password_hash) > 50)
    
    def test_check_password(self):
        """Test password verification."""
        password = "secure_password123"
        self.user.set_password(password)
        
        self.assertTrue(self.user.check_password(password))
        self.assertFalse(self.user.check_password("wrong_password"))
    
    def test_check_password_empty_hash(self):
        """Test password check with empty hash."""
        self.assertFalse(self.user.check_password("any_password"))


class TestTask(unittest.TestCase):
    """Test cases for Task model."""
    
    def test_task_creation(self):
        """Test task creation with defaults."""
        task = Task(title="Test Task", description="Test Description")
        
        self.assertEqual(task.title, "Test Task")
        self.assertEqual(task.description, "Test Description")
        self.assertEqual(task.priority, "medium")
        self.assertEqual(task.status, "todo")
        self.assertIsInstance(task.tags, list)
        self.assertEqual(len(task.tags), 0)
    
    def test_task_with_tags(self):
        """Test task creation with tags."""
        task = Task(title="Test Task", tags=["urgent", "backend"])
        
        self.assertEqual(len(task.tags), 2)
        self.assertIn("urgent", task.tags)
        self.assertIn("backend", task.tags)


class TestDatabaseManager(unittest.TestCase):
    """Test cases for DatabaseManager."""
    
    def setUp(self):
        """Set up test database."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        self.db_manager = DatabaseManager(self.temp_db.name)
    
    def tearDown(self):
        """Clean up test database."""
        os.unlink(self.temp_db.name)
    
    def test_create_user(self):
        """Test user creation."""
        user = User(username="testuser", email="test@example.com")
        user.set_password("password123")
        
        user_id = self.db_manager.create_user(user)
        self.assertIsInstance(user_id, int)
        self.assertGreater(user_id, 0)
    
    def test_get_user_by_username(self):
        """Test user retrieval."""
        user = User(username="testuser", email="test@example.com")
        user.set_password("password123")
        
        user_id = self.db_manager.create_user(user)
        retrieved_user = self.db_manager.get_user_by_username("testuser")
        
        self.assertIsNotNone(retrieved_user)
        self.assertEqual(retrieved_user.username, "testuser")
        self.assertEqual(retrieved_user.email, "test@example.com")
        self.assertEqual(retrieved_user.id, user_id)
    
    def test_create_task(self):
        """Test task creation."""
        # Create a user first
        user = User(username="testuser", email="test@example.com")
        user.set_password("password123")
        user_id = self.db_manager.create_user(user)
        
        # Create a task
        task = Task(
            title="Test Task",
            description="Test Description",
            assignee_id=user_id,
            priority="high",
            tags=["test", "demo"]
        )
        
        task_id = self.db_manager.create_task(task)
        self.assertIsInstance(task_id, int)
        self.assertGreater(task_id, 0)
    
    def test_get_tasks_by_user(self):
        """Test task retrieval by user."""
        # Create a user
        user = User(username="testuser", email="test@example.com")
        user.set_password("password123")
        user_id = self.db_manager.create_user(user)
        
        # Create tasks
        task1 = Task(title="Task 1", assignee_id=user_id)
        task2 = Task(title="Task 2", assignee_id=user_id)
        
        self.db_manager.create_task(task1)
        self.db_manager.create_task(task2)
        
        # Retrieve tasks
        tasks = self.db_manager.get_tasks_by_user(user_id)
        
        self.assertEqual(len(tasks), 2)
        self.assertEqual(tasks[0].title, "Task 2")  # Most recent first
        self.assertEqual(tasks[1].title, "Task 1")


if __name__ == '__main__':
    unittest.main()
EOF

echo ""
echo "Starting Sav Demo Commands..."

# Create first commit
echo ""
echo "📝 Creating first commit with project structure..."
sav commit -m "Initial project structure with models and config" src/app/__init__.py src/app/models.py src/app/config.py README.md tests/test_models.py

# Show status
echo ""
echo "📊 Current repository status:"
sav status --all

# Create additional files to demonstrate more commits
echo ""
echo "📝 Adding API endpoints..."

mkdir -p src/app/api
cat > src/app/api/__init__.py << 'EOF'
"""API package for the Sav Demo application."""
EOF

cat > src/app/api/auth.py << 'EOF'
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
EOF

# Commit API changes
echo ""
echo "📝 Committing API endpoints..."
sav commit -m "Add authentication API with JWT support" src/app/api/__init__.py src/app/api/auth.py

# Show repository status
echo ""
echo "📊 Repository status after API commit:"
sav status --all

# Create a high-risk file to demonstrate policy enforcement
echo ""
echo "🔒 Creating a potentially risky file..."

cat > src/app/secrets.py << 'EOF'
"""
WARNING: This file contains sensitive configuration.
This is a demo file to show Sav's risk assessment capabilities.
"""

# Database credentials (this would trigger security warnings)
DATABASE_URL = "postgresql://admin:super_secret_password@localhost/production_db"

# API keys (high risk patterns)
STRIPE_SECRET_KEY = "sk_live_51H7jF2SIoR89ruTYDiPiKQhPiJDmfzqsMzfUVokw"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  # Weak password

# Encryption keys
ENCRYPTION_KEY = "YourSecretEncryptionKey123"
JWT_SECRET = "super-secret-jwt-key-do-not-share"

# External service URLs
PAYMENT_WEBHOOK_URL = "https://api.example.com/webhook/payments"
NOTIFICATION_SERVICE_URL = "https://notifications.internal.company.com"

# Feature flags
ENABLE_DEBUG_MODE = True
BYPASS_AUTHENTICATION = False
ALLOW_ADMIN_BYPASS = True
EOF

# Commit the risky file
echo ""
echo "📝 Committing potentially risky file..."
sav commit -m "Add secrets configuration (DEMO - shows risk assessment)" src/app/secrets.py

# Show final status
echo ""
echo "📊 Final repository status:"
sav status --all

echo ""
echo "🎯 DEMO COMPLETE!"
echo ""
echo "This demo showed:"
echo "  ✅ Repository initialization with 'sav init'"
echo "  ✅ Multiple commits with realistic code"
echo "  ✅ Risk assessment and policy evaluation"
echo "  ✅ Repository status tracking"
echo ""
echo "Key Sav Shadow VCS features demonstrated:"
echo "  🔍 Automatic risk scoring based on file content"
echo "  🛡️  Policy-based commit approval workflow"
echo "  📋 Comprehensive audit trail"
echo "  🔒 Isolation of changes until human approval"
echo ""
echo "Next steps:"
echo "  📝 Review commits: sav review <commit-id>"
echo "  ✅ Approve safe commits: sav approve <commit-id>"
echo "  ❌ Reject risky commits: sav reject <commit-id>"
echo "  📊 Check status: sav status --all"
echo ""
echo "The risky secrets file will require manual review before approval!" 