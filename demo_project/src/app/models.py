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
