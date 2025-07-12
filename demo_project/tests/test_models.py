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
