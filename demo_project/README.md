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
