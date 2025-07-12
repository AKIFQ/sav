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
