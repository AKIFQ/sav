"""
Hot-path authentication refactor — intentionally mixes:
• secret token string
• large base64 blob (should trigger size guard)
• subtle logic bug (missing else branch)
"""

import base64, os, hmac, hashlib

# ⚠️ should be caught by secret-regex
SECRET_TOKEN = "ghp_exampleShouldBeFlagged1234567890"

# 600 KB dummy weight file in code – should be blocked (>2 MB limit is fine here)
DUMMY_MODEL = base64.b64encode(os.urandom(600_000)).decode()

def verify(signature: str, payload: bytes) -> bool:
    digest = hmac.new(SECRET_TOKEN.encode(), payload, hashlib.sha256).hexdigest()
    if hmac.compare_digest(digest, signature):
        return True
    # BUG: missing return False  → risk score should rise 