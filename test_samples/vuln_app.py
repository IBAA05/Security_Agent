# test_samples/vuln_app.py  — intentionally vulnerable, for testing only
import sqlite3
import hashlib

# Hardcoded credential — should be caught by Gitleaks and Semgrep
API_KEY = "sk-1234567890abcdef1234567890abcdef"
DB_PASSWORD = "supersecret123"

def get_user(username):
    conn = sqlite3.connect("users.db")
    # SQL injection — should be caught by Semgrep
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return conn.execute(query).fetchall()

def hash_password(password):
    # Weak hash — should be caught by Semgrep
    return hashlib.md5(password.encode()).hexdigest()
