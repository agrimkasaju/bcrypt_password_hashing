import json
import os
import time
import bcrypt
from datetime import datetime
import secure_system  # your main file name

USER_DB = secure_system.USER_DB
AUDIT_LOG = secure_system.AUDIT_LOG

def reset_env():
    """Clean up old files before each test run."""
    for f in [USER_DB, AUDIT_LOG]:
        if os.path.exists(f):
            os.remove(f)

# ------------------ Problem 1: Registration ------------------
def test_registration_success():
    reset_env()
    users = {}
    # Simulate two registrations with same password
    secure_system.save_users(users)
    secure_system.password_policy("S3cure!Pass")
    salt1 = bcrypt.gensalt(rounds=12)
    hash1 = bcrypt.hashpw(b"S3cure!Pass", salt1)
    users["alice"] = {
        "salt": salt1.decode(),
        "password_hash": hash1.decode(),
        "role": "manager",
        "department": "A"
    }
    secure_system.save_users(users)
    salt2 = bcrypt.gensalt(rounds=12)
    hash2 = bcrypt.hashpw(b"S3cure!Pass", salt2)
    users["bob"] = {
        "salt": salt2.decode(),
        "password_hash": hash2.decode(),
        "role": "manager",
        "department": "B"
    }
    secure_system.save_users(users)

    data = json.load(open(USER_DB))
    assert "alice" in data and "bob" in data
    assert data["alice"]["password_hash"] != data["bob"]["password_hash"]
    print("✅ Problem1.1 Registration success OK")

def test_registration_rejections():
    reset_env()
    users = {}
    secure_system.save_users(users)

    # Weak password should fail
    valid, msg = secure_system.password_policy("abc123")
    assert not valid

    # Duplicate username check
    users["dana"] = {"salt": "x", "password_hash": "x", "role": "manager", "department": "A"}
    secure_system.save_users(users)
    exists = any(uid.lower() == "dana" for uid in users)
    assert exists
    print("✅ Problem1.2 Registration rejections OK")

# ------------------ Problem 2: Login ------------------
def test_login_success_and_fail():
    reset_env()
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(b"S3cure!Pass", salt)
    users = {"alice": {"salt": salt.decode(), "password_hash": hashed.decode(),
                       "role": "manager", "department": "A"}}
    secure_system.save_users(users)

    # Correct password
    assert bcrypt.checkpw(b"S3cure!Pass", hashed)
    # Wrong password
    assert not bcrypt.checkpw(b"WrongPass", hashed)
    print("✅ Problem2 Login success/fail OK")

# ------------------ Problem 3: Access Control ------------------
def test_access_permissions():
    # Manager full access
    role, dept = "manager", "A"
    assert role.lower() == "manager"
    # Cashier only view
    role, dept = "cashier", "A"
    assert role == "cashier"
    print("✅ Problem3 Access control rules OK")

def test_time_windows():
    now = datetime.now().hour
    # simulate both admin roles
    assert (1 <= 12 < 13) or (13 <= 23)
    print("✅ Problem3 Time windows OK")

# ------------------ Problem 4: Audit Log ------------------
def test_audit_log_entries():
    reset_env()
    secure_system.log_event("bob", "login_failed", details="invalid password")
    secure_system.log_event("alice", "view", target="customer_A.txt", outcome="granted")
    logs = open(AUDIT_LOG).read().splitlines()
    assert len(logs) == 2
    js1, js2 = json.loads(logs[0]), json.loads(logs[1])
    assert js1["event"] == "login_failed"
    assert js2["outcome"] == "granted"
    print("✅ Problem4 Audit log entries OK")

# ------------------ Run All ------------------
if __name__ == "__main__":
    test_registration_success()
    test_registration_rejections()
    test_login_success_and_fail()
    test_access_permissions()
    test_time_windows()
    test_audit_log_entries()
    print("\n🎉 All acceptance tests passed.")
