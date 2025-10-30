import bcrypt
import json
import os
import re
from datetime import datetime

USER_DB = "users.json"
AUDIT_LOG = "audit.log"

# --------------------------
# Helper Functions
# --------------------------
def load_users():
    if not os.path.exists(USER_DB):
        return {}
    with open(USER_DB, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USER_DB, "w") as f:
        json.dump(users, f, indent=4)

def password_policy(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""

# --------------------------
# Registration
# --------------------------
def register():
    users = load_users()
    user_id = input("Enter a unique user ID: ").strip()

    # Check case-insensitively for existing users
    for stored_id in users.keys():
        if stored_id.lower() == user_id.lower():
            print("User ID already exists.")
            return

    password = input("Enter your password: ").strip()
    valid, message = password_policy(password)
    if not valid:
        print("Invalid:", message)
        return

    role = input("Enter your role (manager, cashier, dept_manager, day admin, night admin): ").strip()
    dept = input("Enter department (A or B): ").strip().upper()
    if dept not in ["A", "B"]:
        print("Invalid department.")
        return

    # Generate bcrypt salt and hash
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)

    # Use user_id here, not matched_user_id
    users[user_id] = {
        "salt": salt.decode("utf-8"),
        "password_hash": hashed.decode("utf-8"),
        "role": role,
        "department": dept
    }

    save_users(users)
    print("Registration successful!")

# --------------------------
# Helper: Write Audit Log
# --------------------------
def log_event(user_id, event_type, details=None, target=None, outcome=None):
    """
    Append one JSON event line to audit.log.

    Supports both general events (login, registration)
    and file events (view/edit access with outcome).
    """
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z"),
        "user": user_id,
        "event": event_type
    }

    # Only include fields that apply to this event
    if target is not None:
        entry["target"] = target
    if outcome is not None:
        entry["outcome"] = outcome
    if details is not None:
        entry["details"] = details

    # Append as JSON line
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

# --------------------------
# Helper: File Operations
# --------------------------
def view_file(user_id, target_file):
    """View the content of a department file and log the event."""
    try:
        with open(target_file, "r") as f:
            print("\n----- FILE CONTENT -----")
            print(f.read())
            print("------------------------\n")
        log_event(user_id, "view", target=target_file, outcome="granted")
    except FileNotFoundError:
        print("File not found.")
        log_event(user_id, "view", target=target_file, outcome="denied", details="file not found")
    except Exception as e:
        print("Error reading file:", e)
        log_event(user_id, "view", target=target_file, outcome="denied", details=str(e))


def edit_file(user_id, target_file):
    """Append a new line to a department file and log the event."""
    try:
        new_line = input("Enter line to append: ")
        with open(target_file, "a") as f:
            f.write(f"\n{new_line}")
        print("Edit applied successfully.")
        log_event(user_id, "edit", target=target_file, outcome="granted")
    except Exception as e:
        print("Error editing file:", e)
        log_event(user_id, "edit", target=target_file, outcome="denied", details=str(e))

# --------------------------
# Access Control (Problem 3)
# --------------------------
def access_file(user_id, role, dept):
    """Implements time- and role-based access control with continuous time checking."""
    role = role.lower()

    while True:
        current_hour = datetime.now().hour
        allowed_hours = True

        # Determine time restrictions for admins
        if role == "day admin":
            allowed_hours = (1 <= current_hour < 13)
        elif role == "night admin":
            allowed_hours = (current_hour >= 13 or current_hour < 1)

        # End session if outside shift
        if "admin" in role and not allowed_hours:
            print("\nAccess denied: your permitted hours have ended.")
            log_event(user_id, "access_denied", details=f"{role} outside permitted hours", outcome="denied")
            print("Logging out due to shift restriction...\n")
            exit()

        # User menu
        print("\nAvailable actions: view / edit / logout")
        action = input("Enter action: ").strip().lower()
        if action == "logout":
            print("Logging out...\n")
            log_event(user_id, "logout", details="user logged out")
            exit()

        target_file = input("Enter target file (customer_A.txt / customer_B.txt): ").strip()
        can_view = can_edit = False

        # Permission matrix
        if role == "manager":
            can_view = can_edit = True
        elif role == "dept_manager" and dept == "A" and target_file.lower() == "customer_a.txt":
            can_view = can_edit = True
        elif role == "dept_manager" and dept == "B" and target_file.lower() == "customer_b.txt":
            can_view = can_edit = True
        elif role == "cashier" and dept == "A" and target_file.lower() == "customer_a.txt":
            can_view = True
        elif role == "cashier" and dept == "B" and target_file.lower() == "customer_b.txt":
            can_view = True
        elif role in ["day admin", "night admin"]:
            can_view = can_edit = True

        # Evaluate permission
        if action == "view" and can_view:
            view_file(user_id, target_file)
        elif action == "edit" and can_edit:
            edit_file(user_id, target_file)
        else:
            reason = "insufficient permissions"
            if not can_view and action == "view":
                reason = "not authorized to view this file"
            elif not can_edit and action == "edit":
                reason = "not authorized to edit this file"
            print(f"Access denied ({reason}).")
            log_event(user_id, action, target=target_file, outcome="denied", details=reason)

# --------------------------
# Login (Problem 3.2 + 4)
# --------------------------
def login():
    users = load_users()
    user_id_input = input("Enter your username: ").strip()
    password = input("Enter your password: ").strip()

    # Case-insensitive match
    matched_id = None
    for uid in users.keys():
        if uid.lower() == user_id_input.lower():
            matched_id = uid
            break

    if not matched_id:
        print("Invalid credentials.")
        log_event(user_id_input, "login_failed", details="user ID not found")
        return False, None

    stored_hash = users[matched_id]["password_hash"].encode("utf-8")
    role = users[matched_id]["role"]
    dept = users[matched_id]["department"]

    if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        print("Login successful!")
        log_event(matched_id, "login_success", details="user authenticated")
        while True:
            continue_access = input("Do you want to access files? (yes/no): ").strip().lower()
            if continue_access == "yes":
                access_file(matched_id, role, dept)
            elif continue_access == "no":
                log_event(matched_id, "logout", details="user exited login session")
                break
        return True, matched_id
    else:
        print("Invalid credentials.")
        log_event(matched_id, "login_failed", details="incorrect password")
        return False, None

# --------------------------
# Menu
# --------------------------
if __name__ == "__main__":
    while True:
        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Choose an option: ")
        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            break
        else:
            print("Invalid choice.")
