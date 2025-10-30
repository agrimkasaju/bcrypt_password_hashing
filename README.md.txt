# Secure User Account and Access Control System

## Overview
This program implements a secure user authentication and access control system for an organization with multiple departments. It provides secure registration, role-based access to sensitive department files, and an audit log for all security-related events.

The system enforces password policies, time-based access for administrative roles, and department-based file restrictions. All events are logged in JSON Lines format for accountability and traceability.

---

## Features
- Secure registration with password hashing using bcrypt (cost factor 12)
- Strong password policy requiring uppercase, lowercase, digits, and special characters
- Role-based access control enforcing department-specific permissions
- Time-based enforcement for Day Admin and Night Admin roles
- Append-only audit log for all logins, file views, and edits
- Case-insensitive usernames for login; passwords remain case-sensitive

---

## Setup and Usage

### 1. Requirements
- Python 3.8 or later
- bcrypt library

Install bcrypt if needed:
```bash
pip install bcrypt
```

### 2. Running the Program
```bash
python3 secure_system.py
```

## 3. Files Created
File	Description
- users.json	Stores user credentials (salt, hashed password, role, department)
- audit.log	Append-only log of security events
- customer_A.txt	Department A’s protected file
- customer_B.txt	Department B’s protected file

## 4. Access Control Policy

| Role             | Dept A View | Dept A Edit | Dept B View | Dept B Edit | Time Restriction |
|------------------|--------------|--------------|--------------|--------------|------------------|
| Manager          | Yes          | Yes          | Yes          | Yes          | None             |
| Dept Manager A   | Yes          | Yes          | No           | No           | None             |
| Dept Manager B   | No           | No           | Yes          | Yes          | None             |
| Cashier A        | Yes          | No           | No           | No           | None             |
| Cashier B        | No           | No           | Yes          | No           | None             |
| Day Admin        | Yes          | Yes          | Yes          | Yes          | 01:00–12:59      |
| Night Admin      | Yes          | Yes          | Yes          | Yes          | 13:00–00:59      |
