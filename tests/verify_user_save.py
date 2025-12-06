#!/usr/bin/env python
"""
Quick verification script for user persistence
"""

import sys
import os
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import add_user, load_users, BASE_DIR

# Test user persistence
print("Testing User Persistence Fix...")
print("-" * 50)

# Get the config directory
config_dir = os.path.join(BASE_DIR, 'config')
users_file = os.path.join(config_dir, 'users.json')

print(f"Config directory: {config_dir}")
print(f"Users file path: {users_file}")
print(f"Config dir exists: {os.path.exists(config_dir)}")
print(f"Users file exists: {os.path.exists(users_file)}")

# Load current users
users_data = load_users()
print(f"\nCurrent users: {len(users_data['users'])}")
for user in users_data['users']:
    print(f"  - {user['id']}: {user['name']} ({user['role']})")

# Test adding a new user
print(f"\nAdding test user...")
success, message = add_user('testuser_verify', 'testpass', 'Test User Verify', role='user')
print(f"Add result: {success} - {message}")

# Reload users to verify persistence
users_data = load_users()
print(f"\nUsers after add: {len(users_data['users'])}")

# Check if test user was added
test_user = next((u for u in users_data['users'] if u['id'] == 'testuser_verify'), None)
if test_user:
    print(f"✓ Test user successfully persisted!")
    print(f"  ID: {test_user['id']}")
    print(f"  Name: {test_user['name']}")
    print(f"  Role: {test_user['role']}")
else:
    print(f"✗ Test user NOT found in persisted data")

# Show file contents
print(f"\n" + "=" * 50)
print("File Contents (Last 10 lines):")
print("=" * 50)
with open(users_file, 'r') as f:
    content = f.read()
    lines = content.split('\n')
    for line in lines[-15:]:
        print(line)
