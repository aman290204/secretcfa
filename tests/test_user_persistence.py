#!/usr/bin/env python
"""
Test script to verify user persistence functionality
Tests that users added via the admin interface are properly saved to users.json
"""

import sys
import os
import json
import tempfile
import shutil
from pathlib import Path

# Add parent directory to path to import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import add_user, remove_user, edit_user, load_users, save_users, BASE_DIR


def test_user_persistence():
    """Test user persistence functionality"""
    print("=" * 70)
    print("CFA L1 Quiz - User Persistence Test Suite")
    print("=" * 70)
    
    # Backup original users.json
    config_dir = os.path.join(BASE_DIR, 'config')
    users_file = os.path.join(config_dir, 'users.json')
    backup_file = None
    
    if os.path.exists(users_file):
        backup_file = users_file + '.backup'
        shutil.copy2(users_file, backup_file)
        print(f"\n✓ Backed up original users.json to {backup_file}")
    
    try:
        # Test 1: Add a new user
        print("\n[TEST 1] Adding new user...")
        success, message = add_user('testuser1', 'testpass123', 'Test User 1', role='user')
        print(f"Result: {message}")
        
        if not success:
            print("✗ FAILED: Could not add user")
            return False
        
        # Verify the file was created
        if not os.path.exists(users_file):
            print("✗ FAILED: users.json file was not created")
            return False
        print("✓ users.json file exists")
        
        # Verify user is in file
        loaded_users = load_users()
        user_found = any(u['id'] == 'testuser1' for u in loaded_users['users'])
        if not user_found:
            print("✗ FAILED: User not found in users.json")
            return False
        print("✓ User persisted to users.json")
        
        # Test 2: Add another user
        print("\n[TEST 2] Adding second user...")
        success, message = add_user('testuser2', 'testpass456', 'Test User 2', role='admin')
        print(f"Result: {message}")
        
        if not success:
            print("✗ FAILED: Could not add second user")
            return False
        
        # Verify both users exist
        loaded_users = load_users()
        user1_found = any(u['id'] == 'testuser1' for u in loaded_users['users'])
        user2_found = any(u['id'] == 'testuser2' for u in loaded_users['users'])
        
        if not (user1_found and user2_found):
            print("✗ FAILED: Both users not found in users.json")
            return False
        print(f"✓ Both users persisted (total users: {len(loaded_users['users'])})")
        
        # Test 3: Edit a user
        print("\n[TEST 3] Editing user...")
        success, message = edit_user('testuser1', name='Updated Test User 1', role='admin')
        print(f"Result: {message}")
        
        if not success:
            print("✗ FAILED: Could not edit user")
            return False
        
        # Verify the edit was persisted
        loaded_users = load_users()
        test_user = next((u for u in loaded_users['users'] if u['id'] == 'testuser1'), None)
        if not test_user or test_user['name'] != 'Updated Test User 1' or test_user['role'] != 'admin':
            print("✗ FAILED: User edit not persisted")
            return False
        print("✓ User edit persisted to users.json")
        
        # Test 4: Remove a user
        print("\n[TEST 4] Removing user...")
        success, message = remove_user('testuser2')
        print(f"Result: {message}")
        
        if not success:
            print("✗ FAILED: Could not remove user")
            return False
        
        # Verify the removal was persisted
        loaded_users = load_users()
        user2_found = any(u['id'] == 'testuser2' for u in loaded_users['users'])
        if user2_found:
            print("✗ FAILED: Removed user still in users.json")
            return False
        print("✓ User removal persisted to users.json")
        
        # Test 5: Verify file permissions
        print("\n[TEST 5] Checking file permissions...")
        if os.path.exists(users_file):
            if os.access(users_file, os.R_OK):
                print("✓ users.json is readable")
            else:
                print("✗ WARNING: users.json is not readable")
            
            if os.access(users_file, os.W_OK):
                print("✓ users.json is writable")
            else:
                print("✗ WARNING: users.json is not writable")
        
        print("\n" + "=" * 70)
        print("✓ ALL TESTS PASSED")
        print("=" * 70)
        print("\nUser persistence is working correctly!")
        print(f"Current users in system: {len(loaded_users['users'])}")
        return True
        
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Restore backup if tests failed
        if backup_file and os.path.exists(backup_file):
            print(f"\nRestoring original users.json from backup...")
            shutil.copy2(backup_file, users_file)
            os.remove(backup_file)
            print("✓ Original users.json restored")


if __name__ == '__main__':
    success = test_user_persistence()
    sys.exit(0 if success else 1)
