# database.py
"""
Redis-based session storage for JWT authentication.
Supports single-session enforcement where logging in on Device B logs out Device A.
"""

import redis
import json
import os
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, List

# Redis connection - uses environment variable for connection string
# Set REDIS_URL in your Render environment variables
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')

# Initialize Redis client
try:
    redis_client = redis.from_url(
        REDIS_URL,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5
    )
    # Test connection
    redis_client.ping()
    print(f"✅ Redis connected successfully")
except redis.ConnectionError as e:
    print(f"⚠️  Redis connection failed: {e}")
    print(f"⚠️  Session storage will not work until Redis is configured")
    redis_client = None
except Exception as e:
    print(f"⚠️  Redis initialization error: {e}")
    redis_client = None


def init_db():
    """
    Initialize Redis connection (already done on import).
    This function exists for API consistency with other database implementations.
    """
    if redis_client is None:
        print("⚠️  Redis not connected. Please set REDIS_URL environment variable.")
        return False
    try:
        redis_client.ping()
        print("✅ Redis database initialized")
        return True
    except Exception as e:
        print(f"❌ Redis initialization failed: {e}")
        return False


def invalidate_all_user_sessions(user_id: str) -> bool:
    """
    Delete all active sessions for a specific user.
    This is called when logging in to enforce single-session.
    
    Args:
        user_id: The user ID whose sessions should be invalidated
        
    Returns:
        True if successful, False otherwise
    """
    if redis_client is None:
        return False
    
    try:
        # Get all session tokens for this user
        session_tokens = redis_client.smembers(f'user_sessions:{user_id}')
        
        if session_tokens:
            # Delete each session
            pipeline = redis_client.pipeline()
            for token in session_tokens:
                pipeline.delete(f'session:{user_id}:{token}')
            pipeline.delete(f'user_sessions:{user_id}')
            pipeline.execute()
            
            print(f"🗑️  Invalidated {len(session_tokens)} session(s) for user '{user_id}'")
        
        return True
    except Exception as e:
        print(f"❌ Error invalidating sessions for '{user_id}': {e}")
        return False


def store_session(user_id: str, session_token: str, ip_address: str, 
                 user_agent: str, expires_at: datetime) -> bool:
    """
    Store a new session in Redis with automatic expiration.
    
    Args:
        user_id: The user ID
        session_token: Unique session token
        ip_address: IP address of the client
        user_agent: User agent string
        expires_at: When the session should expire
        
    Returns:
        True if successful, False otherwise
    """
    if redis_client is None:
        return False
    
    try:
        session_data = {
            'user_id': user_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'created_at': datetime.now().isoformat()
        }
        
        # Calculate TTL in seconds
        ttl = int((expires_at - datetime.now()).total_seconds())
        if ttl <= 0:
            print(f"⚠️  Session expires_at is in the past")
            return False
        
        # Store session data with automatic expiration
        redis_client.setex(
            f'session:{user_id}:{session_token}',
            ttl,
            json.dumps(session_data)
        )
        
        # Track this token in the user's session set
        redis_client.sadd(f'user_sessions:{user_id}', session_token)
        redis_client.expire(f'user_sessions:{user_id}', ttl)
        
        print(f"✅ Session stored for user '{user_id}' (expires in {ttl}s)")
        return True
    except Exception as e:
        print(f"❌ Error storing session: {e}")
        return False


def verify_session_token(user_id: str, session_token: str) -> bool:
    """
    Verify that a session token is valid and not expired.
    
    Args:
        user_id: The user ID
        session_token: The session token to verify
        
    Returns:
        True if session is valid, False otherwise
    """
    if redis_client is None:
        return False
    
    try:
        # Check if session exists (will be None if expired or doesn't exist)
        session_data = redis_client.get(f'session:{user_id}:{session_token}')
        
        if session_data is None:
            return False
        
        # Session exists and is not expired (Redis auto-deletes expired keys)
        return True
    except Exception as e:
        print(f"❌ Error verifying session: {e}")
        return False


def delete_session(session_token: str, user_id: Optional[str] = None) -> bool:
    """
    Delete a specific session (used during logout).
    
    Args:
        session_token: The session token to delete
        user_id: Optional user ID (improves performance if provided)
        
    Returns:
        True if successful, False otherwise
    """
    if redis_client is None:
        return False
    
    try:
        if user_id:
            # Delete session and remove from user's session set
            redis_client.delete(f'session:{user_id}:{session_token}')
            redis_client.srem(f'user_sessions:{user_id}', session_token)
        else:
            # If user_id not provided, we need to scan for the session
            # This is slower but handles edge cases
            for key in redis_client.scan_iter(match=f'session:*:{session_token}'):
                redis_client.delete(key)
                # Extract user_id from key pattern session:user_id:token
                parts = key.split(':')
                if len(parts) >= 3:
                    extracted_user_id = ':'.join(parts[1:-1])
                    redis_client.srem(f'user_sessions:{extracted_user_id}', session_token)
        
        print(f"✅ Session deleted: {session_token}")
        return True
    except Exception as e:
        print(f"❌ Error deleting session: {e}")
        return False


def get_user_sessions(user_id: str) -> List[Dict]:
    """
    Get all active sessions for a user (for admin/debugging purposes).
    
    Args:
        user_id: The user ID
        
    Returns:
        List of session data dictionaries
    """
    if redis_client is None:
        return []
    
    try:
        session_tokens = redis_client.smembers(f'user_sessions:{user_id}')
        sessions = []
        
        for token in session_tokens:
            session_data = redis_client.get(f'session:{user_id}:{token}')
            if session_data:
                data = json.loads(session_data)
                data['session_token'] = token
                sessions.append(data)
        
        return sessions
    except Exception as e:
        print(f"❌ Error getting user sessions: {e}")
        return []


def cleanup_expired_sessions():
    """
    Clean up expired sessions.
    Note: Redis automatically deletes expired keys, so this is optional.
    This function is here for API consistency with other database implementations.
    """
    # Redis handles expiration automatically via TTL
    # No manual cleanup needed
    print("ℹ️  Redis automatically handles session expiration via TTL")
    return True


def get_connection_status() -> Dict:
    """
    Get Redis connection status for debugging.
    
    Returns:
        Dictionary with connection status information
    """
    if redis_client is None:
        return {
            'connected': False,
            'error': 'Redis client not initialized',
            'redis_url': REDIS_URL
        }
    
    try:
        redis_client.ping()
        info = redis_client.info('server')
        return {
            'connected': True,
            'redis_version': info.get('redis_version', 'unknown'),
            'redis_url': REDIS_URL.split('@')[-1] if '@' in REDIS_URL else REDIS_URL  # Hide password
        }
    except Exception as e:
        return {
            'connected': False,
            'error': str(e),
            'redis_url': REDIS_URL.split('@')[-1] if '@' in REDIS_URL else REDIS_URL
        }


# ========== USER MANAGEMENT FUNCTIONS ==========

def store_user(user_data: Dict) -> bool:
    """
    Store a user in Redis.
    
    Args:
        user_data: Dictionary containing user info (id, password, name, role, expiry)
        
    Returns:
        True if successful, False otherwise
    """
    if redis_client is None:
        return False
    
    try:
        user_id = user_data.get('id')
        if not user_id:
            return False
        
        # Store user data in Redis (no expiration - users persist forever)
        redis_client.set(
            f'user:{user_id}',
            json.dumps(user_data)
        )
        
        # Add to users set for easy listing
        redis_client.sadd('users:all', user_id)
        
        print(f"✅ User '{user_id}' stored in Redis")
        return True
    except Exception as e:
        print(f"❌ Error storing user: {e}")
        return False


def get_user(user_id: str) -> Optional[Dict]:
    """
    Get a user from Redis.
    
    Args:
        user_id: The user ID
        
    Returns:
        User data dict if found, None otherwise
    """
    if redis_client is None:
        return None
    
    try:
        user_data = redis_client.get(f'user:{user_id}')
        if user_data:
            return json.loads(user_data)
        return None
    except Exception as e:
        print(f"❌ Error getting user: {e}")
        return None


def get_all_users() -> List[Dict]:
    """
    Get all users from Redis.
    
    Returns:
        List of user data dictionaries
    """
    if redis_client is None:
        return []
    
    try:
        user_ids = redis_client.smembers('users:all')
        users = []
        
        for user_id in user_ids:
            user_data = get_user(user_id)
            if user_data:
                users.append(user_data)
        
        return users
    except Exception as e:
        print(f"❌ Error getting all users: {e}")
        return []


def update_user(user_id: str, updates: Dict) -> bool:
    """
    Update a user in Redis.
    
    Args:
        user_id: The user ID
        updates: Dictionary of fields to update
        
    Returns:
        True if successful, False otherwise
    """
    if redis_client is None:
        return False
    
    try:
        # Get existing user
        user_data = get_user(user_id)
        if not user_data:
            return False
        
        # Update fields
        user_data.update(updates)
        
        # Store back
        return store_user(user_data)
    except Exception as e:
        print(f"❌ Error updating user: {e}")
        return False


def delete_user(user_id: str) -> bool:
    """
    Delete a user from Redis.
    
    Args:
        user_id: The user ID
        
    Returns:
        True if successful, False otherwise
    """
    if redis_client is None:
        return False
    
    try:
        # Delete user data
        redis_client.delete(f'user:{user_id}')
        
        # Remove from users set
        redis_client.srem('users:all', user_id)
        
        print(f"✅ User '{user_id}' deleted from Redis")
        return True
    except Exception as e:
        print(f"❌ Error deleting user: {e}")
        return False


def migrate_users_from_json(json_file_path: str) -> int:
    """
    Migrate users from a JSON file to Redis (one-time migration).
    
    Args:
        json_file_path: Path to users.json file
        
    Returns:
        Number of users migrated
    """
    if redis_client is None:
        return 0
    
    try:
        import os
        if not os.path.exists(json_file_path):
            return 0
        
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        users = data.get('users', [])
        migrated = 0
        
        for user in users:
            # Only migrate if user doesn't exist in Redis
            if not get_user(user['id']):
                if store_user(user):
                    migrated += 1
        
        if migrated > 0:
            print(f"✅ Migrated {migrated} users from JSON to Redis")
        
        return migrated
    except Exception as e:
        print(f"❌ Error migrating users: {e}")
        return 0


# ========== QUIZ ATTEMPT STORAGE FUNCTIONS ==========

def generate_attempt_id() -> str:
    """Generate a unique attempt ID"""
    import uuid
    return str(uuid.uuid4())[:12]


def store_quiz_attempt(user_id: str, attempt_data: Dict) -> Optional[str]:
    """
    Store a quiz attempt in Redis, replacing any previous attempt for the same quiz.
    Only keeps the LATEST attempt for each quiz.
    
    Args:
        user_id: The user ID
        attempt_data: Dictionary containing:
            - quiz_name: Name of the quiz/module
            - quiz_type: 'module' or 'mock'
            - total_questions: Total number of questions
            - correct_count: Number of correct answers
            - wrong_count: Number of wrong answers
            - skipped_count: Number of skipped questions
            - score_percent: Score as percentage
            - time_spent_seconds: Time taken in seconds
            - responses: List of individual responses
        
    Returns:
        attempt_id if successful, None otherwise
    """
    if redis_client is None:
        return None
    
    try:
        quiz_name = attempt_data.get('quiz_name') or attempt_data.get('quiz_id')
        
        # Delete any previous attempts for the same quiz
        existing_attempts = get_user_quiz_attempts(user_id, limit=1000)
        for old_attempt in existing_attempts:
            old_quiz_name = old_attempt.get('quiz_name') or old_attempt.get('quiz_id')
            if old_quiz_name == quiz_name:
                old_attempt_id = old_attempt.get('attempt_id')
                if old_attempt_id:
                    # Delete the old attempt
                    redis_client.delete(f'quiz_attempt:{user_id}:{old_attempt_id}')
                    redis_client.zrem(f'user_attempts:{user_id}', old_attempt_id)
                    print(f"🔄 Replaced previous attempt for '{quiz_name}'")
        
        attempt_id = generate_attempt_id()
        
        # Add metadata to attempt
        attempt_data['attempt_id'] = attempt_id
        attempt_data['user_id'] = user_id
        attempt_data['timestamp'] = datetime.now().isoformat()
        
        # Store attempt with key: quiz_attempt:{user_id}:{attempt_id}
        redis_client.set(
            f'quiz_attempt:{user_id}:{attempt_id}',
            json.dumps(attempt_data)
        )
        
        # Add to user's attempts list (sorted set with timestamp as score for ordering)
        redis_client.zadd(
            f'user_attempts:{user_id}',
            {attempt_id: datetime.now().timestamp()}
        )
        
        print(f"✅ Quiz attempt stored for user '{user_id}': {attempt_data.get('quiz_name')} - {attempt_data.get('score_percent')}%")
        return attempt_id
    except Exception as e:
        print(f"❌ Error storing quiz attempt: {e}")
        return None


def get_user_quiz_attempts(user_id: str, limit: int = 50) -> List[Dict]:
    """
    Get all quiz attempts for a user, ordered by most recent first.
    
    Args:
        user_id: The user ID
        limit: Maximum number of attempts to return (default 50)
        
    Returns:
        List of attempt data dictionaries
    """
    if redis_client is None:
        return []
    
    try:
        # Get attempt IDs from sorted set (most recent first)
        attempt_ids = redis_client.zrevrange(f'user_attempts:{user_id}', 0, limit - 1)
        
        attempts = []
        for attempt_id in attempt_ids:
            attempt_data = redis_client.get(f'quiz_attempt:{user_id}:{attempt_id}')
            if attempt_data:
                attempts.append(json.loads(attempt_data))
        
        return attempts
    except Exception as e:
        print(f"❌ Error getting user quiz attempts: {e}")
        return []


def get_quiz_attempt_by_id(user_id: str, attempt_id: str) -> Optional[Dict]:
    """
    Get a specific quiz attempt by ID.
    
    Args:
        user_id: The user ID
        attempt_id: The attempt ID
        
    Returns:
        Attempt data dict if found, None otherwise
    """
    if redis_client is None:
        return None
    
    try:
        attempt_data = redis_client.get(f'quiz_attempt:{user_id}:{attempt_id}')
        if attempt_data:
            return json.loads(attempt_data)
        return None
    except Exception as e:
        print(f"❌ Error getting quiz attempt: {e}")
        return None


def get_user_quiz_stats(user_id: str) -> Dict:
    """
    Get summary statistics for a user's quiz attempts.
    
    Args:
        user_id: The user ID
        
    Returns:
        Dictionary with stats: total_attempts, avg_score, modules_completed, mocks_completed
    """
    if redis_client is None:
        return {'total_attempts': 0, 'avg_score': 0, 'modules_completed': 0, 'mocks_completed': 0}
    
    try:
        attempts = get_user_quiz_attempts(user_id, limit=1000)
        
        if not attempts:
            return {'total_attempts': 0, 'avg_score': 0, 'modules_completed': 0, 'mocks_completed': 0}
        
        total_score = sum(a.get('score_percent', 0) for a in attempts)
        
        # Count UNIQUE modules and mocks completed (for study plan progress)
        unique_modules = set(a.get('quiz_name') or a.get('quiz_id') for a in attempts if a.get('quiz_type') == 'module')
        unique_mocks = set(a.get('quiz_name') or a.get('quiz_id') for a in attempts if a.get('quiz_type') == 'mock')
        
        # Calculate attempts completed today (total, not unique - for today's practice count)
        today_str = datetime.now().date().isoformat()
        today_attempts_list = [a for a in attempts if a.get('timestamp', '').startswith(today_str)]
        today_attempts_count = len(today_attempts_list)  # Total attempts today
        
        # Unique modules completed overall (for study plan bar)
        unique_completed = len(unique_modules) + len(unique_mocks)
        
        # Calculate separate average scores for modules and mocks
        module_attempts = [a for a in attempts if a.get('quiz_type') == 'module']
        mock_attempts = [a for a in attempts if a.get('quiz_type') == 'mock']
        
        module_avg = round(sum(a.get('score_percent', 0) for a in module_attempts) / len(module_attempts), 1) if module_attempts else 0
        mock_avg = round(sum(a.get('score_percent', 0) for a in mock_attempts) / len(mock_attempts), 1) if mock_attempts else 0
        
        return {
            'total_attempts': len(attempts),
            'avg_score': round(total_score / len(attempts), 1) if attempts else 0,
            'avg_module_score': module_avg,
            'avg_mock_score': mock_avg,
            'modules_completed': len(unique_modules),
            'mocks_completed': len(unique_mocks),
            'today_attempts': today_attempts_count,
            'unique_completed': unique_completed
        }
    except Exception as e:
        print(f"❌ Error getting user quiz stats: {e}")
        return {'total_attempts': 0, 'avg_score': 0, 'avg_module_score': 0, 'avg_mock_score': 0, 'modules_completed': 0, 'mocks_completed': 0, 'today_attempts': 0, 'unique_completed': 0}


def delete_quiz_attempt(user_id: str, attempt_id: str) -> bool:
    """
    Delete a specific quiz attempt.
    
    Args:
        user_id: The user ID
        attempt_id: The attempt ID
        
    Returns:
        True if successful, False otherwise
    """
    if redis_client is None:
        return False
    
    try:
        # Delete attempt data
        redis_client.delete(f'quiz_attempt:{user_id}:{attempt_id}')
        
        # Remove from user's attempts list
        redis_client.zrem(f'user_attempts:{user_id}', attempt_id)
        
        print(f"✅ Quiz attempt '{attempt_id}' deleted for user '{user_id}'")
        return True
    except Exception as e:
        print(f"❌ Error deleting quiz attempt: {e}")
        return False


# ========== MOCK TIMER FUNCTIONS ==========

def set_mock_timer(user_id: str, quiz_id: str, duration_seconds: int) -> int:
    """
    Set an authoritative end timestamp for a mock quiz in Redis.
    Structure: mock_timer:{uid}:{qid} -> end_timestamp (Unix epoch seconds)
    
    Returns:
        The end timestamp (existing or newly created)
    """
    if redis_client is None:
        return 0
    
    try:
        # Key for this specific mock attempt
        key = f'mock_timer:{user_id}:{quiz_id}'
        
        # Check if timer already exists (Idempotent resume)
        existing = redis_client.get(key)
        if existing:
            return int(existing)
            
        # Create new end timestamp
        end_timestamp = int(time.time()) + duration_seconds
        
        # Store with TTL (duration + 2 hours buffer)
        # We use a string because Redis SET expects string/bytes
        redis_client.set(key, str(end_timestamp), ex=duration_seconds + 7200)
        
        print(f"⏱️ Started server-side mock timer for user '{user_id}', quiz '{quiz_id}'. Ends at: {end_timestamp}")
        return end_timestamp
    except Exception as e:
        print(f"❌ Error setting mock timer: {e}")
        return 0

def get_mock_timer(user_id: str, quiz_id: str) -> int:
    """
    Get remaining seconds for a mock quiz.
    
    Returns:
        Remaining seconds, or -1 if not found, or 0 if expired.
    """
    if redis_client is None:
        return 0
    
    try:
        end_ts = redis_client.get(f'mock_timer:{user_id}:{quiz_id}')
        if not end_ts:
            return -1 # Timer doesn't exist
            
        remaining = int(end_ts) - int(time.time())
        return max(0, remaining)
    except Exception as e:
        print(f"❌ Error getting mock timer: {e}")
        return 0

def clear_mock_timer(user_id: str, quiz_id: str) -> bool:
    """Clear the mock timer after submission"""
    if redis_client is None:
        return False
    try:
        return bool(redis_client.delete(f'mock_timer:{user_id}:{quiz_id}'))
    except Exception as e:
        print(f"❌ Error clearing mock timer: {e}")
        return False
# ========== LOGIN HISTORY FUNCTIONS ==========

def add_login_history(user_id: str, session_data: Dict):
    """
    Store login history in Redis as a list.
    Keeps only the 20 most recent logins.
    """
    if redis_client is None:
        return
    
    try:
        key = f'user_login_history:{user_id}'
        # Push to the front of the list
        redis_client.lpush(key, json.dumps(session_data))
        # Keep only the last 20 entries
        redis_client.ltrim(key, 0, 19)
    except Exception as e:
        print(f"❌ Error adding login history: {e}")

def get_session_details(user_id: str) -> List[Dict]:
    """
    Get login history for a user from Redis.
    """
    if redis_client is None:
        return []
    
    try:
        key = f'user_login_history:{user_id}'
        items = redis_client.lrange(key, 0, -1)
        return [json.loads(item) for item in items]
    except Exception as e:
        print(f"❌ Error getting login history: {e}")
        return []
