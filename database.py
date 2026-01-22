# database.py
"""
Redis-based session storage for JWT authentication.
Supports single-session enforcement where logging in on Device B logs out Device A.
"""

import redis
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List

# India Standard Time (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))

def get_ist_now():
    """Get current datetime in India Standard Time (UTC+5:30)"""
    return datetime.now(IST)

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
            'created_at': get_ist_now().isoformat()
        }
        
        # Calculate TTL in seconds
        ttl = int((expires_at - get_ist_now()).total_seconds())
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
        # Clear module snapshots first
        clear_user_module_progress(user_id)
        
        # Delete user data
        redis_client.delete(f'user:{user_id}')
        
        # Remove from users set
        redis_client.srem('users:all', user_id)
        
        print(f"✅ User '{user_id}' deleted from Redis")
        return True
    except Exception as e:
        print(f"❌ Error deleting user: {e}")
        return False


def clear_user_module_progress(user_id: str) -> bool:
    """Delete all module progress snapshots for a user."""
    if redis_client is None:
        return False
    try:
        pattern = f"module_progress:{user_id}:*"
        keys = redis_client.keys(pattern)
        if keys:
            # redis_client.delete accepts multiple keys
            redis_client.delete(*keys)
        return True
    except Exception as e:
        print(f"❌ Error clearing module progress: {e}")
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
        attempt_data['timestamp'] = get_ist_now().isoformat()
        
        # Store attempt with key: quiz_attempt:{user_id}:{attempt_id}
        redis_client.set(
            f'quiz_attempt:{user_id}:{attempt_id}',
            json.dumps(attempt_data)
        )
        
        # Add to user's attempts list (sorted set with timestamp as score for ordering)
        redis_client.zadd(
            f'user_attempts:{user_id}',
            {attempt_id: get_ist_now().timestamp()}
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
        # Get snapshots (Snapshots are the single source of truth for progress)
        snapshots = get_all_module_progress(user_id)
        # We still need raw attempts for "today's count" and completed module list
        attempts = get_user_quiz_attempts(user_id, limit=1000)
        
        if not snapshots and not attempts:
            return {'total_attempts': 0, 'avg_score': 0, 'modules_completed': 0, 'mocks_completed': 0, 'today_attempts': 0, 'unique_completed': 0, 'unique_questions_attempted': 0, 'questions_attempted_today': 0}
        
        # Count UNIQUE modules and mocks completed (completed only)
        unique_modules = set(a.get('quiz_name') or a.get('quiz_id') for a in attempts if a.get('quiz_type') == 'module')
        unique_mocks = set(a.get('quiz_name') or a.get('quiz_id') for a in attempts if a.get('quiz_type') == 'mock')
        
        # Calculate attempts completed today (completed only)
        today_str = get_ist_now().date().isoformat()
        today_attempts_list = [a for a in attempts if a.get('timestamp', '').startswith(today_str)]
        today_attempts_count = len(today_attempts_list)  # Number of quizzes today
        today_questions_count = sum(a.get('total_questions', 0) for a in today_attempts_list)
        
        # Unique modules completed overall (for study plan bar)
        unique_completed = len(unique_modules) + len(unique_mocks)
        
        # Aggregators for global stats from snapshots
        total_correct_global = 0
        total_attempted_global = 0
        
        module_correct = 0
        module_attempted = 0
        mock_correct = 0
        mock_attempted = 0

        for m_id, snapshot in snapshots.items():
            is_mock = 'Mock' in m_id
            m_correct = snapshot.get('correct', 0)
            m_attempted = snapshot.get('attempted', 0)
            
            total_correct_global += m_correct
            total_attempted_global += m_attempted
            
            if is_mock:
                mock_correct += m_correct
                mock_attempted += m_attempted
            else:
                module_correct += m_correct
                module_attempted += m_attempted
        
        # Real-time daily progress from Redis counter
        daily_progress_key = f"user_daily_attempted:{user_id}:{today_str}"
        daily_attempted = int(redis_client.get(daily_progress_key) or 0)
        
        # Merge snapshots and historical attempts for accuracy
        global_avg = round(total_correct_global / total_attempted_global * 100, 1) if total_attempted_global > 0 else 0
        module_avg = round(module_correct / module_attempted * 100, 1) if module_attempted > 0 else 0
        mock_avg = round(mock_correct / mock_attempted * 100, 1) if mock_attempted > 0 else 0
        
        # Global/Mock Timing stats from History (since mocks don't use snapshots yet)
        mock_total_c_time = 0
        mock_total_i_time = 0
        mock_total_c_count = 0
        mock_total_i_count = 0
        mock_total_time = 0
        mock_total_q = 0
        
        for a in attempts:
            if a.get('quiz_type') == 'mock':
                mock_total_time += a.get('time_spent_seconds', 0)
                mock_total_q += a.get('total_questions', 0)
                mock_total_c_count += a.get('correct_count', 0)
                mock_total_i_count += a.get('wrong_count', 0)
                
                # Try to get detailed timing from responses if available
                responses = a.get('responses', [])
                for res in responses:
                    t = res.get('time_spent_seconds', 0)
                    if res.get('is_correct'):
                        mock_total_c_time += t
                    else:
                        mock_total_i_time += t

        def fmt_time(s):
            if s >= 60: return f"{int(s//60)}m {int(s%60)}s"
            return f"{int(s)}s"

        mock_avg_time = fmt_time(mock_total_time / mock_total_q) if mock_total_q > 0 else "--"
        mock_avg_c_time = fmt_time(mock_total_c_time / mock_total_c_count) if mock_total_c_count > 0 else "--"
        mock_avg_i_time = fmt_time(mock_total_i_time / mock_total_i_count) if mock_total_i_count > 0 else "--"

        return {
            'total_attempts': len(attempts),
            'avg_score': global_avg,
            'avg_module_score': module_avg,
            'avg_mock_score': mock_avg,
            'modules_completed': len(unique_modules),
            'mocks_completed': len(unique_mocks),
            'today_attempts': today_attempts_count,
            'unique_completed': unique_completed,
            'unique_questions_attempted': total_attempted_global,
            'questions_attempted_today': max(daily_attempted, today_questions_count),
            'mock_avg_time': mock_avg_time,
            'mock_avg_c_time': mock_avg_c_time,
            'mock_avg_i_time': mock_avg_i_time
        }
    except Exception as e:
        print(f"❌ Error getting user quiz stats: {e}")
        return {'total_attempts': 0, 'avg_score': 0, 'avg_module_score': 0, 'avg_mock_score': 0, 'modules_completed': 0, 'mocks_completed': 0, 'today_attempts': 0, 'unique_completed': 0, 'unique_questions_attempted': 0, 'questions_attempted_today': 0}


def update_module_progress(user_id: str, module_id: str, payload: Dict) -> bool:
    """
    Incrementally update the module_progress snapshot in Redis using idempotent question-level state.
    Payload can contain: question_id, is_correct, time_spent_delta, last_index, status, total_questions
    """
    if redis_client is None:
        return False
    
    key = f"module_progress:{user_id}:{module_id}"
    try:
        # Get existing snapshot or initialize new
        existing = redis_client.get(key)
        if existing:
            snapshot = json.loads(existing)
        else:
            snapshot = {
                "questions": {},
                "attempted": 0,
                "correct": 0,
                "time_spent": 0,
                "correct_time_spent": 0,
                "incorrect_time_spent": 0,
                "last_question_index": 0,
                "status": "not_started",
                "updated_at": get_ist_now().isoformat()
            }
        
        # Ensure 'questions' key exists (for migration of old snapshots)
        if "questions" not in snapshot:
            snapshot["questions"] = {}

        q_id = payload.get('question_id')
        if q_id:
            # Update specific question state
            is_correct = payload.get('is_correct', False)
            q_time_delta = payload.get('time_spent_delta', 0)
            
            # Initial track for daily progress if this is a NEW question attempt for this user overall today
            is_new_for_module = q_id not in snapshot["questions"]
            
            if is_new_for_module:
                snapshot["questions"][q_id] = {
                    "attempted": True,
                    "correct": is_correct,
                    "time_spent": q_time_delta
                }
                # Track daily progress deltas separately for NEW module questions only
                today_str = get_ist_now().date().isoformat()
                daily_key = f"user_daily_attempted:{user_id}:{today_str}"
                redis_client.incrby(daily_key, 1)
                redis_client.expire(daily_key, 86400 * 7) # Keep 1 week
            else:
                # Update existing question state (idempotent for counters, additive for time)
                q_state = snapshot["questions"][q_id]
                q_state["correct"] = is_correct 
                q_state["time_spent"] = q_state.get("time_spent", 0) + q_time_delta

        # Apply general metadata
        if payload.get('last_index') is not None:
            snapshot["last_question_index"] = payload.get('last_index')
            
        if payload.get('status'):
            snapshot["status"] = payload.get('status')

        # RECOMPUTE ALL AGGREGATES (Single Source of Truth is snapshot["questions"])
        total_a = 0
        total_c = 0
        total_t = 0
        total_c_t = 0
        total_i_t = 0
        
        for qid, qdata in snapshot["questions"].items():
            total_a += 1
            if qdata.get("correct"):
                total_c += 1
                total_c_t += qdata.get("time_spent", 0)
            else:
                total_i_t += qdata.get("time_spent", 0)
            total_t += qdata.get("time_spent", 0)
            
        snapshot["attempted"] = total_a
        snapshot["correct"] = total_c
        snapshot["time_spent"] = total_t
        snapshot["correct_time_spent"] = total_c_t
        snapshot["incorrect_time_spent"] = total_i_t
        
        # Completion logic based on recomputed attempted count
        total_q_module = payload.get('total_questions')
        if total_q_module and total_a >= total_q_module:
            snapshot["status"] = "completed"
        elif total_a > 0 and snapshot.get("status") == "not_started":
            snapshot["status"] = "in_progress"

        snapshot["updated_at"] = get_ist_now().isoformat()
        
        redis_client.set(key, json.dumps(snapshot))
        return True
    except Exception as e:
        print(f"❌ Error updating module progress: {e}")
        return False


def get_module_progress(user_id: str, module_id: str) -> Optional[Dict]:
    """Get a single module's progress snapshot."""
    if redis_client is None:
        return None
    key = f"module_progress:{user_id}:{module_id}"
    try:
        data = redis_client.get(key)
        return json.loads(data) if data else None
    except Exception:
        return None


def get_all_module_progress(user_id: str) -> Dict[str, Dict]:
    """Get all module progress snapshots for a user."""
    if redis_client is None:
        return {}
    try:
        pattern = f"module_progress:{user_id}:*"
        keys = redis_client.keys(pattern)
        results = {}
        for key in keys:
            data = redis_client.get(key)
            if data:
                # Extract module_id from key
                k_str = key.decode('utf-8') if isinstance(key, bytes) else key
                module_id = k_str.split(':')[-1]
                results[module_id] = json.loads(data)
        return results
    except Exception as e:
        print(f"❌ Error getting all module progress: {e}")
        return {}


def rebuild_snapshots_from_history(user_id: str) -> int:
    """
    Reconstruct module_progress snapshots from historical quiz_attempts.
    This is useful for 'restoring' progress after a migration or reset.
    Returns: Number of modules processed.
    """
    if redis_client is None:
        return 0
    
    try:
        # Get all attempts
        attempts = get_user_quiz_attempts(user_id, limit=1000)
        if not attempts:
            return 0
            
        # Group by module
        modules = {}
        for a in attempts:
            if a.get('quiz_type') != 'module':
                continue
            
            m_id = a.get('quiz_name') or a.get('quiz_id')
            if not m_id:
                continue
            
            # Since we only keep ONE latest attempt, this is easy
            modules[m_id] = a
            
        count = 0
        for m_id, a in modules.items():
            key = f"module_progress:{user_id}:{m_id}"
            
            # Aggregate from responses if available
            correct_time = 0
            incorrect_time = 0
            questions_map = {}
            responses = a.get('responses', [])
            for res in responses:
                # Ensure we have a string ID for the question
                q_id = str(res.get('question_id'))
                if not q_id or q_id == 'None':
                    continue
                    
                t = res.get('time_spent_seconds', 0)
                is_correct = res.get('is_correct', False)
                
                questions_map[q_id] = {
                    "attempted": True,
                    "correct": is_correct,
                    "time_spent": t
                }
                
                if is_correct:
                    correct_time += t
                else:
                    incorrect_time += t

            # Reconstruct snapshot
            snapshot = {
                "questions": questions_map,
                "attempted": (a.get('correct_count', 0) + a.get('wrong_count', 0)),
                "correct": a.get('correct_count', 0),
                "time_spent": a.get('time_spent_seconds', 0),
                "correct_time_spent": correct_time,
                "incorrect_time_spent": incorrect_time,
                "last_question_index": (a.get('total_questions', 1) - 1),
                "status": "completed",
                "updated_at": a.get('timestamp', get_ist_now().isoformat()),
                "is_restored": True
            }
            
            redis_client.set(key, json.dumps(snapshot))
            count += 1
            
        return count
    except Exception as e:
        print(f"❌ Error rebuilding snapshots: {e}")
        return 0


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


# ========== PAUSED PRACTICE ATTEMPTS ==========

def save_paused_attempt(user_id: str, module_id: str, attempt_data: Dict) -> bool:
    """
    Save a paused practice attempt to Redis.
    Only ONE active paused attempt is allowed per module per user.
    
    Args:
        user_id: The user ID
        module_id: The module identifier (e.g., 'Module 1 Rates and Returns')
        attempt_data: Dict containing:
            - started_at: ISO timestamp when quiz started
            - paused_at: ISO timestamp when paused
            - last_question_index: Current question index
            - responses: Array of response objects
            - per_question_time: Array of time spent per question
            - total_time_seconds: Total elapsed time
            - status: 'paused' | 'active' | 'completed'
            
    Returns:
        True if successful, False otherwise
    """
    if redis_client is None:
        return False
    
    try:
        key = f'paused_practice:{user_id}:{module_id}'
        attempt_data['module_id'] = module_id
        attempt_data['user_id'] = user_id
        attempt_data['status'] = 'paused'
        
        redis_client.set(key, json.dumps(attempt_data))
        print(f"💾 Paused attempt saved for user '{user_id}' on module '{module_id}'")
        return True
    except Exception as e:
        print(f"❌ Error saving paused attempt: {e}")
        return False


def get_paused_attempt(user_id: str, module_id: str) -> Optional[Dict]:
    """
    Get a paused practice attempt for a specific module.
    
    Args:
        user_id: The user ID
        module_id: The module identifier
        
    Returns:
        The paused attempt data dict, or None if not found
    """
    if redis_client is None:
        return None
    
    try:
        key = f'paused_practice:{user_id}:{module_id}'
        data = redis_client.get(key)
        if data:
            return json.loads(data)
        return None
    except Exception as e:
        print(f"❌ Error getting paused attempt: {e}")
        return None


def clear_paused_attempt(user_id: str, module_id: str) -> bool:
    """
    Clear a paused practice attempt (called on completion or explicit clear).
    
    Args:
        user_id: The user ID
        module_id: The module identifier
        
    Returns:
        True if successful, False otherwise
    """
    if redis_client is None:
        return False
    
    try:
        key = f'paused_practice:{user_id}:{module_id}'
        result = redis_client.delete(key)
        if result:
            print(f"🗑️ Cleared paused attempt for user '{user_id}' on module '{module_id}'")
        return bool(result)
    except Exception as e:
        print(f"❌ Error clearing paused attempt: {e}")
        return False


def get_all_paused_attempts(user_id: str) -> Dict[str, Dict]:
    """
    Get all paused practice attempts for a user.
    
    Args:
        user_id: The user ID
        
    Returns:
        Dict mapping module_id to attempt data
    """
    if redis_client is None:
        return {}
    
    try:
        pattern = f'paused_practice:{user_id}:*'
        keys = redis_client.keys(pattern)
        result = {}
        
        for key in keys:
            data = redis_client.get(key)
            if data:
                attempt = json.loads(data)
                module_id = attempt.get('module_id', key.split(':')[-1])
                result[module_id] = attempt
        
        return result
    except Exception as e:
        print(f"❌ Error getting all paused attempts: {e}")
        return {}


def clear_all_user_paused_attempts(user_id: str) -> bool:
    """Delete all paused practice attempts for a user."""
    if redis_client is None:
        return False
    try:
        pattern = f"paused_practice:{user_id}:*"
        keys = redis_client.keys(pattern)
        if keys:
            redis_client.delete(*keys)
        return True
    except Exception as e:
        print(f"❌ Error clearing all paused attempts: {e}")
        return False

# ========== RETROSPECTIVE IST CONVERSION ==========

def convert_timestamp_to_ist(timestamp_str: str) -> str:
    """Convert a UTC timestamp string to IST (UTC+5:30)."""
    if not timestamp_str or not isinstance(timestamp_str, str):
        return timestamp_str
    
    try:
        # Try parsing ISO format
        if 'T' in timestamp_str:
            if '+' in timestamp_str or 'Z' in timestamp_str:
                # Already has timezone info
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                dt_ist = dt.astimezone(IST)
            else:
                # Assume UTC, add offset
                dt = datetime.fromisoformat(timestamp_str)
                dt_ist = dt + timedelta(hours=5, minutes=30)
                dt_ist = dt_ist.replace(tzinfo=IST)
            
            return dt_ist.isoformat()
        return timestamp_str
    except Exception as e:
        print(f"⚠️ Could not convert timestamp '{timestamp_str}': {e}")
        return timestamp_str

def run_ist_migration() -> Dict:
    """Run retrospective IST migration for all Redis data."""
    report = {
        'quiz_attempts': 0,
        'paused_practice': 0,
        'sessions': 0,
        'users': 0,
        'total': 0,
        'errors': []
    }
    
    try:
        # 1. Migrate quiz attempts
        attempt_keys = redis_client.keys('quiz_attempt:*')
        for key in attempt_keys:
            try:
                data = redis_client.get(key)
                if data:
                    attempt = json.loads(data)
                    modified = False
                    for field in ['timestamp', 'started_at', 'submitted_at']:
                        if field in attempt:
                            old_val = attempt[field]
                            new_val = convert_timestamp_to_ist(old_val)
                            if old_val != new_val:
                                attempt[field] = new_val
                                modified = True
                    if modified:
                        redis_client.set(key, json.dumps(attempt))
                        report['quiz_attempts'] += 1
            except Exception as e:
                report['errors'].append(f"Attempt {key}: {e}")

        # 2. Migrate paused practice
        pause_keys = redis_client.keys('paused_practice:*')
        for key in pause_keys:
            try:
                data = redis_client.get(key)
                if data:
                    paused = json.loads(data)
                    modified = False
                    for field in ['paused_at', 'started_at']:
                        if field in paused:
                            old_val = paused[field]
                            new_val = convert_timestamp_to_ist(old_val)
                            if old_val != new_val:
                                paused[field] = new_val
                                modified = True
                    if modified:
                        redis_client.set(key, json.dumps(paused))
                        report['paused_practice'] += 1
            except Exception as e:
                report['errors'].append(f"Paused {key}: {e}")

        # 3. Migrate sessions
        session_keys = redis_client.keys('session:*')
        for key in session_keys:
            try:
                data = redis_client.get(key)
                if data:
                    sess = json.loads(data)
                    if 'created_at' in sess:
                        old_val = sess['created_at']
                        new_val = convert_timestamp_to_ist(old_val)
                        if old_val != new_val:
                            sess['created_at'] = new_val
                            ttl = redis_client.ttl(key)
                            if ttl > 0:
                                redis_client.setex(key, ttl, json.dumps(sess))
                            else:
                                redis_client.set(key, json.dumps(sess))
                            report['sessions'] += 1
            except Exception as e:
                report['errors'].append(f"Session {key}: {e}")

        # 4. Migrate users
        user_keys = redis_client.keys('user:*')
        for key in user_keys:
            try:
                data = redis_client.get(key)
                if data:
                    user_data = json.loads(data)
                    if 'created_at' in user_data:
                        old_val = user_data['created_at']
                        new_val = convert_timestamp_to_ist(old_val)
                        if old_val != new_val:
                            user_data['created_at'] = new_val
                            redis_client.set(key, json.dumps(user_data))
                            report['users'] += 1
            except Exception as e:
                report['errors'].append(f"User {key}: {e}")

        report['total'] = report['quiz_attempts'] + report['paused_practice'] + report['sessions'] + report['users']
        
    except Exception as e:
        report['errors'].append(f"Global: {e}")
        
    return report
