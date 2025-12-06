# database.py
"""
Redis-based session storage for JWT authentication.
Supports single-session enforcement where logging in on Device B logs out Device A.
"""

import redis
import json
import os
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
