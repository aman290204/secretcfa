# app.py
from flask import Flask, render_template_string, jsonify, send_file, abort, request, redirect, url_for, session
from functools import wraps
import json, os
from werkzeug.utils import secure_filename
import re
from html import unescape
from datetime import datetime, timedelta, timezone
import jwt
import secrets

# India Standard Time (UTC+5:30) for all timestamps
IST = timezone(timedelta(hours=5, minutes=30))
def get_ist_now():
    return datetime.now(IST)

# Import database functions for session management
import database as db

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Use environment variable in production

# Session configuration for Render - make it work in both local and deployed environments
# Only set SESSION_COOKIE_SECURE to True in production (HTTPS) environments
app.config['SESSION_COOKIE_SECURE'] = 'RENDER' in os.environ  # True on Render, False locally
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ---------- HEALTH CHECK SYSTEM FOR RENDER UPTIME ----------
# Dedicated lightweight endpoint - NO auth, NO Redis, NO side effects

@app.route('/health')
def health_check():
    """
    Render uptime health check endpoint.
    - No authentication required
    - No Redis/database access
    - No session handling
    - Returns immediately with plain text 'OK'
    """
    return 'OK', 200, {'Content-Type': 'text/plain'}

# Self-ping background thread to reduce cold starts
def start_self_ping():
    """Background thread that pings /health every 4 minutes"""
    import threading
    import urllib.request
    
    def ping_loop():
        import time as t
        # Get the base URL from environment or default to localhost
        base_url = os.environ.get('RENDER_EXTERNAL_URL', 'http://localhost:5000')
        health_url = f"{base_url}/health"
        
        while True:
            t.sleep(240)  # 4 minutes
            try:
                urllib.request.urlopen(health_url, timeout=10)
            except:
                pass  # Silently ignore failures
    
    # Start daemon thread (won't block app shutdown)
    ping_thread = threading.Thread(target=ping_loop, daemon=True)
    ping_thread.start()

# Start self-ping only on Render (not locally to avoid issues)
if 'RENDER' in os.environ:
    start_self_ping()

# Track login history for users (format: {user_id: [{'timestamp': ..., 'ip': ..., 'user_agent': ..., 'is_current': bool}]})
# login_history = {}  # Migrated to Redis

# History and recently viewed functions
def add_to_history(session, quiz_data):
    """Add a quiz attempt to user's history"""
    if 'history' not in session:
        session['history'] = []
    
    # Add timestamp
    quiz_data['timestamp'] = get_ist_now().isoformat()
    
    # Add to history (limit to 50 entries)
    session['history'].insert(0, quiz_data)
    if len(session['history']) > 50:
        session['history'] = session['history'][:50]
    
    # Save session
    session.modified = True

def get_user_history(session):
    """Get user's quiz history"""
    return session.get('history', [])

def add_to_recently_viewed(session, item_data):
    """Add an item to user's recently viewed list"""
    if 'recently_viewed' not in session:
        session['recently_viewed'] = []
    
    # Remove if already exists
    session['recently_viewed'] = [item for item in session['recently_viewed'] 
                                 if item['name'] != item_data['name']]
    
    # Add timestamp
    item_data['timestamp'] = get_ist_now().isoformat()
    
    # Add to beginning of list (limit to 10 entries)
    session['recently_viewed'].insert(0, item_data)
    if len(session['recently_viewed']) > 10:
        session['recently_viewed'] = session['recently_viewed'][:10]
    
    # Save session
    session.modified = True

def get_recently_viewed(session):
    """Get user's recently viewed items"""
    return session.get('recently_viewed', [])

# Module category mapping for sorting
MODULE_CATEGORIES = {
    'Quantitative Methods': (1, 11),
    'Economics': (12, 19),
    'Corporate Issuers': (20, 26),
    'Financial Statement Analysis': (27, 38),
    'Equity': (39, 46),
    'Fixed Income': (47, 65),
    'Derivatives': (66, 75),
    'Alternative Investments': (76, 82),
    'Portfolio Management': (83, 88),
    'Ethical and Professional Standards': (89, 93)
}

def get_module_number(filename):
    """Extract module number from filename like 'Module 1 Rates and Returns'"""
    import re
    match = re.search(r'Module\s+(\d+)', filename)
    return int(match.group(1)) if match else 0

def get_module_category(module_num):
    """Get category for a module number"""
    for category, (start, end) in MODULE_CATEGORIES.items():
        if start <= module_num <= end:
            return category
    return 'Unknown'

def get_topic_strengths(user_id):
    """
    Calculate % correct per CFA topic from user quiz attempts.
    Returns list of dicts: [{name, percent, correct, total}, ...]
    """
    attempts = db.get_user_quiz_attempts(user_id, limit=1000)
    
    # Initialize stats for each topic
    topic_stats = {}
    for topic_name in MODULE_CATEGORIES.keys():
        topic_stats[topic_name] = {'correct': 0, 'total': 0}
    
    # Aggregate correct/total from all attempts
    for attempt in attempts:
        quiz_name = attempt.get('quiz_name', '')
        module_num = get_module_number(quiz_name)
        if module_num == 0:
            continue  # Skip non-module quizzes (mocks, etc.)
        topic = get_module_category(module_num)
        if topic in topic_stats:
            topic_stats[topic]['correct'] += attempt.get('correct_count', 0)
            topic_stats[topic]['total'] += attempt.get('total_questions', 0)
    
    # Build results in curriculum order
    results = []
    for topic_name in MODULE_CATEGORIES.keys():
        stats = topic_stats[topic_name]
        pct = round(stats['correct'] / stats['total'] * 100) if stats['total'] > 0 else None
        results.append({
            'name': topic_name,
            'percent': pct,
            'correct': stats['correct'],
            'total': stats['total']
        })
    return results


def sort_modules(files, sort_type='id'):
    """Sort module files based on sort type"""
    modules = [f for f in files if f['is_module']]
    mocks = [f for f in files if f['is_mock']]
    
    if sort_type == 'id':
        modules.sort(key=lambda f: get_module_number(f['name']))
    elif sort_type == 'alphabetical':
        modules.sort(key=lambda f: f['display_name'].lower())
    elif sort_type == 'reverse_alphabetical':
        modules.sort(key=lambda f: f['display_name'].lower(), reverse=True)
    elif sort_type == 'category':
        modules.sort(key=lambda f: (
            MODULE_CATEGORIES.get(get_module_category(get_module_number(f['name'])), (999, 999))[0],
            get_module_number(f['name'])
        ))
    
    # Return mocks first, then sorted modules
    return mocks + modules

# ========== SECURITY & USER MANAGEMENT ==========

def is_user_valid(user):
    """Check if user account is still valid based on expiry date (UTC)"""
    if not user or not user.get('expiry'):
        return True  # No expiry date means valid forever
    
    try:
        from datetime import datetime
        expiry_date = datetime.fromisoformat(user['expiry'])
        current_date = get_ist_now()
        return current_date <= expiry_date
    except:
        return True  # Fallback to valid on parse error

def verify_jwt_token(token):
    """Verify JWT token and return payload if valid"""
    try:
        return jwt.decode(token, app.secret_key, algorithms=['HS256'])
    except:
        return None

def add_user(user_id, password, name, expiry=None, role="user"):
    """Add a new user via Redis"""
    if db.get_user(user_id): return False, "User ID already exists"
    user_data = {'id': user_id, 'password': password, 'name': name, 'role': role, 'expiry': expiry}
    return (True, "User added successfully") if db.store_user(user_data) else (False, "Failed to store user")

def remove_user(user_id):
    """Remove a user via Redis"""
    return (True, "User removed successfully") if db.delete_user(user_id) else (False, "Failed to delete user")

def edit_user(user_id, name=None, role=None, expiry=None, password=None, exam_date=None):
    """Edit an existing user via Redis"""
    user = db.get_user(user_id)
    if not user: return False, "User not found"
    if name is not None: user['name'] = name
    if role is not None: user['role'] = role
    if expiry is not None: user['expiry'] = expiry if expiry else None
    if password is not None and password: user['password'] = password
    if exam_date is not None: user['exam_date'] = exam_date if exam_date else None
    return (True, "User updated successfully") if db.store_user(user) else (False, "Failed to update user")

def get_user_by_id(user_id):
    """Get user with validity status"""
    user = db.get_user(user_id)
    if user: user['is_valid'] = is_user_valid(user)
    return user

def authenticate_user(user_id, password):
    """Authenticate user strictly using Redis data"""
    user = db.get_user(user_id)
    if user and user['password'] == password:
        return user if is_user_valid(user) else None
    return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. JWT Signature & Session existence
        jwt_token = session.get('jwt_token')
        if not jwt_token:
            return redirect(url_for('login'))
        
        payload = verify_jwt_token(jwt_token)
        if not payload:
            session.clear()
            return redirect(url_for('login'))
            
        user_id = payload.get('uid')
        session_token = payload.get('tok')
        
        # 2. User existence in Redis
        user = db.get_user(user_id)
        if not user:
            session.clear()
            return redirect(url_for('login'))
            
        # 3. Account Expiry Check
        if not is_user_valid(user):
            session.clear()
            return render_template_string(LOGIN_TEMPLATE, error="Your account has expired. Please contact support.")
            
        # 4. Session token verification (Single session enforcement)
        if not db.verify_session_token(user_id, session_token):
            session.clear()
            return redirect(url_for('login'))
            
        # Success - populate session for easy template access
        session['user_role'] = user.get('role', 'user')
        session['user_name'] = user.get('name', 'User')
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. JWT & Basic Auth
        jwt_token = session.get('jwt_token')
        if not jwt_token:
            return redirect(url_for('login'))
            
        payload = verify_jwt_token(jwt_token)
        if not payload:
            session.clear()
            return redirect(url_for('login'))
            
        user_id = payload.get('uid')
        session_token = payload.get('tok')
        
        # 2. Admin Existence & Role Check (Redis ONLY)
        user = db.get_user(user_id)
        if not user or user.get('role') != 'admin':
            # Redirect to menu with error if not admin
            return redirect(url_for('menu', error="Access denied. Admin privileges required."))
        
        # 3. Expiry & Session Check
        if not is_user_valid(user) or not db.verify_session_token(user_id, session_token):
             session.clear()
             return redirect(url_for('login'))
             
        return f(*args, **kwargs)
    return decorated_function

# config
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Handle both 'data' and 'Data' folders for case-sensitivity on Render
DATA_FOLDER: str
data_folder_temp = None
for folder_name in ["data", "Data"]:
    potential_path = os.path.join(BASE_DIR, folder_name)
    if os.path.exists(potential_path):
        data_folder_temp = potential_path
        break

# Create data folder if it doesn't exist
if data_folder_temp is None:
    DATA_FOLDER = os.path.join(BASE_DIR, "data")
    os.makedirs(DATA_FOLDER, exist_ok=True)
else:
    DATA_FOLDER = data_folder_temp
UPLOAD_FOLDER = DATA_FOLDER

# places from which we allow loading files (absolute paths)
ALLOWED_DIRS = [
    BASE_DIR,
    DATA_FOLDER,
    # "/mnt/data"  # include this if you use the /mnt/data location
]

# helper: safe absolute path check
def is_allowed_path(abs_path):
    abs_path = os.path.abspath(abs_path)
    for d in ALLOWED_DIRS:
        if abs_path.startswith(os.path.abspath(d) + os.sep) or abs_path == os.path.abspath(d):
            return True
    return False


# ========== JWT Authentication Functions ==========

# JWT secret key (use the same as Flask secret key)
JWT_SECRET_KEY = app.secret_key
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_DAYS = 10  # Token expires in 10 days


def generate_session_token():
    """Generate a cryptographically secure random session token"""
    return secrets.token_urlsafe(32)


def create_jwt_token(user_id, session_token, user_name='', user_role='user'):
    """
    Create a JWT token with user information and session token.
    
    Args:
        user_id: The user's ID
        session_token: Unique session token stored in Redis
        user_name: User's full name (optional)
        user_role: User's role (admin/user)
    
    Returns:
        JWT token string
    """
    payload = {
        'uid': user_id,              # User ID
        'tok': session_token,        # Unique session token (stored in Redis)
        'name': user_name,           # User's name
        'role': user_role,           # User's role
        'exp': datetime.utcnow() + timedelta(days=JWT_EXPIRATION_DAYS),  # Expiration
        'iat': datetime.utcnow(),    # Issued at
    }
    
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


def verify_jwt_token(token):
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded payload dict if valid, None if invalid/expired
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        print("⚠️  JWT token expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"⚠️  Invalid JWT token: {e}")
        return None


def clean_html(raw_html):
    """Strip HTML tags for plain text rendering (used for legacy content)"""
    text = re.sub('<[^<]+?>', '', raw_html)  # remove HTML tags
    return unescape(text).strip()

def preserve_html(raw_html):
    """Preserve HTML content and properly format it for display"""
    if not raw_html:
        return ""
    # Decode HTML entities
    content = unescape(raw_html)
    return content.strip()

def _find_items_structure(raw):
    """
    Try several common shapes for question lists and return a list of item dicts.
    """
    if isinstance(raw, dict) and "items" in raw and isinstance(raw["items"], list):
        return raw["items"]
    if isinstance(raw, dict) and "quiz" in raw and isinstance(raw["quiz"], dict) and "items" in raw["quiz"]:
        return raw["quiz"]["items"]
    if isinstance(raw, list):
        return raw
    # fallback: search for first list-of-dicts value
    if isinstance(raw, dict):
        for v in raw.values():
            if isinstance(v, list) and len(v) and isinstance(v[0], dict):
                return v
    return [raw]  # treat whole file as a single item


def load_questions_from_file(path):
    """
    Load and normalize questions from a JSON file.
    Returns (questions_list, raw_json).
    Each question is normalized to a dict with keys:
      id, title, stem, choices (list of {id,text}), correct (id or None),
      correct_label (A/B/...), feedback (dict).
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    items = _find_items_structure(raw)

    def get_entry(item):
        if isinstance(item, dict) and "entry" in item and isinstance(item["entry"], dict):
            return item["entry"]
        return item if isinstance(item, dict) else {}

    questions = []
    for it in items:
        e = get_entry(it)

        raw_stem = e.get("itemBody") or e.get("stem") or e.get("question") or ""
        # Preserve HTML for tables and other formatted content
        stem = preserve_html(raw_stem)

        choices_src = (e.get("interactionData") or {}).get("choices") or e.get("choices") or []
        choices = []

        if isinstance(choices_src, list):
            for idx, ch in enumerate(choices_src):
                if isinstance(ch, dict):
                    text = ch.get("itemBody") or ch.get("text") or ch.get("choiceText") or ""
                    # Preserve HTML for answer choices as well
                    choices.append({
                        "id": ch.get("id") or ch.get("choiceId") or str(idx),
                        "text": preserve_html(text)
                    })
                elif isinstance(ch, str):
                    choices.append({"id": str(idx), "text": preserve_html(ch)})

                # determine correct answer id (may appear in multiple formats)
        correct_id = None
        scoring = e.get("scoringData") or {}
        if isinstance(scoring, dict):
            correct_id = scoring.get("value") or scoring.get("id")

        # handle alternate keys for correct answer
        if not correct_id:
            correct_id = e.get("correct") or e.get("answer") or e.get("answerKey")

        # if correct answer is a single letter (A/B/C/...), map it to choice id
        if correct_id and len(correct_id) == 1 and correct_id.upper() in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            idx = ord(correct_id.upper()) - 65
            if 0 <= idx < len(choices):
                correct_id = choices[idx].get("id")


        # compute label (A/B/C...)
        correct_label = None
        if correct_id:
            for idx, c in enumerate(choices):
                if (c.get("id") or "") == correct_id:
                    correct_label = chr(65 + idx)
                    break

                # combine answerFeedback and feedback.neutral
        feedback = e.get("answerFeedback") or {}
        if not feedback and e.get("feedback"):
            feedback = e.get("feedback")  # fallback to 'feedback' if answerFeedback is empty

        cleaned_feedback = {}
        if isinstance(feedback, dict):
            for k, v in feedback.items():
                # Preserve HTML in feedback content for proper rendering
                cleaned_feedback[k] = preserve_html(v) if v else ""
        else:
            cleaned_feedback = {"neutral": preserve_html(feedback) if feedback else ""}

        q = {
            "id": it.get("id") or e.get("id") or "",
            "title": e.get("title") or "",
            "stem": stem,
            "choices": choices,
            "correct": correct_id,
            "correct_label": correct_label,
            "feedback": cleaned_feedback,
        }
        questions.append(q)

    return questions, raw

# ---------- NEW ROUTES ----------

@app.route("/data-file-name/<path:filename>")
def data_file_name_route(filename):
    """
    Load and render the UI with the specified filename (relative or absolute).
    Only files inside ALLOWED_DIRS are permitted.
    Example:
      /data-file-name/data1.json
      /data-file-name/uploads/myfile.json
      /data-file-name/relative/path/to/file.json
    """
    # try to resolve possible absolute or relative paths
    # if filename looks like absolute, use it; else join with BASE_DIR and /mnt/data and uploads
    tried_paths = []

    # direct absolute?
    if os.path.isabs(filename):
        tried_paths.append(filename)
    else:
        # common places: BASE_DIR, DATA_FOLDER, UPLOAD_FOLDER
        tried_paths.append(os.path.join(BASE_DIR, filename))
        tried_paths.append(os.path.join(DATA_FOLDER, filename))
        tried_paths.append(os.path.join(UPLOAD_FOLDER, filename))

    # pick first existing allowed path
    chosen = None
    for p in tried_paths:
        if os.path.exists(p) and is_allowed_path(p):
            chosen = os.path.abspath(p)
            break

    if not chosen:
        return jsonify({"error": "file not found or not allowed", "tried": tried_paths}), 404
    
    # print(chosen)
    # Detect Quiz Mode and Metadata
    quiz_meta = raw.get("quiz", {})
    mode = "mock" if quiz_meta.get("type") == "mock_exam" else "practice"
    
    # Get Time Limit (default to 8100s for mocks if 0/missing)
    time_limit = quiz_meta.get("settings", {}).get("session_time_limit_in_seconds", 0)
    if mode == "mock" and not time_limit:
        time_limit = 8100
        
    # Determine if it's a module based on category/filename if not explicitly set
    is_module = not (mode == "mock")

    # render the TEMPLATE with mode and time_limit
    return render_template_string(
        TEMPLATE, 
        questions=questions, 
        total=len(questions), 
        data_source=os.path.basename(chosen), 
        show_home=True, 
        user_role=session.get('user_role', 'user'),
        mode=mode,
        time_limit=time_limit,
        is_mock=(mode == "mock"),
        is_module=is_module,
        quiz_title=quiz_meta.get("name", "Quiz Viewer")
    )

TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Quiz Viewer — All Questions</title>
<style>
:root{--bg:#121212;--card:#0A2540;--card-border:#1a3a5c;--muted:#94a3b8;--accent:#0052A5;--accent-dark:#003d7a;--accent-light:#4d8fd6;--success:#2E7D32;--danger:#C62828;--warning:#fbbf24;--text-primary:#FAFAFA;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37;--jewel-emerald:#2E7D32;--jewel-sapphire:#0052A5;--jewel-amethyst:#6c5ce7;--jewel-ruby:#C62828;--glass-bg:rgba(255,255,255,0.05);--glass-border:rgba(255,255,255,0.1);--sidebar-width:210px}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, var(--bg) 0%, #0A2540 100%);color:var(--text-primary);min-height:100vh;display:flex}
/* Emoji color fix - ensures emojis render with native colors */
.emoji,.sidebar-item-icon{-webkit-text-fill-color:initial;color:inherit}
.container{max-width:1100px;margin:28px auto;padding:0 18px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;background:var(--glass-bg);backdrop-filter:blur(10px);padding:16px;border-radius:12px;border:1px solid var(--glass-border);animation:slideDown 0.4s ease}
.exam-title{font-weight:700;font-size:18px;background:linear-gradient(135deg, var(--accent-light) 0%, var(--gold) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.time-box{padding:8px 12px;border-radius:8px;background:var(--glass-bg);border:1px solid var(--glass-border);font-weight:600;transition:all 0.3s ease;color:var(--accent-light);min-width:110px;text-align:center}
.time-box.warning{color:#facc15}
.time-box.danger{color:#f87171}
.time-box:hover{transform:scale(1.05);box-shadow:0 0 20px rgba(167,139,250,0.3);background:rgba(167,139,250,0.1)}
.card{background:var(--card);padding:22px;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.3);transition:all 0.3s ease;border:1px solid var(--card-border);position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg, transparent, var(--gold), transparent);opacity:0;transition:opacity 0.3s ease}
.card:hover{transform:translateY(-5px);box-shadow:0 16px 40px rgba(167,139,250,0.2);border-color:var(--accent)}
.card:hover::before{opacity:1}
.q-header{display:flex;align-items:flex-start;gap:12px}
.q-num{background:linear-gradient(135deg, var(--jewel-amethyst) 0%, var(--jewel-sapphire) 100%);padding:8px 12px;border-radius:8px;font-weight:700;transition:all 0.3s ease;color:#000;min-width:40px;text-align:center}
.q-num:hover{transform:scale(1.1) rotate(5deg);box-shadow:0 0 20px rgba(167,139,250,0.4)}
.question-text{font-size:15px;line-height:1.6;color:var(--text-secondary)}
/* Table styling for question content - override white backgrounds */
.question-text table,.card table,table{background:var(--card) !important;border-collapse:collapse;width:100%;margin:12px 0;border-radius:8px;overflow:hidden}
.question-text table *,.card table *{background:transparent !important;color:var(--text-secondary) !important}
.question-text th,.card th,th{background:rgba(255,255,255,0.05) !important;color:var(--text-primary) !important;padding:10px 12px;border:1px solid var(--card-border);font-weight:600;text-align:left}
.question-text td,.card td,td{padding:10px 12px;border:1px solid var(--card-border);color:var(--text-secondary) !important}
.question-text tr:nth-child(even),.card tr:nth-child(even){background:rgba(255,255,255,0.02) !important}
.choices{margin-top:14px;border-top:1px solid var(--card-border);padding-top:14px}
.choice-item{display:flex;align-items:flex-start;gap:10px;padding:10px;border-radius:8px;cursor:pointer;transition:all 0.2s ease;color:var(--text-secondary)}
.choice-item:hover{background:rgba(167,139,250,0.1);transform:translateX(5px);border-radius:8px}
.controls{display:flex;justify-content:space-between;align-items:center;margin-top:18px}
.btn{padding:10px 14px;border-radius:8px;border:1px solid var(--glass-border);background:var(--glass-bg);cursor:pointer;font-weight:600;transition:all 0.2s ease;color:var(--text-secondary)}
.btn:hover{transform:translateY(-2px);box-shadow:0 4px 16px rgba(167,139,250,0.2);border-color:var(--accent)}
.btn.primary{background:linear-gradient(135deg, var(--accent-dark) 0%, var(--accent) 100%);color:#fff;border:none}
.btn.primary:hover{background:linear-gradient(135deg, var(--accent) 0%, var(--accent-light) 100%);box-shadow:0 8px 24px rgba(167,139,250,0.4)}
.btn.sort{background:rgba(94,109,127,0.5);color:var(--text-secondary);border:1px solid var(--glass-border)}
.btn.sort:hover{background:rgba(139,92,246,0.3);color:var(--accent-light);transform:translateY(-2px);box-shadow:0 4px 16px rgba(167,139,250,0.3)}
.result{margin-top:12px;padding:12px;border-radius:8px;font-size:14px;animation: fadeIn 0.5s ease-in}
.result.correct{background:rgba(52,211,153,0.15);border:1px solid rgba(52,211,153,0.4);color:var(--success)}
.result.wrong{background:rgba(244,63,94,0.15);border:1px solid rgba(244,63,94,0.4);color:var(--danger)}
.result.info{background:rgba(167,139,250,0.15);border:1px solid rgba(167,139,250,0.4);color:var(--accent-light)}
.explain{margin-top:10px;color:var(--text-muted);background:var(--glass-bg);padding:12px;border-radius:8px;border:1px solid rgba(52,211,153,0.2)}
.goto{display:flex;gap:6px;align-items:center}
input[type="radio"]{width:18px;height:18px;margin-top:3px}
.progress-bar{height:8px;background:rgba(255,255,255,0.1);border-radius:4px;margin-top:16px;overflow:hidden;border:1px solid var(--card-border)}
.progress-fill{height:100%;background:var(--accent);transition:width 0.3s ease}
.progress-text{font-size:12px;color:var(--muted);margin-top:4px;text-align:right}
.final-results{background:var(--card);padding:30px;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.4);text-align:center;animation: fadeIn 0.5s ease-in;border:1px solid var(--card-border)}
.final-score{font-size:48px;font-weight:800;color:var(--accent-light);margin:20px 0}
.final-message{font-size:18px;margin:20px 0;color:var(--text-primary)}
.review-btn{padding:12px 24px;background:var(--accent);color:#fff;border:none;border-radius:8px;font-weight:600;margin:10px;cursor:pointer;transition:all 0.3s ease}
.review-btn:hover{background:var(--accent-dark);transform:translateY(-3px);box-shadow:0 6px 16px rgba(0,82,165,0.3)}
.score-details{margin:20px 0;text-align:left}
.score-details h3{color:var(--text-primary);margin-bottom:15px}
.question-review{padding:12px 16px;margin:8px 0;border-left:4px solid var(--muted);background:rgba(255,255,255,0.05);transition:all 0.3s ease;border-radius:0 8px 8px 0;color:var(--text-primary)}
.question-review:hover{transform:translateX(5px);background:rgba(255,255,255,0.08)}
.question-review.correct{border-left-color:var(--success);background:rgba(46,125,50,0.1)}
.question-review.incorrect{border-left-color:var(--danger);background:rgba(198,40,40,0.1)}
.question-review.skipped{border-left-color:var(--warning);background:rgba(251,191,36,0.1)}
.sort-controls{display:flex;gap:10px;align-items:center;margin-bottom:15px;flex-wrap:wrap}
.sort-label{font-weight:600;color:var(--text-secondary)}
/* Table styles for HTML content rendering */
.question-text table, .choice-item table{
  width:100% !important;border-collapse:collapse !important;margin:15px 0 !important;border:1px solid rgba(167,139,250,0.3) !important;font-size:14px;background:var(--glass-bg) !important
}
.question-text table thead, .choice-item table thead{display:table-header-group}
.question-text table tbody, .choice-item table tbody{display:table-row-group}
.question-text table tr, .choice-item table tr{display:table-row}
.question-text table th, .question-text table td, .choice-item table th, .choice-item table td{
  display:table-cell;padding:12px !important;border:1px solid rgba(167,139,250,0.2) !important;text-align:left !important;background:transparent !important;vertical-align:middle;color:var(--text-secondary) !important
}
.question-text table th, .choice-item table th{
  background:rgba(167,139,250,0.2) !important;font-weight:600 !important;color:var(--accent-light) !important;text-align:center !important
}
.question-text table td, .choice-item table td{background:transparent !important}
.question-text table td[style*="text-align: center"], .question-text table th[style*="text-align: center"],
.choice-item table td[style*="text-align: center"], .choice-item table th[style*="text-align: center"]{
  text-align:center !important
}
.question-text p, .question-text span, .choice-item p, .choice-item span{line-height:1.6;margin:10px 0;color:var(--text-secondary)}
@keyframes fadeIn {
  from {opacity: 0; transform: translateY(-10px);}
  to {opacity: 1; transform: translateY(0);}
}
@keyframes slideDown {
  from {opacity: 0; transform: translateY(-20px);}
  to {opacity: 1; transform: translateY(0);}
}
@media(max-width:900px){ .card{padding:14px} }

body.sidebar-collapsed .sidebar{transform:translateX(-100%)}
body.sidebar-collapsed .main-content{margin-left:0}
.sidebar-toggle{background:none;border:none;font-size:24px;color:var(--text-primary);cursor:pointer;padding:8px;margin-right:15px;display:flex;align-items:center;justify-content:center;border-radius:8px;transition:background 0.2s}
.sidebar-toggle:hover{background:rgba(255,255,255,0.1)}
</style>
</head>
<body>
<div class="container">
  <div class="topbar">
    <div>
      <div class="exam-title">{{ quiz_title }}</div>
      <div style="color:var(--muted);font-size:13px">Source: {{ data_source }} | Mode: {{ mode|capitalize }}</div>
    </div>
    <div style="display:flex;gap:8px;align-items:center">
      <a href="/menu" class="btn" style="text-decoration:none;color:#fff">🏠 Home</a>
      <a href="/logout" class="btn" style="text-decoration:none;color:#fff">Logout</a>
      <div class="time-box" id="timer">--:--:--</div>
    </div>
  </div>

  <div class="card" id="card">
    <div class="q-header">
      <div class="q-num" id="qnum">1</div>
      <div style="flex:1">
        <div style="color:var(--muted);font-size:13px" id="qtitle">Multiple Choice</div>
        <div class="question-text" id="stem">Loading…</div>
      </div>
    </div>

    <div class="progress-bar">
      <div class="progress-fill" id="progressFill" style="width: 0%"></div>
    </div>
    <div class="progress-text" id="progressText">0 of {{ total }} questions answered</div>

    <form id="form" onsubmit="return false;">
      <div class="choices" id="choices"></div>

      <div class="controls">
        <div>
          <button type="button" class="btn" id="prev">← Previous</button>
          <button type="button" class="btn" id="next">Next →</button>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          <div class="goto">
            <label style="font-size:13px;color:var(--muted)">Go to</label>
            <input id="gotoInput" type="number" min="1" style="width:64px;padding:6px;border-radius:6px;border:1px solid #e6eef6;margin-left:6px"/>
            <button class="btn" id="gotoBtn" type="button">Go</button>
          </div>
          <button type="button" class="btn" id="flagBtn" onclick="toggleFlag()" style="background:var(--glass-bg);border:1px solid var(--glass-border)">🏳️ Flag</button>
          <button type="button" class="btn" id="skip">Skip</button>
          {% if mode != 'mock' %}
          <button type="button" class="btn" id="pauseBtn" onclick="pausePractice()" style="background:#f59e0b;color:#000">⏸️ Pause</button>
          {% endif %}
          <button type="button" class="btn primary" id="submit">Submit Answer</button>
          <button type="button" class="btn primary" id="finish">✅ Finish & Save Score</button>

        </div>
      </div>
    </form>

    <div id="feedback"></div>
  </div>

  <div id="finalResults" class="final-results" style="display:none;">
    <h2>Exam Results</h2>
    <div class="final-score" id="finalScore">0%</div>
    <div class="final-message" id="finalMessage"></div>
    <div id="scoreDetails"></div>
    <button class="review-btn" id="reviewAnswers">Review Answers</button>
    <button class="review-btn" onclick="location.reload()">Retake Exam</button>
  </div>
</div>

<script>
const questions = {{ questions | tojson }};
const total = questions.length;
const resumeData = {{ resume_data | tojson }};

// Resuming logic: start from the first unanswered question if resumeData exists
let idx = 0;
if (resumeData.user_answers) {
  const firstUnanswered = resumeData.user_answers.findIndex(ans => ans === null);
  idx = (firstUnanswered === -1) ? (resumeData.last_index || 0) : firstUnanswered;
} else if (resumeData.hasOwnProperty('last_index')) {
  idx = resumeData.last_index;
}

let userAnswers = resumeData.user_answers || new Array(total).fill(null);
let questionStatus = userAnswers.map(ans => ans !== null); 
let currentQuestions = [...questions]; 
let originalOrder = [...Array(total).keys()]; 

// Per-question time tracking
let questionTimes = resumeData.question_times || new Array(total).fill(0);
let questionFlags = resumeData.question_flags || new Array(total).fill(false);
let questionTimeStart = Date.now(); 

// Mode Constants from Backend
const MODE = "{{ mode }}";
const TIME_LIMIT = {{ time_limit }}; 
const IS_MOCK = MODE === "mock";

// Timer Persistence logic
let remainingTime;
let timerStart = Date.now() - ((resumeData.total_time || 0) * 1000);
const startedAtISO = resumeData.hasOwnProperty('started_at') ? resumeData.started_at : new Date().toISOString();

if (IS_MOCK) {
  syncTimerWithServer();
} else {
  // Practice mode upward timer
  startPracticeTimer();
}

async function syncTimerWithServer() {
  try {
    const res = await fetch(`/api/mock/timer-status?quiz_id={{ data_source }}&duration=${TIME_LIMIT}`);
    const data = await res.json();
    remainingTime = data.remaining_seconds;
    
    if (remainingTime <= 0) {
      console.log("⏰ Timer already expired. Auto-submitting...");
      autoSubmitMock();
    } else {
      startMockTimer();
    }
  } catch (err) {
    console.error("Timer sync failed", err);
    remainingTime = TIME_LIMIT;
    startMockTimer();
  }
}

function formatTime(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;

  if (h > 0) {
    return `${h.toString().padStart(2, "0")}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
  }
  return `${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
}

function startMockTimer() {
  const timerEl = document.getElementById("timer");
  
  // Initial display
  timerEl.textContent = formatTime(remainingTime);
  
  const interval = setInterval(() => {
    remainingTime--;
    
    // Check if expired
    if (remainingTime <= 0) {
      clearInterval(interval);
      autoSubmitMock();
    }
    
    timerEl.textContent = formatTime(remainingTime);
    
    // Warning colors
    if (remainingTime <= 300) {
      timerEl.classList.add("danger");
      timerEl.classList.remove("warning");
    } else if (remainingTime <= 1800) {
      timerEl.classList.add("warning");
    }
    
    // Auto-submit at 0
    if (remainingTime <= 0) {
      clearInterval(interval);
      autoSubmitMock();
    }
  }, 1000);
}

function startPracticeTimer() {
  const timerEl = document.getElementById("timer");
  setInterval(() => {
    const elapsed = Math.floor((Date.now() - timerStart) / 1000);
    timerEl.textContent = formatTime(elapsed);
  }, 1000);
}

function autoSubmitMock() {
  // Use a non-blocking notification or immediate action
  console.log("Time is up. Submitting exam...");
  showFinalResults();
}

function saveAttemptToServer(attemptData) {
  // Send quiz attempt data to the server
  fetch('/api/save-attempt', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(attemptData)
  }).then(response => response.json())
    .then(data => {
      if (data.success) {
        console.log('Quiz attempt saved successfully:', data.attempt_id);
      } else {
        console.error('Failed to save quiz attempt:', data.error);
      }
    })
    .catch(err => {
      console.error('Error saving quiz attempt:', err);
    });
}

// ========== PAUSE & RESUME FUNCTIONALITY (Practice Only) ==========
const QUIZ_NAME = "{{ quiz_title }}";
let quizCompleted = false;

function pausePractice() {
  if (IS_MOCK) return; // Never pause mocks
  
  // Update time for current question before pausing
  const now = Date.now();
  questionTimes[idx] += Math.floor((now - questionTimeStart) / 1000);
  
  const pauseData = {
    module_id: QUIZ_NAME,
    started_at: startedAtISO,
    last_question_index: idx,
    user_answers: userAnswers,
    question_times: questionTimes,
    question_flags: questionFlags,
    total_time_seconds: Math.floor((now - timerStart) / 1000)
  };
  
  // Disable button to prevent double-clicks
  const pauseBtn = document.getElementById('pauseBtn');
  if (pauseBtn) {
    pauseBtn.disabled = true;
    pauseBtn.textContent = '⏳ Saving...';
  }
  
  // Use fetch with async - wait for server confirmation before redirect
  fetch('/api/pause-practice', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(pauseData)
  })
  .then(response => response.json())
  .then(data => {
    if (data.status === 'success') {
      console.log('✅ Practice paused successfully');
      window.location.href = '/menu';
    } else {
      alert('Failed to pause: ' + (data.message || 'Unknown error'));
      if (pauseBtn) {
        pauseBtn.disabled = false;
        pauseBtn.textContent = '⏸️ Pause';
      }
    }
  })
  .catch(err => {
    console.error('Error pausing:', err);
    alert('Failed to pause. Please try again.');
    if (pauseBtn) {
      pauseBtn.disabled = false;
      pauseBtn.textContent = '⏸️ Pause';
    }
  });
}

// Auto-pause on tab close, refresh, or navigation (Practice only)
if (!IS_MOCK) {
  window.addEventListener('beforeunload', function(e) {
    if (quizCompleted) return; // Don't pause if already completed
    
    // Update time for current question
    const now = Date.now();
    questionTimes[idx] += Math.floor((now - questionTimeStart) / 1000);
    
    const pauseData = {
      module_id: QUIZ_NAME,
      started_at: startedAtISO,
      last_question_index: idx,
      user_answers: userAnswers,
      question_times: questionTimes,
      question_flags: questionFlags,
      total_time_seconds: Math.floor((now - timerStart) / 1000)
    };
    
    // sendBeacon is reliable even during page unload
    navigator.sendBeacon('/api/pause-practice',
      new Blob([JSON.stringify(pauseData)], {type: 'application/json'})
    );
  });
  
  // Check for paused attempt on page load
  checkForPausedAttempt();
}

async function checkForPausedAttempt() {
  try {
    const res = await fetch(`/api/get-paused-practice?module_id=${encodeURIComponent(QUIZ_NAME)}`);
    const data = await res.json();
    
    if (data.paused_attempt) {
      const paused = data.paused_attempt;
      
      // Restore state
      idx = paused.last_question_index || 0;
      userAnswers = paused.user_answers || new Array(total).fill(null);
      questionTimes = paused.question_times || new Array(total).fill(0);
      questionFlags = paused.question_flags || new Array(total).fill(false);
      
      // Update questionStatus based on restored answers
      for (let i = 0; i < userAnswers.length; i++) {
        questionStatus[i] = userAnswers[i] !== null;
      }
      
      // Adjust timer start to account for previously elapsed time
      const previousElapsed = paused.total_time_seconds || 0;
      timerStart = Date.now() - (previousElapsed * 1000);
      
      // Reset question time start
      questionTimeStart = Date.now();
      
      // Re-render current question with restored state
      render();
      updateProgress();
      
      console.log(`✅ Resumed from question ${idx + 1}, elapsed time: ${previousElapsed}s`);
    }
  } catch (err) {
    console.log('No paused attempt found or error:', err);
  }
}

// Clear paused state on quiz completion
function clearPausedState() {
  if (IS_MOCK) return;
  quizCompleted = true;
  
  fetch('/api/clear-paused-practice', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({module_id: QUIZ_NAME})
  }).catch(err => console.log('Error clearing paused state:', err));
}


function updateProgress() {
  const answeredCount = questionStatus.filter(status => status).length;
  const progressPercent = (answeredCount / total) * 100;
  document.getElementById('progressFill').style.width = progressPercent + '%';
  document.getElementById('progressText').textContent = `${answeredCount} of ${total} questions answered`;
  
  // Update finish button text based on progress
  const finishBtn = document.getElementById('finish');
  if (answeredCount === total) {
    finishBtn.textContent = '🏁 Finish & Save Score';
    finishBtn.style.background = 'linear-gradient(135deg, var(--success) 0%, #4caf50 100%)';
  } else {
    finishBtn.textContent = `✅ Finish (${answeredCount}/${total})`;
    finishBtn.style.background = 'linear-gradient(135deg, var(--accent) 0%, var(--accent-light) 100%)';
  }
}

function stripHtml(html){
  const d = new DOMParser().parseFromString(html,'text/html');
  return d.body.textContent || '';
}

function toggleFlag() {
  questionFlags[idx] = !questionFlags[idx];
  const flagBtn = document.getElementById('flagBtn');
  if (flagBtn) {
    flagBtn.textContent = questionFlags[idx] ? '🚩 Flagged' : '🏳️ Flag';
    flagBtn.style.background = questionFlags[idx] ? 'var(--warning)' : 'var(--glass-bg)';
  }
  autoSave();
}

// Continuous progress saving (Practice only)
function autoSave() {
  if (IS_MOCK || quizCompleted) return;
  
  const now = Date.now();
  const currentElapsed = Math.floor((now - questionTimeStart) / 1000);
  const tempTimes = [...questionTimes];
  tempTimes[idx] += currentElapsed;
  
  // Build responses array for stats calculation (incomplete modules)
  const responses = [];
  userAnswers.forEach((ans, i) => {
    if (ans !== null) {
      const q = questions[i];
      responses.push({
        is_correct: q.correct && ans === q.correct,
        time_spent_seconds: tempTimes[i],
        user_answer: ans
      });
    }
  });

  const pauseData = {
    module_id: QUIZ_NAME,
    started_at: startedAtISO,
    last_question_index: idx,
    user_answers: userAnswers,
    question_times: tempTimes,
    question_flags: questionFlags,
    responses: responses,
    total_time_seconds: Math.floor((now - timerStart) / 1000)
  };
  
  // Use sendBeacon for non-blocking background save
  navigator.sendBeacon('/api/pause-practice', 
    new Blob([JSON.stringify(pauseData)], {type: 'application/json'})
  );
}

function render(i){
  // Save time for previous question before switching
  if (typeof idx !== 'undefined' && idx !== i) {
    const elapsed = Math.floor((Date.now() - questionTimeStart) / 1000);
    questionTimes[idx] += elapsed;
  }
  // Reset timer for new question
  questionTimeStart = Date.now();
  
  idx = i;
  autoSave(); // Save current index
  const q = currentQuestions[i];
  document.getElementById('qnum').textContent = (i+1) + ' / ' + total;
  document.getElementById('stem').innerHTML = q.stem ? q.stem : (q.title || ''); 
  const choicesWrap = document.getElementById('choices');
  choicesWrap.innerHTML = '';
  (q.choices || []).forEach((c,j)=>{
    const label = document.createElement('label');
    label.className = 'choice-item';
    const isChecked = userAnswers[i] === c.id ? 'checked' : '';
    label.innerHTML = `<input type="radio" name="choice" value="${c.id}" id="opt-${j}" ${isChecked}> <div style="font-size:14px">${c.text ? c.text : ''}</div>`;
    label.addEventListener('click', ()=> { 
      document.getElementById('feedback').innerHTML=''; 
      // Auto-save on choice selection
      if (!IS_MOCK) {
        const selectedInput = label.querySelector('input');
        if (selectedInput) {
          userAnswers[idx] = selectedInput.value;
          autoSave();
        }
      }
    });
    
    if (IS_MOCK) {
      label.addEventListener('click', ()=> {
        setTimeout(() => {
          submitAnswerAutomatically(c.id);
        }, 100);
      });
    }
    
    choicesWrap.appendChild(label);
  });
  
  document.getElementById('feedback').innerHTML = '';
  document.getElementById('gotoInput').value = '';
  
  // Update flag button state
  const flagBtn = document.getElementById('flagBtn');
  if (flagBtn) {
    flagBtn.textContent = questionFlags[i] ? '🚩 Flagged' : '🏳️ Flag';
    flagBtn.style.background = questionFlags[i] ? 'var(--warning)' : 'var(--glass-bg)';
  }
  
  // Hide/Show Submit and Skip based on Mode
  if (IS_MOCK) {
    document.getElementById('submit').style.display = 'none';
    document.getElementById('skip').style.display = 'none';
  } else {
    document.getElementById('submit').style.display = 'inline-block';
    document.getElementById('skip').style.display = 'inline-block';
  }

  if (userAnswers[i]) {
    const prevSelected = document.querySelector(`input[value="${userAnswers[i]}"]`);
    if (prevSelected) prevSelected.checked = true;
  }
}

function submitAnswerAutomatically(choiceId) {
  // Only for mock exams - auto-submit when answer is selected
  if (!IS_MOCK) return;
  
  const fbDiv = document.getElementById('feedback');
  fbDiv.innerHTML = '';
  
  userAnswers[idx] = choiceId;
  questionStatus[idx] = true;
  updateProgress();
  
  const q = currentQuestions[idx];
  const correct = q.correct || null;
  
  // Store the result but don't show the answer immediately (mock exam behavior)
  fbDiv.innerHTML = `<div class="result info">Answer submitted. You can review all answers after completing the exam.</div>`;
}

// Function to save quiz attempt to server (Redis)
async function saveAttemptToServer(attemptData) {
  try {
    const response = await fetch('/api/save-attempt', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(attemptData)
    });
    
    const result = await response.json();
    if (result.status === 'success') {
      console.log('✅ Quiz attempt saved with ID:', result.attempt_id);
    } else {
      console.warn('⚠️ Failed to save attempt:', result.message);
    }
  } catch (error) {
    console.error('❌ Error saving quiz attempt:', error);
  }
}


function showFinalResults() {
  // Clear any paused state since quiz is now complete
  clearPausedState();
  
  // Calculate score (5 marks for correct, 0 for wrong/skipped)
  let correctCount = 0;
  let wrongCount = 0;
  let skippedCount = 0;
  let totalScore = 0;
  const maxPossibleScore = total * 5;
  
  // Build responses array for saving
  const responses = [];
  
  currentQuestions.forEach((q, i) => {
    const userAnswer = userAnswers[i];
    const isCorrect = userAnswer && q.correct && userAnswer === q.correct;
    
    if (isCorrect) {
      correctCount++;
      totalScore += 5;
    } else if (userAnswer) {
      wrongCount++;
    } else {
      skippedCount++;
    }
    
    // Build full choice snapshot with labels
    const choiceLabels = ['A', 'B', 'C', 'D', 'E', 'F'];
    const choicesSnapshot = (q.choices || []).map((c, ci) => ({
      id: c.id,
      label: choiceLabels[ci] || String(ci + 1),
      text: c.text || '',
      explanation: (q.feedback && q.feedback[c.id]) ? q.feedback[c.id] : ''
    }));
    
    // Determine user answer label
    let userAnswerLabel = null;
    if (userAnswer) {
      const userIdx = (q.choices || []).findIndex(c => c.id === userAnswer);
      userAnswerLabel = userIdx >= 0 ? choiceLabels[userIdx] : null;
    }
    
    // Determine correct answer label
    let correctAnswerLabel = null;
    if (q.correct) {
      const correctIdx = (q.choices || []).findIndex(c => c.id === q.correct);
      correctAnswerLabel = correctIdx >= 0 ? choiceLabels[correctIdx] : null;
    }
    
    responses.push({
      question_number: i + 1,
      question_id: q.id,
      question_text: q.stem || q.title || '',
      choices: choicesSnapshot,
      correct_answer: q.correct,
      correct_answer_label: correctAnswerLabel,
      user_answer: userAnswer,
      user_answer_label: userAnswerLabel,
      is_correct: isCorrect,
      time_spent_seconds: questionTimes[i] + Math.floor((Date.now() - questionTimeStart) / 1000),
      flagged: questionFlags[i],
      general_feedback: (q.feedback && q.feedback.general) ? q.feedback.general : ''
    });
  });
  
  const scorePercent = Math.round((correctCount / total) * 100);
  const submittedAtISO = new Date().toISOString();
  const timeSpent = Math.floor((Date.now() - timerStart) / 1000);
  
  // Save attempt to server with metadata and timestamps
  saveAttemptToServer({
    quiz_name: '{{ quiz_title }}',
    quiz_id: '{{ data_source }}',
    quiz_type: MODE,
    mode: MODE,
    started_at: startedAtISO,
    submitted_at: submittedAtISO,
    time_limit: TIME_LIMIT,
    total_questions: total,
    correct_count: correctCount,
    wrong_count: wrongCount,
    skipped_count: skippedCount,
    score_percent: scorePercent,
    time_spent_seconds: timeSpent,
    responses: responses
  });
  
  const displayScore = totalScore;
  
  // Hide quiz card and show results
  document.getElementById('card').style.display = 'none';
  document.getElementById('finalResults').style.display = 'block';
  
  // Display score
  document.getElementById('finalScore').textContent = totalScore + '/' + maxPossibleScore;
  document.getElementById('finalMessage').textContent = `You scored ${totalScore} out of ${maxPossibleScore} marks (${scorePercent}%).`;
  
  // Display score details
  let scoreDetails = `<div class="score-details"><h3>Question Review:</h3>`;
  currentQuestions.forEach((q, i) => {
    const userAnswer = userAnswers[i];
    const isCorrect = userAnswer && q.correct && userAnswer === q.correct;
    const statusClass = isCorrect ? 'correct' : (userAnswer ? 'incorrect' : 'skipped');
    const statusText = isCorrect ? 'Correct (+5 marks)' : (userAnswer ? 'Incorrect (0 marks)' : 'Skipped (0 marks)');
    const statusColor = isCorrect ? 'var(--success)' : (userAnswer ? 'var(--danger)' : 'var(--muted)');
    
    // Find the text for the user's answer
    let userAnswerText = 'Not answered';
    if (userAnswer) {
      const choice = q.choices.find(c => c.id === userAnswer);
      userAnswerText = choice ? choice.text : 'Unknown answer';
    }
    
    // Find the correct answer text
    let correctAnswerText = 'Not provided';
    if (q.correct) {
      const correctChoice = q.choices.find(c => c.id === q.correct);
      correctAnswerText = correctChoice ? correctChoice.text : 'Unknown correct answer';
    }
    
    scoreDetails += `
      <div class="question-review ${statusClass}">
        <div><strong>Q${i+1}:</strong> ${statusText}</div>
        <div>Your answer: ${userAnswerText}</div>
        <div>Correct answer: ${correctAnswerText}</div>
      </div>
    `;
  });
  scoreDetails += `</div>`;
  document.getElementById('scoreDetails').innerHTML = scoreDetails;
}

document.getElementById('next').addEventListener('click', ()=>{
  if(idx < total-1) render(idx+1);
});
document.getElementById('prev').addEventListener('click', ()=>{
  if(idx > 0) render(idx-1);
});
document.getElementById('skip').addEventListener('click', ()=>{
  // Mark as answered (null means skipped)
  userAnswers[idx] = null;
  questionStatus[idx] = true;
  updateProgress();
  autoSave();
  
  if(idx < total-1) render(idx+1);
});
document.getElementById('gotoBtn').addEventListener('click', ()=>{
  const n = parseInt(document.getElementById('gotoInput').value||"0",10);
  if(n>=1 && n<= total) render(n-1);
});
document.getElementById('submit').addEventListener('click', ()=>{
  const sel = document.querySelector('input[name="choice"]:checked');
  const fbDiv = document.getElementById('feedback');
  if(!sel){ 
    fbDiv.innerHTML = `<div class="result wrong">Please select an option.</div>`; 
    return; 
  }
  
  const chosen = sel.value;
  userAnswers[idx] = chosen;
  questionStatus[idx] = true;
  updateProgress();
  autoSave();
  
  const q = currentQuestions[idx];
  const correct = q.correct || null;
  
  let resultHTML = '';
  if (correct && chosen === correct) {
    resultHTML += `<div class="result correct">Correct! ✓</div>`;
  } else {
    resultHTML += `<div class="result wrong">Incorrect. ✗</div>`;
  }
  
  if (correct) {
    const correctChoice = q.choices.find(c => c.id === correct);
    const correctLetter = q.choices.indexOf(correctChoice);
    const answerLetter = String.fromCharCode(65 + correctLetter);
    resultHTML += `<div style="margin-top:12px;margin-bottom:20px;padding:12px;background:var(--glass-bg);border-left:4px solid var(--success);\"><div style="font-weight:600;color:var(--success);">✓ Correct Answer: ${answerLetter}</div></div>`;
  }
  
  resultHTML += '<div style="border-top:1px solid var(--card-border);padding-top:14px\"><div style="font-weight:600;color:var(--text-primary);margin-bottom:12px">Answer Explanations:</div>';
  
  // Check if we have individual per-choice feedback or only neutral feedback
  const hasPerChoiceFeedback = q.feedback && Object.keys(q.feedback).some(key => key !== 'neutral' && key !== 'correct' && key !== 'incorrect');
  
  (q.choices || []).forEach((c, j) => {
    const answerLetter = String.fromCharCode(65 + j);
    const isCorrect = c.id === q.correct;
    const isSelected = c.id === chosen;
    
    let optionExplanation = '';
    if (q.feedback) {
      const feedbackKey = c.id;
      // First try to get individual feedback for this choice
      if (q.feedback[feedbackKey]) {
        // Use the individual per-choice feedback (Mock Exam style)
        optionExplanation = q.feedback[feedbackKey];
      } else if (hasPerChoiceFeedback) {
        // If we have per-choice feedback structure, don't show neutral for other choices
        optionExplanation = '';
      } else if (q.feedback.neutral) {
        // For neutral-only feedback, show full explanation only for correct answer
        if (isCorrect) {
          optionExplanation = q.feedback.neutral;
        } else {
          // For incorrect answers, show brief explanation
          optionExplanation = `<p>Incorrect. This is not the correct answer.</p>`;
        }
      }
    }
    
    let borderColor = 'var(--card-border)';
    let labelColor = 'var(--text-muted)';
    let labelText = '';
    
    if (isCorrect) {
      borderColor = 'var(--success)';
      labelColor = 'var(--success)';
      labelText = '✓ Correct';
    } else if (isSelected) {
      borderColor = 'var(--danger)';
      labelColor = 'var(--danger)';
      labelText = '✗ Your Answer';
    } else {
      labelText = 'Incorrect';
    }
    
    resultHTML += `
      <div style="margin-bottom:12px;padding:10px;background:var(--glass-bg);border-radius:8px;border-left:4px solid ${borderColor};">
        <div style="font-weight:600;color:${labelColor};margin-bottom:8px">${answerLetter}. ${labelText}</div>
        <div style="color:var(--text-primary);margin-bottom:8px;font-size:14px">${c.text}</div>
        ${optionExplanation ? `<div style="color:var(--text-muted);font-size:13px;line-height:1.5">${optionExplanation}</div>` : ''}
      </div>
    `;
  });
  resultHTML += '</div>';
  fbDiv.innerHTML = resultHTML;
});

document.getElementById('finish').addEventListener('click', function() {
  console.log('Finish button clicked!');
  const answeredCount = questionStatus.filter(status => status).length;
  if (answeredCount < total) {
    if (!confirm(`You have only answered ${answeredCount} of ${total} questions. Finish anyway?`)) {
      return;
    }
  }
  showFinalResults();
});

document.getElementById('reviewAnswers').addEventListener('click', ()=>{
  // Redirect to the all questions view
  window.location.href = '/all-questions/' + '{{ data_source[:-5] }}'; // Remove .json extension
});

function escapeHtml(s){ if(!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\\n/g,'<br>'); }

// initial render
if(total === 0){
  document.body.innerHTML = '<div style="padding:40px;font-family:Inter,Arial">No questions found — check data1.json.</div>';
} else {
  render(0);
  updateProgress();
}

// Screenshot and Screen Recording Prevention for Regular Users
const userRole = '{{ user_role }}';
if (userRole !== 'admin') {
  class ScreenProtection {
    constructor() {
      this.blackScreenActive = false;
      this.setupScreenProtection();
    }

    setupScreenProtection() {
      this.createBlackScreenOverlay();
      this.monitorScreenshotAttempts();
      this.monitorScreenRecording();
    }

    createBlackScreenOverlay() {
      const overlay = document.createElement('div');
      overlay.id = 'blackScreenOverlay';
      overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:#000000;display:none;z-index:999999;opacity:1';
      
      const warningText = document.createElement('div');
      warningText.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:#ffffff;font-size:24px;font-weight:bold;text-align:center;font-family:Arial,sans-serif;z-index:1000000;white-space:pre-wrap;max-width:80%';
      warningText.textContent = 'Screenshots and screen recording are disabled for this session';
      
      overlay.appendChild(warningText);
      document.body.appendChild(overlay);
    }

    showBlackScreen(duration = 1500) {
      const overlay = document.getElementById('blackScreenOverlay');
      if (overlay && !this.blackScreenActive) {
        overlay.style.display = 'block';
        this.blackScreenActive = true;
        
        setTimeout(() => {
          overlay.style.display = 'none';
          this.blackScreenActive = false;
        }, duration);
      }
    }

    monitorScreenshotAttempts() {
      document.addEventListener('keydown', (e) => {
        let triggerBlackScreen = false;
        
        // Windows/Linux PrintScreen key
        if (e.key === 'PrintScreen') { triggerBlackScreen = true; }
        if (e.shiftKey && e.key === 'PrintScreen') { triggerBlackScreen = true; }
        
        // Windows snipping tool: Shift+Windows+S or Ctrl+Shift+S
        if (e.metaKey && e.shiftKey && (e.key === 's' || e.key === 'S')) { triggerBlackScreen = true; }
        if (e.ctrlKey && e.shiftKey && (e.key === 's' || e.key === 'S')) { triggerBlackScreen = true; }
        
        // Mac screenshot shortcuts
        if (e.metaKey && e.shiftKey && e.key === '3') { triggerBlackScreen = true; }
        if (e.metaKey && e.shiftKey && e.key === '4') { triggerBlackScreen = true; }
        if (e.metaKey && e.shiftKey && e.key === '5') { triggerBlackScreen = true; }
        
        // Chrome/Edge print to PDF: Ctrl+P or Shift+Ctrl+P
        if (e.ctrlKey && !e.shiftKey && (e.key === 'p' || e.key === 'P')) { triggerBlackScreen = true; }
        if (e.ctrlKey && e.shiftKey && (e.key === 'p' || e.key === 'P')) { triggerBlackScreen = true; }
        
        if (triggerBlackScreen) {
          e.preventDefault();
          this.showBlackScreen(1500);
          return false;
        }
      });
    }

    monitorScreenRecording() {
      if (navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia) {
        const originalGetDisplayMedia = navigator.mediaDevices.getDisplayMedia;
        navigator.mediaDevices.getDisplayMedia = (...args) => {
          window.screenProtection.showBlackScreen(2000);
          return originalGetDisplayMedia.apply(navigator.mediaDevices, args);
        };
      }
    }
  }

  window.screenProtection = new ScreenProtection();

  // Disable text selection
  document.addEventListener('selectstart', function(e) {
    e.preventDefault();
    return false;
  });

  // Disable right-click context menu
  document.addEventListener('contextmenu', function(e) {
    e.preventDefault();
    return false;
  });

  // Disable common keyboard shortcuts for regular users
  document.addEventListener('keydown', function(e) {
    if (e.ctrlKey && e.key === 'c') { e.preventDefault(); return false; }
    if (e.ctrlKey && e.key === 'p') { e.preventDefault(); return false; }
    if (e.ctrlKey && e.key === 'u') { e.preventDefault(); return false; }
    if (e.key === 'F12') { e.preventDefault(); return false; }
    if (e.ctrlKey && e.shiftKey && e.key === 'I') { e.preventDefault(); return false; }
    if (e.ctrlKey && e.shiftKey && e.key === 'J') { e.preventDefault(); return false; }
    if (e.ctrlKey && e.shiftKey && e.key === 'C') { e.preventDefault(); return false; }
  });
}

function toggleSidebar() {
  document.body.classList.toggle('sidebar-collapsed');
}
</script>
</body>
</html>
"""


@app.route("/upload-data", methods=["POST"])
def upload_data():
    """
    Upload a JSON file via multipart/form-data form field named 'file'.
    Saves the file into uploads/ with a secure filename and returns the URL to open it.
    """
    if "file" not in request.files:
        return jsonify({"error": "no file field in request (use key 'file')"}), 400
    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "empty filename"}), 400
    filename = secure_filename(f.filename) if f.filename else "default.json"
    dest = os.path.join(UPLOAD_FOLDER, filename)
    f.save(dest)
    # return the UI URL for the uploaded file
    url = url_for("data_file_name_route", filename=os.path.join("uploads", filename))
    return jsonify({"message": "uploaded", "filename": filename, "open_url": url})

@app.route("/load-file")
def load_file_preview():
    # Quick preview endpoint: ?path=relative_or_absolute_path
    # Returns parsed JSON (raw) if allowed.
    p = request.args.get("path")
    if not p:
        return jsonify({"error": "path query param missing"}), 400
    # resolve as in data_file_name_route
    tried_paths = []
    if os.path.isabs(p):
        tried_paths.append(p)
    else:
        tried_paths.append(os.path.join(BASE_DIR, p))
        tried_paths.append(os.path.join(DATA_FOLDER, p))
        tried_paths.append(os.path.join(UPLOAD_FOLDER, p))
    chosen = None
    for tp in tried_paths:
        if os.path.exists(tp) and is_allowed_path(tp):
            chosen = os.path.abspath(tp)
            break
    if not chosen:
        return jsonify({"error": "file not found or not allowed", "tried": tried_paths}), 404
    with open(chosen, "r", encoding="utf-8") as fh:
        parsed = json.load(fh)
    return jsonify({"path": chosen, "parsed": parsed})

# ---------- existing routes ----------


@app.route("/")
def index():
    # Redirect to login page as the default route
    return redirect(url_for('login'))

# Login Routes with JWT Authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication handler with JWT"""
    if request.method == 'GET':
        # Show login form
        error = request.args.get('error', '')
        return render_template_string(LOGIN_TEMPLATE, error=error)
    
    # POST request - process login
    user_id = request.form.get('user_id', '').strip()
    password = request.form.get('password', '').strip()
    
    if not user_id or not password:
        return render_template_string(LOGIN_TEMPLATE, error="Please enter both user ID and password")
    
    # Validate credentials
    user = authenticate_user(user_id, password)
    
    if not user:
        return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials or account expired")
    
    # ===== SINGLE-SESSION ENFORCEMENT =====
    # Step 1: Invalidate all existing sessions for this user (logs out other devices)
    db.invalidate_all_user_sessions(user_id)
    print(f"🔐 Logging in user '{user_id}' - invalidated all previous sessions")
    
    # Step 2: Generate new session token
    session_token = secrets.token_urlsafe(32)
    
    # Step 3: Store session in Redis with expiration
    expires_at = get_ist_now() + timedelta(days=10)
    success = db.store_session(
        user_id=user_id,
        session_token=session_token,
        ip_address=request.remote_addr or 'Unknown',
        user_agent=request.headers.get('User-Agent', 'Unknown'),
        expires_at=expires_at
    )
    
    if not success:
        return render_template_string(LOGIN_TEMPLATE, 
            error="Session storage failed. Please check Redis connection.")
    
    # Step 4: Create JWT token with session token embedded
    jwt_token = create_jwt_token(
        user_id=user['id'],
        session_token=session_token,
        user_name=user.get('name', ''),
        user_role=user.get('role', 'user')
    )
    
    # Step 5: Store JWT in Flask session (maintains backward compatibility)
    session['jwt_token'] = jwt_token
    session['user_id'] = user['id']
    session['user_name'] = user.get('name', '')
    session['user_role'] = user.get('role', 'user')
    session.modified = True
    
    print(f"✅ User '{user_id}' logged in successfully")
    
    # Redirect to menu for all users
    return redirect(url_for('menu'))

@app.route('/logout')
def logout():
    """Logout and invalidate current session in Redis"""
    # Get user info before clearing session
    user_id = session.get('user_id')
    jwt_token = session.get('jwt_token')
    
    # If we have a JWT, extract the session token and delete it from Redis
    if jwt_token:
        payload = verify_jwt_token(jwt_token)
        if payload:
            session_token = payload.get('tok')
            if session_token and user_id:
                # Delete this specific session from Redis
                db.delete_session(session_token, user_id)
                print(f"🔓 User '{user_id}' logged out - session invalidated")
    
    # Clear Flask session
    session.clear()
    session.modified = True
    
    # Redirect to login page
    return redirect(url_for('login'))

@app.route('/add-user', methods=['GET', 'POST'])
@admin_required
def add_user_route():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')
        name = request.form.get('name')
        role = request.form.get('role', 'user')
        expiry = request.form.get('expiry')
        if not user_id or not password or not name:
            return render_template_string(ADD_USER_TEMPLATE, error="All fields are required")
        success, message = add_user(user_id, password, name, expiry, role)
        return render_template_string(ADD_USER_TEMPLATE, success=message if success else None, error=None if success else message)
    return render_template_string(ADD_USER_TEMPLATE)

@app.route('/remove-user', methods=['GET', 'POST'])
@admin_required
def remove_user_route():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        if not user_id:
            users = db.get_all_users()
            return render_template_string(REMOVE_USER_TEMPLATE, users=users, error="User ID is required")
        success, message = remove_user(user_id)
        users = db.get_all_users()
        return render_template_string(REMOVE_USER_TEMPLATE, users=users, success=message if success else None, error=None if success else message)
    users = db.get_all_users()
    return render_template_string(REMOVE_USER_TEMPLATE, users=users)

@app.route('/manage-users')
@admin_required
def manage_users():
    users_list = db.get_all_users()
    # Add validity status to each user with defensive checks
    for user in users_list:
        if not isinstance(user, dict): continue
        # Ensure 'id' exists for the template
        if 'id' not in user and 'user_id' in user:
            user['id'] = user['user_id']
        user['is_valid'] = is_user_valid(user)
    return render_template_string(MANAGE_USERS_TEMPLATE, users=users_list)

@app.route('/admin/migrate-ist')
@admin_required
def migrate_ist_route():
    """Trigger retrospective IST migration."""
    try:
        report = db.run_ist_migration()
        return jsonify({
            "status": "success",
            "message": "IST Migration completed",
            "report": report
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/edit-user/<user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user_route(user_id):
    if request.method == 'POST':
        name = request.form.get('name')
        role = request.form.get('role')
        expiry = request.form.get('expiry')
        password = request.form.get('password')
        if not name:
            user = get_user_by_id(user_id)
            return render_template_string(EDIT_USER_TEMPLATE, user=user, error="Full name is required"), 400
        success, message = edit_user(user_id, name=name, role=role, expiry=expiry, password=password)
        if success: return redirect(url_for('manage_users'))
        user = get_user_by_id(user_id)
        return render_template_string(EDIT_USER_TEMPLATE, user=user, error=message), 400
    user = get_user_by_id(user_id)
    if not user: return redirect(url_for('manage_users'))
    return render_template_string(EDIT_USER_TEMPLATE, user=user)

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user_id = session.get('user_id')
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        if not name:
            user = get_user_by_id(user_id)
            return render_template_string(USER_PROFILE_TEMPLATE, user=user, error="Full name is required"), 400
        success, message = edit_user(user_id, name=name, password=password)
        if success:
            session['user_name'] = name
            session.modified = True
            user = get_user_by_id(user_id)
            return render_template_string(USER_PROFILE_TEMPLATE, user=user, success="Profile updated successfully!"), 200
        user = get_user_by_id(user_id)
        return render_template_string(USER_PROFILE_TEMPLATE, user=user, error=message), 400
    user = get_user_by_id(user_id)
    if not user: return redirect(url_for('logout'))
    return render_template_string(USER_PROFILE_TEMPLATE, user=user)



@app.route("/menu")
@login_required
def menu():
    # Display menu with all available JSON files - now protected behind login
    
    files = []
    
    # Get all JSON files from the data folder
    if os.path.exists(DATA_FOLDER):
        for filename in sorted(os.listdir(DATA_FOLDER)):
            if filename.endswith('.json'):
                file_path = os.path.join(DATA_FOLDER, filename)
                # Get file size
                try:
                    file_size = os.path.getsize(file_path)
                    size_kb = file_size / 1024
                    
                    # Try to count questions
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            items = _find_items_structure(data)
                            question_count = len(items)
                    except Exception:
                        question_count = 0
                    
                    # Remove .json extension for the link
                    name_without_ext = filename[:-5] if filename.endswith('.json') else filename
                    
                    files.append({
                        'name': filename,
                        'display_name': name_without_ext,
                        'size': f"{size_kb:.1f} KB",
                        'questions': question_count,
                        'is_mock': 'Mock' in filename,
                        'is_module': filename.startswith('Module')
                    })
                except Exception as e:
                    print(f"⚠️ Error loading file '{filename}' for user '{session.get('user_id')}': {e}")
                    import traceback
                    traceback.print_exc()
                    pass
    
    # Debug output
    print(f"🔍 DEBUG - User: {session.get('user_id')}, Role: {session.get('user_role')}, Files found: {len(files)}")
    print(f"🔍 DATA_FOLDER: {DATA_FOLDER}, exists: {os.path.exists(DATA_FOLDER)}")
    if os.path.exists(DATA_FOLDER):
        all_files = os.listdir(DATA_FOLDER)
        json_files = [f for f in all_files if f.endswith('.json')]
        print(f"🔍 JSON files in folder: {len(json_files)}")
    
    # Get sort type from request
    sort_type = request.args.get('sort', 'id')
    files = sort_modules(files, sort_type)
    
    # Get recently viewed items
    recently_viewed_items = get_recently_viewed(session)
    
    # Calculate file categories
    modules = [f for f in files if f['is_module']]
    mocks = [f for f in files if f['is_mock']]
    
    # Get user stats from Redis for dashboard
    user_id = session.get('user_id')
    stats = db.get_user_quiz_stats(user_id) if user_id else {'total_attempts': 0, 'avg_score': 0, 'modules_completed': 0, 'mocks_completed': 0}
    
    # Pass everything to template
    user_data = get_user_by_id(user_id) if user_id else {}
    # Default to 6 months from now if no exam date set
    from datetime import date, timedelta
    default_exam_date = (date.today() + timedelta(days=180)).isoformat()
    exam_date = user_data.get('exam_date') or default_exam_date
    
    # Calculate topic strengths for Strengths & Weaknesses section
    topic_strengths = get_topic_strengths(user_id) if user_id else []
    
    # Calculate total questions in the system (sum of all quiz file questions)
    total_questions = sum(f.get('questions', 0) for f in files)
    
    # Calculate daily target: remaining questions / days left until exam
    from math import ceil
    try:
        exam_date_obj = date.fromisoformat(exam_date)
        days_left = max(1, (exam_date_obj - date.today()).days)  # Minimum 1 day
    except:
        days_left = 180  # Default to 180 days if parsing fails
    
    remaining_questions = max(0, total_questions - stats.get('unique_questions_attempted', 0))
    daily_target = ceil(remaining_questions / days_left) if days_left > 0 else remaining_questions
    
    # Calculate study progress percentage
    study_progress_pct = round(stats.get('unique_questions_attempted', 0) / total_questions * 100, 1) if total_questions > 0 else 0
    
    return render_template_string(
        MENU_TEMPLATE, 
        files=files, 
        total_files=len(files),
        total_modules=len(modules),
        debug_modules=len(modules), 
        debug_mocks=len(mocks), 
        session=session, 
        recently_viewed=recently_viewed_items, 
        current_sort=sort_type, 
        user_role=session.get('user_role', 'user'), 
        stats=stats,
        exam_date=exam_date,
        topic_strengths=topic_strengths,
        total_questions=total_questions,
        daily_target=daily_target,
        study_progress_pct=study_progress_pct,
        days_left=days_left
    )



@app.route("/recently-viewed")
@login_required
def recently_viewed():
    """Display user's recently viewed items"""
    recently_viewed_items = get_recently_viewed(session)
    return render_template_string(RECENTLY_VIEWED_TEMPLATE, recently_viewed=recently_viewed_items, session=session)


@app.route("/all")
@login_required
def flashcards():
    """Display flashcards from CFA curriculum PDF"""
    # Check if flashcards JSON exists
    flashcard_path = os.path.join(DATA_FOLDER, 'flashcards.json')
    cards = []
    
    if os.path.exists(flashcard_path):
        try:
            with open(flashcard_path, 'r', encoding='utf-8') as f:
                cards = json.load(f)
        except:
            cards = []
    
    return render_template_string(FLASHCARD_TEMPLATE, 
                                  cards=cards, 
                                  total_cards=len(cards),
                                  session=session)

@app.route("/history")
@login_required
def history():
    """Display user's quiz history from Redis for persistent tracking"""
    user_id = session.get('user_id')
    
    # Get attempts from Redis (limit to 50 for history page)
    attempts = db.get_user_quiz_attempts(user_id, limit=50)
    
    # Map Redis attempt data to match history template expectations if necessary
    # or update the template to match Redis data structure. 
    # Let's update the template to be more robust.
    
    return render_template_string(HISTORY_TEMPLATE, history=attempts, session=session)

@app.route("/save-quiz-result", methods=["POST"])
@login_required
def save_quiz_result():
    """Save quiz result to user's history"""
    try:
        # Get quiz data from request
        quiz_data = request.get_json()
        
        # Add to history
        add_to_history(session, quiz_data)
        
        # Also add to recently viewed
        add_to_recently_viewed(session, {
            'name': quiz_data.get('quiz_name', 'Unknown Quiz'),
            'type': 'quiz_result'
        })
        
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ========== QUIZ ATTEMPT RECORDING ROUTES ==========

@app.route("/api/save-attempt", methods=["POST"])
@login_required
def save_attempt():
    """Save a completed quiz attempt with all responses to Redis"""
    try:
        data = request.get_json()
        user_id = session.get('user_id')
        quiz_id = data.get('quiz_id')
        mode = data.get('mode', data.get('quiz_type', 'practice'))
        
        if not user_id:
            return jsonify({"status": "error", "message": "Not logged in"}), 401
            
        # Final Verification: Authoritative Time Calculation for Mocks
        time_spent_seconds = data.get('time_spent_seconds', 0)
        if mode == 'mock' and quiz_id:
            remaining = db.get_mock_timer(user_id, quiz_id)
            
            # If timer expired, we use the full duration
            # Default duration 8100 (CFA Mock)
            limit = data.get('time_limit', 8100)
            
            if remaining <= 0 and remaining != -1:
                # Timer expired (or forced submission)
                time_spent_seconds = limit
            elif remaining > 0:
                # Calculate server-side elapsed time
                time_spent_seconds = limit - remaining
                
            # Clear the timer from Redis upon successful submission
            db.clear_mock_timer(user_id, quiz_id)
        
        # Get timestamps from frontend (ISO format)
        started_at = data.get('started_at')  # ISO timestamp when quiz started
        submitted_at = data.get('submitted_at') or get_ist_now().isoformat()  # Fallback to now (IST)
        
        # If we have both timestamps, calculate time from them (more accurate)
        if started_at and submitted_at and mode != 'mock':
            try:
                from datetime import datetime as dt
                start_dt = dt.fromisoformat(started_at.replace('Z', '+00:00'))
                end_dt = dt.fromisoformat(submitted_at.replace('Z', '+00:00'))
                time_spent_seconds = int((end_dt - start_dt).total_seconds())
            except:
                pass  # Keep frontend time if parsing fails
        
        # Prepare attempt data with full snapshot for review
        attempt_data = {
            'quiz_id': quiz_id,
            'quiz_name': data.get('quiz_name', 'Unknown Quiz'),
            'quiz_type': mode,
            'mode': mode,
            'started_at': started_at,
            'submitted_at': submitted_at,
            'total_questions': data.get('total_questions', 0),
            'correct_count': data.get('correct_count', 0),
            'wrong_count': data.get('wrong_count', 0),
            'skipped_count': data.get('skipped_count', 0),
            'score_percent': data.get('score_percent', 0),
            'time_spent_seconds': time_spent_seconds,
            'responses': data.get('responses', [])
        }
        
        # Store in Redis
        attempt_id = db.store_quiz_attempt(user_id, attempt_data)
        
        if attempt_id:
            # Clear legacy session history if it exists to preserve memory
            if 'history' in session:
                session.pop('history')
                
            return jsonify({"status": "success", "attempt_id": attempt_id})
        else:
            return jsonify({"status": "error", "message": "Failed to store attempt"}), 500
            
    except Exception as e:
        print(f"❌ Error saving attempt: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/clear-my-attempts", methods=["POST"])
@login_required
def clear_my_attempts():
    """Clear all quiz attempts for the current user"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"status": "error", "message": "Not logged in"}), 401
        
        # Get all attempt IDs for this user
        if db.redis_client:
            attempt_ids = db.redis_client.zrange(f'user_attempts:{user_id}', 0, -1)
            deleted_count = 0
            
            # Delete each attempt
            for attempt_id in attempt_ids:
                if isinstance(attempt_id, bytes):
                    attempt_id = attempt_id.decode('utf-8')
                db.redis_client.delete(f'quiz_attempt:{user_id}:{attempt_id}')
                deleted_count += 1
            
            # Clear the user's attempts list
            db.redis_client.delete(f'user_attempts:{user_id}')
            
            return jsonify({
                "status": "success",
                "message": f"Cleared {deleted_count} attempts",
                "deleted_count": deleted_count
            })
        else:
            return jsonify({"status": "error", "message": "Redis not available"}), 500
            
    except Exception as e:
        print(f"❌ Error clearing attempts: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/pause-practice", methods=["POST"])
@login_required
def pause_practice():
    """Save paused practice attempt state to Redis (Practice modules only)"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        if not user_id:
            return jsonify({"status": "error", "message": "Not logged in"}), 401
        
        module_id = data.get('module_id')
        if not module_id:
            return jsonify({"status": "error", "message": "module_id required"}), 400
        
        # Build attempt data
        attempt_data = {
            'started_at': data.get('started_at'),
            'paused_at': get_ist_now().isoformat(),
            'last_question_index': data.get('last_question_index', 0),
            'user_answers': data.get('user_answers', []),
            'question_times': data.get('question_times', []),
            'question_flags': data.get('question_flags', []),
            'responses': data.get('responses', []),
            'total_time_seconds': data.get('total_time_seconds', 0),
            'status': 'paused'
        }
        
        success = db.save_paused_attempt(user_id, module_id, attempt_data)
        
        if success:
            return jsonify({"status": "success", "message": "Practice paused"})
        else:
            return jsonify({"status": "error", "message": "Failed to save"}), 500
            
    except Exception as e:
        print(f"❌ Error pausing practice: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/get-paused-practice")
@login_required
def get_paused_practice():
    """Get paused practice attempt for a specific module"""
    try:
        user_id = session.get('user_id')
        module_id = request.args.get('module_id')
        
        if not user_id:
            return jsonify({"status": "error", "message": "Not logged in"}), 401
        
        if not module_id:
            return jsonify({"status": "error", "message": "module_id required"}), 400
        
        paused = db.get_paused_attempt(user_id, module_id)
        
        if paused:
            return jsonify({"status": "success", "paused_attempt": paused})
        else:
            return jsonify({"status": "success", "paused_attempt": None})
            
    except Exception as e:
        print(f"❌ Error getting paused practice: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/clear-paused-practice", methods=["POST"])
@login_required
def clear_paused_practice():
    """Clear paused practice attempt (called on completion)"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        module_id = data.get('module_id')
        
        if not user_id:
            return jsonify({"status": "error", "message": "Not logged in"}), 401
        
        if not module_id:
            return jsonify({"status": "error", "message": "module_id required"}), 400
        
        db.clear_paused_attempt(user_id, module_id)
        return jsonify({"status": "success", "message": "Paused state cleared"})
        
    except Exception as e:
        print(f"❌ Error clearing paused practice: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/mock/timer-status")

@login_required
def mock_timer_status():
    """Authoritative endpoint to get or initialize a mock exam timer"""
    quiz_id = request.args.get('quiz_id')
    duration = int(request.args.get('duration', 8100))
    user_id = session.get('user_id')
    
    if not quiz_id:
        return jsonify({"error": "quiz_id required"}), 400
        
    remaining = db.get_mock_timer(user_id, quiz_id)
    
    # If no timer exists, initialize it (Idempotent start)
    if remaining == -1:
        end_ts = db.set_mock_timer(user_id, quiz_id, duration)
        remaining = duration
        
    return jsonify({
        "remaining_seconds": remaining,
        "is_expired": remaining <= 0,
        "quiz_id": quiz_id
    })


@app.route("/profile")
@login_required
def profile():
    """Display user profile with stats and activity"""
    user_id = session.get('user_id')
    user_data = get_user_by_id(user_id) if user_id else {}
    stats = db.get_user_quiz_stats(user_id) if user_id else {}
    attempts = db.get_user_quiz_attempts(user_id, limit=10) if user_id else []
    
    return render_template_string(PROFILE_TEMPLATE,
                                  user=user_data,
                                  stats=stats,
                                  recent_attempts=attempts,
                                  session=session)


@app.route("/my-scores")
@login_required
def my_scores():
    """Display user's quiz scores and history from Redis"""
    user_id = session.get('user_id')
    
    # Get attempts from Redis
    attempts = db.get_user_quiz_attempts(user_id, limit=50)
    stats = db.get_user_quiz_stats(user_id)
    
    return render_template_string(MY_SCORES_TEMPLATE, 
                                  attempts=attempts, 
                                  stats=stats,
                                  session=session,
                                  user_role=session.get('user_role', 'user'))


@app.route("/review-attempt/<attempt_id>")
@login_required
def review_attempt(attempt_id):
    """Review a specific attempt with question-by-question breakdown - renders from stored snapshot only"""
    user_id = session.get('user_id')
    
    # Get attempt from Redis - contains full question snapshots
    attempt = db.get_quiz_attempt_by_id(user_id, attempt_id)
    
    if not attempt:
        return redirect(url_for('my_scores'))
    
    # Responses already contain full question data (stored at submission time)
    responses = attempt.get('responses', [])
    
    is_mock = attempt.get('quiz_type') == 'mock' or attempt.get('mode') == 'mock'
    
    return render_template_string(REVIEW_ATTEMPT_TEMPLATE,
                                  attempt=attempt,
                                  responses=responses,
                                  is_mock=is_mock,
                                  session=session)


@app.route("/attempt/<attempt_id>")
@login_required
def view_attempt(attempt_id):
    """View detailed responses for a specific quiz attempt"""
    user_id = session.get('user_id')
    
    # Get attempt from Redis
    attempt = db.get_quiz_attempt_by_id(user_id, attempt_id)
    
    if not attempt:
        return render_template_string("""
            <html><body style="font-family:Inter,Arial;padding:40px;background:#0f1419;color:var(--glass-bg);">
                <h2>Attempt Not Found</h2>
                <p>This quiz attempt could not be found or has expired.</p>
                <a href="/my-scores" style="color:#a78bfa;">← Back to My Scores</a>
            </body></html>
        """)
    
    return render_template_string(ATTEMPT_DETAILS_TEMPLATE, 
                                  attempt=attempt,
                                  session=session,
                                  user_role=session.get('user_role', 'user'))


@app.route("/api/delete-attempt/<attempt_id>", methods=["DELETE"])
@login_required
def delete_attempt(attempt_id):
    """Delete a specific quiz attempt"""
    user_id = session.get('user_id')
    
    success = db.delete_quiz_attempt(user_id, attempt_id)
    
    if success:
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "error", "message": "Failed to delete attempt"}), 500


# ---------- TEMPLATES ----------

LOGIN_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Login - CFA Level 1 Quiz</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--muted:#94a3b8;--accent:#a78bfa;--success:#34d399;--danger:#f87171;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--gold:#d4af37}
body{margin:0;font-family:'Inter','Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);color:#0f1724;height:100vh;display:flex;align-items:center;justify-content:center}
.login-container{max-width:450px;width:90%;margin:20px auto;padding:40px;background:var(--card);border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.4);text-align:center;animation: fadeInUp 0.5s ease-out;border:1px solid rgba(167,139,250,0.2)}
.login-icon{font-size:64px;margin-bottom:20px;animation: bounce 1s ease infinite}
.login-container h1{font-size:32px;margin:0 0 12px 0;background:linear-gradient(135deg, #a78bfa 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.login-container p{color:var(--text-secondary);font-size:16px;margin:0 0 30px 0}
.form-group{margin-bottom:24px;text-align:left}
.form-group label{display:block;margin-bottom:8px;font-weight:600;color:var(--text-secondary);font-size:15px}
.form-group input{width:100%;padding:14px;border:1px solid rgba(167,139,250,0.3);border-radius:10px;font-size:16px;transition:all 0.3s;background:rgba(255,255,255,0.05);color:var(--text-primary)}
.form-group input::placeholder{color:var(--text-secondary);opacity:0.7}
.form-group input:focus{border-color:var(--accent);outline:none;box-shadow:0 0 0 3px rgba(167,139,250,0.2);background:rgba(255,255,255,0.08)}
.btn{padding:14px 24px;background:linear-gradient(135deg, #8b5cf6 0%, #a78bfa 100%);color:#fff;border:none;border-radius:10px;font-weight:600;cursor:pointer;width:100%;font-size:16px;transition:all 0.3s;margin-top:10px;box-shadow:0 4px 15px rgba(139,92,246,0.3)}
.btn:hover{background:linear-gradient(135deg, #a78bfa 0%, #c4b5fd 100%);transform:translateY(-3px);box-shadow:0 8px 25px rgba(167,139,250,0.4)}
.error{color:var(--danger);background:rgba(244,63,94,0.15);padding:16px;border-radius:10px;margin-bottom:24px;border:1px solid rgba(244,63,94,0.3);animation: shake 0.5s ease}
.links{margin-top:24px;font-size:15px}
.links a{color:var(--accent);text-decoration:none;font-weight:600}
.links a:hover{color:var(--text-primary);text-decoration:underline}
@keyframes fadeInUp{from{opacity:0;transform:translateY(30px)}to{opacity:1;transform:translateY(0)}}
@keyframes bounce{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}
@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-5px)}75%{transform:translateX(5px)}}
</style>
</head>
<body>
<div class="login-container">
  <div class="login-icon">🔐</div>
  <h1>Welcome to CFA Level 1 Quiz</h1>
  <p>Sign in to access your CFA Level 1 Quiz Platform</p>
  
  {% if error %}
  <div class="error {% if 'Another user' in error %}single-user{% endif %}">
    <div>{{ error }}</div>
  </div>
  {% endif %}
  
  <form method="POST">
    <div class="form-group">
      <label for="user_id">User ID</label>
      <input type="text" id="user_id" name="user_id" required placeholder="Enter your user ID">
    </div>
    <div class="form-group">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required placeholder="Enter your password">
    </div>
    <button type="submit" class="btn">Sign In</button>
  </form>
</div>
</body>
</html>
"""



PRACTICE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Practice Dashboard</title>
<style>
:root{--bg:#121212;--card:#0A2540;--card-border:#1a3a5c;--muted:#94a3b8;--accent:#0052A5;--accent-dark:#003d7a;--accent-light:#4d8fd6;--success:#2E7D32;--danger:#C62828;--warning:#fbbf24;--text-primary:#FAFAFA;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37;--jewel-emerald:#2E7D32;--jewel-sapphire:#0052A5;--jewel-amethyst:#6c5ce7;--jewel-ruby:#C62828;--glass-bg:rgba(255,255,255,0.05);--glass-border:rgba(255,255,255,0.1);--sidebar-width:210px}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, var(--bg) 0%, #0A2540 100%);color:var(--text-primary);min-height:100vh;display:flex}
.emoji,.sidebar-item-icon{-webkit-text-fill-color:initial;color:inherit}
.sidebar{width:var(--sidebar-width);background:var(--card);border-right:1px solid var(--card-border);padding:20px 0;display:flex;flex-direction:column;position:fixed;height:100vh;left:0;top:0;z-index:100;transition:transform 0.3s ease}
.sidebar-logo{padding:0 20px 20px 20px;border-bottom:1px solid var(--card-border);margin-bottom:12px}
.sidebar-logo h2{margin:0;font-size:16px;font-weight:800;background:linear-gradient(135deg, var(--accent-light) 0%, var(--gold) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sidebar-nav{flex:1;display:flex;flex-direction:column;gap:4px;padding:0 12px}
.sidebar-item{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:8px;color:var(--text-secondary);text-decoration:none;font-size:13px;font-weight:500;transition:all 0.2s}
.sidebar-item:hover{background:rgba(255,255,255,0.08);color:var(--text-primary)}
.sidebar-item.active{background:linear-gradient(135deg, var(--accent) 0%, var(--accent-light) 100%);color:#fff;font-weight:600}
.sidebar-item-icon{font-size:16px;width:20px;text-align:center}
.sidebar-footer{padding:16px 20px;border-top:1px solid var(--card-border);margin-top:auto}
.sidebar-user{font-size:11px;color:var(--text-muted)}
.sidebar-user strong{color:var(--text-primary);display:block;font-size:13px;margin-top:4px}
.sidebar-logout{display:block;margin-top:12px;padding:8px 12px;background:linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);color:#fff;text-decoration:none;border-radius:6px;font-size:12px;font-weight:600;text-align:center}
.sidebar-logout:hover{opacity:0.9}
.main-content{margin-left:var(--sidebar-width);flex:1;min-height:100vh;transition:margin-left 0.3s ease}
.container{max-width:1100px;margin:24px auto;padding:0 32px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;border-bottom:1px solid var(--card-border);padding-bottom:12px}
.header h1{font-size:24px;margin:0;font-weight:700;color:var(--text-primary)}
.reset-link{color:var(--gold);text-decoration:none;font-size:14px;font-weight:600}
.reset-link:hover{text-decoration:underline}
.completion-section{margin-bottom:32px}
.completion-label{font-size:14px;color:var(--text-secondary);margin-bottom:8px;display:block}
.progress-bar-outer{background:rgba(0,40,80,0.6);height:24px;border-radius:12px;overflow:hidden;border:1px solid var(--card-border)}
.progress-bar-fill{height:100%;background:linear-gradient(90deg, var(--accent) 0%, var(--accent-light) 100%);width:0%;transition:width 0.5s ease;border-radius:12px}
.metrics-row{display:flex;gap:1px;background:var(--card-border);border:1px solid var(--card-border);border-radius:8px;overflow:hidden;margin-bottom:40px}
.metric-box{background:var(--card);padding:24px;flex:1;display:flex;flex-direction:column;justify-content:center}
.metric-box.large{flex:0 0 200px;text-align:center;border-right:1px solid var(--card-border)}
.metric-value.large{font-size:48px;font-weight:800;line-height:1;margin-bottom:8px;color:var(--accent-light)}
.metric-label.large{font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px}
.metric-content{border-left:4px solid var(--accent);padding-left:12px}
.metric-value{font-size:18px;font-weight:700;color:var(--text-primary);margin-bottom:4px}
.metric-label{font-size:12px;color:var(--text-muted)}
.tabs{display:flex;gap:32px;border-bottom:1px solid var(--card-border);margin-bottom:24px}
.tab{padding:12px 0;font-size:16px;font-weight:600;color:var(--text-muted);cursor:pointer;position:relative;text-decoration:none}
.tab.active{color:var(--accent-light)}
.tab.active::after{content:'';position:absolute;bottom:-1px;left:0;right:0;height:3px;background:var(--accent-light)}
.topics-table{width:100%;border-collapse:collapse}
.topics-table th{text-align:left;font-size:12px;text-transform:uppercase;color:var(--text-muted);padding:12px;border-bottom:1px solid var(--card-border)}
.topics-table td{padding:12px;border-bottom:1px solid var(--card-border);font-size:14px}
.topic-header{font-weight:700;color:var(--accent-light)}
.subtopic-item{padding-left:32px !important}
.subtopic-link{color:var(--text-primary);text-decoration:none}
.subtopic-link:hover{color:var(--accent-light);text-decoration:underline}
.text-right{text-align:right}
.sidebar-toggle{background:none;border:none;font-size:24px;color:var(--text-primary);cursor:pointer;padding:8px;margin-right:15px;display:flex;align-items:center;justify-content:center;border-radius:8px}
body.sidebar-collapsed .sidebar{transform:translateX(-100%)}
body.sidebar-collapsed .main-content{margin-left:0}
@media(max-width:768px){
  .metrics-row{flex-direction:column}
  .metric-box.large{flex:none;border-right:none;border-bottom:1px solid var(--card-border)}
  .main-content{margin-left:0 !important}
  .sidebar{transform:translateX(-100%)}
}
</style>
</head>
<body>
<div class="sidebar">
  <div class="sidebar-logo">
    <h2>CFA Level 1</h2>
  </div>
  <nav class="sidebar-nav">
    <a href="/menu" class="sidebar-item">
      <span class="sidebar-item-icon">🏠</span> Home
    </a>
    <a href="/all" class="sidebar-item">
      <span class="sidebar-item-icon">📇</span> Flashcards
    </a>
    <a href="/practice" class="sidebar-item active">
      <span class="sidebar-item-icon">📖</span> Practice
    </a>
    <a href="/mocks" class="sidebar-item">
      <span class="sidebar-item-icon">🎯</span> Mock Exams
    </a>
    <a href="/my-scores" class="sidebar-item">
      <span class="sidebar-item-icon">📊</span> My Scores
    </a>
  </nav>
  <div class="sidebar-footer">
    <div class="sidebar-user">
      Logged in as:
      <strong>{{ session.user_name }}</strong>
    </div>
    <a href="/logout" class="sidebar-logout">Logout</a>
  </div>
</div>
<div class="main-content">
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center">
      <button class="sidebar-toggle" onclick="document.body.classList.toggle('sidebar-collapsed')">☰</button>
      <h1>Dashboard</h1>
    </div>
    <a href="#" class="reset-link">Reset Questions</a>
  </div>
  <div class="completion-section">
    <span class="completion-label">Completion</span>
    <div class="progress-bar-outer">
      <div class="progress-bar-fill" style="width: {{ completion_percent }}%"></div>
    </div>
  </div>
  <div class="metrics-row">
    <div class="metric-box large">
      <div class="metric-value large">{{ avg_correct }}%</div>
      <div class="metric-label large">Correct</div>
    </div>
    <div class="metric-box">
      <div class="metric-content">
        <div class="metric-value">{{ questions_taken }} of {{ total_questions }}</div>
        <div class="metric-label">Questions Taken</div>
      </div>
    </div>
    <div class="metric-box">
      <div class="metric-content">
        <div class="metric-value">{{ avg_answer_time }}</div>
        <div class="metric-label">Avg. Answer Time</div>
      </div>
    </div>
    <div class="metric-box">
      <div class="metric-content">
        <div class="metric-value">{{ avg_correct_time }}</div>
        <div class="metric-label">Avg. Correct Answer Time</div>
      </div>
    </div>
    <div class="metric-box">
      <div class="metric-content">
        <div class="metric-value">{{ avg_incorrect_time }}</div>
        <div class="metric-label">Avg. Incorrect Answer Time</div>
      </div>
    </div>
    <div class="metric-box">
      <div class="metric-content">
        <div class="metric-value">{{ avg_session_duration }}</div>
        <div class="metric-label">Avg. Session Duration</div>
      </div>
    </div>
  </div>
  <div class="tabs">
    <a href="#" class="tab active">Question Categories</a>
    <a href="/reports" class="tab">Reports</a>
  </div>
  <table class="topics-table">
    <thead>
      <tr>
        <th>Category Name</th>
        <th class="text-right">Complete</th>
        <th class="text-right">% Correct</th>
      </tr>
    </thead>
    <tbody>
      {% for topic in topics %}
      <tr class="topic-row">
        <td class="topic-header">{{ topic.name }}</td>
        <td class="text-right">{{ topic.complete }} of {{ topic.total }}</td>
        <td class="text-right">{{ topic.percent_correct if topic.percent_correct != '--' else '--' }}{% if topic.percent_correct != '--' %}%{% endif %}</td>
      </tr>
      {% for sub in topic.subtopics %}
      <tr>
        <td class="subtopic-item">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span class="subtopic-link">{{ sub.display_name }}</span>
            <div style="display:flex;gap:8px">
              {% if sub.status == 'in_progress' %}
                <a href="/{{ sub.full_name }}" class="btn" style="padding:4px 8px;font-size:11px;background:var(--warning);color:#000;border-radius:4px;text-decoration:none">Resume</a>
              {% elif sub.status == 'completed' %}
                <a href="/{{ sub.full_name }}" class="btn" style="padding:4px 8px;font-size:11px;background:var(--success);color:#000;border-radius:4px;text-decoration:none">Review</a>
              {% else %}
                <a href="/{{ sub.full_name }}" class="btn" style="padding:4px 8px;font-size:11px;background:var(--accent);color:#000;border-radius:4px;text-decoration:none">Start</a>
              {% endif %}
            </div>
          </div>
        </td>
        <td class="text-right" style="color:{% if sub.status == 'completed' %}var(--success){% elif sub.status == 'in_progress' %}var(--warning){% else %}var(--text-secondary){% endif %}">
          {{ sub.complete }} of {{ sub.total }}
        </td>
        <td class="text-right">{{ sub.percent_correct if sub.percent_correct != '--' else '--' }}{% if sub.percent_correct != '--' %}%{% endif %}</td>
      </tr>
      {% endfor %}
      {% endfor %}
    </tbody>
  </table>
</div>
</div>
</body>
</html>
"""

MOCK_EXAMS_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Mock Exams Dashboard</title>
<style>
:root{--bg:#121212;--card:#0A2540;--card-border:#1a3a5c;--muted:#94a3b8;--accent:#0052A5;--accent-dark:#003d7a;--accent-light:#4d8fd6;--success:#2E7D32;--danger:#C62828;--warning:#fbbf24;--text-primary:#FAFAFA;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37;--jewel-emerald:#2E7D32;--jewel-sapphire:#0052A5;--jewel-amethyst:#6c5ce7;--jewel-ruby:#C62828;--glass-bg:rgba(255,255,255,0.05);--glass-border:rgba(255,255,255,0.1);--sidebar-width:210px}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:var(--bg);color:var(--text-primary);min-height:100vh;display:flex}
.sidebar{width:var(--sidebar-width);background:var(--card);border-right:1px solid var(--card-border);padding:20px 0;display:flex;flex-direction:column;position:fixed;height:100vh;left:0;top:0;z-index:100;transition:transform 0.3s ease}
.sidebar-logo{padding:0 20px 20px 20px;border-bottom:1px solid var(--card-border);margin-bottom:12px}
.sidebar-logo h2{margin:0;font-size:16px;font-weight:800;background:linear-gradient(135deg, var(--accent-light) 0%, var(--gold) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sidebar-nav{flex:1;display:flex;flex-direction:column;gap:4px;padding:0 12px}
.sidebar-item{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:8px;color:var(--text-secondary);text-decoration:none;font-size:13px;font-weight:500;transition:all 0.2}
.sidebar-item:hover{background:rgba(255,255,255,0.08);color:var(--text-primary)}
.sidebar-item.active{background:linear-gradient(135deg, var(--accent) 0%, var(--accent-light) 100%);color:#fff;font-weight:600}
.sidebar-item-icon{font-size:16px;width:20px;text-align:center}
.sidebar-footer{padding:16px 20px;border-top:1px solid var(--card-border);margin-top:auto}
.sidebar-user{font-size:11px;color:var(--text-muted)}
.sidebar-user strong{color:var(--text-primary);display:block;font-size:13px;margin-top:4px}
.sidebar-logout{display:block;margin-top:12px;padding:8px 12px;background:linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);color:#fff;text-decoration:none;border-radius:6px;font-size:12px;font-weight:600;text-align:center}
.main-content{margin-left:var(--sidebar-width);flex:1;min-height:100vh;transition:margin-left 0.3s ease}
.container{max-width:1100px;margin:24px auto;padding:0 24px}
.header-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;border-bottom:1px solid var(--card-border);padding-bottom:10px}
.header-left{display:flex;align-items:center;gap:20px}
.header-left h1{font-size:24px;margin:0;color:var(--text-primary)}
.top-tabs{display:flex;gap:30px}
.top-tab{color:var(--text-secondary);text-decoration:none;font-size:14px;padding-bottom:10px;border-bottom:2px solid transparent;transition:all 0.2s}
.top-tab:hover{color:var(--accent-light)}
.top-tab.active{color:var(--accent-light);border-bottom-color:var(--accent-light);font-weight:600}
.dashboard-card{background:var(--card);border:1px solid var(--card-border);border-radius:4px;margin-bottom:20px;overflow:hidden}
.card-header{padding:12px 20px;background:rgba(255,255,255,0.02);border-bottom:1px solid var(--card-border);font-size:14px;color:var(--text-secondary)}
.card-content{padding:20px}
.completion-label{display:block;margin-bottom:8px;font-size:14px;color:var(--text-secondary)}
.progress-bar-outer{width:100%;height:14px;background:rgba(255,255,255,0.1);border-radius:7px;overflow:hidden;margin-bottom:20px}
.progress-bar-fill{height:100%;background:var(--accent);transition:width 0.5s ease-out}
.metrics-row{display:flex;align-items:center;gap:0;background:var(--card);border:1px solid var(--card-border);border-radius:4px;margin-bottom:30px;overflow:hidden}
.metric-box{flex:1;padding:20px;display:flex;flex-direction:column;gap:5px;border-right:1px solid var(--card-border)}
.metric-box:last-child{border-right:none}
.metric-box.large{flex:1.2;background:rgba(255,255,255,0.03);align-items:center;justify-content:center;border-right:2px solid var(--card-border)}
.metric-value{font-size:18px;font-weight:700;color:var(--text-primary)}
.metric-value.large{font-size:42px;color:var(--text-primary)}
.metric-label{font-size:13px;color:var(--text-muted);text-transform:none}
.metric-label.large{font-size:16px;color:var(--text-muted)}
.sub-tabs{display:flex;gap:25px;margin-bottom:0;border-bottom:1px solid var(--card-border);padding-left:10px}
.sub-tab{color:var(--text-secondary);text-decoration:none;font-size:14px;padding:12px 5px;border-bottom:2px solid transparent;transition:all 0.2s}
.sub-tab:hover{color:var(--accent-light)}
.sub-tab.active{color:var(--accent-light);border-bottom-color:var(--accent-light);font-weight:600}
.mocks-table{width:100%;border-collapse:collapse;margin-top:0;background:var(--card)}
.mocks-table th{text-align:left;padding:12px 20px;font-size:12px;text-transform:uppercase;color:var(--text-muted);border-bottom:1px solid var(--card-border);font-weight:600}
.mocks-table td{padding:14px 20px;border-bottom:1px solid var(--card-border);font-size:14px;color:var(--text-secondary)}
.mock-link{color:var(--accent-light);text-decoration:none}
.mock-link:hover{text-decoration:underline}
.status-fulfilled{color:var(--jewel-emerald);font-weight:600}
.text-right{text-align:right}
.sidebar-toggle{background:none;border:none;font-size:24px;color:var(--text-primary);cursor:pointer;padding:8px;margin-right:15px;display:flex;align-items:center;justify-content:center;border-radius:8px}
body.sidebar-collapsed .sidebar{transform:translateX(-100%)}
body.sidebar-collapsed .main-content{margin-left:0}
@media(max-width:900px){
  .metrics-row{flex-direction:column;align-items:stretch}
  .metric-box{border-right:none;border-bottom:1px solid var(--card-border)}
  .metric-box.large{border-right:none;border-bottom:2px solid var(--card-border)}
  .main-content{margin-left:0 !important}
  .sidebar{transform:translateX(-100%)}
}
</style>
</head>
<body>
<div class="sidebar">
  <div class="sidebar-logo">
    <h2>CFA Level 1</h2>
  </div>
  <nav class="sidebar-nav">
    <a href="/menu" class="sidebar-item">
      <span class="sidebar-item-icon">🏠</span> Home
    </a>
    <a href="/all" class="sidebar-item">
      <span class="sidebar-item-icon">📇</span> Flashcards
    </a>
    <a href="/practice" class="sidebar-item">
      <span class="sidebar-item-icon">📖</span> Practice
    </a>
    <a href="/mocks" class="sidebar-item active">
      <span class="sidebar-item-icon">🎯</span> Mock Exams
    </a>
    <a href="/my-scores" class="sidebar-item">
      <span class="sidebar-item-icon">📊</span> My Scores
    </a>
  </nav>
  <div class="sidebar-footer">
    <div class="sidebar-user">
      Logged in as:
      <strong>{{ session.user_name }}</strong>
    </div>
    <a href="/logout" class="sidebar-logout">Logout</a>
  </div>
</div>
<div class="main-content">
<div class="container">
  <div class="header-row">
    <div class="header-left">
      <button class="sidebar-toggle" onclick="document.body.classList.toggle('sidebar-collapsed')">☰</button>
      <h1>Mock Exams</h1>
    </div>
    <div class="top-tabs">
      <a href="#" class="top-tab active">Dashboard</a>
      <a href="#" class="top-tab">Confidence Levels</a>
      <a href="#" class="top-tab">Notes</a>
      <a href="#" class="top-tab">Bookmarks</a>
    </div>
  </div>

  <div class="dashboard-card">
    <div class="card-header">Dashboard</div>
    <div class="card-content">
      <div class="completion-section">
        <span class="completion-label">Completion</span>
        <div class="progress-bar-outer">
          <div class="progress-bar-fill" style="width: {{ completion_percent }}%"></div>
        </div>
      </div>
      
      <div class="metrics-row">
        <div class="metric-box large">
          <div class="metric-value large">{{ avg_correct }}%</div>
          <div class="metric-label large">Correct</div>
        </div>
        <div class="metric-box">
          <div class="metric-value">{{ exams_taken }} of {{ total_exams }}</div>
          <div class="metric-label">Mock Exams Taken</div>
        </div>
        <div class="metric-box">
          <div class="metric-value">{{ avg_answer_time }}</div>
          <div class="metric-label">Avg. Answer Time</div>
        </div>
        <div class="metric-box">
          <div class="metric-value">{{ avg_correct_time }}</div>
          <div class="metric-label">Avg. Correct Answer Time</div>
        </div>
        <div class="metric-box">
          <div class="metric-value">{{ avg_incorrect_time }}</div>
          <div class="metric-label">Avg. Incorrect Answer Time</div>
        </div>
      </div>

      <div class="sub-tabs">
        <a href="#" class="sub-tab active">Mock Exams</a>
        <a href="#" class="sub-tab">Reports</a>
      </div>
      
      <table class="mocks-table">
        <thead>
          <tr>
            <th>Mock Exam Name</th>
            <th>Mock Exam Length</th>
            <th>Mock Exam Time</th>
            <th>% Correct</th>
            <th>Requirement Status</th>
          </tr>
        </thead>
        <tbody>
          {% for mock in mocks %}
          <tr>
            <td><a href="/{{ mock.name }}" class="mock-link">{{ mock.display_name }}</a></td>
            <td>{{ mock.questions }} Questions</td>
            <td>{{ mock.time_limit }}</td>
            <td>
              {% if mock.completed %}
                {{ mock.score }}% ({{ mock.correct }} / {{ mock.questions }})
              {% endif %}
            </td>
            <td>
              {% if mock.completed %}
                <span class="status-fulfilled">Fulfilled</span>
              {% else %}
                Not Started
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>
</div>
</body>
</html>
"""

MENU_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>CFA Level 1 - Quiz Menu</title>
<style>
:root{--bg:#121212;--card:#0A2540;--card-border:#1a3a5c;--muted:#94a3b8;--accent:#0052A5;--accent-dark:#003d7a;--accent-light:#4d8fd6;--success:#2E7D32;--danger:#C62828;--warning:#fbbf24;--text-primary:#FAFAFA;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37;--jewel-emerald:#2E7D32;--jewel-sapphire:#0052A5;--jewel-amethyst:#6c5ce7;--jewel-ruby:#C62828;--glass-bg:rgba(255,255,255,0.05);--glass-border:rgba(255,255,255,0.1);--sidebar-width:210px}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, var(--bg) 0%, #0A2540 100%);color:var(--text-primary);min-height:100vh;display:flex}
.emoji,.sidebar-item-icon{-webkit-text-fill-color:initial;color:inherit}
.sidebar{width:var(--sidebar-width);background:var(--card);border-right:1px solid var(--card-border);padding:20px 0;display:flex;flex-direction:column;position:fixed;height:100vh;left:0;top:0;z-index:100;transition:transform 0.3s ease}
.sidebar-logo{padding:0 20px 20px 20px;border-bottom:1px solid var(--card-border);margin-bottom:12px}
.sidebar-logo h2{margin:0;font-size:16px;font-weight:800;background:linear-gradient(135deg, var(--accent-light) 0%, var(--gold) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sidebar-nav{flex:1;display:flex;flex-direction:column;gap:4px;padding:0 12px}
.sidebar-item{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:8px;color:var(--text-secondary);text-decoration:none;font-size:13px;font-weight:500;transition:all 0.2s}
.sidebar-item:hover{background:rgba(255,255,255,0.08);color:var(--text-primary)}
.sidebar-item.active{background:linear-gradient(135deg, var(--accent) 0%, var(--accent-light) 100%);color:#fff;font-weight:600}
.sidebar-item-icon{font-size:16px;width:20px;text-align:center}
.sidebar-footer{padding:16px 20px;border-top:1px solid var(--card-border);margin-top:auto}
.sidebar-user{font-size:11px;color:var(--text-muted)}
.sidebar-user strong{color:var(--text-primary);display:block;font-size:13px;margin-top:4px}
.sidebar-logout{display:block;margin-top:12px;padding:8px 12px;background:linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);color:#fff;text-decoration:none;border-radius:6px;font-size:12px;font-weight:600;text-align:center}
.sidebar-logout:hover{opacity:0.9}
.main-content{margin-left:var(--sidebar-width);flex:1;min-height:100vh;transition:margin-left 0.3s ease}
.container{max-width:1000px;margin:24px auto;padding:0 24px}
.header{position:relative;margin-bottom:32px;animation:slideDown 0.4s ease;text-align:left}
.user-actions{display:flex;align-items:center;justify-content:center;gap:15px;margin:20px 0;flex-wrap:wrap}
.user-info{background:var(--glass-bg);padding:10px 18px;border-radius:50px;font-size:14px;box-shadow:0 4px 15px rgba(167,139,250,0.15);transition:all 0.3s ease;border:1px solid var(--glass-border);color:var(--text-secondary)}
.btn{padding:10px 20px;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;display:inline-block;transition:all 0.3s;border:1px solid var(--glass-border);cursor:pointer}
.btn-primary{background:linear-gradient(135deg, #8b5cf6 0%, #a78bfa 100%);color:#fff;border:none;box-shadow:0 4px 15px rgba(139,92,246,0.3)}
.btn-primary:hover{background:linear-gradient(135deg, #a78bfa 0%, #c4b5fd 100%);transform:translateY(-2px);box-shadow:0 8px 25px rgba(167,139,250,0.4)}
.btn-secondary{background:var(--glass-bg);color:var(--text-secondary);border:1px solid var(--glass-border)}
.btn-secondary:hover{background:rgba(167,139,250,0.15);color:var(--accent-light);border-color:var(--accent);transform:translateY(-2px);box-shadow:0 4px 15px rgba(167,139,250,0.2)}
.btn-admin{background:linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%);color:#fff;border:none;box-shadow:0 4px 15px rgba(139,92,246,0.3)}
.btn-logout{background:linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);color:#fff;border:none;box-shadow:0 4px 15px rgba(244,63,94,0.3)}
.search-box{max-width:500px;margin:30px auto 24px;position:relative;transition:all 0.3s}
.search-box input{width:100%;padding:14px 16px 14px 44px;border:1px solid var(--card-border);border-radius:12px;font-size:16px;transition:all 0.3s;box-shadow:0 4px 15px rgba(167,139,250,0.1);background:var(--card);color:var(--text-primary)}
.search-box::before{content:'🔍';position:absolute;left:16px;top:50%;transform:translateY(-50%);font-size:18px}
.section{margin-bottom:40px}
.section-title{font-size:22px;font-weight:700;margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid var(--card-border);color:var(--text-primary)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:20px}
.card{background:var(--card);padding:20px;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.3);transition:all 0.3s;border:1px solid var(--card-border);position:relative;overflow:hidden}
.card:hover{box-shadow:0 12px 40px rgba(167,139,250,0.25);border-color:var(--accent);transform:translateY(-4px)}
.card-title{font-weight:700;font-size:16px;margin-bottom:12px;color:var(--text-primary);line-height:1.4}
.card-meta{display:flex;gap:16px;font-size:13px;color:var(--text-muted);margin-bottom:16px;flex-wrap:wrap}
.card-actions{display:flex;gap:10px}
.completed-badge{background:linear-gradient(135deg, var(--jewel-emerald) 0%, var(--jewel-sapphire) 100%);color:white;padding:4px 8px;border-radius:4px;font-size:12px;margin-left:10px;font-weight:600}
.modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:none;align-items:center;justify-content:center;z-index:1000}
.modal-overlay.active{display:flex}
.modal-content{background:var(--card);border-radius:16px;padding:30px;max-width:700px;width:90%;max-height:80vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,0.5);border:1px solid rgba(167,139,250,0.3)}
.modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--card-border)}
.modal-title{font-size:24px;font-weight:800;margin:0;background:linear-gradient(135deg, #a78bfa 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.modal-close{background:none;border:none;font-size:24px;cursor:pointer;color:var(--text-secondary)}
.session-info{background:rgba(167,139,250,0.08);border-radius:12px;padding:16px;margin-bottom:20px;border-left:4px solid var(--accent)}
.session-info-row{display:flex;justify-content:space-between;margin-bottom:12px;font-size:14px}
.session-label{color:var(--text-secondary);font-weight:600}
.session-value{color:var(--text-primary);word-break:break-all}
.session-history{margin-top:24px}
.session-history-title{font-size:16px;font-weight:700;margin-bottom:16px;color:var(--accent)}
.session-list{display:flex;flex-direction:column;gap:12px}
.session-item{background:rgba(167,139,250,0.05);border:1px solid rgba(167,139,250,0.2);border-radius:8px;padding:12px}
.session-item.current{border-color:var(--success);background:rgba(52,211,153,0.1)}
.session-item-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.session-item-time{font-size:13px;font-weight:600;color:var(--accent)}
.session-item-badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:12px;background:var(--success);color:white}
.session-item-details{font-size:12px;color:var(--text-muted);display:grid;gap:6px}
.session-item-detail{display:flex;align-items:flex-start;gap:6px}
.session-item-detail-label{font-weight:600;min-width:50px;color:var(--text-secondary)}
.session-item-detail-value{word-break:break-all;flex:1}
.sidebar-toggle{background:none;border:none;font-size:24px;color:var(--text-primary);cursor:pointer;padding:8px;margin-right:15px;display:flex;align-items:center;justify-content:center;border-radius:8px;transition:background 0.2s}
.sidebar-toggle:hover{background:rgba(255,255,255,0.1)}
body.sidebar-collapsed .sidebar{transform:translateX(-100%)}
body.sidebar-collapsed .main-content{margin-left:0}
/* CFA Dashboard Styles */
.dashboard-top{display:flex;gap:20px;align-items:stretch;margin-bottom:30px;flex-wrap:wrap}
.countdown-box{background:linear-gradient(135deg, #0A2540 0%, #0052A5 100%);padding:20px;border-radius:12px;min-width:160px;text-align:center;color:#fff;box-shadow:0 4px 15px rgba(0,82,165,0.3);position:relative}
.countdown-number{font-size:56px;font-weight:800;line-height:1}
.countdown-label{font-size:12px;text-transform:uppercase;margin-bottom:4px;opacity:0.9}
.countdown-date{font-size:11px;margin-top:6px;opacity:0.8;display:flex;align-items:center;justify-content:center;gap:4px}
.progress-card{flex:1;min-width:250px;background:var(--card);padding:24px;border-radius:12px;border:1px solid var(--card-border);display:flex;flex-direction:column;justify-content:center;box-shadow: 0 4px 12px rgba(0,0,0,0.2)}
.progress-label{font-size:14px;color:var(--text-secondary);font-weight:600;margin-bottom:12px;display:flex;justify-content:space-between}
.progress-bar-outer{background:rgba(255,255,255,0.05);height:12px;border-radius:6px;overflow:hidden;border:none}
.progress-bar-fill{height:100%;border-radius:6px;transition:width 0.5s ease}
.progress-bar-fill.orange{background:linear-gradient(90deg, #f59e0b 0%, #fbbf24 100%)}
.score-circles{display:flex;justify-content:center;gap:40px;padding:40px;background:var(--card);border-radius:12px;margin-bottom:30px;border:1px solid var(--card-border);box-shadow: 0 4px 20px rgba(0,0,0,0.3)}
.score-circle{text-align:center}
.score-ring{width:140px;height:140px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-direction:column;margin:0 auto 12px;position:relative}
.score-ring svg{transform:rotate(-90deg);width:100%;height:100%}
.score-ring circle{fill:none;stroke-width:10;stroke-linecap:round}
.score-ring .bg{stroke:rgba(255,255,255,0.05)}
.score-ring .progress{transition:stroke-dashoffset 1s ease-out;stroke-dasharray: 283;stroke-dashoffset: 283}
.score-value{font-size:32px;font-weight:800;color:var(--text-primary);position:absolute;top:50%;left:50%;transform:translate(-50%, -50%);text-align:center;line-height:1}
.score-suffix{font-size:14px;color:var(--text-muted);display:block;font-weight:600;margin-top:5px}
.score-label{font-size:16px;color:var(--text-secondary);font-weight:700;margin-bottom:25px}
.score-ring.blue .progress{stroke:var(--accent)}
.score-ring.green .progress{stroke:var(--success)}
.score-ring.purple .progress{stroke:var(--jewel-amethyst)}
.action-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:30px}
.task-section{background:rgba(0,82,165,0.1);border-radius:12px;padding:24px;display:flex;align-items:center;gap:20px;border:1px solid rgba(0,82,165,0.2)}
.task-section.purple{background:rgba(108,92,231,0.1);border-color:rgba(108,92,231,0.2)}
.task-icon{font-size:24px}
.task-info{flex:1}
.task-title{font-weight:700;color:var(--text-primary);font-size:18px;margin-bottom:4px}
.task-meta{font-size:14px;color:var(--text-muted)}
.task-btn{background:var(--accent);color:#fff;border:none;padding:12px 24px;border-radius:6px;font-weight:600;cursor:pointer;white-space:nowrap;transition:all 0.2s;text-decoration:none}
.task-btn.purple{background:var(--jewel-amethyst)}
.task-btn:hover{opacity:0.9;transform:translateY(-2px)}
/* Strengths & Weaknesses Section */
.strengths-section{margin-top:30px;background:var(--card);border:1px solid var(--card-border);border-radius:8px;padding:24px}
.strengths-header{font-size:20px;font-weight:700;margin-bottom:8px;color:var(--text-primary)}
.strengths-desc{color:var(--text-muted);font-size:13px;margin-bottom:20px}
.strength-row{display:flex;align-items:center;padding:12px 0;border-bottom:1px solid var(--card-border)}
.strength-row:last-child{border-bottom:none}
.topic-name{flex:0 0 280px;font-weight:600;color:var(--text-primary);font-size:14px}
.progress-track{flex:1;height:10px;background:rgba(255,255,255,0.05);border-radius:0;overflow:hidden;margin:0 20px}
.progress-fill-bar{height:100%;transition:width 0.5s}
.progress-fill-bar.green{background:#2E7D32}
.progress-fill-bar.yellow{background:#F9A825}
.progress-fill-bar.red{background:#C62828}
.progress-fill-bar.grey{background:#555}
.pct-value{flex:0 0 60px;text-align:right;font-weight:700;font-size:14px;color:var(--text-primary)}
@media(max-width:768px){
  .main-content{margin-left:0 !important}
  .sidebar{transform:translateX(-100%)}
  .score-circles{flex-direction:column;gap:30px}
  .action-grid{grid-template-columns:1fr}
  .topic-name{flex:0 0 150px;font-size:12px}
}
@keyframes slideDown {
  from {opacity: 0; transform: translateY(-20px);}
  to {opacity: 1; transform: translateY(0);}
}
</style>
</head>
<body>
<div class="sidebar">
  <div class="sidebar-logo">
    <h2>CFA Level 1</h2>
  </div>
  <nav class="sidebar-nav">
    <a href="/menu" class="sidebar-item active">
      <span class="sidebar-item-icon">🏠</span> Home
    </a>
    <a href="/all" class="sidebar-item">
      <span class="sidebar-item-icon">📇</span> Flashcards
    </a>
    <a href="/practice" class="sidebar-item">
      <span class="sidebar-item-icon">📖</span> Practice
    </a>
    <a href="/mocks" class="sidebar-item">
      <span class="sidebar-item-icon">🎯</span> Mock Exams
    </a>
    <a href="/my-scores" class="sidebar-item">
      <span class="sidebar-item-icon">📊</span> My Scores
    </a>
  </nav>
  <div class="sidebar-footer">
    <div class="sidebar-user">
      Logged in as:
      <strong>{{ session.user_name }}</strong>
    </div>
    {% if session.user_role == 'admin' %}
    <a href="/manage-users" class="sidebar-item" style="padding: 6px 14px; margin-top: 5px; background: rgba(167,139,250,0.1)">
      <span class="sidebar-item-icon">👥</span> Admin
    </a>
    {% endif %}
    <a href="/logout" class="sidebar-logout">Logout</a>
  </div>
</div>

<div class="main-content">
<div class="container">
  <div class="header">
    <div style="display: flex; align-items: center; justify-content: space-between">
      <div style="display: flex; align-items: center">
        <button class="sidebar-toggle" onclick="toggleSidebar()">☰</button>
        <h2 style="font-size: 26px; font-weight: 700; color: var(--text-primary); margin: 0">Welcome to CFA Program Level I</h2>
      </div>
      <div class="user-actions">
        <span class="user-info">👤 {{ session.user_name }}</span>
        <a href="/edit-profile" class="btn btn-secondary">👤 Profile</a>
        <button id="sessionDetailsBtn" class="btn btn-secondary" onclick="openSessionModal()">🔐 Sessions</button>
        <a href="/logout" class="btn btn-logout">🔓 Logout</a>
      </div>
    </div>
  </div>

  {% set modules = [] %}
  {% set mocks = [] %}
  {% for file in files %}
    {% if file.is_module %}
      {% set _ = modules.append(file) %}
    {% elif file.is_mock %}
      {% set _ = mocks.append(file) %}
    {% endif %}
  {% endfor %}

  <!-- CFA-Style Dashboard -->
  <div class="dashboard-area">
    <!-- TOP METRICS ROW -->
    <div class="dashboard-top">
      <!-- Days Until -->
      <div class="countdown-box" onclick="document.getElementById('examDatePicker').showPicker ? document.getElementById('examDatePicker').showPicker() : document.getElementById('examDatePicker').click()" style="cursor:pointer" title="Click to change exam date">
        <div class="countdown-label">Days Until</div>
        <div class="countdown-number" id="daysUntil">--</div>
        <div class="countdown-date">📅 <span id="examDate">Exam Date</span></div>
        <input type="date" id="examDatePicker" value="{{ exam_date }}" style="position:absolute;opacity:0;pointer-events:none" onchange="updateExamDate(this.value)">
      </div>

      <!-- Today's Study Progress -->
      <div class="progress-card">
        <div class="progress-label">
          <span>Today's Study Progress</span>
          <span style="color: var(--text-primary)">{{ stats.questions_attempted_today|default(0) }}/{{ daily_target }} 📚</span>
        </div>
        <div class="progress-bar-outer">
          <div class="progress-bar-fill orange" style="width: {{ [stats.questions_attempted_today|default(0) / daily_target * 100, 100]|min if daily_target > 0 else 0 }}%"></div>
        </div>
      </div>

      <!-- Study Progress (Overall) -->
      <div class="progress-card">
        <div class="progress-label">
          <span>Study Progress</span>
          <span style="color: var(--text-primary)">{{ study_progress_pct }}% complete</span>
        </div>
        <div class="progress-bar-outer">
          <div class="progress-bar-fill orange" style="width: {{ study_progress_pct }}%"></div>
        </div>
      </div>
    </div>
    
    <!-- PERFORMANCE METRICS (CIRCULAR RINGS) -->
    <div class="score-circles">
      <div class="score-circle">
        <div class="score-label">Modules Completed</div>
        <div class="score-ring blue">
          <svg viewBox="0 0 100 100">
            <circle class="bg" cx="50" cy="50" r="45"></circle>
            <circle class="progress" cx="50" cy="50" r="45" style="stroke-dasharray: 283; stroke-dashoffset: {{ 283 - (stats.modules_completed|default(0) / total_modules|default(93) * 283) if total_modules|default(93) > 0 else 283 }}"></circle>
          </svg>
          <div class="score-value">{{ stats.modules_completed|default(0) }}<span class="score-suffix">/ {{ total_modules|default(93) }} Modules</span></div>
        </div>
      </div>
      
      <div class="score-circle">
        <div class="score-label">Avg. Score on Practice</div>
        <div class="score-ring green">
          <svg viewBox="0 0 100 100">
            <circle class="bg" cx="50" cy="50" r="45"></circle>
            <circle class="progress" cx="50" cy="50" r="45" style="stroke-dasharray: 283; stroke-dashoffset: {{ 283 - (stats.avg_module_score|default(0) / 100 * 283) }}"></circle>
          </svg>
          <div class="score-value">{{ stats.avg_module_score|default(0)|int }}%<span class="score-suffix">% Correct</span></div>
        </div>
      </div>
      
      <div class="score-circle">
        <div class="score-label">Avg. Score on Mock Exams</div>
        <div class="score-ring purple">
          <svg viewBox="0 0 100 100">
            <circle class="bg" cx="50" cy="50" r="45"></circle>
            <circle class="progress" cx="50" cy="50" r="45" style="stroke-dasharray: 283; stroke-dashoffset: {{ 283 - (stats.avg_mock_score|default(0) / 100 * 283) }}"></circle>
          </svg>
          <div class="score-value">{{ stats.avg_mock_score|default(0)|int }}%<span class="score-suffix">% Correct</span></div>
        </div>
      </div>
    </div>

    <!-- ACTION SECTION -->
    <div class="action-grid">
      <div class="task-section">
        <div class="task-icon">📖</div>
        <div class="task-info">
          <div class="task-title">Practice: Start a Quiz</div>
          <div class="task-meta">{{ modules|length }} Modules Available</div>
        </div>
        <a href="/practice" class="task-btn">Start Practice →</a>
      </div>
      <div class="task-section purple">
        <div class="task-icon">🎯</div>
        <div class="task-info">
          <div class="task-title">Mock Exams Available</div>
          <div class="task-meta">{{ mocks|length }} Mock Exams Available</div>
        </div>
        <a href="/mocks" class="task-btn purple">Start Mock →</a>
      </div>
    </div>
  </div>

  <div class="search-box">
    <input type="text" id="searchInput" onkeyup="filterModules()" placeholder="Search modules or exams..." />
  </div>

  <!-- STRENGTHS & WEAKNESSES SECTION -->
  <div class="strengths-section">
    <div class="strengths-header">Strengths & Weaknesses</div>
    <p class="strengths-desc">Your performance by CFA curriculum topic</p>
    
    {% for topic in topic_strengths %}
    <div class="strength-row">
      <div class="topic-name">{{ topic.name }}</div>
      <div class="progress-track">
        {% if topic.percent is not none %}
        <div class="progress-fill-bar {% if topic.percent >= 70 %}green{% elif topic.percent >= 50 %}yellow{% else %}red{% endif %}" style="width: {{ topic.percent }}%"></div>
        {% else %}
        <div class="progress-fill-bar grey" style="width: 0%"></div>
        {% endif %}
      </div>
      <div class="pct-value">{% if topic.percent is not none %}{{ topic.percent }}%{% else %}N/A{% endif %}</div>
    </div>
    {% endfor %}
  </div>

  {% if not files %}
  <div class="empty">
    <div class="empty-icon">📂</div>
    <p>No quiz files found in the data folder.</p>
  </div>
  {% endif %}
</div> <!-- end container -->
</div> <!-- end main-content -->

<div id="sessionModal" class="modal-overlay">
  <div class="modal-content">
    <div class="modal-header">
      <h2 class="modal-title">🔐 Session Details</h2>
      <button class="modal-close" onclick="closeSessionModal()">&times;</button>
    </div>
    <div class="session-info">
      <div class="session-info-row">
        <span class="session-label">User ID:</span>
        <span class="session-value" id="userIdDisplay">Loading...</span>
      </div>
      <div class="session-info-row">
        <span class="session-label">Full Name:</span>
        <span class="session-value" id="userNameDisplay">Loading...</span>
      </div>
    </div>
    <div class="session-history">
      <h3 class="session-history-title">📝 Login History</h3>
      <div class="session-list" id="sessionList"></div>
    </div>
  </div>
</div>

<script>
function toggleSidebar() { document.body.classList.toggle('sidebar-collapsed'); }
function openSessionModal() { document.getElementById('sessionModal').classList.add('active'); loadSessionDetails(); }
function closeSessionModal() { document.getElementById('sessionModal').classList.remove('active'); }

function filterModules() {
  const input = document.getElementById('searchInput');
  const filter = input.value.toLowerCase();
  const cards = document.getElementsByClassName('card');
  for (let card of cards) {
    const name = card.getAttribute('data-name');
    card.style.display = name.includes(filter) ? "" : "none";
  }
}

// Exam Countdown
document.addEventListener('DOMContentLoaded', function() {
  const examDateStr = "{{ exam_date }}";
  if (examDateStr) {
    const examDate = new Date(examDateStr);
    const today = new Date();
    const diffTime = examDate - today;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    document.getElementById('daysUntil').textContent = diffDays > 0 ? diffDays : 0;
    const options = { day: '2-digit', month: '2-digit', year: 'numeric' };
    document.getElementById('examDate').textContent = examDate.toLocaleDateString('en-GB', options).split('/').join('-');
  }
});

function updateExamDate(newDate) {
  fetch('/api/update-exam-date', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({exam_date: newDate})
  }).then(() => window.location.reload());
}

async function loadSessionDetails() {
  const res = await fetch('/api/session-details');
  const data = await res.json();
  document.getElementById('userIdDisplay').textContent = data.user_id;
  document.getElementById('userNameDisplay').textContent = data.user_name;
  const list = document.getElementById('sessionList');
  list.innerHTML = data.sessions.map(s => `
    <div class="session-item ${s.is_current ? 'current' : ''}">
      <div class="session-item-header">
        <span class="session-item-time">📅 ${new Date(s.timestamp).toLocaleString()}</span>
        ${s.is_current ? '<span class="session-item-badge">CURRENT</span>' : ''}
      </div>
      <div class="session-item-details">IP: ${s.ip}</div>
    </div>
  `).join('');
}
</script>
</body>
</html>
"""

HISTORY_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Quiz History</title>
<style>
body{font-family:sans-serif;background:#121212;color:#fff;padding:20px}
.card{background:#1e293b;padding:15px;margin-bottom:10px;border-radius:8px}
.btn{display:inline-block;padding:8px 16px;background:#a78bfa;color:#000;text-decoration:none;border-radius:4px}
</style>
</head>
<body>
<h1>Quiz History</h1>
<a href="/menu" style="color:#a78bfa">Back to Menu</a>
{% for attempt in history %}<div class="card"><h3>{{ attempt.quiz_name }}</h3><p>Score: {{ attempt.score_percent }}% | Date: {{ attempt.timestamp }}</p><a href="/view-attempt/{{ attempt.id }}" class="btn">View Details</a></div>{% endfor %}
</body>
</html>
"""

RECENTLY_VIEWED_TEMPLATE = """
<!doctype html>
<html><head><title>Recently Viewed</title></head>
<body style="background:#121212;color:#fff;font-family:sans-serif;padding:20px">
<h1>Recently Viewed</h1>
{% for item in recently_viewed %}<div><h3>{{ item.name }}</h3><a href="/{{ item.name }}" style="color:#a78bfa">Take Again</a></div>{% endfor %}
</body>
</html>
"""

ADD_USER_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Add User - CFA Level 1 Quiz</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--card-border:#2d3748;--muted:#94a3b8;--accent:#a78bfa;--accent-dark:#8b5cf6;--accent-light:#c4b5fd;--success:#34d399;--danger:#f87171;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--gold:#d4af37}
body{margin:0;font-family:'Inter','Segoe UI',Arial,sans-serif;background:linear-gradient(135deg, #0f1419 0%, #1e293b 100%);color:var(--text-primary);min-height:100vh;display:flex;align-items:center;justify-content:center}
.form-card{background:var(--card);border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.4);padding:40px;border:1px solid rgba(167,139,250,0.2);width:90%;max-width:500px}
.header{display:flex;align-items:center;gap:16px;margin-bottom:32px}
.header h1{font-size:28px;margin:0;background:linear-gradient(135deg, #a78bfa 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;font-weight:800}
.form-group{margin-bottom:24px}
.form-group label{display:block;margin-bottom:8px;font-weight:600;color:var(--text-secondary);font-size:14px}
.form-group input, .form-group select{width:100%;padding:12px;border:1px solid rgba(167,139,250,0.3);border-radius:8px;background:rgba(255,255,255,0.05);color:var(--text-primary);font-size:15px;transition:all 0.3s}
.form-group input:focus{border-color:var(--accent);outline:none;background:rgba(255,255,255,0.08)}
.btn{padding:12px 24px;background:linear-gradient(135deg, var(--accent-dark) 0%, var(--accent) 100%);color:#fff;border:none;border-radius:10px;font-weight:600;cursor:pointer;width:100%;font-size:16px;transition:all 0.3s}
.btn:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(167,139,250,0.4)}
.error{color:var(--danger);background:rgba(244,63,94,0.15);padding:12px;border-radius:8px;margin-bottom:20px;font-size:14px;border:1px solid rgba(244,63,94,0.3)}
.success{color:var(--success);background:rgba(52,211,153,0.15);padding:12px;border-radius:8px;margin-bottom:20px;font-size:14px;border:1px solid rgba(52,211,153,0.3)}
</style>
</head>
<body>
<div class="form-card">
  <div class="header"><h1>➕ Add New User</h1></div>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  {% if success %}<div class="success">{{ success }}</div>{% endif %}
  <form method="POST">
    <div class="form-group"><label>Full Name</label><input type="text" name="name" required placeholder="Enter full name"></div>
    <div class="form-group"><label>User ID</label><input type="text" name="user_id" required placeholder="Enter user ID"></div>
    <div class="form-group"><label>Password</label><input type="password" name="password" required placeholder="Enter password"></div>
    <div class="form-group"><label>Role</label><select name="role"><option value="user">User</option><option value="admin">Administrator</option></select></div>
    <div class="form-group"><label>Expiry Date (Optional)</label><input type="date" name="expiry"></div>
    <button type="submit" class="btn">Add User</button>
  </form>
  <div style="margin-top:20px;text-align:center"><a href="/manage-users" style="color:var(--accent);text-decoration:none;font-weight:600">← Back to Manage Users</a></div>
</div>
</body>
</html>
"""

REMOVE_USER_TEMPLATE = """
<!doctype html>
<html><head><title>Remove User</title></head>
<body style="background:#121212;color:#fff;font-family:sans-serif;padding:20px">
<h1>Remove User</h1>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="POST">
<input type="text" name="user_id" placeholder="User ID" required><br>
<button type="submit">Remove User</button>
</form>
</body>
</html>
"""

MANAGE_USERS_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Manage Users - CFA Level 1 Quiz</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--card-border:#2d3748;--muted:#94a3b8;--accent:#a78bfa;--accent-dark:#8b5cf6;--accent-light:#c4b5fd;--success:#34d399;--danger:#f87171;--warning:#fbbf24;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--gold:#d4af37}
body{margin:0;font-family:'Inter','Segoe UI',Arial,sans-serif;background:linear-gradient(135deg, var(--bg) 0%, #1e293b 100%);color:var(--text-primary);min-height:100vh}
.container{max-width:1100px;margin:28px auto;padding:0 18px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:40px;flex-wrap:wrap;gap:20px}
.header h1{font-size:32px;margin:0;background:linear-gradient(135deg, #a78bfa 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;font-weight:800}
.btn{padding:10px 20px;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;display:inline-block;transition:all 0.3s;background:var(--accent);color:#000}
.user-card{background:var(--card);padding:20px;border-radius:12px;border:1px solid var(--card-border);margin-bottom:12px;display:flex;justify-content:space-between;align-items:center}
.user-name{font-weight:700;font-size:18px;color:var(--text-primary)}
.user-meta{color:var(--text-secondary);font-size:14px;margin-top:4px}
.tag{padding:4px 8px;border-radius:4px;font-size:12px;font-weight:700;margin-left:10px}
.tag-admin{background:var(--accent);color:#000}
.tag-user{background:var(--card-border);color:var(--text-secondary)}
.status-valid{color:var(--success)}
.status-expired{color:var(--danger)}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>👥 Manage Users</h1>
    <div style="display:flex;gap:12px">
      <a href="/add-user" class="btn">➕ Add User</a>
      <a href="/menu" class="btn" style="background:var(--card-border);color:var(--text-primary)">🏠 Menu</a>
    </div>
  </div>
  {% if users %}
  {% for user in users %}
  <div class="user-card">
    <div>
      <div class="user-name">
        {{ user.name }}
        {% if user.role == 'admin' %}<span class="tag tag-admin">ADMIN</span>{% else %}<span class="tag tag-user">USER</span>{% endif %}
      </div>
      <div class="user-meta">
        <strong>ID:</strong> {{ user.id }} | 
        <strong>Status:</strong> <span class="{% if user.is_valid %}status-valid{% else %}status-expired{% endif %}">{% if user.is_valid %}Valid{% else %}Expired{% endif %}</span>
        {% if user.expiry %} | <strong>Expires:</strong> {{ user.expiry }}{% endif %}
      </div>
    </div>
    <a href="/edit-user/{{ user.id }}" class="btn" style="background:var(--card-border);color:var(--accent)">✏️ Edit</a>
  </div>
  {% endfor %}
  {% else %}
  <p style="text-align:center;padding:40px;color:var(--text-muted)">No users found.</p>
  {% endif %}
</div>
</body>
</html>
"""

EDIT_USER_TEMPLATE = """
<!doctype html>
<html><head><title>Edit User</title></head>
<body style="background:#121212;color:#fff;font-family:sans-serif;padding:20px">
<h1>Edit User: {{ user.id }}</h1>
<form method="POST">
<input type="text" name="name" value="{{ user.name }}" required><br>
<input type="password" name="password" placeholder="New Password (optional)"><br>
<select name="role"><option value="user" {% if user.role=='user' %}selected{% endif %}>User</option><option value="admin" {% if user.role=='admin' %}selected{% endif %}>Admin</option></select><br>
<button type="submit">Update User</button>
</form>
</body>
</html>
"""

USER_PROFILE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Edit Profile - CFA Level 1</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--card-border:#2d3748;--accent:#a78bfa;--accent-dark:#8b5cf6;--success:#34d399;--danger:#f87171;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-muted:#94a3b8}
body{margin:0;font-family:'Inter','Segoe UI',Arial,sans-serif;background:linear-gradient(135deg, #0f1419 0%, #1a202c 100%);color:var(--text-primary);min-height:100vh}
.container{max-width:600px;margin:40px auto;padding:0 20px}
.nav-back{display:inline-flex;align-items:center;gap:8px;color:var(--accent);text-decoration:none;margin-bottom:24px;font-weight:600;font-size:14px}
.nav-back:hover{text-decoration:underline}
.card{background:var(--card);border:1px solid var(--card-border);border-radius:16px;padding:32px;box-shadow:0 4px 24px rgba(0,0,0,0.3)}
.card-header{margin-bottom:28px;text-align:center}
.card-header h1{font-size:28px;font-weight:700;margin:0 0 8px 0;background:linear-gradient(135deg, #a78bfa 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.card-header p{color:var(--text-muted);margin:0;font-size:14px}
.avatar{width:80px;height:80px;border-radius:50%;background:linear-gradient(135deg, var(--accent) 0%, #d4af37 100%);display:flex;align-items:center;justify-content:center;margin:0 auto 16px;font-size:32px;font-weight:700;color:#000}
.form-group{margin-bottom:20px}
.form-group label{display:block;font-size:13px;font-weight:600;color:var(--text-secondary);margin-bottom:8px}
.form-group input{width:100%;padding:14px 16px;border:1px solid var(--card-border);border-radius:10px;background:rgba(255,255,255,0.05);color:var(--text-primary);font-size:15px;transition:all 0.2s;box-sizing:border-box}
.form-group input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(167,139,250,0.15)}
.form-group input::placeholder{color:var(--text-muted)}
.form-hint{font-size:12px;color:var(--text-muted);margin-top:6px}
.btn{width:100%;padding:14px;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;transition:all 0.2s}
.btn-primary{background:linear-gradient(135deg, var(--accent) 0%, var(--accent-dark) 100%);color:#000}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 4px 16px rgba(167,139,250,0.4)}
.alert{padding:14px 16px;border-radius:10px;margin-bottom:20px;font-size:14px;font-weight:500}
.alert-success{background:rgba(52,211,153,0.15);color:var(--success);border:1px solid rgba(52,211,153,0.3)}
.alert-error{background:rgba(248,113,113,0.15);color:var(--danger);border:1px solid rgba(248,113,113,0.3)}
.info-row{display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--card-border);font-size:14px}
.info-row:last-child{border-bottom:none}
.info-label{color:var(--text-muted)}
.info-value{color:var(--text-primary);font-weight:600}
</style>
</head>
<body>
<div class="container">
  <a href="/menu" class="nav-back">← Back to Dashboard</a>
  
  <div class="card">
    <div class="card-header">
      <div class="avatar">{{ user.name[:1]|upper if user.name else 'U' }}</div>
      <h1>Edit Profile</h1>
      <p>Update your account information</p>
    </div>
    
    {% if success %}
    <div class="alert alert-success">✓ {{ success }}</div>
    {% endif %}
    {% if error %}
    <div class="alert alert-error">⚠ {{ error }}</div>
    {% endif %}
    
    <form method="POST">
      <div class="form-group">
        <label for="name">Full Name</label>
        <input type="text" id="name" name="name" value="{{ user.name }}" required placeholder="Enter your full name"/>
      </div>
      
      <div class="form-group">
        <label for="password">New Password</label>
        <input type="password" id="password" name="password" placeholder="Leave blank to keep current password"/>
        <div class="form-hint">Only fill this if you want to change your password</div>
      </div>
      
      <button type="submit" class="btn btn-primary">💾 Save Changes</button>
    </form>
    
    <div style="margin-top:24px;padding-top:20px;border-top:1px solid var(--card-border)">
      <div class="info-row">
        <span class="info-label">User ID</span>
        <span class="info-value">{{ user.user_id|default('N/A') }}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Account Status</span>
        <span class="info-value" style="color:var(--success)">{{ 'Active' if user.is_valid else 'Expired' }}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Role</span>
        <span class="info-value">{{ user.role|default('user')|capitalize }}</span>
      </div>
    </div>
  </div>
</div>
</body>
</html>
"""


MY_SCORES_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>My Scores - CFA Level 1</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--card-border:#2d3748;--accent:#a78bfa;--accent-dark:#8b5cf6;--success:#34d399;--danger:#f87171;--warning:#fbbf24;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-muted:#94a3b8}
body{margin:0;font-family:'Inter','Segoe UI',Arial,sans-serif;background:var(--bg);color:var(--text-primary);min-height:100vh}
.container{max-width:1100px;margin:28px auto;padding:0 18px}
.header{margin-bottom:30px}
.header h1{font-size:28px;font-weight:700;margin:0 0 8px 0;background:linear-gradient(135deg, #a78bfa 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header p{color:var(--text-muted);margin:0}
.stats-row{display:flex;gap:20px;margin-bottom:30px;flex-wrap:wrap}
.stat-card{background:var(--card);border:1px solid var(--card-border);border-radius:12px;padding:20px;flex:1;min-width:150px}
.stat-value{font-size:32px;font-weight:700;color:var(--text-primary)}
.stat-label{font-size:13px;color:var(--text-muted);margin-top:4px}
.attempts-table{width:100%;border-collapse:collapse;background:var(--card);border-radius:12px;overflow:hidden}
.attempts-table th{text-align:left;padding:14px 20px;background:rgba(255,255,255,0.03);font-size:12px;text-transform:uppercase;color:var(--text-muted);border-bottom:1px solid var(--card-border)}
.attempts-table td{padding:14px 20px;border-bottom:1px solid var(--card-border);font-size:14px}
.attempts-table tr:last-child td{border-bottom:none}
.score-badge{padding:4px 12px;border-radius:20px;font-weight:600;font-size:13px}
.score-high{background:rgba(52,211,153,0.2);color:var(--success)}
.score-mid{background:rgba(251,191,36,0.2);color:var(--warning)}
.score-low{background:rgba(248,113,113,0.2);color:var(--danger)}
.btn{padding:8px 16px;border-radius:8px;font-size:13px;font-weight:600;text-decoration:none;display:inline-block;transition:all 0.2s}
.btn-primary{background:var(--accent);color:#000}
.btn-secondary{background:rgba(255,255,255,0.05);color:var(--text-secondary);border:1px solid var(--card-border)}
.empty{text-align:center;padding:60px 20px;color:var(--text-muted)}
.nav-back{display:inline-flex;align-items:center;gap:8px;color:var(--accent);text-decoration:none;margin-bottom:20px;font-weight:600}
</style>
</head>
<body>
<div class="container">
  <a href="/menu" class="nav-back">← Back to Menu</a>
  
  <div class="header">
    <h1>📊 My Scores</h1>
    <p>Your quiz attempts and performance history</p>
  </div>
  
  <div class="stats-row">
    <div class="stat-card">
      <div class="stat-value">{{ stats.total_attempts|default(0) }}</div>
      <div class="stat-label">Total Attempts</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ stats.avg_module_score|default(0)|int }}%</div>
      <div class="stat-label">Avg. Practice Score</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ stats.avg_mock_score|default(0)|int }}%</div>
      <div class="stat-label">Avg. Mock Score</div>
    </div>
  </div>
  
  {% if attempts %}
  <table class="attempts-table">
    <thead>
      <tr>
        <th>Quiz Name</th>
        <th>Type</th>
        <th>Date</th>
        <th>Score</th>
        <th>Time Spent</th>
        <th>Action</th>
      </tr>
    </thead>
    <tbody>
      {% for attempt in attempts %}
      <tr>
        <td>{{ attempt.quiz_name }}</td>
        <td>{{ 'Mock' if attempt.quiz_type == 'mock' else 'Practice' }}</td>
        <td>{{ attempt.timestamp[:10] if attempt.timestamp else 'N/A' }}</td>
        <td>
          <span class="score-badge {% if attempt.score_percent >= 70 %}score-high{% elif attempt.score_percent >= 50 %}score-mid{% else %}score-low{% endif %}">
            {{ attempt.score_percent }}%
          </span>
        </td>
        <td>{{ (attempt.time_spent_seconds // 60)|int }}m {{ attempt.time_spent_seconds % 60 }}s</td>
        <td>
          <a href="/review-attempt/{{ attempt.attempt_id }}" class="btn btn-primary">Review</a>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">
    <h3>No attempts yet</h3>
    <p>Complete a quiz to see your scores here.</p>
    <a href="/practice" class="btn btn-primary" style="margin-top:16px">Start Practice</a>
  </div>
  {% endif %}
</div>
</body>
</html>
"""

ATTEMPT_DETAILS_TEMPLATE = """
<!doctype html>
<html><head><title>Attempt Details</title></head>
<body style="background:#121212;color:#fff;font-family:sans-serif;padding:20px">
<h1>Attempt: {{ attempt.quiz_name }}</h1>
<p>Score: {{ attempt.score_percent }}%</p>
<a href="/my-scores" style="color:#a78bfa">Back to Scores</a>
</body>
</html>
"""

REVIEW_ATTEMPT_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Review Attempt - {{ attempt.quiz_name }}</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--card-border:#2d3748;--accent:#a78bfa;--success:#34d399;--danger:#f87171;--warning:#fbbf24;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-muted:#94a3b8}
body{margin:0;font-family:'Inter','Segoe UI',Arial,sans-serif;background:var(--bg);color:var(--text-primary);min-height:100vh}
.container{max-width:900px;margin:28px auto;padding:0 18px}
.nav-back{display:inline-flex;align-items:center;gap:8px;color:var(--accent);text-decoration:none;margin-bottom:20px;font-weight:600}
.header{margin-bottom:30px;padding-bottom:20px;border-bottom:1px solid var(--card-border)}
.header h1{font-size:24px;font-weight:700;margin:0 0 8px 0}
.summary{display:flex;gap:20px;flex-wrap:wrap;margin-bottom:8px}
.summary-item{font-size:14px;color:var(--text-secondary)}
.summary-item strong{color:var(--text-primary)}
.question-card{background:var(--card);border:1px solid var(--card-border);border-radius:12px;margin-bottom:20px;overflow:hidden}
.question-card.correct{border-left:4px solid var(--success)}
.question-card.incorrect{border-left:4px solid var(--danger)}
.question-card.skipped{border-left:4px solid var(--text-muted)}
.q-header{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;background:rgba(255,255,255,0.02);cursor:pointer}
.q-header:hover{background:rgba(255,255,255,0.04)}
.q-num{font-size:14px;font-weight:700;color:var(--accent)}
.q-meta{display:flex;gap:12px;font-size:12px;color:var(--text-muted);align-items:center}
.q-flag{color:var(--warning)}
.q-time{color:var(--text-secondary)}
.result-badge{padding:4px 10px;border-radius:12px;font-size:12px;font-weight:600}
.result-correct{background:rgba(52,211,153,0.2);color:var(--success)}
.result-incorrect{background:rgba(248,113,113,0.2);color:var(--danger)}
.result-skipped{background:rgba(148,163,184,0.2);color:var(--text-muted)}
.q-body{padding:20px;display:none}
.q-body.expanded{display:block}
.q-stem{font-size:15px;line-height:1.6;margin-bottom:20px}
.choice{padding:14px;border-radius:8px;margin-bottom:12px;font-size:14px;border:1px solid var(--card-border)}
.choice.correct-answer{border-color:var(--success);background:rgba(52,211,153,0.08)}
.choice.user-selected{border-color:var(--accent);background:rgba(167,139,250,0.08)}
.choice.user-selected.wrong{border-color:var(--danger);background:rgba(248,113,113,0.08)}
.choice-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px}
.choice-label{font-weight:700;color:var(--text-primary)}
.choice-tag{font-size:11px;font-weight:600;padding:2px 8px;border-radius:4px}
.tag-correct{background:var(--success);color:#000}
.tag-your{background:var(--danger);color:#fff}
.tag-your-correct{background:var(--success);color:#000}
.choice-text{color:var(--text-secondary);line-height:1.5}
.choice-explanation{margin-top:10px;padding-top:10px;border-top:1px solid var(--card-border);font-size:13px;color:var(--text-muted);line-height:1.5}
.general-feedback{margin-top:16px;padding:16px;background:rgba(167,139,250,0.05);border-radius:8px;border-left:3px solid var(--accent)}
.general-feedback-title{font-size:13px;font-weight:700;color:var(--accent);margin-bottom:8px}
.general-feedback-content{font-size:14px;color:var(--text-secondary);line-height:1.6}
.your-answer-summary{font-size:13px;color:var(--text-muted);margin-bottom:12px}
.your-answer-summary strong{color:var(--text-primary)}
</style>
</head>
<body>
<div class="container">
  <a href="/my-scores" class="nav-back">← Back to My Scores</a>
  
  <div class="header">
    <h1>Review: {{ attempt.quiz_name }}</h1>
    <div class="summary">
      <div class="summary-item"><strong>Score:</strong> {{ attempt.score_percent }}%</div>
      <div class="summary-item"><strong>Result:</strong> {{ attempt.correct_count }} / {{ attempt.total_questions }} correct</div>
      <div class="summary-item"><strong>Time:</strong> {{ (attempt.time_spent_seconds // 60)|int }}m {{ attempt.time_spent_seconds % 60 }}s</div>
    </div>
  </div>
  
  {% for resp in responses %}
  <div class="question-card {% if resp.is_correct %}correct{% elif resp.user_answer %}incorrect{% else %}skipped{% endif %}">
    <div class="q-header" onclick="toggleQuestion(this)">
      <div class="q-num">Question {{ resp.question_number|default(loop.index) }}</div>
      <div class="q-meta">
        {% if resp.flagged %}<span class="q-flag">🚩</span>{% endif %}
        <span class="q-time">⏱️ {{ resp.time_spent_seconds|default(0) }}s</span>
        <span class="result-badge {% if resp.is_correct %}result-correct{% elif resp.user_answer %}result-incorrect{% else %}result-skipped{% endif %}">
          {% if resp.is_correct %}✓ Correct{% elif resp.user_answer %}✗ Incorrect{% else %}Skipped{% endif %}
        </span>
      </div>
    </div>
    
    <div class="q-body">
      <div class="q-stem">{{ resp.question_text|safe }}</div>
      
      <div class="your-answer-summary">
        <strong>Your Answer:</strong> {{ resp.user_answer_label if resp.user_answer_label else 'Skipped' }} | 
        <strong>Correct Answer:</strong> {{ resp.correct_answer_label|default('N/A') }}
      </div>
      
      {% for choice in resp.choices %}
      <div class="choice 
        {% if choice.id == resp.correct_answer %}correct-answer{% endif %}
        {% if choice.id == resp.user_answer %}user-selected{% if choice.id != resp.correct_answer %} wrong{% endif %}{% endif %}">
        <div class="choice-header">
          <span class="choice-label">{{ choice.label }}. {{ choice.text|safe|truncate(100) }}</span>
          <span>
            {% if choice.id == resp.correct_answer %}<span class="choice-tag {% if choice.id == resp.user_answer %}tag-your-correct{% else %}tag-correct{% endif %}">{% if choice.id == resp.user_answer %}✓ Your Correct Answer{% else %}✓ Correct{% endif %}</span>{% endif %}
            {% if choice.id == resp.user_answer and choice.id != resp.correct_answer %}<span class="choice-tag tag-your">Your Answer</span>{% endif %}
          </span>
        </div>
        {% if choice.explanation %}
        <div class="choice-explanation">{{ choice.explanation|safe }}</div>
        {% endif %}
      </div>
      {% endfor %}
      
      {% if not is_mock and resp.general_feedback %}
      <div class="general-feedback">
        <div class="general-feedback-title">General Explanation</div>
        <div class="general-feedback-content">{{ resp.general_feedback|safe }}</div>
      </div>
      {% endif %}
    </div>
  </div>
  {% endfor %}
</div>

<script>
function toggleQuestion(header) {
  const body = header.nextElementSibling;
  body.classList.toggle('expanded');
}
// Auto-expand first 3 questions
document.addEventListener('DOMContentLoaded', function() {
  const bodies = document.querySelectorAll('.q-body');
  bodies.forEach((b, i) => { if (i < 3) b.classList.add('expanded'); });
});
</script>
</body>
</html>
"""

PROFILE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Profile - CFA Level 1</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--card-border:#2d3748;--accent:#a78bfa;--success:#34d399;--text-primary:#f1f5f9;--text-muted:#94a3b8}
body{margin:0;font-family:'Inter','Segoe UI',Arial,sans-serif;background:var(--bg);color:var(--text-primary);min-height:100vh}
.container{max-width:900px;margin:28px auto;padding:0 18px}
.nav-back{display:inline-flex;align-items:center;gap:8px;color:var(--accent);text-decoration:none;margin-bottom:20px;font-weight:600}
.profile-header{display:flex;gap:24px;align-items:center;margin-bottom:30px}
.avatar{width:80px;height:80px;border-radius:50%;background:linear-gradient(135deg,var(--accent) 0%,#d4af37 100%);display:flex;align-items:center;justify-content:center;font-size:32px;font-weight:700;color:#000}
.user-info h1{font-size:24px;margin:0 0 4px 0}
.user-info p{margin:0;color:var(--text-muted);font-size:14px}
.status-badge{display:inline-block;padding:4px 12px;border-radius:12px;font-size:12px;font-weight:600;margin-top:8px;background:rgba(52,211,153,0.2);color:var(--success)}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;margin-bottom:30px}
.stat-card{background:var(--card);border:1px solid var(--card-border);border-radius:12px;padding:20px;text-align:center}
.stat-value{font-size:28px;font-weight:700}
.stat-label{font-size:12px;color:var(--text-muted);margin-top:4px}
.section-title{font-size:18px;font-weight:700;margin-bottom:16px}
.activity-list{background:var(--card);border:1px solid var(--card-border);border-radius:12px;overflow:hidden}
.activity-item{padding:14px 20px;border-bottom:1px solid var(--card-border);display:flex;justify-content:space-between;align-items:center}
.activity-item:last-child{border-bottom:none}
.activity-name{font-weight:600}
.activity-meta{font-size:13px;color:var(--text-muted)}
.activity-score{font-weight:700;color:var(--success)}
</style>
</head>
<body>
<div class="container">
  <a href="/menu" class="nav-back">← Back to Dashboard</a>
  <div class="profile-header">
    <div class="avatar">{{ user.name[:1]|upper if user.name else 'U' }}</div>
    <div class="user-info">
      <h1>{{ user.name|default('User') }}</h1>
      <p>{{ user.email|default(session.get('user_id', 'N/A')) }}</p>
      <span class="status-badge">Active</span>
    </div>
  </div>
  <div class="stats-grid">
    <div class="stat-card"><div class="stat-value">{{ stats.total_attempts|default(0) }}</div><div class="stat-label">Total Attempts</div></div>
    <div class="stat-card"><div class="stat-value">{{ stats.avg_module_score|default(0)|int }}%</div><div class="stat-label">Avg Practice</div></div>
    <div class="stat-card"><div class="stat-value">{{ stats.avg_mock_score|default(0)|int }}%</div><div class="stat-label">Avg Mock</div></div>
    <div class="stat-card"><div class="stat-value">{{ stats.modules_completed|default(0) }}</div><div class="stat-label">Modules Done</div></div>
  </div>
  <div class="section-title">📊 Recent Activity</div>
  {% if recent_attempts %}
  <div class="activity-list">
    {% for attempt in recent_attempts %}
    <div class="activity-item">
      <div><div class="activity-name">{{ attempt.quiz_name }}</div><div class="activity-meta">{{ attempt.timestamp[:10] if attempt.timestamp else 'N/A' }}</div></div>
      <div class="activity-score">{{ attempt.score_percent }}%</div>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <p style="color:var(--text-muted)">No recent activity. Start practicing!</p>
  {% endif %}
  <div style="margin-top:20px"><a href="/my-scores" style="color:var(--accent);text-decoration:none;font-weight:600">View All Scores →</a></div>
</div>
</body>
</html>
"""

FLASHCARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Flashcards - CFA Level 1</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--card-border:#2d3748;--accent:#a78bfa;--success:#34d399;--text-primary:#f1f5f9;--text-muted:#94a3b8}
body{margin:0;font-family:'Inter','Segoe UI',Arial,sans-serif;background:var(--bg);color:var(--text-primary);min-height:100vh}
.container{max-width:800px;margin:28px auto;padding:0 18px}
.nav-back{display:inline-flex;align-items:center;gap:8px;color:var(--accent);text-decoration:none;margin-bottom:20px;font-weight:600}
.header{margin-bottom:30px}
.header h1{font-size:24px;font-weight:700;margin:0 0 8px 0}
.header p{color:var(--text-muted);font-size:14px;margin:0}
.flashcard{background:var(--card);border:1px solid var(--card-border);border-radius:16px;padding:40px;min-height:200px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all 0.3s;text-align:center;margin-bottom:20px}
.flashcard:hover{border-color:var(--accent);transform:translateY(-4px)}
.flashcard-term{font-size:24px;font-weight:700}
.flashcard-definition{font-size:18px;color:var(--text-muted);line-height:1.6}
.controls{display:flex;gap:16px;justify-content:center;margin-bottom:20px}
.btn{padding:12px 24px;border-radius:8px;font-weight:600;cursor:pointer;border:none;transition:all 0.2s}
.btn-prev,.btn-next{background:var(--card);color:var(--text-primary);border:1px solid var(--card-border)}
.btn-prev:hover,.btn-next:hover{border-color:var(--accent);background:rgba(167,139,250,0.1)}
.counter{text-align:center;color:var(--text-muted);font-size:14px}
.empty{text-align:center;padding:60px 20px;color:var(--text-muted)}
.empty h2{color:var(--text-primary);margin-bottom:8px}
</style>
</head>
<body>
<div class="container">
  <a href="/menu" class="nav-back">← Back to Dashboard</a>
  <div class="header">
    <h1>📇 Flashcards</h1>
    <p>{{ total_cards }} cards from CFA Curriculum</p>
  </div>
  
  {% if cards %}
  <div class="flashcard" id="flashcard" onclick="flipCard()">
    <div id="cardContent" class="flashcard-term"></div>
  </div>
  
  <div class="controls">
    <button class="btn btn-prev" onclick="prevCard()">← Previous</button>
    <button class="btn btn-next" onclick="nextCard()">Next →</button>
  </div>
  
  <div class="counter">Card <span id="cardNum">1</span> of {{ total_cards }}</div>
  
  <script>
  const cards = {{ cards|tojson }};
  let idx = 0;
  let showingTerm = true;
  
  function render() {
    const card = cards[idx];
    const content = showingTerm ? card.term : card.definition;
    document.getElementById('cardContent').textContent = content;
    document.getElementById('cardContent').className = showingTerm ? 'flashcard-term' : 'flashcard-definition';
    document.getElementById('cardNum').textContent = idx + 1;
  }
  
  function flipCard() {
    showingTerm = !showingTerm;
    render();
  }
  
  function nextCard() {
    idx = (idx + 1) % cards.length;
    showingTerm = true;
    render();
  }
  
  function prevCard() {
    idx = (idx - 1 + cards.length) % cards.length;
    showingTerm = true;
    render();
  }
  
  render();
  </script>
  {% else %}
  <div class="empty">
    <h2>No Flashcards Yet</h2>
    <p>Flashcards will be available after the CFA PDF is processed.</p>
    <p>Check back soon!</p>
  </div>
  {% endif %}
</div>
</body>
</html>
"""

@app.route('/api/session-details')
@login_required
def get_session_details_api():
    """API endpoint to get session details for the current user"""
    user_id = session.get('user_id')
    sessions = db.get_session_details(user_id)
    
    return jsonify({
        'user_id': user_id,
        'user_name': session.get('user_name'),
        'sessions': sessions
    })


@app.route('/api/update-exam-date', methods=['POST'])
@login_required
def update_exam_date():
    """Update user's exam date - supports unlimited changes"""
    try:
        data = request.get_json()
        user_id = session.get('user_id')
        new_date = data.get('exam_date')
        
        if not user_id or not new_date:
            return jsonify({'status': 'error', 'message': 'Missing data'}), 400
        
        # Validate date format
        try:
            from datetime import date
            date.fromisoformat(new_date)
        except:
            return jsonify({'status': 'error', 'message': 'Invalid date format'}), 400
        
        # Update user's exam date in Redis using proper update method
        success = db.update_user(user_id, {'exam_date': new_date})
        
        if success:
            print(f"📅 Updated exam date for user '{user_id}' to {new_date}")
            return jsonify({'status': 'success', 'exam_date': new_date})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to update'}), 500
    except Exception as e:
        print(f"❌ Error updating exam date: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/practice')
@login_required
def practice_dashboard():
    user_id = session.get('user_id')
    stats = db.get_user_quiz_stats(user_id)
    attempts = db.get_user_quiz_attempts(user_id, limit=1000)
    paused_attempts = db.get_all_paused_attempts(user_id)
    
    # Load all module files to get total questions
    all_files = []
    for f in os.listdir(DATA_FOLDER):
        if f.endswith(".json") and f.startswith("Module"):
            name = f[:-5]
            path = os.path.join(DATA_FOLDER, f)
            try:
                with open(path, 'r', encoding='utf-8') as jf:
                    raw = json.load(jf)
                    items = _find_items_structure(raw)
                    all_files.append({
                        'name': name,
                        'questions': len(items),
                        'num': get_module_number(name)
                    })
            except: continue

    # Topic mapping
    topics_data = []
    total_q_all = 0
    total_c_all = 0
    
    for topic_name, (start, end) in MODULE_CATEGORIES.items():
        topic_modules = [f for f in all_files if start <= f['num'] <= end]
        # Sort topic_modules numerically by 'num'
        topic_modules.sort(key=lambda x: x['num'])
        
        topic_total_q = sum(m['questions'] for m in topic_modules)
        topic_complete_q = 0
        topic_scores = []
        
        subtopics = []
        for i, m in enumerate(topic_modules):
            full_name = m['name']
            # Clean display name: remove "Module 123 " prefix
            clean_name = re.sub(r'^Module\s+\d+\s*', '', full_name).strip()
            # Prefix with sequence number
            display_name = f"{i+1}. {clean_name}"
            
            # Find latest attempt for this module (completed)
            attempt = next((a for a in attempts if (a.get('quiz_name') == full_name or a.get('quiz_id') == full_name)), None)
            
            # Find paused attempt
            paused_data = paused_attempts.get(full_name)
            
            # Determine status and progress
            if attempt:
                is_completed = True
                status = 'completed'
                m_comp = m['questions']
                m_score = attempt.get('score_percent', '--')
            elif paused_data:
                is_completed = False
                status = 'in_progress'
                ans_list = paused_data.get('user_answers', [])
                m_comp = sum(1 for a in ans_list if a is not None)
                
                # Calculate accuracy for in-progress module
                m_responses = paused_data.get('responses', [])
                m_correct = sum(1 for r in m_responses if r.get('is_correct'))
                m_attempted = len(m_responses)
                m_score = round(m_correct / m_attempted * 100, 0) if m_attempted > 0 else '--'
                if m_score != '--': m_score = int(m_score)
            else:
                is_completed = False
                status = 'not_started'
                m_comp = 0
                m_score = '--'
            
            topic_complete_q += m_comp
            if m_score != '--': topic_scores.append(m_score)
            
            subtopics.append({
                'full_name': full_name,
                'display_name': display_name,
                'total': m['questions'],
                'complete': m_comp,
                'percent_correct': m_score,
                'status': status
            })
        
        avg_topic_score = round(sum(topic_scores) / len(topic_scores), 0) if topic_scores else '--'
        if avg_topic_score != '--': avg_topic_score = int(avg_topic_score)

        topics_data.append({
            'name': topic_name,
            'total': topic_total_q,
            'complete': topic_complete_q,
            'percent_correct': avg_topic_score,
            'subtopics': subtopics
        })
        total_q_all += topic_total_q
        total_c_all += topic_complete_q

    # Global metrics
    questions_taken = total_c_all
    total_questions = total_q_all
    completion_percent = round((questions_taken / total_questions * 100), 1) if total_questions > 0 else 0
    
    # Calculate timing metrics and accuracy from all attempts (completed and paused)
    all_answer_times = []
    correct_answer_times = []
    incorrect_answer_times = []
    session_durations = []
    
    total_correct_global = 0
    total_attempted_global = 0
    
    # Process both completed and paused attempts for a unified stats view
    all_attempts_to_process = list(attempts) + list(paused_attempts.values())
    
    for attempt in all_attempts_to_process:
        is_paused = attempt.get('status') == 'paused'
        
        # Session duration (only for completed or if total_time_seconds is set)
        time_spent = attempt.get('time_spent_seconds', 0)
        if time_spent and time_spent > 0:
            session_durations.append(time_spent)
        elif not is_paused:
            started_at = attempt.get('started_at')
            submitted_at = attempt.get('submitted_at')
            if started_at and submitted_at:
                from datetime import datetime
                try:
                    start = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
                    end = datetime.fromisoformat(submitted_at.replace('Z', '+00:00'))
                    duration = (end - start).total_seconds()
                    if 0 < duration < 86400:
                        session_durations.append(duration)
                except:
                    pass
        
        # Per-question timing and correctness from responses
        responses = attempt.get('responses', [])
        for resp in responses:
            total_attempted_global += 1
            if resp.get('is_correct'):
                total_correct_global += 1
            
            time_sec = resp.get('time_spent_seconds', 0)
            if time_sec and time_sec > 0:
                all_answer_times.append(time_sec)
                if resp.get('is_correct'):
                    correct_answer_times.append(time_sec)
                else:
                    incorrect_answer_times.append(time_sec)
    
    # Accuracy based on attempted questions (User Requirement)
    avg_correct = round((total_correct_global / total_attempted_global * 100), 0) if total_attempted_global > 0 else 0
    
    # Compute averages - show "--" only if no questions have been attempted
    def format_time(seconds):
        if seconds >= 60:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        return f"{int(seconds)}s"
    
    has_attempts = total_attempted_global > 0
    
    avg_answer_time = format_time(sum(all_answer_times) / len(all_answer_times)) if all_answer_times else "--"
    avg_correct_time = format_time(sum(correct_answer_times) / len(correct_answer_times)) if correct_answer_times else "--"
    avg_incorrect_time = format_time(sum(incorrect_answer_times) / len(incorrect_answer_times)) if incorrect_answer_times else "--"
    avg_session_duration = format_time(sum(session_durations) / len(session_durations)) if session_durations else "--"
    
    return render_template_string(
        PRACTICE_TEMPLATE,
        completion_percent=completion_percent,
        avg_correct=int(avg_correct),
        questions_taken=questions_taken,
        total_questions=total_questions,
        avg_answer_time=avg_answer_time,
        avg_correct_time=avg_correct_time,
        avg_incorrect_time=avg_incorrect_time,
        avg_session_duration=avg_session_duration,
        topics=topics_data
    )


@app.route('/mocks')
@login_required
def mock_dashboard():
    user_id = session.get('user_id')
    stats = db.get_user_quiz_stats(user_id)
    attempts = db.get_user_quiz_attempts(user_id, limit=1000)
    
    mock_files = []
    for f in os.listdir(DATA_FOLDER):
        if f.endswith(".json") and ('Mock' in f or f.startswith('Mock')):
            name = f[:-5]
            path = os.path.join(DATA_FOLDER, f)
            try:
                with open(path, 'r', encoding='utf-8') as jf:
                    raw = json.load(jf)
                    items = _find_items_structure(raw)
                    
                    # Determine time limit (default 135 mins = 02:15:00)
                    quiz_meta = raw.get("quiz", {})
                    time_sec = quiz_meta.get("settings", {}).get("session_time_limit_in_seconds", 8100)
                    h = time_sec // 3600
                    m = (time_sec % 3600) // 60
                    s = time_sec % 60
                    time_str = f"{h:02d}:{m:02d}:{s:02d}"
                    
                    # Find latest attempt
                    attempt = next((a for a in attempts if (a.get('quiz_name') == name or a.get('quiz_id') == name)), None)
                    completed = attempt is not None
                    score = attempt.get('score_percent', 0) if completed else 0
                    correct = attempt.get('correct_count', 0) if completed else 0
                    
                    # DISPLAY-ONLY NAME CLEANUP: Strip all leading text before "Mock Exam"
                    cleaned_name = name
                    if "Mock Exam" in name:
                        cleaned_name = name[name.find("Mock Exam"):]
                    
                    mock_files.append({
                        'name': name,
                        'display_name': cleaned_name,
                        'questions': len(items),
                        'time_limit': time_str,
                        'completed': completed,
                        'score': int(score),
                        'correct': correct
                    })
            except: continue
    
    # DETERMINISTIC PRIORITY ORDERING
    def get_mock_sort_key(m):
        dname = m['display_name']
        # Priority Group 1: Lettered mocks (A, B)
        # Match "Mock Exam A Session 1"
        match_letter = re.search(r'Mock Exam\s+([A-Z])\s+Session\s+(\d+)', dname)
        if match_letter:
            return (0, match_letter.group(1), int(match_letter.group(2)))
        
        # Priority Group 2: Numbered mocks (1, 2)
        # Match "Mock Exam 1 Session 1"
        match_num = re.search(r'Mock Exam\s+(\d+)\s+Session\s+(\d+)', dname)
        if match_num:
            return (1, int(match_num.group(1)), int(match_num.group(2)))
            
        # Fallback: All other mocks sorted alphabetically at the end
        return (2, dname, 0)

    mock_files.sort(key=get_mock_sort_key)
    
    total_exams = len(mock_files)
    exams_taken = stats.get('mocks_completed', 0)
    avg_correct = stats.get('avg_mock_score', 0)
    completion_percent = round((exams_taken / total_exams * 100), 1) if total_exams > 0 else 0
    
    return render_template_string(
        MOCK_EXAMS_TEMPLATE,
        completion_percent=completion_percent,
        avg_correct=int(avg_correct),
        exams_taken=exams_taken,
        total_exams=total_exams,
        avg_answer_time="--",
        avg_correct_time="--",
        avg_incorrect_time="--",
        mocks=mock_files
    )

# Catch-all route - MUST be defined LAST after all specific routes
@app.route("/<path:filename>")
@login_required
def file(filename):
    # Try to find the file in the data folder (case-insensitive)
    FilePath = os.path.join(DATA_FOLDER, filename + ".json")
    print(f"Looking for file: {FilePath}")
    
    # Determine if this is a mock exam or study module
    is_mock = 'Mock' in filename
    is_module = filename.startswith('Module')
    mode = "mock" if is_mock else "module"
    
    # Default time limit (135 mins for mock, 0 for practice)
    time_limit = 8100 if is_mock else 0
    
    if FilePath and os.path.exists(FilePath) and is_allowed_path(FilePath):
        try:
            questions, raw = load_questions_from_file(FilePath)
            # Track recently viewed item
            add_to_recently_viewed(session, {'name': filename})
        except Exception as e:
            print(f"Error loading file: {e}")
            questions = []
    else:
        print(f"File not found: {FilePath}")
        questions = []
    
    # Fetch saved progress if this is a module
    resume_data = {}
    if is_module:
        paused = db.get_paused_attempt(session.get('user_id'), filename)
        if paused:
            resume_data = {
                'last_index': paused.get('last_question_index', 0),
                'user_answers': paused.get('user_answers', []),
                'question_times': paused.get('question_times', []),
                'question_flags': paused.get('question_flags', []),
                'total_time': paused.get('total_time_seconds', 0)
            }
    
    return render_template_string(
        TEMPLATE,
        questions=questions,
        total=len(questions),
        data_source=(os.path.basename(FilePath) if FilePath else "none"),
        is_mock=is_mock,
        is_module=is_module,
        mode=mode,
        time_limit=time_limit,
        user_role=session.get('user_role', 'user'),
        quiz_title=filename,
        resume_data=resume_data
    )

if __name__ == "__main__":
    # Initialize Redis database connection
    print("="* 50)
    print("🚀 Starting CFA Level 1 Quiz Application")
    print("=" * 50)
    
    # Initialize database (Redis)
    db_status = db.init_db()
    if not db_status:
        print("⚠️  WARNING: Redis not connected!")
        print("⚠️  Set REDIS_URL environment variable to enable session management")
        print("⚠️  Single-session authentication will not work until Redis is configured")
    else:
        # Migrate users from JSON to Redis (one-time migration on startup)
        users_json_path = os.path.join(BASE_DIR, 'config', 'users.json')
        migrated_count = db.migrate_users_from_json(users_json_path)
        if migrated_count > 0:
            print(f"📦 Migrated {migrated_count} users from JSON to Redis")
        else:
            print("✅ User credentials loaded from Redis")
    
    print("=" * 50)
    
    # Use environment variable for port (Render sets this)
    port = int(os.environ.get("PORT", 5000))
    # Bind to 0.0.0.0 for Render deployment
    app.run(host="0.0.0.0", port=port, debug=False)