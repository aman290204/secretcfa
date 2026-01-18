# app.py
from flask import Flask, render_template_string, jsonify, send_file, abort, request, redirect, url_for, session
from functools import wraps
import json, os
from werkzeug.utils import secure_filename
import re
from html import unescape
from datetime import datetime, timedelta
import jwt
import secrets

# Import database functions for session management
import database as db

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Use environment variable in production

# Session configuration for Render - make it work in both local and deployed environments
# Only set SESSION_COOKIE_SECURE to True in production (HTTPS) environments
app.config['SESSION_COOKIE_SECURE'] = 'RENDER' in os.environ  # True on Render, False locally
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Track login history for users (format: {user_id: [{'timestamp': ..., 'ip': ..., 'user_agent': ..., 'is_current': bool}]})
# login_history = {}  # Migrated to Redis

# History and recently viewed functions
def add_to_history(session, quiz_data):
    """Add a quiz attempt to user's history"""
    if 'history' not in session:
        session['history'] = []
    
    # Add timestamp
    quiz_data['timestamp'] = datetime.now().isoformat()
    
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
    item_data['timestamp'] = datetime.now().isoformat()
    
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
        current_date = datetime.now()
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
:root{--bg:#121212;--card:#0A2540;--card-border:#1a3a5c;--muted:#94a3b8;--accent:#0052A5;--accent-dark:#003d7a;--accent-light:#4d8fd6;--success:#2E7D32;--danger:#C62828;--warning:#fbbf24;--text-primary:#FAFAFA;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37;--jewel-emerald:#2E7D32;--jewel-sapphire:#0052A5;--jewel-amethyst:#6c5ce7;--jewel-ruby:#C62828;--glass-bg:rgba(255,255,255,0.05);--glass-border:rgba(255,255,255,0.1)}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, var(--bg) 0%, #0A2540 100%);color:var(--text-primary);min-height:100vh}
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
.progress-bar{height:8px;background:#e2e8f0;border-radius:4px;margin-top:16px;overflow:hidden}
.progress-fill{height:100%;background:var(--accent);transition:width 0.3s ease}
.progress-text{font-size:12px;color:var(--muted);margin-top:4px;text-align:right}
.final-results{background:#fff;padding:30px;border-radius:8px;box-shadow:0 6px 20px rgba(15,23,42,0.08);text-align:center;animation: fadeIn 0.5s ease-in}
.final-score{font-size:48px;font-weight:800;color:var(--accent);margin:20px 0}
.final-message{font-size:18px;margin:20px 0}
.review-btn{padding:12px 24px;background:var(--accent);color:#fff;border:none;border-radius:6px;font-weight:600;margin:10px;cursor:pointer;transition:all 0.3s ease}
.review-btn:hover{background:#0952cc;transform:translateY(-3px);box-shadow:0 6px 16px rgba(11,105,255,0.3)}
.score-details{margin:20px 0;text-align:left}
.question-review{padding:10px;margin:5px 0;border-left:3px solid var(--muted);background:#f8fafc;transition:all 0.3s ease}
.question-review:hover{transform:translateX(5px)}
.question-review.correct{border-left-color:var(--success)}
.question-review.incorrect{border-left-color:var(--danger)}
.question-review.skipped{border-left-color:var(--muted)}
.sort-controls{display:flex;gap:10px;align-items:center;margin-bottom:15px;flex-wrap:wrap}
.sort-label{font-weight:600;color:#334155}
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
      <a href="/menu" class="btn" style="text-decoration:none;color:#0f1724">🏠 Home</a>
      <a href="/logout" class="btn" style="text-decoration:none;color:#0f1724">Logout</a>
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
          <button type="button" class="btn" id="skip">Skip</button>
          <button type="button" class="btn primary" id="submit">Submit Answer</button>
          <button type="button" class="btn primary" id="finish" style="display:none;">Finish Exam</button>
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
let idx = 0;
const total = questions.length;
let userAnswers = new Array(total).fill(null);
let questionStatus = new Array(total).fill(false); // false = not answered, true = answered
let currentQuestions = [...questions]; // Working copy of questions for sorting
let originalOrder = [...Array(total).keys()]; // Keep track of original order

// Check if this is a mock exam or study module
// Mode Constants from Backend
const MODE = "{{ mode }}";
const TIME_LIMIT = {{ time_limit }}; // in seconds
const IS_MOCK = MODE === "mock";

// Timer Persistence logic
let remainingTime;
let timerStart = Date.now();

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

function updateProgress() {
  const answeredCount = questionStatus.filter(status => status).length;
  const progressPercent = (answeredCount / total) * 100;
  document.getElementById('progressFill').style.width = progressPercent + '%';
  document.getElementById('progressText').textContent = `${answeredCount} of ${total} questions answered`;
  
  // Show finish button when all questions are answered
  if (answeredCount === total) {
    document.getElementById('finish').style.display = 'inline-block';
    document.getElementById('finish').textContent = IS_MOCK ? '🏁 Finish Exam' : '✅ Finish & Save Score';
  } else {
    document.getElementById('finish').style.display = 'none';
  }
}

function stripHtml(html){
  const d = new DOMParser().parseFromString(html,'text/html');
  return d.body.textContent || '';
}

function render(i){
  idx = i;
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
    label.addEventListener('click', ()=> { document.getElementById('feedback').innerHTML=''; });
    
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
    
    // Find answer texts
    let userAnswerText = 'Not answered';
    if (userAnswer) {
      const choice = q.choices.find(c => c.id === userAnswer);
      userAnswerText = choice ? choice.text.replace(/<[^>]*>/g, '').substring(0, 100) : 'Unknown';
    }
    
    let correctAnswerText = 'N/A';
    if (q.correct) {
      const correctChoice = q.choices.find(c => c.id === q.correct);
      correctAnswerText = correctChoice ? correctChoice.text.replace(/<[^>]*>/g, '').substring(0, 100) : 'Unknown';
    }
    
    responses.push({
      question_id: q.id,
      user_answer: userAnswer,
      correct_answer: q.correct,
      is_correct: isCorrect,
      user_answer_text: userAnswerText,
      correct_answer_text: correctAnswerText
    });
  });
  
  const scorePercent = Math.round((correctCount / total) * 100);
  const timeSpent = Math.floor((Date.now() - start) / 1000);
  
  // Save attempt to server with metadata
  saveAttemptToServer({
    quiz_name: '{{ quiz_title }}',
    quiz_id: '{{ data_source }}',
    quiz_type: MODE,
    mode: MODE,
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

document.getElementById('finish').addEventListener('click', ()=>{
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
    exam_date = user_data.get('exam_date', '2025-05-26')
    
    return render_template_string(
        MENU_TEMPLATE, 
        files=files, 
        total_files=len(files), 
        debug_modules=len(modules), 
        debug_mocks=len(mocks), 
        session=session, 
        recently_viewed=recently_viewed_items, 
        current_sort=sort_type, 
        user_role=session.get('user_role', 'user'), 
        stats=stats,
        exam_date=exam_date
    )


@app.route("/recently-viewed")
@login_required
def recently_viewed():
    """Display user's recently viewed items"""
    recently_viewed_items = get_recently_viewed(session)
    return render_template_string(RECENTLY_VIEWED_TEMPLATE, recently_viewed=recently_viewed_items, session=session)

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
        
        # Prepare attempt data
        attempt_data = {
            'quiz_id': quiz_id,
            'quiz_name': data.get('quiz_name', 'Unknown Quiz'),
            'quiz_type': mode,
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


@app.route("/attempt/<attempt_id>")
@login_required
def view_attempt(attempt_id):
    """View detailed responses for a specific quiz attempt"""
    user_id = session.get('user_id')
    
    # Get attempt from Redis
    attempt = db.get_quiz_attempt_by_id(user_id, attempt_id)
    
    if not attempt:
        return render_template_string("""
            <html><body style="font-family:Inter,Arial;padding:40px;background:#0f1419;color:#f1f5f9;">
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

MENU_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>CFA Level 1 - Quiz Menu</title>
<style>
:root{--bg:#121212;--card:#0A2540;--card-border:#1a3a5c;--muted:#94a3b8;--accent:#0052A5;--accent-dark:#003d7a;--accent-light:#4d8fd6;--success:#2E7D32;--danger:#C62828;--warning:#fbbf24;--text-primary:#FAFAFA;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37;--jewel-emerald:#2E7D32;--jewel-sapphire:#0052A5;--jewel-amethyst:#6c5ce7;--jewel-ruby:#C62828;--glass-bg:rgba(255,255,255,0.05);--glass-border:rgba(255,255,255,0.1)}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, var(--bg) 0%, #0A2540 100%);color:var(--text-primary);min-height:100vh}
.container{max-width:1200px;margin:28px auto;padding:0 18px}
.header{position:relative;margin-bottom:32px;animation:slideDown 0.4s ease;padding-right:50px}
.header-content{text-align:center}
.header h1{font-size:32px;font-weight:800;margin:0 0 8px 0;background:linear-gradient(135deg, #a78bfa 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-0.5px}
.header p{color:var(--text-muted);font-size:14px;margin:0}
.user-actions{display:flex;align-items:center;justify-content:center;gap:15px;margin:20px 0;flex-wrap:wrap}
.user-info{background:var(--glass-bg);padding:10px 18px;border-radius:50px;font-size:14px;box-shadow:0 4px 15px rgba(167,139,250,0.15);transition:all 0.3s ease;border:1px solid var(--glass-border);color:var(--text-secondary)}
.user-info:hover{transform:scale(1.05);box-shadow:0 8px 25px rgba(167,139,250,0.25);background:rgba(167,139,250,0.1)}
.btn{padding:10px 20px;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;display:inline-block;transition:all 0.3s;border:1px solid var(--glass-border);cursor:pointer}
.btn-primary{background:linear-gradient(135deg, #8b5cf6 0%, #a78bfa 100%);color:#fff;border:none;box-shadow:0 4px 15px rgba(139,92,246,0.3)}
.btn-primary:hover{background:linear-gradient(135deg, #a78bfa 0%, #c4b5fd 100%);transform:translateY(-2px);box-shadow:0 8px 25px rgba(167,139,250,0.4)}
.btn-secondary{background:var(--glass-bg);color:var(--text-secondary);border:1px solid var(--glass-border)}
.btn-secondary:hover{background:rgba(167,139,250,0.15);color:var(--accent-light);border-color:var(--accent);transform:translateY(-2px);box-shadow:0 4px 15px rgba(167,139,250,0.2)}
.btn-admin{background:linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%);color:#fff;border:none;box-shadow:0 4px 15px rgba(139,92,246,0.3)}
.btn-admin:hover{background:linear-gradient(135deg, #a78bfa 0%, #818cf8 100%);transform:translateY(-2px);box-shadow:0 8px 25px rgba(139,92,246,0.4)}
.btn-logout{background:linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);color:#fff;border:none;box-shadow:0 4px 15px rgba(244,63,94,0.3)}
.btn-logout:hover{background:linear-gradient(135deg, #f87171 0%, #f43f5e 100%);transform:translateY(-2px);box-shadow:0 8px 25px rgba(244,63,94,0.4)}
.admin-actions{display:flex;align-items:center}
.stats{display:flex;gap:16px;justify-content:center;margin:20px 0;flex-wrap:wrap}
.stat-box{background:var(--card);padding:16px 24px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.3);text-align:center;min-width:150px;transition:all 0.3s ease;border:1px solid var(--card-border);position:relative;overflow:hidden}
.stat-box::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg, transparent, var(--gold), transparent)}
.stat-box:hover{transform:translateY(-5px);box-shadow:0 8px 30px rgba(167,139,250,0.25);border-color:var(--accent)}
.stat-box .number{font-size:28px;font-weight:800;background:linear-gradient(135deg, var(--accent) 0%, var(--gold) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:4px}
.stat-box .label{font-size:14px;color:var(--text-muted)}
.search-box{max-width:500px;margin:0 auto 24px;position:relative;transition:all 0.3s}
.search-box:hover{transform:scale(1.02)}
.search-box input{width:100%;padding:14px 16px 14px 44px;border:1px solid var(--card-border);border-radius:12px;font-size:16px;transition:all 0.3s;box-shadow:0 4px 15px rgba(167,139,250,0.1);background:var(--card);color:var(--text-primary)}
.search-box input::placeholder{color:var(--text-muted)}
.search-box input:focus{border-color:var(--accent);outline:none;box-shadow:0 0 0 3px rgba(167,139,250,0.2)}
.search-box::before{content:'🔍';position:absolute;left:16px;top:50%;transform:translateY(-50%);font-size:18px}
.section{margin-bottom:40px}
.section-title{font-size:22px;font-weight:700;margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid var(--card-border);color:var(--text-primary)}
.sort-controls{display:flex;gap:15px;align-items:center;margin-bottom:25px;flex-wrap:wrap;padding:15px;background:var(--glass-bg);border-radius:12px;border:1px solid var(--glass-border)}
.sort-label{font-weight:600;color:var(--text-secondary);font-size:14px}
.sort-btn{padding:8px 14px;border-radius:8px;font-size:13px;font-weight:600;text-decoration:none;display:inline-block;transition:all 0.2s;border:1px solid var(--glass-border);background:var(--glass-bg);color:var(--text-secondary);cursor:pointer}
.sort-btn:hover{border-color:var(--accent);color:var(--accent-light);background:rgba(167,139,250,0.1)}
.sort-btn.active{background:linear-gradient(135deg, #8b5cf6 0%, #a78bfa 100%);color:#fff;border-color:var(--accent)}
.sort-dropdown{padding:10px 14px;border-radius:8px;font-size:14px;font-weight:600;border:1px solid var(--card-border);background:var(--card);color:var(--text-primary);cursor:pointer;transition:all 0.3s;min-width:180px;box-shadow:0 4px 15px rgba(0,0,0,0.3)}
.sort-dropdown:hover{border-color:var(--accent);color:var(--accent-light);box-shadow:0 8px 25px rgba(167,139,250,0.2)}
.sort-dropdown:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(167,139,250,0.2)}
.sort-dropdown option{background:var(--card);color:var(--text-primary)}
.category-group{margin-top:25px;padding:20px;background:rgba(167,139,250,0.08);border-radius:12px;border-left:4px solid var(--accent);transition:all 0.3s ease;box-shadow:0 4px 20px rgba(0,0,0,0.2)}
.category-group:hover{box-shadow:0 8px 30px rgba(167,139,250,0.2);transform:translateY(-2px)}
.category-name{font-size:18px;font-weight:700;color:var(--text-primary);margin-bottom:15px;display:flex;align-items:center;gap:10px}
.category-range{font-size:14px;font-weight:500;color:var(--accent-light);background:rgba(167,139,250,0.2);padding:4px 10px;border-radius:20px}
.category-modules{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:20px}
.recently-viewed-panel{background:linear-gradient(135deg, rgba(16,185,129,0.1) 0%, rgba(10,165,233,0.1) 100%);padding:20px;border-radius:12px;margin-bottom:30px;border:1px solid rgba(52,211,153,0.2)}
.recently-viewed-title{font-size:18px;font-weight:700;margin-bottom:15px;color:var(--jewel-emerald);display:flex;align-items:center;gap:8px}
.recently-viewed-items{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}
.recently-viewed-item{background:var(--card);padding:12px;border-radius:8px;border:1px solid rgba(52,211,153,0.3);transition:all 0.2s}
.recently-viewed-item:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(52,211,153,0.2);border-color:var(--jewel-emerald)}
.recently-viewed-item a{color:var(--jewel-emerald);text-decoration:none;font-weight:600;font-size:14px;display:block;margin-bottom:6px}
.recently-viewed-item a:hover{color:var(--accent-light)}
.recently-viewed-item .timestamp{font-size:12px;color:var(--text-muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:20px}
.card{background:var(--card);padding:20px;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.3);transition:all 0.3s;border:1px solid var(--card-border);position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;width:100%;height:1px;background:linear-gradient(90deg, transparent, var(--gold), transparent);transform:scaleX(0);transform-origin:left;transition:transform 0.3s ease}
.card:hover{box-shadow:0 12px 40px rgba(167,139,250,0.25);border-color:var(--accent);transform:translateY(-4px)}
.card:hover::before{transform:scaleX(1)}
.card-title{font-weight:700;font-size:16px;margin-bottom:12px;color:var(--text-primary);line-height:1.4}
.card-meta{display:flex;gap:16px;font-size:13px;color:var(--text-muted);margin-bottom:16px;flex-wrap:wrap}
.card-meta span{display:flex;align-items:center;gap:6px}
.card-actions{display:flex;gap:10px}
.empty{text-align:center;padding:80px 20px;color:var(--text-muted)}
.empty-icon{font-size:64px;margin-bottom:20px;opacity:0.5}
.debug-info{background:rgba(251,191,36,0.1);padding:10px;border-radius:8px;margin:10px 0;font-size:12px;color:var(--warning);border:1px solid rgba(251,191,36,0.3);animation: fadeIn 0.5s ease-in}
.completed-badge{background:linear-gradient(135deg, var(--jewel-emerald) 0%, var(--jewel-sapphire) 100%);color:white;padding:4px 8px;border-radius:4px;font-size:12px;margin-left:10px;font-weight:600}
.modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:none;align-items:center;justify-content:center;z-index:1000;animation:fadeIn 0.3s ease}
.modal-overlay.active{display:flex}
.modal-content{background:var(--card);border-radius:16px;padding:30px;max-width:700px;width:90%;max-height:80vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,0.5);border:1px solid rgba(167,139,250,0.3);animation:slideDown 0.3s ease}
.modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--card-border)}
.modal-title{font-size:24px;font-weight:800;margin:0;background:linear-gradient(135deg, #a78bfa 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.modal-close{background:none;border:none;font-size:24px;cursor:pointer;color:var(--text-secondary);transition:color 0.2s;padding:0;width:30px;height:30px;display:flex;align-items:center;justify-content:center}
.modal-close:hover{color:var(--accent)}
.session-info{background:rgba(167,139,250,0.08);border-radius:12px;padding:16px;margin-bottom:20px;border-left:4px solid var(--accent)}
.session-info-row{display:flex;justify-content:space-between;margin-bottom:12px;font-size:14px}
.session-info-row:last-child{margin-bottom:0}
.session-label{color:var(--text-secondary);font-weight:600}
.session-value{color:var(--text-primary);word-break:break-all}
.session-history{margin-top:24px}
.session-history-title{font-size:16px;font-weight:700;margin-bottom:16px;color:var(--accent)}
.session-list{display:flex;flex-direction:column;gap:12px}
.session-item{background:rgba(167,139,250,0.05);border:1px solid rgba(167,139,250,0.2);border-radius:8px;padding:12px;transition:all 0.2s}
.session-item.current{border-color:var(--success);background:rgba(52,211,153,0.1)}
.session-item-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.session-item-time{font-size:13px;font-weight:600;color:var(--accent)}
.session-item-badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:12px;background:var(--success);color:white}
.session-item-details{font-size:12px;color:var(--text-muted);display:grid;gap:6px}
.session-item-detail{display:flex;align-items:flex-start;gap:6px}
.session-item-detail-label{font-weight:600;min-width:50px;color:var(--text-secondary)}
.session-item-detail-value{word-break:break-all;flex:1}
.session-empty{text-align:center;padding:20px;color:var(--text-muted);font-style:italic}
.hamburger-menu{display:none;position:fixed;top:0;right:0;z-index:100;padding:16px}
.hamburger-btn{background:none;border:none;font-size:28px;cursor:pointer;color:var(--text-primary);transition:all 0.3s;padding:8px;display:flex;align-items:center;justify-content:center;width:44px;height:44px}
.hamburger-btn:hover{color:var(--accent);transform:scale(1.1)}
.hamburger-btn.active{color:var(--accent)}
.hamburger-dropdown{position:absolute;top:100%;right:0;background:var(--card);border:1px solid var(--card-border);border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.4);min-width:250px;padding:0;margin-top:10px;display:none;flex-direction:column;gap:0;animation:slideDown 0.3s ease;z-index:101}
.hamburger-dropdown.active{display:flex}
.hamburger-dropdown-item{padding:14px 20px;border-bottom:1px solid var(--card-border);transition:all 0.2s;cursor:pointer;display:flex;align-items:center;gap:10px;text-decoration:none;color:var(--text-secondary);font-weight:600;font-size:14px}
.hamburger-dropdown-item:last-child{border-bottom:none}
.hamburger-dropdown-item:hover{background:rgba(167,139,250,0.15);color:var(--accent-light)}
.hamburger-dropdown-item.logout{color:var(--danger)}
.hamburger-dropdown-item.logout:hover{background:rgba(244,63,94,0.15)}
.hamburger-dropdown-item.admin{color:var(--accent)}
.hamburger-dropdown-item.admin:hover{background:rgba(139,92,246,0.15)}
.hamburger-dropdown-divider{height:1px;background:var(--card-border);margin:10px 0}
.hamburger-user-info{padding:16px 20px;background:rgba(167,139,250,0.08);border-bottom:1px solid var(--card-border);border-radius:12px 12px 0 0;color:var(--text-secondary);font-size:13px;font-weight:600}
.hamburger-user-info-value{color:var(--text-primary);font-weight:700;margin-top:4px;word-break:break-word}
@keyframes fadeIn {
  from {opacity: 0; transform: translateY(-10px);}
  to {opacity: 1; transform: translateY(0);}
}
@keyframes slideDown {
  from {opacity: 0; transform: translateY(-20px);}
  to {opacity: 1; transform: translateY(0);}
}
@media(max-width:768px){
  .hamburger-menu{display:block}
  .user-actions{display:none !important}
  .header{padding-right:0}
  .grid{grid-template-columns:1fr}
  .admin-actions{width:100%}
  .btn{width:100%;text-align:center}
  .header h1{font-size:24px}
  .dashboard-top{flex-direction:column}
  .countdown-box{width:auto;min-width:unset}
  .score-circles{flex-direction:column;gap:20px}
}
/* CFA Dashboard Styles */
.dashboard{background:#f5f7fa;border-radius:16px;padding:24px;margin-bottom:30px;border:1px solid #e1e5eb}
.dashboard-top{display:flex;gap:24px;margin-bottom:24px;align-items:flex-start}
.countdown-box{background:linear-gradient(135deg, #0A2540 0%, #0052A5 100%);padding:20px;border-radius:12px;min-width:140px;text-align:center;color:#fff;box-shadow:0 4px 15px rgba(0,82,165,0.3)}
.countdown-number{font-size:48px;font-weight:800;line-height:1}
.countdown-label{font-size:14px;text-transform:uppercase;margin-top:4px;opacity:0.9}
.countdown-date{font-size:12px;margin-top:6px;opacity:0.8;display:flex;align-items:center;justify-content:center;gap:4px}
.progress-section{flex:1}
.progress-label{font-size:14px;color:#1a202c;font-weight:600;margin-bottom:8px;display:flex;justify-content:space-between}
.progress-bar-outer{background:#e2e8f0;height:24px;border-radius:12px;overflow:hidden;margin-bottom:16px}
.progress-bar-fill{height:100%;border-radius:12px;transition:width 0.5s ease}
.progress-bar-fill.orange{background:linear-gradient(90deg, #f59e0b 0%, #fbbf24 100%)}
.progress-bar-fill.green{background:linear-gradient(90deg, #2E7D32 0%, #4caf50 100%)}
.task-section{background:#e3f2fd;border-radius:12px;padding:16px;display:flex;align-items:center;gap:16px;border-left:4px solid #0052A5}
.task-icon{font-size:24px}
.task-info{flex:1}
.task-title{font-weight:700;color:#1a202c;font-size:15px;margin-bottom:4px}
.task-meta{font-size:13px;color:#64748b}
.task-btn{background:#0052A5;color:#fff;border:none;padding:12px 24px;border-radius:8px;font-weight:600;cursor:pointer;white-space:nowrap;transition:all 0.2s}
.task-btn:hover{background:#003d7a;transform:translateY(-2px)}
.score-circles{display:flex;justify-content:center;gap:40px;padding:20px 0}
.score-circle{text-align:center}
.score-ring{width:120px;height:120px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-direction:column;margin:0 auto 12px;position:relative}
.score-ring::before{content:'';position:absolute;inset:0;border-radius:50%;border:8px solid #e2e8f0}
.score-ring.green{border:8px solid #2E7D32;border-color:#2E7D32 #2E7D32 #e2e8f0 #e2e8f0}
.score-ring.blue{border:8px solid #0052A5;border-color:#0052A5 #0052A5 #e2e8f0 #e2e8f0}
.score-value{font-size:32px;font-weight:800;color:#1a202c}
.score-suffix{font-size:14px;color:#64748b;font-weight:600}
.score-label{font-size:14px;color:#64748b;font-weight:600}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="header-content">
      <h1>📚 CFA Level 1 Quiz Menu</h1>
      <p>Select a module or mock exam to start practicing</p>
    </div>
    <!-- User info and actions -->
    <div class="user-actions">
      <span class="user-info">👤 Logged in as: <strong>{{ session.user_name }}</strong></span>
      <a href="/edit-profile" class="btn btn-secondary">👤 Edit Profile</a>
      <button id="sessionDetailsBtn" class="btn btn-secondary">🔐 Session Details</button>
      {% if session.user_role == 'admin' %}
      <div class="admin-actions">
        <a href="/manage-users" class="btn btn-admin">👥 Manage Users</a>
      </div>
      {% endif %}
      <a href="/logout" class="btn btn-logout">🔓 Logout</a>
    </div>
    
    <!-- Hamburger Menu -->
    <div class="hamburger-menu">
      <button class="hamburger-btn" id="hamburgerBtn" onclick="toggleHamburgerMenu()">☰</button>
      <div class="hamburger-dropdown" id="hamburgerDropdown">
        <div class="hamburger-user-info">
          Logged in as:
          <div class="hamburger-user-info-value">{{ session.user_name }}</div>
        </div>
        <a href="/edit-profile" class="hamburger-dropdown-item">👤 Edit Profile</a>
        <button id="sessionDetailsBtnMobile" class="hamburger-dropdown-item" onclick="toggleHamburgerMenu(); openSessionModal();">🔐 Session Details</button>
        {% if session.user_role == 'admin' %}
        <a href="/manage-users" class="hamburger-dropdown-item admin">👥 Manage Users</a>
        {% endif %}
        <a href="/logout" class="hamburger-dropdown-item logout">🔓 Logout</a>
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
  <div class="dashboard">
    <div class="dashboard-top">
      <!-- Countdown Box -->
      <div class="countdown-box">
        <div class="countdown-number" id="daysUntil">--</div>
        <div class="countdown-label">Days Until</div>
        <div class="countdown-date">📅 <span id="examDate">Exam Date</span></div>
      </div>
      
      <!-- Progress Section -->
      <div class="progress-section">
        <div class="progress-label">
          <span>Today's Progress</span>
          <span id="todayProgress">{{ stats.today_completed|default(0) }}/{{ total_files }}</span>
        </div>
        <div class="progress-bar-outer">
          <div class="progress-bar-fill orange" id="todayBar" style="width: {{ ((stats.today_completed|default(0)) / total_files * 100)|int if total_files > 0 else 0 }}%"></div>
        </div>
        
        <div class="progress-label">
          <span>Study Plan Progress</span>
          <span id="studyProgress">{{ stats.avg_score|default(0) }}%</span>
        </div>
        <div class="progress-bar-outer">
          <div class="progress-bar-fill green" id="studyBar" style="width: {{ stats.avg_score|default(0) }}%"></div>
        </div>
        
        <!-- Task Section -->
        <div class="task-section">
          <div class="task-icon">📝</div>
          <div class="task-info">
            <div class="task-title">Practice: Start a Quiz</div>
            <div class="task-meta">{{ modules|length }} Modules • {{ mocks|length }} Mock Exams Available</div>
          </div>
          <a href="#mockGrid" class="task-btn">Start Quiz →</a>
        </div>
      </div>
    </div>
    
    <!-- Score Circles -->
    <div class="score-circles">
      <div class="score-circle">
        <div class="score-ring green">
          <span class="score-value">{{ stats.modules_completed|default(0) }}</span>
        </div>
        <div class="score-label">Modules Completed</div>
      </div>
      <div class="score-circle">
        <div class="score-ring blue">
          <span class="score-value">{{ stats.mocks_completed|default(0) }}</span>
        </div>
        <div class="score-label">Mocks Completed</div>
      </div>
    </div>
  </div>

  <div class="search-box">
    <input type="text" id="searchInput" placeholder="Search modules or exams..." />
  </div>

  {% if recently_viewed %}
  <div class="recently-viewed-panel">
    <div class="recently-viewed-title">👀 Recently Viewed</div>
    <div class="recently-viewed-items">
      {% for item in recently_viewed %}
      <div class="recently-viewed-item">
        <a href="/{{ item.name }}">{{ item.name }}</a>
        <div class="timestamp">{{ item.timestamp[5:10] if item.timestamp else 'N/A' }}</div>
      </div>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <div style="display:flex;gap:10px;margin-bottom:20px;align-items:center;flex-wrap:wrap">
    <a href="/my-scores" class="btn btn-primary">📊 My Scores</a>
    <a href="/history" class="btn btn-secondary">📋 Quiz History</a>
    <a href="/recently-viewed" class="btn btn-secondary">👁️ Recently Viewed</a>
  </div>

  {% if mocks %}
  <div class="section">
    <div class="section-title">🎯 Mock Exams ({{ mocks|length }})</div>
    <div class="grid" id="mockGrid">
      {% for file in mocks %}
      <div class="card" data-name="{{ file.display_name|lower }}">
        <div class="card-title">{{ file.display_name }}
          {% if file.completed %}
          <span class="completed-badge">Completed</span>
          {% endif %}
        </div>
        <div class="card-meta">
          <span>📝 {{ file.questions }} questions</span>
        </div>
        <div class="card-actions">
          <a href="/{{ file.display_name }}" class="btn btn-primary">Start Quiz</a>
        </div>
      </div>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  {% if modules %}
  <div class="section">
    <div class="section-title">📖 Study Modules ({{ modules|length }})</div>
    <div class="sort-controls">
      <span class="sort-label">Sort:</span>
      <select id="sortDropdown" class="sort-dropdown">
        <option value="id">By Module ID</option>
        <option value="alphabetical">A-Z</option>
        <option value="reverse_alphabetical">Z-A</option>
        <option value="category">By Category</option>
      </select>
    </div>
    <div id="modulesContainer">
      <div class="grid" id="moduleGrid">
      {% for file in modules %}
      <div class="card" data-name="{{ file.display_name|lower }}">
        <div class="card-title">{{ file.display_name }}
          {% if file.completed %}
          <span class="completed-badge">Completed</span>
          {% endif %}
        </div>
        <div class="card-meta">
          <span>📝 {{ file.questions }} questions</span>
        </div>
        <div class="card-actions">
          <a href="/{{ file.display_name }}" class="btn btn-primary">Start Quiz</a>
        </div>
      </div>
      {% endfor %}
      </div>
    </div>
  </div>
  {% endif %}

  {% if not files %}
  <div class="empty">
    <div class="empty-icon">📂</div>
    <p>No quiz files found in the data folder.</p>
  </div>
  {% endif %}
</div>

<!-- Session Details Modal -->
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
      <div class="session-info-row">
        <span class="session-label">Active Sessions:</span>
        <span class="session-value" id="activeSessionCount">Loading...</span>
      </div>
    </div>
    
    <div class="session-history">
      <h3 class="session-history-title">📝 Login History</h3>
      <div class="session-list" id="sessionList">
        <div class="session-empty">Loading session history...</div>
      </div>
    </div>
  </div>
</div>

<script>
// CFA Dashboard Logic
document.addEventListener('DOMContentLoaded', function() {
  // 1. Exam Countdown
  const examDateStr = "{{ exam_date }}";
  const examDate = new Date(examDateStr); 
  const today = new Date();
  const diffTime = examDate - today;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  
  document.getElementById('daysUntil').textContent = diffDays > 0 ? diffDays : 0;
  
  const options = { day: '2-digit', month: '2-digit', year: 'numeric' };
  document.getElementById('examDate').textContent = examDate.toLocaleDateString('en-GB', options).split('/').join('-');

  // 2. Animate Progress Bars
  setTimeout(() => {
    const bars = document.querySelectorAll('.progress-bar-fill');
    bars.forEach(bar => {
      // Trigger reflow to ensure transition
      bar.style.width = bar.style.width; 
    });
  }, 100);
});

function openSessionModal() {
  const modal = document.getElementById('sessionModal');
  modal.classList.add('active');
  loadSessionDetails();
}

function closeSessionModal() {
  const modal = document.getElementById('sessionModal');
  modal.classList.remove('active');
}

function formatDate(isoString) {
  const date = new Date(isoString);
  const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const month = monthNames[date.getMonth()];
  const day = date.getDate();
  const year = date.getFullYear();
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  return `${month} ${day}, ${year} at ${hours}:${minutes}`;
}

function parseUserAgent(userAgent) {
  if (!userAgent || userAgent === 'Unknown') return 'Unknown Browser';
  
  // Simple browser detection
  if (userAgent.includes('Chrome')) return 'Chrome';
  if (userAgent.includes('Safari')) return 'Safari';
  if (userAgent.includes('Firefox')) return 'Firefox';
  if (userAgent.includes('Edge')) return 'Edge';
  if (userAgent.includes('Opera')) return 'Opera';
  
  return userAgent.substring(0, 50);
}

async function loadSessionDetails() {
  try {
    const response = await fetch('/api/session-details');
    const data = await response.json();
    
    // Update header info
    document.getElementById('userIdDisplay').textContent = data.user_id || 'N/A';
    document.getElementById('userNameDisplay').textContent = data.user_name || 'N/A';
    document.getElementById('activeSessionCount').textContent = data.sessions.length || 0;
    
    // Build session list
    const sessionList = document.getElementById('sessionList');
    
    if (!data.sessions || data.sessions.length === 0) {
      sessionList.innerHTML = '<div class="session-empty">No session history found</div>';
      return;
    }
    
    sessionList.innerHTML = data.sessions.map((session, index) => `
      <div class="session-item ${session.is_current ? 'current' : ''}">
        <div class="session-item-header">
          <span class="session-item-time">📅 ${formatDate(session.timestamp)}</span>
          ${session.is_current ? '<span class="session-item-badge">CURRENT</span>' : ''}
        </div>
        <div class="session-item-details">
          <div class="session-item-detail">
            <span class="session-item-detail-label">IP:</span>
            <span class="session-item-detail-value">${session.ip || 'Unknown'}</span>
          </div>
          <div class="session-item-detail">
            <span class="session-item-detail-label">Browser:</span>
            <span class="session-item-detail-value">${parseUserAgent(session.user_agent)}</span>
          </div>
        </div>
      </div>
    `).join('');
    
  } catch (error) {
    console.error('Error loading session details:', error);
    document.getElementById('sessionList').innerHTML = '<div class="session-empty">Error loading session details</div>';
  }
}

// Close modal when clicking overlay
document.getElementById('sessionModal').addEventListener('click', (e) => {
  if (e.target.id === 'sessionModal') {
    closeSessionModal();
  }
});

// Add event listener to Session Details button
const sessionDetailsBtn = document.getElementById('sessionDetailsBtn');
if (sessionDetailsBtn) {
  sessionDetailsBtn.addEventListener('click', openSessionModal);
}

// Hamburger Menu Functions
function toggleHamburgerMenu() {
  const dropdown = document.getElementById('hamburgerDropdown');
  const btn = document.getElementById('hamburgerBtn');
  const isActive = dropdown.classList.contains('active');
  
  if (isActive) {
    dropdown.classList.remove('active');
    btn.classList.remove('active');
  } else {
    dropdown.classList.add('active');
    btn.classList.add('active');
  }
}

// Close hamburger menu when clicking outside
document.addEventListener('click', (e) => {
  const hamburgerMenu = document.querySelector('.hamburger-menu');
  const hamburgerBtn = document.getElementById('hamburgerBtn');
  const hamburgerDropdown = document.getElementById('hamburgerDropdown');
  
  if (hamburgerMenu && !hamburgerMenu.contains(e.target)) {
    hamburgerDropdown.classList.remove('active');
    hamburgerBtn.classList.remove('active');
  }
});

const searchInput = document.getElementById('searchInput');
const sortDropdown = document.getElementById('sortDropdown');
const modulesContainer = document.getElementById('modulesContainer');

// Module number regex and category mapping
const MODULE_CATEGORIES = {
  'Quantitative Methods': { start: 1, end: 11, order: 0 },
  'Economics': { start: 12, end: 19, order: 1 },
  'Corporate Issuers': { start: 20, end: 26, order: 2 },
  'Financial Statement Analysis': { start: 27, end: 38, order: 3 },
  'Equity': { start: 39, end: 46, order: 4 },
  'Fixed Income': { start: 47, end: 65, order: 5 },
  'Derivatives': { start: 66, end: 75, order: 6 },
  'Alternative Investments': { start: 76, end: 82, order: 7 },
  'Portfolio Management': { start: 83, end: 88, order: 8 },
  'Ethical and Professional Standards': { start: 89, end: 93, order: 9 }
};

function getModuleNumber(displayName) {
  const match = displayName.match(/Module\s+(\d+)/);
  return match ? parseInt(match[1]) : 0;
}

function getModuleCategory(moduleNum) {
  for (const [category, range] of Object.entries(MODULE_CATEGORIES)) {
    if (moduleNum >= range.start && moduleNum <= range.end) {
      return category;
    }
  }
  return 'Unknown';
}

// Store original cards on page load
let originalCards = [];

function getAllModuleCards() {
  // If we have original cards stored, use them
  if (originalCards.length > 0) {
    return originalCards;
  }
  // Otherwise get cards from the container
  return modulesContainer ? Array.from(modulesContainer.querySelectorAll('.card')) : [];
}

function storeOriginalCards() {
  originalCards = modulesContainer ? Array.from(modulesContainer.querySelectorAll('.card')) : [];
}

function sortByModuleId(cards) {
  return Array.from(cards).sort((a, b) => {
    const numA = getModuleNumber(a.querySelector('.card-title').textContent);
    const numB = getModuleNumber(b.querySelector('.card-title').textContent);
    return numA - numB;
  });
}

function sortAlphabetical(cards) {
  return Array.from(cards).sort((a, b) => {
    const titleA = a.querySelector('.card-title').textContent.toLowerCase();
    const titleB = b.querySelector('.card-title').textContent.toLowerCase();
    return titleA.localeCompare(titleB);
  });
}

function sortReverseAlphabetical(cards) {
  return Array.from(cards).sort((a, b) => {
    const titleA = a.querySelector('.card-title').textContent.toLowerCase();
    const titleB = b.querySelector('.card-title').textContent.toLowerCase();
    return titleB.localeCompare(titleA);
  });
}

function sortByCategory(cards) {
  const cardArray = Array.from(cards);
  
  // Create a map of categories with their modules
  const categoryMap = {};
  
  // Initialize all categories in exact order to ensure they exist
  const categoryOrder = [
    'Quantitative Methods',
    'Economics',
    'Corporate Issuers',
    'Financial Statement Analysis',
    'Equity',
    'Fixed Income',
    'Derivatives',
    'Alternative Investments',
    'Portfolio Management',
    'Ethical and Professional Standards'
  ];
  
  categoryOrder.forEach(category => {
    categoryMap[category] = [];
  });
  
  cardArray.forEach(card => {
    const title = card.querySelector('.card-title').textContent.trim();
    const moduleNum = getModuleNumber(title);
    const category = getModuleCategory(moduleNum);
    
    // Only add to known categories
    if (category !== 'Unknown' && categoryMap[category]) {
      categoryMap[category].push({ card, moduleNum, title });
    }
  });
  
  // Sort modules within each category by module number
  categoryOrder.forEach(category => {
    categoryMap[category].sort((a, b) => a.moduleNum - b.moduleNum);
  });
  
  // Return sorted structure with categories in proper order
  return { categoryMap, sortedCategories: categoryOrder };
}

function renderGridLayout(sortType) {
  const cards = getAllModuleCards();
  if (cards.length === 0) return;
  
  if (sortType === 'category') {
    renderCategoryView(cards);
  } else {
    let sortedCards;
    if (sortType === 'alphabetical') {
      sortedCards = sortAlphabetical(cards);
    } else if (sortType === 'reverse_alphabetical') {
      sortedCards = sortReverseAlphabetical(cards);
    } else {
      sortedCards = sortByModuleId(cards);
    }
    renderGridView(sortedCards);
  }
}

function renderGridView(sortedCards) {
  const html = '<div class="grid" id="moduleGrid">' + 
    sortedCards.map(card => card.outerHTML).join('') + 
    '</div>';
  modulesContainer.innerHTML = html;
}

function renderCategoryView(cards) {
  const { categoryMap, sortedCategories } = sortByCategory(cards);
  let html = '';
  
  sortedCategories.forEach(category => {
    const modules = categoryMap[category];
    
    // Only render categories that have modules
    if (modules.length > 0) {
      html += `<div class="category-group" data-category="${category}">
        <div class="category-name">📂 ${category} <span class="category-range">(Modules ${MODULE_CATEGORIES[category].start}-${MODULE_CATEGORIES[category].end})</span></div>
        <div class="category-modules">`;
      
      // Clone each card and add it to the HTML
      modules.forEach(({ card }) => {
        // Clone the card element to avoid moving DOM nodes
        const clonedCard = card.cloneNode(true);
        html += clonedCard.outerHTML;
      });
      
      html += '</div></div>';
    }
  });
  
  modulesContainer.innerHTML = html;
  
  // Re-attach event listeners to new cards
  setTimeout(() => {
    addCardAnimations();
  }, 50);
}

// Handle sort dropdown change
function showLoadingIndicator() {
  // Add a loading indicator to modules container
  const loadingHTML = `
    <div style="display:flex;justify-content:center;align-items:center;height:200px;">
      <div style="font-size:24px;margin-right:15px">🔄</div>
      <div style="font-size:18px;color:var(--muted)">Sorting modules...</div>
    </div>
  `;
  modulesContainer.innerHTML = loadingHTML;
}

if (sortDropdown) {
  sortDropdown.addEventListener('change', (e) => {
    const sortType = e.target.value;
    
    // Store original cards before showing loading indicator
    if (originalCards.length === 0) {
      storeOriginalCards();
    }
    
    // Show loading indicator
    showLoadingIndicator();
    
    // Add slight delay to show loading indicator
    setTimeout(() => {
      renderGridLayout(sortType);
      
      // Reapply search filter after sorting
      if (searchInput && searchInput.value) {
        applySearchFilter();
      }
    }, 100);
  });
  
  // Set initial value based on current sort
  const currentSort = '{{ current_sort }}';
  if (currentSort && currentSort !== '') {
    sortDropdown.value = currentSort;
  }
}

// Search functionality
function applySearchFilter() {
  if (!searchInput) return;
  const term = searchInput.value.toLowerCase();
  
  // Handle both grid view and category view
  const allCards = modulesContainer.querySelectorAll('.card');
  let visibleCount = 0;
  
  allCards.forEach(card => {
    const name = card.dataset.name || '';
    const isVisible = name.includes(term);
    card.style.display = isVisible ? '' : 'none';
    if (isVisible) visibleCount++;
  });
  
  // Show/hide category groups based on whether they have visible cards
  const categoryGroups = modulesContainer.querySelectorAll('.category-group');
  categoryGroups.forEach(group => {
    const visibleCards = group.querySelectorAll('.card:not([style*="display: none"])');
    group.style.display = visibleCards.length > 0 ? '' : 'none';
  });
  
  // Update stats if search term exists
  if (term) {
    console.log(`Found ${visibleCount} matching modules`);
  }
}

if (searchInput) {
  searchInput.addEventListener('input', applySearchFilter);
}

// Add smooth animations to cards when they appear
function addCardAnimations() {
  const cards = modulesContainer ? modulesContainer.querySelectorAll('.card') : [];
  cards.forEach((card, index) => {
    card.style.opacity = '0';
    card.style.transform = 'translateY(20px)';
    setTimeout(() => {
      card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
      card.style.opacity = '1';
      card.style.transform = 'translateY(0)';
    }, 50 * index);
  });
}

document.addEventListener('DOMContentLoaded', function() {
  // Store original cards on page load
  setTimeout(() => {
    storeOriginalCards();
    addCardAnimations();
  }, 100);
});

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
</script>
</body>
</html>
"""

# My Scores Template - Shows user's quiz attempts with scores
MY_SCORES_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>My Scores - CFA Level 1</title>
<style>
:root{--bg:#121212;--card:#0A2540;--card-border:#1a3a5c;--muted:#94a3b8;--accent:#0052A5;--accent-dark:#003d7a;--accent-light:#4d8fd6;--success:#2E7D32;--danger:#C62828;--warning:#fbbf24;--text-primary:#FAFAFA;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37;--jewel-emerald:#2E7D32;--jewel-sapphire:#0052A5;--jewel-amethyst:#6c5ce7;--jewel-ruby:#C62828;--glass-bg:rgba(255,255,255,0.05);--glass-border:rgba(255,255,255,0.1)}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, var(--bg) 0%, #0A2540 100%);color:var(--text-primary);min-height:100vh}
.container{max-width:1200px;margin:28px auto;padding:0 18px}
.header{text-align:center;margin-bottom:32px}
.header h1{font-size:32px;font-weight:800;margin:0 0 8px 0;background:linear-gradient(135deg, #0052A5 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.header p{color:var(--text-muted);font-size:14px;margin:0}
.nav-actions{display:flex;align-items:center;justify-content:center;gap:15px;margin:20px 0;flex-wrap:wrap}
.btn{padding:10px 20px;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;display:inline-block;transition:all 0.3s;border:1px solid var(--glass-border);cursor:pointer}
.btn-primary{background:linear-gradient(135deg, #8b5cf6 0%, #a78bfa 100%);color:#fff;border:none;box-shadow:0 4px 15px rgba(139,92,246,0.3)}
.btn-primary:hover{background:linear-gradient(135deg, #a78bfa 0%, #c4b5fd 100%);transform:translateY(-2px);box-shadow:0 8px 25px rgba(167,139,250,0.4)}
.btn-secondary{background:var(--glass-bg);color:var(--text-secondary);border:1px solid var(--glass-border)}
.btn-secondary:hover{background:rgba(167,139,250,0.15);color:var(--accent-light);border-color:var(--accent);transform:translateY(-2px)}
.btn-danger{background:linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);color:#fff;border:none;font-size:12px;padding:6px 12px}
.btn-danger:hover{transform:translateY(-2px)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;margin:30px 0}
.stat-box{background:var(--card);padding:20px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.3);text-align:center;transition:all 0.3s ease;border:1px solid var(--card-border);position:relative;overflow:hidden}
.stat-box::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg, var(--accent), var(--gold))}
.stat-box:hover{transform:translateY(-5px);box-shadow:0 8px 30px rgba(167,139,250,0.25);border-color:var(--accent)}
.stat-box .number{font-size:32px;font-weight:800;background:linear-gradient(135deg, var(--accent) 0%, var(--gold) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.stat-box .label{font-size:13px;color:var(--text-muted);margin-top:4px}
.section-title{font-size:22px;font-weight:700;margin:30px 0 20px;padding-bottom:12px;border-bottom:1px solid var(--card-border);color:var(--text-primary)}
.attempts-table{width:100%;border-collapse:collapse;background:var(--card);border-radius:12px;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,0.3)}
.attempts-table th,.attempts-table td{padding:16px;text-align:left;border-bottom:1px solid var(--card-border)}
.attempts-table th{background:rgba(167,139,250,0.15);color:var(--accent-light);font-weight:700;font-size:13px;text-transform:uppercase;letter-spacing:0.5px}
.attempts-table tr:hover{background:rgba(167,139,250,0.08)}
.attempts-table td{color:var(--text-secondary);font-size:14px}
.score-badge{display:inline-block;padding:6px 12px;border-radius:20px;font-weight:700;font-size:13px}
.score-high{background:rgba(52,211,153,0.2);color:var(--success)}
.score-medium{background:rgba(251,191,36,0.2);color:var(--warning)}
.score-low{background:rgba(248,113,113,0.2);color:var(--danger)}
.quiz-type{display:inline-block;padding:4px 10px;border-radius:15px;font-size:11px;font-weight:600;text-transform:uppercase}
.quiz-type.module{background:rgba(14,165,233,0.2);color:var(--jewel-sapphire)}
.quiz-type.mock{background:rgba(244,63,94,0.2);color:var(--jewel-ruby)}
.empty{text-align:center;padding:60px 20px;color:var(--text-muted)}
.empty-icon{font-size:64px;margin-bottom:20px;opacity:0.5}
.filter-tabs{display:flex;gap:10px;margin-bottom:20px}
.filter-tab{padding:8px 16px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600;background:var(--glass-bg);border:1px solid var(--glass-border);color:var(--text-secondary);transition:all 0.2s}
.filter-tab:hover{border-color:var(--accent);color:var(--accent-light)}
.filter-tab.active{background:linear-gradient(135deg, #8b5cf6 0%, #a78bfa 100%);color:#fff;border-color:var(--accent)}
@media(max-width:768px){.attempts-table{display:block;overflow-x:auto}.stats{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>📊 My Scores</h1>
    <p>Track your quiz performance across all modules and mocks</p>
  </div>
  
  <div class="nav-actions">
    <a href="/menu" class="btn btn-secondary">🏠 Menu</a>
    <a href="/history" class="btn btn-secondary">📋 Session History</a>
  </div>
  
  <div class="stats">
    <div class="stat-box">
      <div class="number">{{ stats.total_attempts }}</div>
      <div class="label">Total Attempts</div>
    </div>
    <div class="stat-box">
      <div class="number">{{ stats.avg_score }}%</div>
      <div class="label">Average Score</div>
    </div>
    <div class="stat-box">
      <div class="number">{{ stats.modules_completed }}</div>
      <div class="label">Modules Done</div>
    </div>
    <div class="stat-box">
      <div class="number">{{ stats.mocks_completed }}</div>
      <div class="label">Mocks Done</div>
    </div>
  </div>
  
  <h2 class="section-title">📝 Recent Attempts</h2>
  
  <div class="filter-tabs">
    <div class="filter-tab active" onclick="filterAttempts('all')">All</div>
    <div class="filter-tab" onclick="filterAttempts('module')">Modules</div>
    <div class="filter-tab" onclick="filterAttempts('mock')">Mocks</div>
  </div>
  
  {% if attempts %}
  <table class="attempts-table" id="attemptsTable">
    <thead>
      <tr>
        <th>Quiz Name</th>
        <th>Type</th>
        <th>Score</th>
        <th>Questions</th>
        <th>Date</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {% for attempt in attempts %}
      <tr data-type="{{ attempt.quiz_type }}">
        <td><strong>{{ attempt.quiz_name }}</strong></td>
        <td><span class="quiz-type {{ attempt.quiz_type }}">{{ attempt.quiz_type }}</span></td>
        <td>
          {% if attempt.score_percent >= 70 %}
          <span class="score-badge score-high">{{ attempt.score_percent }}%</span>
          {% elif attempt.score_percent >= 50 %}
          <span class="score-badge score-medium">{{ attempt.score_percent }}%</span>
          {% else %}
          <span class="score-badge score-low">{{ attempt.score_percent }}%</span>
          {% endif %}
        </td>
        <td>{{ attempt.correct_count }}/{{ attempt.total_questions }} correct</td>
        <td>{{ attempt.timestamp[:10] }} {{ attempt.timestamp[11:16] }}</td>
        <td>
          <a href="/attempt/{{ attempt.attempt_id }}" class="btn btn-primary" style="font-size:12px;padding:6px 12px">View Details</a>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">
    <div class="empty-icon">📭</div>
    <h3>No quiz attempts yet</h3>
    <p>Complete some quizzes to see your scores here!</p>
    <a href="/menu" class="btn btn-primary" style="margin-top:20px">Start Practicing</a>
  </div>
  {% endif %}
</div>

<script>
function filterAttempts(type) {
  const tabs = document.querySelectorAll('.filter-tab');
  tabs.forEach(tab => tab.classList.remove('active'));
  event.target.classList.add('active');
  
  const rows = document.querySelectorAll('#attemptsTable tbody tr');
  rows.forEach(row => {
    if (type === 'all' || row.dataset.type === type) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
}
</script>
</body>
</html>
"""

# Attempt Details Template - Shows detailed responses for a specific attempt
ATTEMPT_DETAILS_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Attempt Details - CFA Level 1</title>
<style>
:root{--bg:#121212;--card:#0A2540;--card-border:#1a3a5c;--muted:#94a3b8;--accent:#0052A5;--accent-dark:#003d7a;--accent-light:#4d8fd6;--success:#2E7D32;--danger:#C62828;--warning:#fbbf24;--text-primary:#FAFAFA;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37;--glass-bg:rgba(255,255,255,0.05);--glass-border:rgba(255,255,255,0.1)}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, var(--bg) 0%, #0A2540 100%);color:var(--text-primary);min-height:100vh}
.container{max-width:1000px;margin:28px auto;padding:0 18px}
.header{text-align:center;margin-bottom:32px}
.header h1{font-size:28px;font-weight:800;margin:0 0 8px 0;background:linear-gradient(135deg, #0052A5 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.header p{color:var(--text-muted);font-size:14px;margin:0}
.nav-actions{display:flex;align-items:center;justify-content:center;gap:15px;margin:20px 0}
.btn{padding:10px 20px;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;display:inline-block;transition:all 0.3s;border:1px solid var(--glass-border);cursor:pointer}
.btn-secondary{background:var(--glass-bg);color:var(--text-secondary);border:1px solid var(--glass-border)}
.btn-secondary:hover{background:rgba(167,139,250,0.15);color:var(--accent-light);border-color:var(--accent)}
.summary-card{background:var(--card);padding:24px;border-radius:12px;margin-bottom:24px;border:1px solid var(--card-border);display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:20px;text-align:center}
.summary-item .value{font-size:28px;font-weight:800;background:linear-gradient(135deg, var(--accent) 0%, var(--gold) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.summary-item .label{font-size:12px;color:var(--text-muted);margin-top:4px}
.response-card{background:var(--card);padding:20px;border-radius:12px;margin-bottom:16px;border-left:4px solid var(--muted);border:1px solid var(--card-border);transition:all 0.2s}
.response-card.correct{border-left-color:var(--success)}
.response-card.incorrect{border-left-color:var(--danger)}
.response-card.skipped{border-left-color:var(--warning)}
.response-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.question-num{font-weight:700;color:var(--accent-light)}
.status-badge{padding:4px 12px;border-radius:15px;font-size:12px;font-weight:600}
.status-badge.correct{background:rgba(52,211,153,0.2);color:var(--success)}
.status-badge.incorrect{background:rgba(248,113,113,0.2);color:var(--danger)}
.status-badge.skipped{background:rgba(251,191,36,0.2);color:var(--warning)}
.response-detail{font-size:14px;color:var(--text-secondary);margin-top:8px}
.response-detail strong{color:var(--text-primary)}
@media(max-width:768px){.summary-card{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>{{ attempt.quiz_name }}</h1>
    <p>Attempted on {{ attempt.timestamp[:10] }} at {{ attempt.timestamp[11:16] }}</p>
  </div>
  
  <div class="nav-actions">
    <a href="/my-scores" class="btn btn-secondary">← Back to My Scores</a>
    <a href="/menu" class="btn btn-secondary">🏠 Menu</a>
  </div>
  
  <div class="summary-card">
    <div class="summary-item">
      <div class="value">{{ attempt.score_percent }}%</div>
      <div class="label">Score</div>
    </div>
    <div class="summary-item">
      <div class="value">{{ attempt.correct_count }}</div>
      <div class="label">Correct</div>
    </div>
    <div class="summary-item">
      <div class="value">{{ attempt.wrong_count }}</div>
      <div class="label">Wrong</div>
    </div>
    <div class="summary-item">
      <div class="value">{{ attempt.skipped_count }}</div>
      <div class="label">Skipped</div>
    </div>
    <div class="summary-item">
      <div class="value">{{ attempt.total_questions }}</div>
      <div class="label">Total</div>
    </div>
    <div class="summary-item">
      <div class="value">{{ (attempt.time_spent_seconds // 60) }}m</div>
      <div class="label">Time Spent</div>
    </div>
  </div>
  
  <h2 style="color:var(--text-primary);margin:24px 0 16px">📋 Response Details</h2>
  
  {% if attempt.responses %}
    {% for resp in attempt.responses %}
    <div class="response-card {{ 'correct' if resp.is_correct else ('skipped' if not resp.user_answer else 'incorrect') }}">
      <div class="response-header">
        <span class="question-num">Question {{ loop.index }}</span>
        {% if resp.is_correct %}
        <span class="status-badge correct">✓ Correct</span>
        {% elif not resp.user_answer %}
        <span class="status-badge skipped">○ Skipped</span>
        {% else %}
        <span class="status-badge incorrect">✗ Incorrect</span>
        {% endif %}
      </div>
      <div class="response-detail">
        <strong>Your Answer:</strong> {{ resp.user_answer_text if resp.user_answer_text else 'Not answered' }}
      </div>
      {% if not resp.is_correct %}
      <div class="response-detail">
        <strong>Correct Answer:</strong> {{ resp.correct_answer_text if resp.correct_answer_text else 'N/A' }}
      </div>
      {% endif %}
    </div>
    {% endfor %}
  {% else %}
  <p style="color:var(--text-muted);text-align:center;padding:40px">No detailed responses recorded for this attempt.</p>
  {% endif %}
</div>
</body>
</html>
"""

# Templates for history and recently viewed pages
HISTORY_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Quiz History - CFA Level 1</title>
<style>
:root{--bg:#121212;--card:#0A2540;--card-border:#1a3a5c;--muted:#94a3b8;--accent:#0052A5;--accent-dark:#003d7a;--accent-light:#4d8fd6;--success:#2E7D32;--danger:#C62828;--warning:#fbbf24;--text-primary:#FAFAFA;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37;--jewel-emerald:#2E7D32;--jewel-sapphire:#0052A5;--jewel-amethyst:#6c5ce7;--jewel-ruby:#C62828;--glass-bg:rgba(255,255,255,0.05);--glass-border:rgba(255,255,255,0.1)}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, var(--bg) 0%, #0A2540 100%);color:var(--text-primary);min-height:100vh}
.container{max-width:1200px;margin:28px auto;padding:0 18px}
.header{text-align:center;margin-bottom:32px}
.header h1{font-size:32px;font-weight:800;margin:0 0 8px 0;background:linear-gradient(135deg, #0052A5 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.header p{color:var(--text-muted);font-size:14px;margin:0}
.user-actions{display:flex;align-items:center;justify-content:center;gap:15px;margin:20px 0;flex-wrap:wrap}
.user-info{background:var(--glass-bg);padding:10px 18px;border-radius:50px;font-size:14px;box-shadow:0 4px 15px rgba(167,139,250,0.15);transition:all 0.3s ease;border:1px solid var(--glass-border);color:var(--text-secondary)}
.user-info:hover{transform:scale(1.05);box-shadow:0 8px 25px rgba(167,139,250,0.25);background:rgba(167,139,250,0.1)}
.btn{padding:10px 20px;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;display:inline-block;transition:all 0.3s;border:1px solid var(--glass-border);cursor:pointer}
.btn-primary{background:linear-gradient(135deg, #8b5cf6 0%, #a78bfa 100%);color:#fff;border:none;box-shadow:0 4px 15px rgba(139,92,246,0.3)}
.btn-primary:hover{background:linear-gradient(135deg, #a78bfa 0%, #c4b5fd 100%);transform:translateY(-2px);box-shadow:0 8px 25px rgba(167,139,250,0.4)}
.btn-secondary{background:var(--glass-bg);color:var(--text-secondary);border:1px solid var(--glass-border)}
.btn-secondary:hover{background:rgba(167,139,250,0.15);color:var(--accent-light);border-color:var(--accent);transform:translateY(-2px);box-shadow:0 4px 15px rgba(167,139,250,0.2)}
.btn-logout{background:linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);color:#fff;border:none;box-shadow:0 4px 15px rgba(244,63,94,0.3)}
.btn-logout:hover{background:linear-gradient(135deg, #f87171 0%, #f43f5e 100%);transform:translateY(-2px);box-shadow:0 8px 25px rgba(244,63,94,0.4)}
.stats{display:flex;gap:16px;justify-content:center;margin:20px 0;flex-wrap:wrap}
.stat-box{background:var(--card);padding:16px 24px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.3);text-align:center;min-width:150px;transition:all 0.3s ease;border:1px solid var(--card-border)}
.stat-box:hover{transform:translateY(-5px);box-shadow:0 8px 30px rgba(167,139,250,0.25);border-color:var(--accent)}
.stat-box .number{font-size:28px;font-weight:800;background:linear-gradient(135deg, var(--accent) 0%, var(--gold) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:4px}
.stat-box .label{font-size:14px;color:var(--text-muted)}
.section{margin-bottom:40px}
.section-title{font-size:22px;font-weight:700;margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid var(--card-border);color:var(--text-primary)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:20px}
.card{background:var(--card);padding:20px;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.3);transition:all 0.3s;border:1px solid var(--card-border)}
.card:hover{box-shadow:0 12px 40px rgba(167,139,250,0.25);border-color:var(--accent);transform:translateY(-4px)}
.card-title{font-weight:700;font-size:16px;margin-bottom:12px;color:var(--text-primary);line-height:1.4}
.card-meta{display:flex;gap:16px;font-size:13px;color:var(--text-muted);margin-bottom:16px;flex-wrap:wrap}
.card-meta span{display:flex;align-items:center;gap:6px}
.card-actions{display:flex;gap:10px}
.empty{text-align:center;padding:80px 20px;color:var(--text-muted)}
.empty-icon{font-size:64px;margin-bottom:20px;opacity:0.5}
.debug-info{background:rgba(251,191,36,0.1);padding:10px;border-radius:8px;margin:10px 0;font-size:12px;color:var(--warning);border:1px solid rgba(251,191,36,0.3);animation: fadeIn 0.5s ease-in}
.completed-badge{background:linear-gradient(135deg, var(--jewel-emerald) 0%, var(--jewel-sapphire) 100%);color:white;padding:4px 8px;border-radius:4px;font-size:12px;margin-left:10px;font-weight:600}
@keyframes fadeIn{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
@media(max-width:768px){.grid{grid-template-columns:1fr}.user-actions{flex-direction:column;gap:10px}.btn{width:100%;text-align:center}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>📚 Quiz History</h1>
    <p>Your past quiz attempts and performance</p>
    <!-- User info and actions -->
    <div class="user-actions">
      <span class="user-info">👤 Logged in as: <strong>{{ session.user_name }}</strong></span>
      <a href="/menu" class="btn btn-secondary">🏠 Menu</a>
      <a href="/logout" class="btn btn-logout">🔓 Logout</a>
    </div>
  </div>

  {% if history %}
  <div class="section">
    <div class="section-title">📋 Your Quiz History ({{ history|length }})</div>
    <div class="grid">
      {% for attempt in history %}
      <div class="card">
        <div class="card-title">{{ attempt.quiz_name }}</div>
        <div class="card-meta">
          <span>📅 {{ attempt.timestamp[:10] }}</span>
          <span>⏰ {{ attempt.timestamp[11:16] }}</span>
          <span>📊 {{ attempt.score_percent }}%</span>
        </div>
        <div class="card-meta">
          <span>✅ {{ attempt.correct_count }} correct</span>
          <span>❌ {{ attempt.wrong_count }} incorrect</span>
          <span>⚪ {{ attempt.skipped_count }} skipped</span>
        </div>
        <div class="card-actions">
          <a href="/attempt/{{ attempt.attempt_id }}" class="btn btn-primary">Details</a>
        </div>
      </div>
      {% endfor %}
    </div>
  </div>
  {% else %}
  <div class="empty">
    <div class="empty-icon">📋</div>
    <h3>No Quiz History</h3>
    <p>You haven't taken any quizzes yet.</p>
    <a href="/menu" class="btn btn-primary">Start a Quiz</a>
  </div>
  {% endif %}
</div>
</body>
</html>
"""

RECENTLY_VIEWED_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Recently Viewed - CFA Level 1</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--card-border:#2d3748;--muted:#94a3b8;--accent:#a78bfa;--accent-dark:#8b5cf6;--accent-light:#c4b5fd;--success:#34d399;--danger:#f87171;--warning:#fbbf24;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37;--jewel-emerald:#10b981;--jewel-sapphire:#0ea5e9;--jewel-amethyst:#a78bfa;--jewel-ruby:#f43f5e;--glass-bg:rgba(255,255,255,0.05);--glass-border:rgba(255,255,255,0.1)}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, var(--bg) 0%, #1e293b 100%);color:var(--text-primary);min-height:100vh}
.container{max-width:1200px;margin:28px auto;padding:0 18px}
.header{text-align:center;margin-bottom:32px}
.header h1{font-size:32px;font-weight:800;margin:0 0 8px 0;background:linear-gradient(135deg, #a78bfa 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.header p{color:var(--text-muted);font-size:14px;margin:0}
.user-actions{display:flex;align-items:center;justify-content:center;gap:15px;margin:20px 0;flex-wrap:wrap}
.user-info{background:var(--glass-bg);padding:10px 18px;border-radius:50px;font-size:14px;box-shadow:0 4px 15px rgba(167,139,250,0.15);transition:all 0.3s ease;border:1px solid var(--glass-border);color:var(--text-secondary)}
.user-info:hover{transform:scale(1.05);box-shadow:0 8px 25px rgba(167,139,250,0.25);background:rgba(167,139,250,0.1)}
.btn{padding:10px 20px;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;display:inline-block;transition:all 0.3s;border:1px solid var(--glass-border);cursor:pointer}
.btn-primary{background:linear-gradient(135deg, #8b5cf6 0%, #a78bfa 100%);color:#fff;border:none;box-shadow:0 4px 15px rgba(139,92,246,0.3)}
.btn-primary:hover{background:linear-gradient(135deg, #a78bfa 0%, #c4b5fd 100%);transform:translateY(-2px);box-shadow:0 8px 25px rgba(167,139,250,0.4)}
.btn-secondary{background:var(--glass-bg);color:var(--text-secondary);border:1px solid var(--glass-border)}
.btn-secondary:hover{background:rgba(167,139,250,0.15);color:var(--accent-light);border-color:var(--accent);transform:translateY(-2px);box-shadow:0 4px 15px rgba(167,139,250,0.2)}
.btn-logout{background:linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);color:#fff;border:none;box-shadow:0 4px 15px rgba(244,63,94,0.3)}
.btn-logout:hover{background:linear-gradient(135deg, #f87171 0%, #f43f5e 100%);transform:translateY(-2px);box-shadow:0 8px 25px rgba(244,63,94,0.4)}
.stats{display:flex;gap:16px;justify-content:center;margin:20px 0;flex-wrap:wrap}
.stat-box{background:var(--card);padding:16px 24px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.3);text-align:center;min-width:150px;transition:all 0.3s ease;border:1px solid var(--card-border)}
.stat-box:hover{transform:translateY(-5px);box-shadow:0 8px 30px rgba(167,139,250,0.25);border-color:var(--accent)}
.stat-box .number{font-size:28px;font-weight:800;background:linear-gradient(135deg, var(--accent) 0%, var(--gold) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:4px}
.stat-box .label{font-size:14px;color:var(--text-muted)}
.section{margin-bottom:40px}
.section-title{font-size:22px;font-weight:700;margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid var(--card-border);color:var(--text-primary)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:20px}
.card{background:var(--card);padding:20px;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.3);transition:all 0.3s;border:1px solid var(--card-border)}
.card:hover{box-shadow:0 12px 40px rgba(167,139,250,0.25);border-color:var(--accent);transform:translateY(-4px)}
.card-title{font-weight:700;font-size:16px;margin-bottom:12px;color:var(--text-primary);line-height:1.4}
.card-meta{display:flex;gap:16px;font-size:13px;color:var(--text-muted);margin-bottom:16px;flex-wrap:wrap}
.card-meta span{display:flex;align-items:center;gap:6px}
.card-actions{display:flex;gap:10px}
.empty{text-align:center;padding:80px 20px;color:var(--text-muted)}
.empty-icon{font-size:64px;margin-bottom:20px;opacity:0.5}
.debug-info{background:rgba(251,191,36,0.1);padding:10px;border-radius:8px;margin:10px 0;font-size:12px;color:var(--warning);border:1px solid rgba(251,191,36,0.3);animation: fadeIn 0.5s ease-in}
.completed-badge{background:linear-gradient(135deg, var(--jewel-emerald) 0%, var(--jewel-sapphire) 100%);color:white;padding:4px 8px;border-radius:4px;font-size:12px;margin-left:10px;font-weight:600}
@keyframes fadeIn{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
@media(max-width:768px){.grid{grid-template-columns:1fr}.user-actions{flex-direction:column;gap:10px}.btn{width:100%;text-align:center}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>👁️ Recently Viewed</h1>
    <p>Your recently accessed study materials</p>
    <!-- User info and actions -->
    <div class="user-actions">
      <span class="user-info">👤 Logged in as: <strong>{{ session.user_name }}</strong></span>
      <a href="/menu" class="btn btn-secondary">🏠 Menu</a>
      <a href="/logout" class="btn btn-logout">🔓 Logout</a>
    </div>
  </div>

  {% if recently_viewed %}
  <div class="section">
    <div class="section-title">📋 Recently Viewed Items ({{ recently_viewed|length }})</div>
    <div class="grid">
      {% for item in recently_viewed %}
      <div class="card">
        <div class="card-title">{{ item.name }}</div>
        <div class="card-meta">
          <span>📅 {{ item.timestamp[:10] }}</span>
          <span>⏰ {{ item.timestamp[11:16] }}</span>
        </div>
        <div class="card-actions">
          <a href="/quiz/{{ item.name }}" class="btn btn-primary">View Again</a>
        </div>
      </div>
      {% endfor %}
    </div>
  </div>
  {% else %}
  <div class="empty">
    <div class="empty-icon">👁️</div>
    <h3>No Recently Viewed Items</h3>
    <p>You haven't viewed any study materials yet.</p>
    <a href="/menu" class="btn btn-primary">Browse Materials</a>
  </div>
  {% endif %}
</div>
</body>
</html>
"""

ALL_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>All Questions - CFA Level 1</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--card-border:#2d3748;--muted:#94a3b8;--accent:#a78bfa;--accent-dark:#8b5cf6;--accent-light:#c4b5fd;--success:#34d399;--danger:#f87171;--warning:#fbbf24;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37;--jewel-emerald:#10b981;--jewel-sapphire:#0ea5e9;--jewel-amethyst:#a78bfa;--jewel-ruby:#f43f5e;--glass-bg:rgba(255,255,255,0.05);--glass-border:rgba(255,255,255,0.1)}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, var(--bg) 0%, #1e293b 100%);color:var(--text-primary);min-height:100vh}
.container{max-width:1100px;margin:28px auto;padding:0 18px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;background:var(--glass-bg);backdrop-filter:blur(10px);padding:16px;border-radius:12px;border:1px solid var(--glass-border);animation:slideDown 0.4s ease}
.exam-title{font-weight:700;font-size:18px;background:linear-gradient(135deg, var(--accent-light) 0%, var(--gold) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.time-box{padding:8px 12px;border-radius:8px;background:var(--glass-bg);border:1px solid var(--glass-border);font-weight:600;transition:all 0.3s ease;color:var(--accent-light);min-width:110px;text-align:center}
.time-box.warning{color:#facc15}
.time-box.danger{color:#f87171}
.time-box:hover{transform:scale(1.05);box-shadow:0 0 20px rgba(167,139,250,0.3);background:rgba(167,139,250,0.1)}
.card{background:var(--card);padding:22px;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.3);transition:all 0.3s ease;border:1px solid var(--card-border);position:relative;overflow:hidden;margin-bottom:18px}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg, transparent, var(--gold), transparent);opacity:0;transition:opacity 0.3s ease}
.card:hover{transform:translateY(-5px);box-shadow:0 16px 40px rgba(167,139,250,0.2);border-color:var(--accent)}
.card:hover::before{opacity:1}
.q-header{display:flex;align-items:flex-start;gap:12px}
.q-num{background:linear-gradient(135deg, var(--jewel-amethyst) 0%, var(--jewel-sapphire) 100%);padding:8px 12px;border-radius:8px;font-weight:700;transition:all 0.3s ease;color:#000;min-width:40px;text-align:center}
.q-num:hover{transform:scale(1.1) rotate(5deg);box-shadow:0 0 20px rgba(167,139,250,0.4)}
.question-text{font-size:15px;line-height:1.6;color:var(--text-secondary)}
.choices{margin-top:14px;border-top:1px solid var(--card-border);padding-top:14px}
.choice-item{display:flex;align-items:flex-start;gap:10px;padding:10px;border-radius:8px;cursor:pointer;transition:all 0.2s ease;color:var(--text-secondary)}
.choice-item:hover{background:rgba(167,139,250,0.1);transform:translateX(5px);border-radius:8px}
.controls{display:flex;justify-content:space-between;align-items:center;margin-top:18px}
.btn{padding:10px 14px;border-radius:8px;border:1px solid var(--glass-border);background:var(--glass-bg);cursor:pointer;font-weight:600;transition:all 0.2s ease;color:var(--text-secondary)}
.btn:hover{transform:translateY(-2px);box-shadow:0 4px 16px rgba(167,139,250,0.2);border-color:var(--accent)}
.btn.primary{background:linear-gradient(135deg, var(--accent-dark) 0%, var(--accent) 100%);color:#fff;border:none}
.btn.primary:hover{background:linear-gradient(135deg, var(--accent) 0%, var(--accent-light) 100%);box-shadow:0 8px 24px rgba(167,139,250,0.4)}
.result{margin-top:12px;padding:12px;border-radius:8px;font-size:14px;animation: fadeIn 0.5s ease-in}
.result.correct{background:rgba(52,211,153,0.15);border:1px solid rgba(52,211,153,0.4);color:var(--success)}
.result.wrong{background:rgba(244,63,94,0.15);border:1px solid rgba(244,63,94,0.4);color:var(--danger)}
.result.info{background:rgba(167,139,250,0.15);border:1px solid rgba(167,139,250,0.4);color:var(--accent-light)}
.explain{margin-top:10px;color:var(--text-muted);background:var(--glass-bg);padding:12px;border-radius:8px;border:1px solid rgba(52,211,153,0.2)}
.progress-bar{height:8px;background:#e2e8f0;border-radius:4px;margin-top:16px;overflow:hidden}
.progress-fill{height:100%;background:var(--accent);transition:width 0.3s ease}
.progress-text{font-size:12px;color:var(--muted);margin-top:4px;text-align:right}
input[type="radio"]{width:18px;height:18px;margin-top:3px}
.explanation{background:rgba(52,211,153,0.1);border:1px solid rgba(52,211,153,0.3);border-radius:8px;padding:20px;margin-top:15px;display:none;line-height:1.6}
.explanation .correct-answer{color:var(--text-primary);font-weight:700;font-size:16px;margin-bottom:15px;padding-bottom:10px;border-bottom:2px solid rgba(52,211,153,0.3)}
.explanation .feedback-option{margin:15px 0;padding:15px;border-radius:6px;background:var(--card)}
.explanation .feedback-option.correct-option{border-left:4px solid var(--success);background:rgba(52,211,153,0.1)}
.explanation .feedback-option.incorrect-option{border-left:4px solid var(--danger);background:rgba(244,63,94,0.1)}
.explanation .feedback-option-header{font-weight:700;font-size:15px;margin-bottom:10px;color:var(--text-primary)}
.explanation .feedback-option.correct-option .feedback-option-header{color:var(--success)}
.explanation .feedback-option.incorrect-option .feedback-option-header{color:var(--danger)}
.explanation .feedback-option-text{color:var(--text-secondary);font-size:14px;line-height:1.7}
.explanation .feedback-option-text p{margin:8px 0}
.explanation .feedback-option-text strong,.explanation .feedback-option-text b{color:var(--text-primary);font-weight:600}
.explanation .feedback-option-text em,.explanation .feedback-option-text i{font-style:italic}
.explanation .feedback-option-text ul,.explanation .feedback-option-text ol{margin:10px 0;padding-left:25px}
.explanation .feedback-option-text li{margin:5px 0}
.explanation .feedback-option-text table{width:100% !important;border-collapse:collapse !important;margin:12px 0 !important;border:1px solid rgba(167,139,250,0.2) !important;font-size:13px}
.explanation .feedback-option-text table tbody{display:table-row-group}
.explanation .feedback-option-text table thead{display:table-header-group}
.explanation .feedback-option-text table tr{display:table-row}
.explanation .feedback-option-text table th,.explanation .feedback-option-text table td{display:table-cell;padding:8px 10px !important;border:1px solid rgba(167,139,250,0.2) !important;text-align:left !important;background:transparent !important;vertical-align:middle;color:var(--text-secondary) !important}
.explanation .feedback-option-text table th{background:rgba(167,139,250,0.2) !important;font-weight:600 !important}
.explanation .feedback-option-text table td{background:transparent !important}
.explanation .feedback-option-text table td[style*="text-align: center"],.explanation .feedback-option-text table th[style*="text-align: center"]{text-align:center !important}
.question-text table, .choice-item table{width:100% !important;border-collapse:collapse !important;margin:15px 0 !important;border:1px solid rgba(167,139,250,0.3) !important;font-size:14px;background:var(--glass-bg) !important}
.question-text table thead, .choice-item table thead{display:table-header-group}
.question-text table tbody, .choice-item table tbody{display:table-row-group}
.question-text table tr, .choice-item table tr{display:table-row}
.question-text table th, .question-text table td, .choice-item table th, .choice-item table td{display:table-cell;padding:12px !important;border:1px solid rgba(167,139,250,0.2) !important;text-align:left !important;background:transparent !important;vertical-align:middle;color:var(--text-secondary) !important}
.question-text table th, .choice-item table th{background:rgba(167,139,250,0.2) !important;font-weight:600 !important;color:var(--accent-light) !important;text-align:center !important}
.question-text table td, .choice-item table td{background:transparent !important}
.question-text table td[style*="text-align: center"], .question-text table th[style*="text-align: center"], .choice-item table td[style*="text-align: center"], .choice-item table th[style*="text-align: center"]{text-align:center !important}
.question-text p, .question-text span, .choice-item p, .choice-item span{line-height:1.6;margin:10px 0;color:var(--text-secondary)}
@keyframes fadeIn {from {opacity: 0; transform: translateY(-10px);} to {opacity: 1; transform: translateY(0);}}
@keyframes slideDown {from {opacity: 0; transform: translateY(-20px);} to {opacity: 1; transform: translateY(0);}}
@media(max-width:900px){ .card{padding:14px} }
</style>
</head>
<body>
<div class="container">
  <div class="topbar">
    <div>
      <div class="exam-title">All Questions — {{ total }} questions</div>
      <div style="color:var(--muted);font-size:13px">Source: {{ data_source }}</div>
    </div>
    <div style="display:flex;gap:8px;align-items:center">
      <a href="/menu" class="btn" style="text-decoration:none;color:#0f1724">🏠 Home</a>
      <a href="/logout" class="btn" style="text-decoration:none;color:#0f1724">Logout</a>
      <div class="time-box" id="timer">--:--:--</div>
    </div>
  </div>

  <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px">
    {% if is_mock %}
    <button type="button" class="btn primary" onclick="showAllAnswers()" id="showAllBtn">📋 Show All Answers</button>
    <button type="button" class="btn primary" onclick="hideAllAnswers()" id="hideAllBtn" style="display:none;">🙈 Hide All Answers</button>
    {% else %}
    <button type="button" class="btn primary" onclick="showAllAnswers()" id="showAllBtn">📋 Show All Answers</button>
    {% endif %}
    <a href="/menu" class="btn primary" style="text-decoration:none;color:#0f1724">🏠 Back to Menu</a>
  </div>

  <div id="allQuestionsContainer" style="display:flex;flex-direction:column;gap:20px;margin-bottom:20px">
    {% for question in questions %}
    <div class="card" data-question-index="{{ loop.index0 }}">
      <div class="q-header">
        <div class="q-num">{{ loop.index }}</div>
        <div style="flex:1">
          <div style="color:var(--muted);font-size:13px">Question {{ loop.index }}</div>
          <div class="question-text">{{ question.stem | safe }}</div>
        </div>
      </div>

      <div class="choices">
        {% for choice in question.choices %}
        <label class="choice-item">
          <input type="radio" name="choice-{{ loop.index0 }}" value="{{ choice.id }}" class="q-radio">
          <div style="font-size:14px">{{ choice.text | safe }}</div>
        </label>
        {% endfor %}
      </div>

      {% if is_mock %}
      <div class="controls" style="justify-content:flex-end">
        <button type="button" class="btn primary" onclick="showAnswer({{ loop.index0 }})">Show Answer</button>
      </div>
      {% else %}
      <div class="controls" style="justify-content:flex-end">
        <button type="button" class="btn primary" onclick="submitQuestion({{ loop.index0 }})">Submit Answer</button>
      </div>
      {% endif %}

      <div class="feedback" id="feedback-{{ loop.index0 }}"></div>
    </div>
    {% endfor %}
  </div>
</div>

<script>
const questions = {{ questions | tojson }};
const isMock = {{ is_mock | tojson }};
let userAnswers = new Array(questions.length).fill(null);
let answersShown = false; // Track if answers are currently shown for mocks

// Timer
let start = Date.now();
setInterval(()=> {
  const s = Math.floor((Date.now()-start)/1000);
  const mm = String(Math.floor(s/60)).padStart(2,'0'), ss = String(s%60).padStart(2,'0');
  document.getElementById('timer').textContent = `Time ${mm}:${ss}`;
}, 500);

function showAnswer(questionIdx) {
  const q = questions[questionIdx];
  const radioName = `choice-${questionIdx}`;
  const fbDiv = document.getElementById(`feedback-${questionIdx}`);
  
  const correct = q.correct || null;
  
  let resultHTML = `<div class="result correct">✓ Correct Answer</div>`;
  
  // Show explanations
  const hasPerChoiceFeedback = q.feedback && Object.keys(q.feedback).some(key => key !== 'neutral' && key !== 'correct' && key !== 'incorrect');
  
  resultHTML += '<div style="border-top:1px solid var(--card-border);padding-top:14px;margin-top:12px"><div style="font-weight:600;color:var(--text-primary);margin-bottom:12px">Answer Explanations:</div>';
  
  (q.choices || []).forEach((c, j) => {
    const answerLetter = String.fromCharCode(65 + j);
    const isAnswerCorrect = c.id === correct;
    
    let optionExplanation = '';
    if (q.feedback) {
      const feedbackKey = c.id;
      if (q.feedback[feedbackKey]) {
        optionExplanation = q.feedback[feedbackKey];
      } else if (hasPerChoiceFeedback) {
        optionExplanation = '';
      } else if (q.feedback.neutral) {
        if (isAnswerCorrect) {
          optionExplanation = q.feedback.neutral;
        }
      }
    }
    
    if (optionExplanation || isAnswerCorrect) {
      const feedbackClass = isAnswerCorrect ? 'correct-option' : 'incorrect-option';
      const statusText = isAnswerCorrect ? '✓ Correct Answer' : '';
      if (optionExplanation || isAnswerCorrect) {
        resultHTML += `<div class="explanation" style="display:block;margin:12px 0"><div class="feedback-option ${feedbackClass}"><div class="feedback-option-header">${answerLetter}. ${statusText}</div><div class="feedback-option-text">${optionExplanation || (isAnswerCorrect ? '<p>This is the correct answer.</p>' : '')}</div></div></div>`;
      }
    }
  });
  
  resultHTML += '</div>';
  fbDiv.innerHTML = resultHTML;
  
  // Auto-check the radio button to the correct answer
  const correctRadio = document.querySelector(`input[name="${radioName}"][value="${correct}"]`);
  if (correctRadio) {
    correctRadio.checked = true;
  }
}

function submitQuestion(questionIdx) {
  const q = questions[questionIdx];
  const radioName = `choice-${questionIdx}`;
  const chosen = document.querySelector(`input[name="${radioName}"]:checked`);
  
  if (!chosen) {
    document.getElementById(`feedback-${questionIdx}`).innerHTML = '<div class="result info">Please select an answer first.</div>';
    return;
  }
  
  const fbDiv = document.getElementById(`feedback-${questionIdx}`);
  fbDiv.innerHTML = '';
  
  userAnswers[questionIdx] = chosen.value;
  
  const correct = q.correct || null;
  const isCorrect = chosen.value === correct;
  
  let resultHTML = `<div class="result ${isCorrect ? 'correct' : 'wrong'}">${isCorrect ? '✓ Correct!' : '✗ Wrong!'}</div>`;
  
  // Show explanations
  const hasPerChoiceFeedback = q.feedback && Object.keys(q.feedback).some(key => key !== 'neutral' && key !== 'correct' && key !== 'incorrect');
  
  resultHTML += '<div style="border-top:1px solid var(--card-border);padding-top:14px;margin-top:12px"><div style="font-weight:600;color:var(--text-primary);margin-bottom:12px">Answer Explanations:</div>';
  
  (q.choices || []).forEach((c, j) => {
    const answerLetter = String.fromCharCode(65 + j);
    const isAnswerCorrect = c.id === q.correct;
    const isAnswerSelected = c.id === chosen.value;
    
    let optionExplanation = '';
    if (q.feedback) {
      const feedbackKey = c.id;
      if (q.feedback[feedbackKey]) {
        optionExplanation = q.feedback[feedbackKey];
      } else if (hasPerChoiceFeedback) {
        optionExplanation = '';
      } else if (q.feedback.neutral) {
        if (isAnswerCorrect) {
          optionExplanation = q.feedback.neutral;
        } else {
          optionExplanation = '<p>Incorrect. This is not the correct answer.</p>';
        }
      }
    }
    
    if (optionExplanation) {
      const feedbackClass = isAnswerCorrect ? 'correct-option' : 'incorrect-option';
      const statusIcon = isAnswerCorrect ? '✓' : (isAnswerSelected ? '✗' : '');
      const statusText = isAnswerCorrect ? 'Correct' : (isAnswerSelected ? 'Your Answer' : '');
      resultHTML += `<div class="explanation" style="display:block;margin:12px 0"><div class="feedback-option ${feedbackClass}"><div class="feedback-option-header">${answerLetter}. ${statusIcon} ${statusText}</div><div class="feedback-option-text">${optionExplanation}</div></div></div>`;
    }
  });
  
  resultHTML += '</div>';
  fbDiv.innerHTML = resultHTML;
}

function showAllAnswers() {
  if (isMock && answersShown) return; // Prevent re-execution if already shown
  
  const showAllBtn = document.getElementById('showAllBtn');
  const hideAllBtn = document.getElementById('hideAllBtn');
  
  showAllBtn.disabled = true;
  showAllBtn.textContent = '⏳ Revealing answers...';
  
  questions.forEach((q, idx) => {
    const fbDiv = document.getElementById(`feedback-${idx}`);
    
    const correct = q.correct || null;
    
    let resultHTML = `<div class="result correct">✓ Correct Answer</div>`;
    
    // Show explanations
    const hasPerChoiceFeedback = q.feedback && Object.keys(q.feedback).some(key => key !== 'neutral' && key !== 'correct' && key !== 'incorrect');
    
    resultHTML += '<div style="border-top:1px solid var(--card-border);padding-top:14px;margin-top:12px"><div style="font-weight:600;color:var(--text-primary);margin-bottom:12px">Answer Explanations:</div>';
    
    (q.choices || []).forEach((c, j) => {
      const answerLetter = String.fromCharCode(65 + j);
      const isAnswerCorrect = c.id === correct;
      
      let optionExplanation = '';
      if (q.feedback) {
        const feedbackKey = c.id;
        if (q.feedback[feedbackKey]) {
          optionExplanation = q.feedback[feedbackKey];
        } else if (hasPerChoiceFeedback) {
          optionExplanation = '';
        } else if (q.feedback.neutral) {
          if (isAnswerCorrect) {
            optionExplanation = q.feedback.neutral;
          }
        }
      }
      
      if (optionExplanation || isAnswerCorrect) {
        const feedbackClass = isAnswerCorrect ? 'correct-option' : 'incorrect-option';
        const statusText = isAnswerCorrect ? '✓ Correct Answer' : '';
        if (optionExplanation || isAnswerCorrect) {
          resultHTML += `<div class="explanation" style="display:block;margin:12px 0"><div class="feedback-option ${feedbackClass}"><div class="feedback-option-header">${answerLetter}. ${statusText}</div><div class="feedback-option-text">${optionExplanation || (isAnswerCorrect ? '<p>This is the correct answer.</p>' : '')}</div></div></div>`;
        }
      }
    });
    
    resultHTML += '</div>';
    fbDiv.innerHTML = resultHTML;
  });
  
  showAllBtn.disabled = false;
  showAllBtn.textContent = '📋 Show All Answers';
  answersShown = true;
  
  // Auto-check the radio buttons to the correct answers
  questions.forEach((q, idx) => {
    const radioName = `choice-${idx}`;
    const correctRadio = document.querySelector(`input[name="${radioName}"][value="${q.correct}"]`);
    if (correctRadio) {
      correctRadio.checked = true;
    }
  });
  
  // For mock exams, show the Hide button and hide the Show button
  if (isMock) {
    showAllBtn.style.display = 'none';
    hideAllBtn.style.display = 'inline-block';
  }
  
  // Scroll to first question
  document.querySelector('.card').scrollIntoView({ behavior: 'smooth' });
}

function hideAllAnswers() {
  if (!isMock || !answersShown) return; // Only for mock exams
  
  const showAllBtn = document.getElementById('showAllBtn');
  const hideAllBtn = document.getElementById('hideAllBtn');
  
  questions.forEach((q, idx) => {
    const fbDiv = document.getElementById(`feedback-${idx}`);
    fbDiv.innerHTML = ''; // Clear all feedback
  });
  
  // Clear all radio selections
  questions.forEach((q, idx) => {
    const radioName = `choice-${idx}`;
    const radios = document.querySelectorAll(`input[name="${radioName}"]`);
    radios.forEach(radio => radio.checked = false);
  });
  
  answersShown = false;
  
  // Show the Show button and hide the Hide button
  showAllBtn.style.display = 'inline-block';
  hideAllBtn.style.display = 'none';
  
  // Scroll to top
  window.scrollTo({ top: 0, behavior: 'smooth' });
}
</script>
</body>
</html>
"""

@app.route("/all-questions/<path:filename>")
@login_required
def all_questions_file(filename):
    """
    New route: Display all questions on a single page in cards.
    Examples:
      /all-questions/data1.json
      /all-questions/uploads/myfile.json
    """
    filename = filename + ".json"
    tried_paths = []
    if os.path.isabs(filename):
        tried_paths.append(filename)
    else:
        tried_paths.append(os.path.join(BASE_DIR, filename))
        tried_paths.append(os.path.join(DATA_FOLDER, filename))
        tried_paths.append(os.path.join(UPLOAD_FOLDER, filename))
    
    chosen = None
    for p in tried_paths:
        if os.path.exists(p) and is_allowed_path(p):
            chosen = os.path.abspath(p)
            break

    if not chosen:
        return jsonify({"error": "File not found or not allowed", "tried": tried_paths}), 404

    try:
        questions, raw = load_questions_from_file(chosen)
    except Exception as e:
        return jsonify({"error": "Failed to load JSON", "detail": str(e)}), 500

    # Determine if this is a mock exam
    is_mock = 'Mock' in os.path.basename(chosen)
    return render_template_string(
        ALL_TEMPLATE, 
        questions=questions, 
        total=len(questions), 
        data_source=os.path.basename(chosen), 
        is_mock=is_mock,
        user_role=session.get('user_role', 'user')
    )


@app.route("/debug-all-questions/<path:filename>")
@login_required
def debug_all_questions_file(filename):
    """
    Debug route: Display all questions with detailed information about the data structure.
    """
    filename = filename + ".json"
    tried_paths = []
    if os.path.isabs(filename):
        tried_paths.append(filename)
    else:
        tried_paths.append(os.path.join(BASE_DIR, filename))
        tried_paths.append(os.path.join(DATA_FOLDER, filename))
        tried_paths.append(os.path.join(UPLOAD_FOLDER, filename))
    
    chosen = None
    for p in tried_paths:
        if os.path.exists(p) and is_allowed_path(p):
            chosen = os.path.abspath(p)
            break

    if not chosen:
        return jsonify({"error": "File not found or not allowed", "tried": tried_paths}), 404

    try:
        questions, raw = load_questions_from_file(chosen)
    except Exception as e:
        return jsonify({"error": "Failed to load JSON", "detail": str(e)}), 500

    # Create a debug template to show the data structure
    debug_template = """
    <!doctype html>
    <html lang="en">
    <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>Debug All Questions - CFA Level 1</title>
    <style>
    :root{--bg:#f6f8fb;--card:#fff;--muted:#6b7280;--accent:#0b69ff;--success:#10b981;--danger:#ef4444;--warning:#f59e0b}
    body{margin:0;font-family:Inter,Arial,Helvetica,sans-serif;background:var(--bg);color:#0f1724}
    .container{max-width:1200px;margin:28px auto;padding:0 18px}
    .header{text-align:center;margin-bottom:32px}
    .header h1{font-size:32px;font-weight:800;margin:0 0 8px 0;color:#0f1724}
    .header p{color:var(--muted);font-size:14px;margin:0}
    .btn{padding:10px 20px;border-radius:8px;font-size:14px;font-weight:600;text-decoration:none;display:inline-block;transition:all 0.2s;border:none;cursor:pointer}
    .btn-primary{background:var(--accent);color:#fff}
    .btn-primary:hover{background:#0952cc;transform:translateY(-2px);box-shadow:0 4px 12px rgba(11,105,255,0.2)}
    .btn-secondary{background:#f1f5f9;color:#0f1724}
    .btn-secondary:hover{background:#e2e8f0;transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,0.1)}
    .question{background:#fff;padding:20px;margin-bottom:20px;border-radius:12px;box-shadow:0 4px 16px rgba(0,0,0,0.06);position:relative}
    .question-title{font-weight:700;font-size:16px;margin-bottom:12px;color:#0f1724}
    .question-meta{color:var(--muted);font-size:13px;margin-bottom:15px}
    .debug-info{margin:15px 0;padding:15px;background:#f0f9ff;border:1px solid #bae6fd;border-radius:8px;font-family:monospace;font-size:14px}
    .debug-key{font-weight:bold;color:#0b69ff}
    </style>
    </head>
    <body>
    <div class="container">
      <div class="header">
        <h1>🔍 Debug All Questions - {{ data_source }}</h1>
        <p>Complete question list from {{ data_source }}</p>
        <div style="margin:20px 0">
          <a href="/menu" class="btn btn-secondary">🏠 Back to Menu</a>
        </div>
      </div>
      
      {% if questions %}
      <div>
        <h2>Total Questions: {{ total }}</h2>
        {% for question in questions %}
        <div class="question">
          <div class="question-title">Q{{ loop.index }}: {{ question.stem[:100] }}...</div>
          <div class="question-meta">ID: {{ question.id }}</div>
          
          <div class="debug-info">
            <div><span class="debug-key">Correct ID:</span> {{ question.correct|default('None') }}</div>
            <div><span class="debug-key">Correct Label:</span> {{ question.correct_label|default('None') }}</div>
            <div><span class="debug-key">Feedback Keys:</span> {{ question.feedback.keys()|list|default('None') if question.feedback else 'None' }}</div>
            <div><span class="debug-key">Has Neutral Feedback:</span> {{ 'Yes' if question.feedback and 'neutral' in question.feedback else 'No' }}</div>
            <div><span class="debug-key">Feedback (neutral):</span> {{ question.feedback.neutral|default('None') if question.feedback else 'None' }}</div>
          </div>
        </div>
        {% endfor %}
      </div>
      {% else %}
      <p>No questions found in this file.</p>
      {% endif %}
      
      <a href="/menu" class="btn btn-primary" style="margin-top:20px">🏠 Back to Menu</a>
    </div>
    </body>
    </html>
    """
    
    return render_template_string(debug_template, questions=questions, total=len(questions), data_source=os.path.basename(chosen))



def add_login_session(user_id):
    """Record a login session for tracking via Redis"""
    session_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': request.remote_addr or 'Unknown',
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'is_current': True
    }
    db.add_login_history(user_id, session_entry)

# Root route - redirect to login
@app.route('/')
def home():
    """Homepage - redirect to login if not authenticated, otherwise to manage users"""
    if 'user_id' in session and 'jwt_token' in session:
        # User is logged in, redirect to manage users
        return redirect(url_for('manage_users'))
    else:
        # Not logged in, redirect to login
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
    session_token = generate_session_token()
    
    # Step 3: Store session in Redis with expiration
    expires_at = datetime.now() + timedelta(days=JWT_EXPIRATION_DAYS)
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
    
    # Step 6: Track login for history
    add_login_session(user_id)
    
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

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Central admin dashboard for system monitoring and management"""
    users = db.get_all_users()
    total_users = len(users)
    active_users = len([u for u in users if is_user_valid(u)])
    admin_users = len([u for u in users if u.get('role') == 'admin'])
    
    stats = {
        'total_users': total_users,
        'active_users': active_users,
        'admin_users': admin_users,
        'redis_connected': db.redis_client is not None
    }
    
    return render_template_string(ADMIN_DASHBOARD_TEMPLATE, stats=stats)


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
            return render_template_string(REMOVE_USER_TEMPLATE, users=db.get_all_users(), error="User ID required")
        success, message = remove_user(user_id)
        return render_template_string(REMOVE_USER_TEMPLATE, users=db.get_all_users(), success=message if success else None, error=None if success else message)
    return render_template_string(REMOVE_USER_TEMPLATE, users=db.get_all_users())

@app.route('/manage-users')
@admin_required
def manage_users():
    users = db.get_all_users()
    for user in users: user['is_valid'] = is_user_valid(user)
    return render_template_string(MANAGE_USERS_TEMPLATE, users=users)

@app.route('/edit-user/<user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user_route(user_id):
    if request.method == 'POST':
        name = request.form.get('name')
        role = request.form.get('role')
        expiry = request.form.get('expiry')
        password = request.form.get('password')
        if not name:
            return render_template_string(EDIT_USER_TEMPLATE, user=get_user_by_id(user_id), error="Full name is required"), 400
        success, message = edit_user(user_id, name=name, role=role, expiry=expiry, password=password)
        if success: return redirect(url_for('manage_users'))
        return render_template_string(EDIT_USER_TEMPLATE, user=get_user_by_id(user_id), error=message), 400
    return render_template_string(EDIT_USER_TEMPLATE, user=get_user_by_id(user_id))

# Admin Dashboard Template
ADMIN_DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin Dashboard - CFA Level 1 Quiz</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--card-border:#2d3748;--muted:#94a3b8;--accent:#a78bfa;--accent-dark:#8b5cf6;--accent-light:#c4b5fd;--success:#34d399;--danger:#f87171;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, #0f1419 0%, #1e293b 100%);color:var(--text-primary);min-height:100vh}
.container{max-width:1100px;margin:28px auto;padding:0 18px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;animation:slideDown 0.4s ease}
.header h1{font-size:32px;margin:0;background:linear-gradient(135deg, #a78bfa 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-0.5px;font-weight:800}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:20px;margin-bottom:40px}
.stat-card{background:var(--card);padding:24px;border-radius:16px;border:1px solid var(--card-border);box-shadow:0 10px 30px rgba(0,0,0,0.3);transition:all 0.3s ease}
.stat-card:hover{transform:translateY(-5px);border-color:var(--accent)}
.stat-val{font-size:36px;font-weight:800;color:var(--accent);margin-bottom:4px}
.stat-label{color:var(--text-muted);font-size:14px;font-weight:600;text-transform:uppercase;letter-spacing:1px}
.admin-actions{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px}
.action-card{background:var(--card);padding:30px;border-radius:16px;border:1px solid var(--card-border);text-align:center;transition:all 0.3s ease}
.action-card:hover{transform:translateY(-5px);border-color:var(--gold)}
.action-icon{font-size:48px;margin-bottom:20px}
.action-title{font-size:20px;font-weight:700;margin-bottom:12px}
.action-desc{color:var(--text-muted);font-size:14px;margin-bottom:24px;line-height:1.5}
.btn{display:inline-block;padding:12px 24px;background:linear-gradient(135deg, var(--accent-dark) 0%, var(--accent) 100%);color:#fff;text-decoration:none;border-radius:10px;font-weight:600;transition:all 0.3s}
.btn:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(167,139,250,0.3)}
@keyframes slideDown{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:translateY(0)}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>👑 Admin Dashboard</h1>
    <a href="/menu" class="btn" style="background:var(--card-border)">🏠 Back to Menu</a>
  </div>
  
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-val">{{ stats.total_users }}</div>
      <div class="stat-label">Total Users</div>
    </div>
    <div class="stat-card">
      <div class="stat-val">{{ stats.active_users }}</div>
      <div class="stat-label">Valid Accounts</div>
    </div>
    <div class="stat-card">
      <div class="stat-val">{{ stats.admin_users }}</div>
      <div class="stat-label">Administrators</div>
    </div>
    <div class="stat-card">
      <div class="stat-val">{% if stats.redis_connected %}✅{% else %}❌{% endif %}</div>
      <div class="stat-label">Redis Status</div>
    </div>
  </div>
  
  <div class="admin-actions">
    <div class="action-card">
      <div class="action-icon">👥</div>
      <div class="action-title">Manage Users</div>
      <div class="action-desc">View all users, check expiry status, and manage roles across the system.</div>
      <a href="/manage-users" class="btn">Go to User Manager</a>
    </div>
    <div class="action-card">
      <div class="action-icon">➕</div>
      <div class="action-title">Add New User</div>
      <div class="action-desc">Quickly create new student accounts with specific duration and roles.</div>
      <a href="/add-user" class="btn">Create User</a>
    </div>
  </div>
</div>
</body>
</html>
"""

# Edit User Template
EDIT_USER_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Edit User - CFA Level 1 Quiz</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--card-border:#2d3748;--muted:#94a3b8;--accent:#a78bfa;--accent-dark:#8b5cf6;--accent-light:#c4b5fd;--success:#34d399;--danger:#f87171;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, #0f1419 0%, #1e293b 100%);color:var(--text-primary);min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{max-width:1100px;margin:28px auto;padding:0 18px;width:100%}
.form-card{background:var(--card);border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.4);padding:40px;border:1px solid rgba(167,139,250,0.2);animation:slideDown 0.5s ease-out;max-width:600px;margin:0 auto}
.header{display:flex;align-items:center;gap:16px;margin-bottom:32px}
.header-icon{font-size:48px}
.header-content h1{font-size:32px;margin:0 0 8px 0;background:linear-gradient(135deg, #a78bfa 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-0.5px;font-weight:800}
.header-content p{color:var(--text-secondary);font-size:15px;margin:0}
.form-group{margin-bottom:24px;text-align:left}
.form-group label{display:block;margin-bottom:8px;font-weight:600;color:var(--text-secondary);font-size:15px}
.form-group input, .form-group select{width:100%;padding:12px 14px;border:1px solid rgba(167,139,250,0.3);border-radius:8px;font-size:15px;transition:all 0.3s;background:rgba(255,255,255,0.05);color:var(--text-primary)}
.form-group input::placeholder, .form-group select::placeholder{color:var(--text-muted);opacity:0.7}
.form-group input:focus, .form-group select:focus{border-color:var(--accent);outline:none;box-shadow:0 0 0 3px rgba(167,139,250,0.2);background:rgba(255,255,255,0.08)}
.form-group input:read-only{background:rgba(0,0,0,0.3);opacity:0.7;cursor:not-allowed}
.form-actions{display:flex;gap:12px;margin-top:32px;flex-wrap:wrap}
.btn{padding:12px 24px;background:linear-gradient(135deg, var(--accent-dark) 0%, var(--accent) 100%);color:#fff;border:none;border-radius:10px;font-weight:600;cursor:pointer;font-size:15px;transition:all 0.3s ease;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:8px;box-shadow:0 4px 15px rgba(139,92,246,0.3);flex:1}
.btn:hover{background:linear-gradient(135deg, var(--accent) 0%, var(--accent-light) 100%);transform:translateY(-3px);box-shadow:0 8px 24px rgba(167,139,250,0.4)}
.btn-secondary{background:var(--accent-dark);opacity:0.6;flex:1}
.btn-secondary:hover{opacity:1;transform:translateY(-3px)}
.error{color:var(--danger);background:rgba(244,63,94,0.15);padding:16px;border-radius:10px;margin-bottom:24px;border:1px solid rgba(244,63,94,0.3);animation:shake 0.5s ease}
.field-help{color:var(--text-muted);font-size:13px;margin-top:6px}
@keyframes slideDown{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:translateY(0)}}
@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-5px)}75%{transform:translateX(5px)}}
@media(max-width:600px){.form-card{padding:24px}.header{flex-direction:column;text-align:center}.header-icon{font-size:40px}.header-content h1{font-size:24px}.form-actions{flex-direction:column}.btn{width:100%}}
</style>
</head>
<body>
<div class="container">
  <div class="form-card">
    <div class="header">
      <div class="header-icon">✏️</div>
      <div class="header-content">
        <h1>Edit User</h1>
        <p>Update user account information</p>
      </div>
    </div>
    
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
    
    <form method="POST">
      <div class="form-group">
        <label for="name">Full Name</label>
        <input type="text" id="name" name="name" value="{{ user.name }}" required placeholder="Enter full name">
      </div>
      
      <div class="form-group">
        <label for="user_id">User ID (Cannot be changed)</label>
        <input type="text" id="user_id" name="user_id" value="{{ user.id }}" readonly placeholder="User ID">
        <div class="field-help">User ID cannot be modified for security reasons.</div>
      </div>
      
      <div class="form-group">
        <label for="password">Password (Leave empty to keep current)</label>
        <input type="password" id="password" name="password" placeholder="Enter new password (optional)">
        <div class="field-help">Only enter a new password if you want to change it.</div>
      </div>
      
      <div class="form-group">
        <label for="role">Role</label>
        <select id="role" name="role" required>
          <option value="user" {% if user.role == 'user' %}selected{% endif %}>User</option>
          <option value="admin" {% if user.role == 'admin' %}selected{% endif %}>Administrator</option>
        </select>
      </div>
      
      <div class="form-group">
        <label for="expiry">Expiry Date (Optional)</label>
        <input type="date" id="expiry" name="expiry" value="{{ user.expiry if user.expiry else '' }}" placeholder="Select expiry date">
        <div class="field-help">Leave empty for no expiry date (account valid forever).</div>
      </div>
      
      <div class="form-actions">
        <button type="submit" class="btn">💾 Save Changes</button>
        <a href="/manage-users" class="btn btn-secondary">❌ Cancel</a>
      </div>
    </form>
  </div>
</div>
</body>
</html>
"""

# Login Template
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

# Add User Template
ADD_USER_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Add User - CFA Level 1 Quiz</title>
<style>
:root{--bg:#f0f4f8;--card:#fff;--muted:#64748b;--accent:#0b69ff;--success:#10b981;--danger:#ef4444;--warning:#f59e0b}
body{margin:0;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:var(--bg);color:#0f1724}
.container{max-width:1100px;margin:28px auto;padding:0 18px}
.login-container{max-width:600px;margin:50px auto;padding:30px;background:#fff;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,0.1);text-align:center;animation: fadeIn 0.5s ease}
.form-group{margin-bottom:24px;text-align:left}
.form-group label{display:block;margin-bottom:8px;font-weight:600;color:#334155;font-size:15px}
.form-group input, .form-group select{width:100%;padding:14px;border:2px solid #e2e8f0;border-radius:10px;font-size:16px;transition:all 0.3s}
.form-group input:focus, .form-group select:focus{border-color:var(--accent);outline:none;box-shadow:0 0 0 3px rgba(11,105,255,0.1)}
.btn{padding:14px 24px;background:var(--accent);color:#fff;border:none;border-radius:10px;font-weight:600;cursor:pointer;font-size:16px;transition:all 0.3s;margin-top:10px;box-shadow:0 4px 12px rgba(11,105,255,0.2)}
.btn:hover{background:#0952cc;transform:translateY(-3px);box-shadow:0 8px 20px rgba(11,105,255,0.3)}
.btn-secondary{background:#64748b;color:#fff;text-decoration:none;display:inline-block;padding:14px 24px;transition:all 0.3s}
.btn-secondary:hover{background:#475569;transform:translateY(-3px);box-shadow:0 8px 20px rgba(100,116,139,0.3)}
.error{color:var(--danger);background:rgba(239,68,68,0.08);padding:16px;border-radius:10px;margin-bottom:24px;border:1px solid rgba(239,68,68,0.2);animation: shake 0.5s ease}
.success{color:var(--success);background:rgba(16,185,129,0.08);padding:16px;border-radius:10px;margin-bottom:24px;border:1px solid rgba(16,185,129,0.2);animation: fadeIn 0.5s ease}
.links{margin-top:24px;font-size:15px}
.links a{color:var(--accent);text-decoration:none;font-weight:600}
.links a:hover{text-decoration:underline}
.header-icon{font-size:48px;margin-bottom:20px}
@keyframes fadeIn {
  from {opacity: 0; transform: translateY(20px);}
  to {opacity: 1; transform: translateY(0);}
}
@keyframes shake {
  0%, 100% {transform: translateX(0);}
  25% {transform: translateX(-5px);}
  75% {transform: translateX(5px);}
}
</style>
</head>
<body>
<div class="container">
  <div class="login-container">
    <div class="header-icon">👤</div>
    <h1>Add New User</h1>
    <p>Create a new account for CFA Level 1 Quiz Platform</p>
    
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
    
    {% if success %}
    <div class="success">{{ success }}</div>
    {% endif %}
    
    <form method="POST">
      <div class="form-group">
        <label for="name">Full Name</label>
        <input type="text" id="name" name="name" required placeholder="Enter full name">
      </div>
      <div class="form-group">
        <label for="user_id">User ID</label>
        <input type="text" id="user_id" name="user_id" required placeholder="Enter user ID">
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required placeholder="Enter password">
      </div>
      <div class="form-group">
        <label for="role">Role</label>
        <select id="role" name="role">
          <option value="user">User</option>
          <option value="admin">Administrator</option>
        </select>
      </div>
      <div class="form-group">
        <label for="expiry">Expiry Date (optional)</label>
        <input type="date" id="expiry" name="expiry">
      </div>
      <button type="submit" class="btn">Create Account</button>
    </form>
    
    <div class="links">
      <p><a href="/manage-users" class="btn-secondary">👥 Manage Users</a> | <a href="/menu">🏠 Menu</a></p>
    </div>
  </div>
</div>
</body>
</html>
"""

# Remove User Template
REMOVE_USER_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Remove User - CFA Level 1 Quiz</title>
<style>
:root{--bg:#f0f4f8;--card:#fff;--muted:#64748b;--accent:#0b69ff;--success:#10b981;--danger:#ef4444;--warning:#f59e0b}
body{margin:0;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:var(--bg);color:#0f1724}
.container{max-width:1100px;margin:28px auto;padding:0 18px}
.login-container{max-width:600px;margin:50px auto;padding:30px;background:#fff;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,0.1);text-align:center;animation: fadeIn 0.5s ease}
.form-group{margin-bottom:24px;text-align:left}
.form-group label{display:block;margin-bottom:8px;font-weight:600;color:#334155;font-size:15px}
.form-group input{width:100%;padding:14px;border:2px solid #e2e8f0;border-radius:10px;font-size:16px;transition:all 0.3s}
.form-group input:focus{border-color:var(--accent);outline:none;box-shadow:0 0 0 3px rgba(11,105,255,0.1)}
.btn{padding:14px 24px;background:var(--danger);color:#fff;border:none;border-radius:10px;font-weight:600;cursor:pointer;font-size:16px;transition:all 0.3s;margin-right:10px;box-shadow:0 4px 12px rgba(239,68,68,0.2)}
.btn:hover{background:#dc2626;transform:translateY(-3px);box-shadow:0 8px 20px rgba(239,68,68,0.3)}
.btn-secondary{background:var(--accent);color:#fff;text-decoration:none;display:inline-block;padding:14px 24px;transition:all 0.3s}
.btn-secondary:hover{background:#0952cc;transform:translateY(-3px);box-shadow:0 8px 20px rgba(11,105,255,0.3)}
.error{color:var(--danger);background:rgba(239,68,68,0.08);padding:16px;border-radius:10px;margin-bottom:24px;border:1px solid rgba(239,68,68,0.2)}
.success{color:var(--success);background:rgba(16,185,129,0.08);padding:16px;border-radius:10px;margin-bottom:24px;border:1px solid rgba(16,185,129,0.2)}
.links{margin-top:24px;font-size:15px}
.links a{color:var(--accent);text-decoration:none;font-weight:600}
.links a:hover{text-decoration:underline}
.user-list{margin-top:30px;text-align:left}
.user-item{display:flex;justify-content:space-between;align-items:center;padding:20px;border:1px solid #e2e8f0;border-radius:12px;margin-bottom:15px;background:#f8fafc;transition:all 0.3s;animation: fadeIn 0.3s ease}
.user-item:hover{box-shadow:0 4px 12px rgba(0,0,0,0.05);transform:translateY(-2px)}
.user-info h3{margin:0;font-size:18px;color:#0f1724}
.user-info p{margin:8px 0 0 0;color:var(--muted);font-size:14px}
.admin-badge{background:#8b5cf6;color:white;padding:4px 10px;border-radius:20px;font-size:12px;margin-left:10px;font-weight:600}
.header-icon{font-size:48px;margin-bottom:20px}
@keyframes fadeIn {
  from {opacity: 0; transform: translateY(20px);}
  to {opacity: 1; transform: translateY(0);}
}
@keyframes shake {
  0%, 100% {transform: translateX(0);}
  25% {transform: translateX(-5px);}
  75% {transform: translateX(5px);}
}
</style>
</head>
<body>
<div class="container">
  <div class="login-container">
    <div class="header-icon">🗑</div>
    <h1>Remove User</h1>
    <p>Remove a user from the CFA Level 1 Quiz Platform</p>
    
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
    
    {% if success %}
    <div class="success">{{ success }}</div>
    {% endif %}
    
    <form method="POST">
      <div class="form-group">
        <label for="user_id">User ID to Remove</label>
        <input type="text" id="user_id" name="user_id" required placeholder="Enter User ID to remove">
      </div>
      <button type="submit" class="btn">Remove User</button>
      <a href="/manage-users" class="btn btn-secondary">👥 Manage Users</a>
    </form>
    
    <div class="user-list">
      <h2>Current Users</h2>
      {% for user in users %}
      <div class="user-item">
        <div class="user-info">
          <h3>{{ user.name }} ({{ user.id }})
            {% if user.role == 'admin' %}
            <span class="admin-badge">ADMIN</span>
            {% endif %}
          </h3>
          <p>Role: {{ user.role | capitalize }}
          {% if user.expiry %}
          | Expires: {{ user.expiry }}
          {% else %}
          | No expiry date
          {% endif %}
          </p>
        </div>
      </div>
      {% endfor %}
    </div>
    
    <div class="links">
      <p><a href="/menu">🏠 Menu</a></p>
    </div>
  </div>
</div>
</body>
</html>
"""

# Manage Users Template
MANAGE_USERS_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Manage Users - CFA Level 1 Quiz</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--card-border:#2d3748;--muted:#94a3b8;--accent:#a78bfa;--accent-dark:#8b5cf6;--accent-light:#c4b5fd;--success:#34d399;--danger:#f87171;--warning:#fbbf24;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37;--jewel-emerald:#10b981;--jewel-sapphire:#0ea5e9;--jewel-amethyst:#a78bfa;--jewel-ruby:#f43f5e;--glass-bg:rgba(255,255,255,0.05);--glass-border:rgba(255,255,255,0.1)}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, var(--bg) 0%, #1e293b 100%);color:var(--text-primary);min-height:100vh}
.container{max-width:1100px;margin:28px auto;padding:0 18px}
.content-card{background:var(--card);border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.4);padding:40px;border:1px solid rgba(167,139,250,0.2);animation:slideDown 0.5s ease-out}
.header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:40px;flex-wrap:wrap;gap:20px}
.header-left{display:flex;align-items:flex-start;gap:20px}
.header-icon{font-size:56px}
.header-content h1{font-size:36px;margin:0 0 8px 0;background:linear-gradient(135deg, #a78bfa 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-0.5px;font-weight:800}
.header-content p{color:var(--text-secondary);font-size:16px;margin:0;line-height:1.6}
.page-description{color:var(--text-muted);font-size:15px;margin:8px 0 0 0}
.action-buttons{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:30px}
.btn{padding:12px 20px;background:linear-gradient(135deg, var(--accent-dark) 0%, var(--accent) 100%);color:#fff;border:none;border-radius:10px;font-weight:600;cursor:pointer;font-size:15px;transition:all 0.3s ease;text-decoration:none;display:inline-flex;align-items:center;gap:8px;box-shadow:0 4px 15px rgba(139,92,246,0.3)}
.btn:hover{background:linear-gradient(135deg, var(--accent) 0%, var(--accent-light) 100%);transform:translateY(-3px);box-shadow:0 8px 24px rgba(167,139,250,0.4)}
.btn-danger{background:linear-gradient(135deg, #f43f5e 0%, #f87171 100%);box-shadow:0 4px 15px rgba(244,63,94,0.3)}
.btn-danger:hover{background:linear-gradient(135deg, #f87171 0%, #fb7185 100%);box-shadow:0 8px 24px rgba(244,63,94,0.4)}
.btn-secondary{background:var(--glass-bg);color:var(--text-secondary);border:1px solid var(--glass-border);text-decoration:none;box-shadow:none}
.btn-secondary:hover{background:rgba(167,139,250,0.15);border-color:var(--accent);color:var(--accent-light)}
.user-list{margin-top:30px}
.list-header{display:flex;align-items:center;margin-bottom:20px}
.list-header h2{font-size:22px;margin:0;color:var(--text-primary);background:linear-gradient(135deg, var(--accent-light) 0%, var(--gold) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;font-weight:700}
.list-header .count{background:var(--glass-bg);border:1px solid var(--glass-border);color:var(--accent-light);padding:6px 14px;border-radius:20px;font-size:14px;font-weight:600;margin-left:12px}
.user-item{display:flex;justify-content:space-between;align-items:center;padding:22px;background:var(--card);border:1px solid var(--card-border);border-radius:12px;margin-bottom:12px;transition:all 0.3s ease;position:relative;overflow:hidden}
.user-item::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg, transparent, var(--gold), transparent);opacity:0;transition:opacity 0.3s ease}
.user-item:hover{transform:translateY(-4px);border-color:var(--accent);box-shadow:0 12px 32px rgba(167,139,250,0.2)}
.user-item:hover::before{opacity:1}
.user-info{flex:1}
.user-info h3{margin:0 0 8px 0;font-size:18px;color:var(--text-primary);font-weight:700;display:flex;align-items:center;gap:10px}
.user-info p{margin:8px 0 0 0;color:var(--text-secondary);font-size:14px;line-height:1.6}
.user-status{display:flex;gap:12px;align-items:center;margin-top:10px;flex-wrap:wrap}
.status-badge{padding:6px 12px;border-radius:8px;font-size:13px;font-weight:600;transition:all 0.3s ease}
.valid{background:rgba(52,211,153,0.2);color:var(--success);border:1px solid rgba(52,211,153,0.4)}
.expired{background:rgba(244,63,94,0.2);color:var(--danger);border:1px solid rgba(244,63,94,0.4)}
.admin-badge{background:linear-gradient(135deg, #8b5cf6 0%, #a78bfa 100%);color:#fff;padding:6px 12px;border-radius:8px;font-size:12px;font-weight:700;letter-spacing:0.5px}
.role-badge{background:var(--glass-bg);color:var(--text-secondary);padding:6px 12px;border-radius:8px;border:1px solid var(--glass-border);font-size:13px;font-weight:600}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.links{margin-top:32px;padding-top:24px;border-top:1px solid var(--card-border);text-align:center}
.links a{color:var(--accent);text-decoration:none;font-weight:600;display:inline-flex;align-items:center;gap:8px;padding:10px 16px;background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:8px;transition:all 0.3s ease}
.links a:hover{background:rgba(167,139,250,0.15);border-color:var(--accent);color:var(--accent-light);transform:translateY(-2px)}
.empty-state{text-align:center;padding:40px 20px;color:var(--text-muted)}
.empty-state p{font-size:16px;margin:0 0 20px 0}
@keyframes slideDown{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:translateY(0)}}
@keyframes fadeIn{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
@media(max-width:768px){.header{flex-direction:column}.header-content h1{font-size:28px}.content-card{padding:24px}.user-item{flex-direction:column;align-items:flex-start}.user-info h3{width:100%}.actions{width:100%;justify-content:flex-start}}
</style>
</head>
<body>
<div class="container">
  <div class="content-card">
    <div class="header">
      <div class="header-left">
        <div class="header-icon">👥</div>
        <div class="header-content">
          <h1>Manage Users</h1>
          <p class="page-description">Manage user accounts for the CFA Level 1 Quiz Platform</p>
        </div>
      </div>
      <a href="/menu" class="btn btn-secondary">🏠 Back to Menu</a>
    </div>
    
    <div class="action-buttons">
      <a href="/add-user" class="btn">➕ Add New User</a>
      <a href="/remove-user" class="btn btn-danger">🗑 Remove User</a>
    </div>
    
    <div class="user-list">
      <div class="list-header">
        <h2>User List</h2>
        <div class="count">{{ users|length }} user{% if users|length != 1 %}s{% endif %}</div>
      </div>
      
      {% if users %}
      {% for user in users %}
      <div class="user-item">
        <div class="user-info">
          <h3>
            {{ user.name }}
            {% if user.role == 'admin' %}
            <span class="admin-badge">ADMIN</span>
            {% else %}
            <span class="role-badge">{{ user.role | capitalize }}</span>
            {% endif %}
          </h3>
          <p><strong>ID:</strong> {{ user.id }}</p>
          <div class="user-status">
            {% if user.expiry %}
            <span><strong>Expires:</strong> {{ user.expiry }}</span>
            <span class="status-badge {% if user.is_valid %}valid{% else %}expired{% endif %}">
              {% if user.is_valid %}✓ Valid{% else %}✗ Expired{% endif %}
            </span>
            {% else %}
            <span><strong>Status:</strong> No expiry date</span>
            <span class="status-badge valid">✓ Valid</span>
            {% endif %}
          </div>
        </div>
        <div class="actions">
          <a href="/edit-user/{{ user.id }}" class="btn" style="padding:10px 16px;font-size:14px;gap:6px;background:linear-gradient(135deg, #0ea5e9 0%, #06b6d4 100%);box-shadow:0 4px 12px rgba(6,182,212,0.3);">✏️ Edit</a>
        </div>
      </div>
      {% endfor %}
      {% else %}
      <div class="empty-state">
        <p>No users found in the system.</p>
        <a href="/add-user" class="btn">➕ Add First User</a>
      </div>
      {% endif %}
    </div>
    
    <div class="links">
      <a href="/menu">🏠 Back to Menu</a>
    </div>
  </div>
</div>
</body>
</html>
"""

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Allow users to edit their own profile"""
    user_id = session.get('user_id')
    
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        exam_date = request.form.get('exam_date')
        
        # Validate required fields
        if not name:
            user = get_user_by_id(user_id)
            return render_template_string(USER_PROFILE_TEMPLATE, user=user, error="Full name is required"), 400
        
        # Call edit_user function (admin can edit all, regular users only their own)
        success, message = edit_user(user_id, name=name, password=password, exam_date=exam_date)
        
        if success:
            # Update session with new name
            session['user_name'] = name
            session.modified = True
            user = get_user_by_id(user_id)
            return render_template_string(USER_PROFILE_TEMPLATE, user=user, success="Profile updated successfully!"), 200
        else:
            user = get_user_by_id(user_id)
            return render_template_string(USER_PROFILE_TEMPLATE, user=user, error=message), 400
    
    # GET request - show profile form
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for('logout'))
    
    return render_template_string(USER_PROFILE_TEMPLATE, user=user)

# User Profile Template (Self-service profile editing for regular users)
USER_PROFILE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>My Profile - CFA Level 1 Quiz</title>
<style>
:root{--bg:#0f1419;--card:#1a202c;--card-border:#2d3748;--muted:#94a3b8;--accent:#a78bfa;--accent-dark:#8b5cf6;--accent-light:#c4b5fd;--success:#34d399;--danger:#f87171;--text-primary:#f1f5f9;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, #0f1419 0%, #1e293b 100%);color:var(--text-primary);min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{max-width:1100px;margin:28px auto;padding:0 18px;width:100%}
.profile-card{background:var(--card);border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.4);padding:40px;border:1px solid rgba(167,139,250,0.2);animation:slideDown 0.5s ease-out;max-width:600px;margin:0 auto}
.header{display:flex;align-items:center;gap:16px;margin-bottom:32px}
.header-icon{font-size:48px}
.header-content h1{font-size:32px;margin:0 0 8px 0;background:linear-gradient(135deg, #a78bfa 0%, #d4af37 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-0.5px;font-weight:800}
.header-content p{color:var(--text-secondary);font-size:15px;margin:0}
.info-section{background:rgba(167,139,250,0.08);border-radius:12px;padding:20px;margin-bottom:24px;border-left:4px solid var(--accent)}
.info-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.info-row:last-child{margin-bottom:0}
.info-label{color:var(--text-secondary);font-weight:600;font-size:14px}
.info-value{color:var(--text-primary);font-weight:700;font-size:15px}
.form-group{margin-bottom:24px;text-align:left}
.form-group label{display:block;margin-bottom:8px;font-weight:600;color:var(--text-secondary);font-size:15px}
.form-group input{width:100%;padding:12px 14px;border:1px solid rgba(167,139,250,0.3);border-radius:8px;font-size:15px;transition:all 0.3s;background:rgba(255,255,255,0.05);color:var(--text-primary)}
.form-group input::placeholder{color:var(--text-muted);opacity:0.7}
.form-group input:focus{border-color:var(--accent);outline:none;box-shadow:0 0 0 3px rgba(167,139,250,0.2);background:rgba(255,255,255,0.08)}
.form-group input:read-only{background:rgba(0,0,0,0.3);opacity:0.7;cursor:not-allowed}
.form-actions{display:flex;gap:12px;margin-top:32px;flex-wrap:wrap}
.btn{padding:12px 24px;background:linear-gradient(135deg, var(--accent-dark) 0%, var(--accent) 100%);color:#fff;border:none;border-radius:10px;font-weight:600;cursor:pointer;font-size:15px;transition:all 0.3s ease;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:8px;box-shadow:0 4px 15px rgba(139,92,246,0.3);flex:1}
.btn:hover{background:linear-gradient(135deg, var(--accent) 0%, var(--accent-light) 100%);transform:translateY(-3px);box-shadow:0 8px 24px rgba(167,139,250,0.4)}
.btn-secondary{background:var(--accent-dark);opacity:0.6;flex:1}
.btn-secondary:hover{opacity:1;transform:translateY(-3px)}
.error{color:var(--danger);background:rgba(244,63,94,0.15);padding:16px;border-radius:10px;margin-bottom:24px;border:1px solid rgba(244,63,94,0.3);animation:shake 0.5s ease}
.success{color:var(--success);background:rgba(52,211,153,0.15);padding:16px;border-radius:10px;margin-bottom:24px;border:1px solid rgba(52,211,153,0.3);animation:slideDown 0.5s ease}
.field-help{color:var(--text-muted);font-size:13px;margin-top:6px}
@keyframes slideDown{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:translateY(0)}}
@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-5px)}75%{transform:translateX(5px)}}
@media(max-width:600px){.profile-card{padding:24px}.header{flex-direction:column;text-align:center}.header-icon{font-size:40px}.header-content h1{font-size:24px}.form-actions{flex-direction:column}.btn{width:100%}.info-row{flex-direction:column;align-items:flex-start;gap:8px}}
</style>
</head>
<body>
<div class="container">
  <div class="profile-card">
    <div class="header">
      <div class="header-icon">👤</div>
      <div class="header-content">
        <h1>My Profile</h1>
        <p>Update your account information</p>
      </div>
    </div>
    
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
    
    {% if success %}
    <div class="success">{{ success }}</div>
    {% endif %}
    
    <div class="info-section">
      <div class="info-row">
        <span class="info-label">User ID:</span>
        <span class="info-value">{{ user.id }}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Role:</span>
        <span class="info-value">
          {% if user.role == 'admin' %}
          👑 Administrator
          {% else %}
          📚 User
          {% endif %}
        </span>
      </div>
      {% if user.expiry %}
      <div class="info-row">
        <span class="info-label">Account Expires:</span>
        <span class="info-value">{{ user.expiry }}</span>
      </div>
      {% else %}
      <div class="info-row">
        <span class="info-label">Account Status:</span>
        <span class="info-value">🔄 No expiry date</span>
      </div>
      {% endif %}
    </div>
    
    <form method="POST">
      <div class="form-group">
        <label for="name">Full Name</label>
        <input type="text" id="name" name="name" value="{{ user.name }}" required placeholder="Enter your full name">
      </div>
      
      <div class="form-group">
        <label for="password">Password (Leave empty to keep current)</label>
        <input type="password" id="password" name="password" placeholder="Enter new password (optional)">
        <div class="field-help">Only enter a new password if you want to change it.</div>
      </div>
      
      <div class="form-group">
        <label for="exam_date">Target Exam Date</label>
        <input type="date" id="exam_date" name="exam_date" value="{{ user.exam_date if user.exam_date else '' }}">
        <div class="field-help">Setting this date will update the countdown on your dashboard.</div>
      </div>
      
      <div class="form-actions">
        <button type="submit" class="btn">💾 Save Changes</button>
        <a href="/menu" class="btn btn-secondary">❌ Cancel</a>
      </div>
    </form>
  </div>
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
        quiz_title=filename
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