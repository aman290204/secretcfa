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
:root{--bg:#121212;--card:#0A2540;--card-border:#1a3a5c;--muted:#94a3b8;--accent:#0052A5;--accent-dark:#003d7a;--accent-light:#4d8fd6;--success:#2E7D32;--danger:#C62828;--warning:#fbbf24;--text-primary:#FAFAFA;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--gold:#d4af37;--jewel-emerald:#2E7D32;--jewel-sapphire:#0052A5;--jewel-amethyst:#6c5ce7;--jewel-ruby:#C62828;--glass-bg:rgba(255,255,255,0.05);--glass-border:rgba(255,255,255,0.1);--sidebar-width:210px}
body{margin:0;font-family:'Inter','Segoe UI',Arial,Helvetica,sans-serif;background:linear-gradient(135deg, var(--bg) 0%, #0A2540 100%);color:var(--text-primary);min-height:100vh;display:flex}
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
          <button type="button" class="btn" id="skip">Skip</button>
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
  const timeSpent = Math.floor((Date.now() - timerStart) / 1000);
  
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
.progress-bar-outer{background:rgba(255,255,255,0.05);height:24px;border-radius:12px;overflow:hidden;border:1px solid var(--card-border)}
.progress-bar-fill{height:100%;background:rgba(255,255,255,0.1);width:0%;transition:width 0.5s ease}
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
    <a href="/menu#mockGrid" class="sidebar-item">
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
        <td class="subtopic-item"><a href="/{{ sub.name }}" class="subtopic-link">{{ sub.name }}</a></td>
        <td class="text-right">{{ sub.complete }} of {{ sub.total }}</td>
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
@media(max-width:768px){
  .main-content{margin-left:0 !important}
  .sidebar{transform:translateX(-100%)}
  .score-circles{flex-direction:column;gap:30px}
  .action-grid{grid-template-columns:1fr}
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
    <a href="/menu#mockGrid" class="sidebar-item">
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

      <!-- Knowledge Goal -->
      <div class="progress-card">
        <div class="progress-label">
          <span>Today's Knowledge Goal</span>
          <span style="color: var(--text-primary)">{{ stats.today_attempts|default(0) }}/390 🎯</span>
        </div>
        <div class="progress-bar-outer">
          <div class="progress-bar-fill orange" style="width: {{ [stats.today_attempts|default(0) * 0.25, 100]|min }}%"></div>
        </div>
      </div>

      <!-- Study Progress -->
      <div class="progress-card">
        <div class="progress-label">
          <span>Study Plan Progress</span>
          <span style="color: var(--text-primary)">{{ ((stats.unique_completed|default(0)) / total_files * 100)|int if total_files > 0 else 0 }}%</span>
        </div>
        <div class="progress-bar-outer">
          <div class="progress-bar-fill orange" style="width: {{ ((stats.unique_completed|default(0)) / total_files * 100)|int if total_files > 0 else 0 }}%"></div>
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
        <a href="#mockGrid" class="task-btn purple">Start Mock →</a>
      </div>
    </div>
  </div>

  <div class="search-box">
    <input type="text" id="searchInput" onkeyup="filterModules()" placeholder="Search modules or exams..." />
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
  {% endif %}

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

@app.route('/practice')
@login_required
def practice_dashboard():
    user_id = session.get('user_id')
    stats = db.get_user_quiz_stats(user_id)
    attempts = db.get_user_quiz_attempts(user_id, limit=1000)
    
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
        topic_total_q = sum(m['questions'] for m in topic_modules)
        topic_complete_q = 0
        topic_scores = []
        
        subtopics = []
        for m in topic_modules:
            # Find latest attempt for this module
            attempt = next((a for a in attempts if (a.get('quiz_name') == m['name'] or a.get('quiz_id') == m['name'])), None)
            m_comp = m['questions'] if attempt else 0
            m_score = attempt.get('score_percent', '--') if attempt else '--'
            topic_complete_q += m_comp
            if m_score != '--': topic_scores.append(m_score)
            
            subtopics.append({
                'name': m['name'],
                'total': m['questions'],
                'complete': m_comp,
                'percent_correct': m_score
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
    avg_correct = stats.get('avg_module_score', 0)
    questions_taken = total_c_all
    total_questions = total_q_all
    completion_percent = round((questions_taken / total_questions * 100), 1) if total_questions > 0 else 0
    
    return render_template_string(
        PRACTICE_TEMPLATE,
        completion_percent=completion_percent,
        avg_correct=int(avg_correct),
        questions_taken=questions_taken,
        total_questions=total_questions,
        avg_answer_time="--",
        avg_correct_time="--",
        avg_incorrect_time="--",
        avg_session_duration="--",
        topics=topics_data
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