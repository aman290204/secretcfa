import os

file_path = r'c:\Users\aman2\Downloads\secretcfa\secretcfa-main\app.py'

with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find the start and end of MENU_TEMPLATE
start_idx = -1
end_idx = -1

for i, line in enumerate(lines):
    if line.strip().startswith('MENU_TEMPLATE = """'):
        start_idx = i
    if start_idx != -1 and line.strip() == '"""' and i > start_idx + 10: # Rough heuristic for the end of the template
        # Check if next line starts with RESULTS_TEMPLATE or another template or a route
        if i + 1 < len(lines) and (lines[i+1].strip().startswith('@app.route') or lines[i+1].strip().startswith('USER_PROFILE_TEMPLATE')):
             end_idx = i
             break

if start_idx == -1 or end_idx == -1:
    print(f"Error: Could not find MENU_TEMPLATE bounds (Start: {start_idx}, End: {end_idx})")
    # Narrower search if the above failed
    for i, line in enumerate(lines):
        if 'MENU_TEMPLATE = """' in line: start_idx = i
        if start_idx != -1 and line.strip() == '"""' and i > start_idx:
             # Look for the last """ before edit_profile or similar
             end_idx = i
    
    if start_idx == -1 or end_idx == -1:
        exit(1)

print(f"Found MENU_TEMPLATE from line {start_idx+1} to {end_idx+1}")

clean_template = r'''MENU_TEMPLATE = """
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
    <a href="/menu#moduleGrid" class="sidebar-item">
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
        <a href="#moduleGrid" class="task-btn">Start Practice →</a>
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
'''

with open(file_path, 'w', encoding='utf-8', newline='\r\n') as f:
    # We replace everything between start_idx and end_idx
    # But it's easier to just reconstruct the file.
    new_lines = lines[:start_idx]
    new_lines.append(clean_template)
    new_lines.extend(lines[end_idx+1:])
    f.writelines(new_lines)

print("✅ MENU_TEMPLATE fully cleaned and restructured")
