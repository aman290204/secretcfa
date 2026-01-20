# CFA Level 1 Practice Platform

A comprehensive web-based learning platform for CFA Level 1 exam preparation with quiz practice, mock exams, and detailed performance analytics.

## Features

### 📚 Study Modules
- 93 topic-specific practice modules covering all CFA Level 1 curriculum areas
- Per-question feedback and explanations
- Progress tracking per topic

### 📝 Mock Exams
- Full-length mock exams (90 questions, 2h 15m timed)
- CFA-style format with A/B/C options
- Server-side timer persistence (survives page refresh)

### 📊 Performance Analytics
- **Strengths & Weaknesses Dashboard** - Visual topic-wise performance bars
- **My Scores** - Complete attempt history with scores and time spent
- **Review Attempt** - Question-by-question breakdown with explanations

### ⏱️ Accurate Time Tracking
- Server-side timestamp capture (not affected by tab inactivity)
- Per-question time tracking
- Total session time calculation

### 🔒 User Authentication
- Secure login with session management
- Admin panel for user management
- Redis-backed session persistence

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Flask (Python) |
| Database | Redis |
| Frontend | Vanilla JS + CSS |
| Hosting | Render.com |

---

## Installation

### Prerequisites
- Python 3.9+
- Redis (local or cloud instance)

### Setup

```bash
# Clone the repository
git clone <repo-url>
cd secretcfa-main

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export REDIS_URL="redis://localhost:6379"
export SECRET_KEY="your-secret-key"

# Run the app
python app.py
```

---

## Project Structure

```
secretcfa-main/
├── app.py              # Main Flask application with all routes and templates
├── database.py         # Redis database operations
├── data/               # Quiz JSON files
│   ├── Module *.json   # Practice modules
│   └── *Mock*.json     # Mock exams
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

---

## Key Routes

| Route | Description |
|-------|-------------|
| `/` | Login page |
| `/menu` | Dashboard home |
| `/practice` | Practice modules by topic |
| `/mocks` | Mock exams list |
| `/my-scores` | Attempt history |
| `/review-attempt/<id>` | Detailed review of an attempt |
| `/<quiz_name>` | Take a quiz |

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/save-attempt` | POST | Save quiz attempt with full snapshot |
| `/api/clear-my-attempts` | POST | Clear all attempts for current user |
| `/api/mock/timer-status` | GET | Get/init mock exam timer |

---

## Data Storage

### Quiz Attempt Schema (Redis)
```json
{
  "quiz_id": "Module 1 Rates and Returns",
  "quiz_name": "Module 1 Rates and Returns",
  "mode": "practice",
  "started_at": "2026-01-20T15:30:00.000Z",
  "submitted_at": "2026-01-20T15:35:00.000Z",
  "time_spent_seconds": 300,
  "score_percent": 80,
  "correct_count": 8,
  "total_questions": 10,
  "responses": [
    {
      "question_number": 1,
      "question_text": "...",
      "choices": [{"label": "A", "text": "...", "explanation": "..."}],
      "correct_answer_label": "B",
      "user_answer_label": "A",
      "is_correct": false,
      "time_spent_seconds": 45
    }
  ]
}
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `REDIS_URL` | Redis connection URL |
| `SECRET_KEY` | Flask secret key |
| `RENDER` | Set to "true" in production |

---

## Development

```bash
# Run in development mode
python app.py

# Syntax check
python -m py_compile app.py

# Clear test data (in browser console)
fetch('/api/clear-my-attempts', {method:'POST'}).then(r=>r.json()).then(console.log)
```

---

## License

Private - All rights reserved.
