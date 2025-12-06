# CFA Level 1 Quiz Application - JWT Authentication Setup

This application now uses JWT (JSON Web Tokens) with Redis for single-session authentication.

## 🔐 Single-Session Authentication

When a user logs in on Device B, they will be automatically logged out from Device A. Only one active session per user is allowed.

## 🚀 Local Development Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Install and Run Redis Locally

**Windows (using Memurai - Redis-compatible)**:
```bash
# Download from: https://www.memurai.com/
# Or use Windows Subsystem for Linux (WSL) with Redis
```

**macOS**:
```bash
brew install redis
redis-server
```

**Linux**:
```bash
sudo apt-get install redis-server
sudo systemctl start redis
```

**Docker (all platforms)**:
```bash
docker run -d -p 6379:6379 redis:latest
```

### 3. Set Environment Variables (Optional for Local)

By default, the app connects to `redis://localhost:6379`. To use a different Redis instance:

```bash
# Windows (PowerShell)
$env:REDIS_URL="redis://localhost:6379"

# macOS/Linux
export REDIS_URL="redis://localhost:6379"
```

### 4. Run the Application

```bash
python app.py
```

The app will start on `http://localhost:5000` and show Redis connection status.

## ☁️ Deployment on Render

### 1. Add Redis Service on Render

1. Go to your Render dashboard
2. Click "New +" → "Redis"
3. Choose a name (e.g., `cfa-quiz-redis`)
4. Select the Free plan or Starter plan ($7/month)
5. Click "Create Redis"
6. Copy the **Internal Redis URL** (looks like `redis://red-xxxxx:6379`)

### 2. Configure Your Web Service

1. Go to your Web Service on Render
2. Click "Environment" tab
3. Add a new environment variable:
   - **Key**: `REDIS_URL`
   - **Value**: (paste the Internal Redis URL from step 1)
4. Add another environment variable for JWT secret:
   - **Key**: `SECRET_KEY`
   - **Value**: (generate a random secret, e.g., use `openssl rand -hex 32`)

### 3. Deploy

1. Push your code to GitHub
2. Render will automatically deploy
3. Check the logs to verify Redis connection:
   ```
   ✅ Redis connected successfully
   ```

## 🔑 How It Works

### Login Flow

1. User enters credentials on `/login`
2. System validates credentials against `config/users.json`
3. **All existing sessions for that user are invalidated** (logs out other devices)
4. New session token is generated
5. Session is stored in Redis with 10-day expiration
6. JWT token is created and stored in Flask session
7. User is redirected to `/menu`

### Protected Routes

Every protected route checks:
1. Flask session has `user_id`
2. Flask session has valid `jwt_token`
3. JWT is not expired
4. Session token from JWT exists in Redis

If any check fails → redirect to login

### Logout Flow

1. Extract session token from JWT
2. Delete session from Redis
3. Clear Flask session
4. Redirect to login

## 📝 Testing Single-Session

1. **Login on Chrome**: Go to `http://localhost:5000/login`, log in as `aman2902`
2. **Login on Firefox**: Open another browser, go to same URL, log in with same credentials
3. **Back to Chrome**: Try to click on any module or navigate
4. **Expected Result**: Chrome should redirect to login with session invalid message

## 🔧 Troubleshooting

### Redis Connection Failed

If you see:
```
⚠️  WARNING: Redis not connected!
```

**Fixes**:
1. Make sure Redis is running: `redis-cli ping` (should return "PONG")
2. Check `REDIS_URL` environment variable
3. For Render: Verify the Redis service is created and URL is correct

### Session Not Invalidating

1. Check Redis is running and connected
2. View logs for: `🔐 Logging in user 'xxx' - invalidated all previous sessions`
3. Verify DeVice A sees the logout by checking for 401/redirect

## 📚 Files Modified

- `database.py` - New file for Redis session management
- `app.py` - Added JWT authentication logic
- `requirements.txt` - Added PyJWT and redis dependencies

## 🎯 Default Users

From `config/users.json`:
- **Admin**: `nitish2005` / `nitish2005`
- **Admin**: `aman2902` / `aman2902`
- **User**: `aaryan` / `aaryan`

## 📞 Support

If you encounter issues, check:
1. Redis connection status in app startup logs
2. Browser console for any JavaScript errors
3. Flask logs for authentication errors
