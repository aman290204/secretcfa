# Quick Guide: User Management & Admin Access

## 🔑 Default Admin Accounts

Login with these credentials to access admin features:
- **Username**: `aman2902` | **Password**: `aman2902`
- **Username**: `nitish2005` | **Password**: `nitish2005`

## 🎯 Accessing Admin Panel

1. **Login**: Go to `http://localhost:5000/login` (or your Render URL)
2. **Navigate to Admin**: After login, go to `http://localhost:5000/manage-users`

**Direct Admin Routes:**
- `/manage-users` - User management dashboard
- `/add-user` - Create new users
- `/edit-user/<user_id>` - Edit specific user
- `/remove-user` - Delete users
- `/profile` - Your profile settings

## ➕ Creating New Users

### Method 1: Web Interface (Easiest)

1. Login as admin (`aman2902`)
2. Go to: `/manage-users`
3. Click "➕ Add New User"
4. Fill the form:
   ```
   Full Name: John Doe
   User ID: johndoe
   Password: securepass123
   Role: User (or Administrator)
   Expiry Date: (optional - leave blank for no expiry)
   ```
5. Click "Create Account"

### Method 2: Edit JSON File

Edit `config/users.json`:

```json
{
    "users": [
        {
            "id": "newuser",
            "password": "password123",
            "name": "New User Name",
            "role": "user",
            "expiry": ""
        }
    ]
}
```

**Note**: Changes to JSON file require app restart.

## 🗑️ Deleting Users

1. Go to `/manage-users`
2. Click "Edit" next to any user
3. Or go to `/remove-user` to select and delete

## 🚀 Upstash Redis Setup

### Getting Your Redis URL

Your Upstash console should show TWO types of URLs:

**1. Redis URL (what we need):**
```
rediss://default:YOURPASSWORD@helping-foal-5132.upstash.io:6379
```

**2. REST URL (what you provided):**
```
https://helping-foal-5132.upstash.io
```

### Where to Find Redis URL

1. Go to https://console.upstash.com/
2. Click your database ("helping-foal-5132")
3. Look for section "Connect your database"
4. Copy the **Redis** connection string (not REST)

### Setting Environment Variable

**On Render:**
```
REDIS_URL=rediss://default:YOURPASSWORD@helping-foal-5132.upstash.io:6379
```

**Locally (Windows PowerShell):**
```powershell
$env:REDIS_URL="rediss://default:YOURPASSWORD@helping-foal-5132.upstash.io:6379"
```

## ✅ Testing

After setting `REDIS_URL`:

1. **Start app**: `python app.py`
2. **Check logs**: Should see `✅ Redis connected successfully`
3. **Login**: Use `aman2902` / `aman2902`
4. **Test single-session**: Login from another browser → first session should be logged out

## 🔒 Security Notes

- Admin users can: create/edit/delete users, access all features
- Regular users can: access quizzes, view their profile
- Change default passwords in production
- Keep `SECRET_KEY` environment variable secure
