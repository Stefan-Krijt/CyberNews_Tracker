# 🔐 CyberNews Tracker

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1+-green.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A comprehensive cybersecurity intelligence platform built with Flask. Features real-time news aggregation, CVE vulnerability tracking, role-based access control, and secure authentication.

## 📸 Screenshots

| Dashboard | Admin Panel | CVE Database |
|-----------|-------------|--------------|
| *Add screenshot here* | *Add screenshot here* | *Add screenshot here* |

## ✨ Features

### 🔐 Authentication & Security
- Session-based authentication with HttpOnly cookies
- Password hashing using Werkzeug
- Role-based access control (Admin / User)
- Bearer token protection for intelligence API
- Audit logging for authentication attempts
- Server-side session storage

### 📰 Cybersecurity News
- Live news feed from NewsAPI
- Static fallback when API unavailable
- 3-column responsive grid layout
- Manual refresh button

### 🗄️ CVE Vulnerability Tracker
- SQLite database with recent vulnerabilities
- Severity badges (Critical, High, Medium, Low)
- CVSS scores (0-10)
- Direct links to NVD entries
- Statistics dashboard

### 🎖️ Intelligence Feed
- Bearer token protected API
- Role-based data access: Full technical details for admins, Summary reports for analysts, Public briefs for readonly users

### 👥 User Management
- User registration with validation
- Profile page (update email, change password)
- Admin panel for user management
- Role and token assignment

## 🛠️ Tech Stack

| Category | Technology |
|----------|------------|
| Backend | Flask (Python) |
| Frontend | HTML5, CSS3, JavaScript |
| Templating | Jinja2 |
| Database | SQLite, JSON |
| Authentication | Session cookies + Bearer tokens |
| APIs | NewsAPI, NVD |

## 📦 Installation

```bash
git clone https://github.com/yourusername/cybernews-tracker.git
cd cybernews-tracker
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo "NEWS_API_KEY=your_key_here" > .env
python web_app.py
```

## 🚀 Usage

1. Open `http://localhost:5000`
2. Register a new account
3. Login and explore: Dashboard (live news), Vulnerabilities (CVE database), Intelligence (Bearer token feed), Profile (account management)

## 📁 Project Structure

```
cybernews-tracker/
├── web_app.py
├── requirements.txt
├── .env
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── user_dashboard.html
│   ├── admin_dashboard.html
│   ├── vulnerabilities.html
│   ├── intelligence.html
│   ├── profile.html
│   ├── admin_users.html
│   ├── contact_form.html
│   └── confirmation.html
├── static/
│   └── style.css
└── data/
    ├── users.json
    ├── audit.log
    └── cves.db
```

## 🔒 Security Features

| Feature | Implementation |
|---------|----------------|
| Password Storage | Werkzeug hashing |
| Session Cookies | HttpOnly, SameSite=Lax |
| Role Storage | Server-side |
| Session Expiration | 1 hour |
| Audit Logging | All login attempts |
| Bearer Token | Role-based API access |

## 📡 API Endpoints

| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| /api/news | GET | Static news | None |
| /api/live-news | GET | Live news | None |
| /api/intelligence-feed | GET | Intel reports | Bearer token |

## 📄 License

MIT License

---

**Built with 🔒 security in mind**
