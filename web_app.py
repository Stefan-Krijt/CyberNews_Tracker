# ===== IMPORTS =====
from flask import Flask, render_template, request, redirect, url_for, make_response, flash
from datetime import datetime
import uuid
import os
import requests
import json
import sqlite3
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from contextlib import contextmanager

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))


# ===== CVE DATABASE HELPER =====
@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect('data/cves.db')
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def get_recent_cves(limit=20):
    """Fetch the most recent CVEs from database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT cve_id, cvss_score, severity, description, published, vendor, product
            FROM vulnerabilities 
            ORDER BY published DESC 
            LIMIT ?
        ''', (limit,))
        return cursor.fetchall()

def get_cve_by_id(cve_id):
    """Fetch a single CVE by its ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM vulnerabilities WHERE cve_id = ?', (cve_id,))
        return cursor.fetchone()


# ===== SERVER-SIDE SESSION STORAGE =====
sessions = {}


# ===== USER STORAGE (JSON FILE) =====
USERS_FILE = 'data/users.json'

def load_users():
    """Load users from JSON file"""
    if not os.path.exists('data'):
        os.makedirs('data')
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    """Save users to JSON file"""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)


# ===== AUDIT LOG =====
AUDIT_LOG_FILE = 'data/audit.log'

def log_audit(username, ip_address, status):
    """Log authentication attempts"""
    if not os.path.exists('data'):
        os.makedirs('data')
    with open(AUDIT_LOG_FILE, 'a') as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] User: {username} | IP: {ip_address} | Status: {status}\n")


# ===== ACTIVE TOKENS FOR BEARER AUTHORIZATION =====
# These will be populated dynamically as users are created/promoted
USER_TOKENS = {}
ACTIVE_TOKENS = {}

def assign_user_token(username, token_role):
    """Assign a token to a user based on role"""
    users_data = load_users()
    
    if username not in users_data:
        return False
    
    # Remove existing token if any
    if username in USER_TOKENS:
        old_token = USER_TOKENS[username]["token"]
        if old_token in ACTIVE_TOKENS:
            del ACTIVE_TOKENS[old_token]
        del USER_TOKENS[username]
    
    if token_role == "admin":
        token = f"admin_token_{username[:3]}_{str(uuid.uuid4())[:8]}"
        ACTIVE_TOKENS[token] = {"role": "admin", "user": username}
        USER_TOKENS[username] = {"token": token, "role": "admin"}
        
    elif token_role == "analyst":
        token = f"analyst_token_{username[:3]}_{str(uuid.uuid4())[:8]}"
        ACTIVE_TOKENS[token] = {"role": "analyst", "user": username}
        USER_TOKENS[username] = {"token": token, "role": "analyst"}
        
    elif token_role == "readonly":
        token = f"readonly_token_{username[:3]}_{str(uuid.uuid4())[:8]}"
        ACTIVE_TOKENS[token] = {"role": "readonly", "user": username}
        USER_TOKENS[username] = {"token": token, "role": "readonly"}
    else:
        return False
    
    return True

def get_user_token(username):
    """Get user's assigned token"""
    if username in USER_TOKENS:
        return USER_TOKENS[username]["token"]
    # Assign default readonly token for new users
    assign_user_token(username, "readonly")
    return USER_TOKENS.get(username, {}).get("token", None)


# ===== HELPER FUNCTION =====
def get_current_user():
    """Extracts session_token from cookie and returns user data if valid"""
    session_token = request.cookies.get('session_token')
    if session_token and session_token in sessions:
        return sessions[session_token]
    return None


# ===== ROUTE: home =====
@app.route('/')
def home():
    user = get_current_user()
    if user:
        return redirect(url_for('user_dashboard'))
    else:
        return redirect(url_for('login_page'))


# ===== ROUTE: /news =====
@app.route('/news')                                                         
def news():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_page'))
    
    last_updated = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    return render_template("news.html", 
                          username=user["username"], 
                          last_updated=last_updated,
                          session_role=user["role"])


# ===== ROUTE: User Dashboard =====
@app.route('/user-dashboard')
def user_dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_page'))
    
    if user["role"] not in ["user", "admin"]:  
        return "Access Denied", 403
    
    articles = [
        {"title": "New AI Breakthrough", "summary": "Researchers develop self-improving models.", "date": "2025-11-03"},
        {"title": "Cyberattack on Major Bank", "summary": "Millions of accounts affected.", "date": "2025-11-02"},
        {"title": "Flask 3.0 Released", "summary": "The new version simplifies async routing.", "date": "2025-11-01"}
    ]
    last_updated = datetime.now().strftime("%Y-%m-%d %H:%M")

    return render_template("user_dashboard.html", 
                          username=user["username"], 
                          role=user["role"],
                          articles=articles, 
                          last_updated=last_updated,
                          session_role=user["role"]) 


# ===== ROUTE: Admin Dashboard =====
@app.route('/admin-dashboard')
def admin_dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_page'))
    
    if user["role"] != "admin":
        return "Access Denied: Admin dashboard requires 'admin' role.", 403
    
    articles = [
        {"title": "New AI Breakthrough", "summary": "Researchers develop self-improving models.", "date": "2025-11-03"},
        {"title": "Cyberattack on Major Bank", "summary": "Millions of accounts affected.", "date": "2025-11-02"},
        {"title": "Flask 3.0 Released", "summary": "The new version simplifies async routing.", "date": "2025-11-01"}
    ]
    last_updated = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    active_sessions = []
    for sid, data in sessions.items():
        active_sessions.append({
            "username": data["username"],
            "role": data["role"],
            "login_time": data["login_time"]
        })
    
    return render_template("admin_dashboard.html", 
                          username=user["username"], 
                          role=user["role"],
                          articles=articles, 
                          last_updated=last_updated,
                          active_sessions=active_sessions,
                          session_role=user["role"])


# ===== ROUTE: /contact =====
@app.route('/contact', methods=['GET'])
def contact():
    user = get_current_user()
    return render_template('contact_form.html', 
                          username=user["username"] if user else None,
                          session_role=user["role"] if user else None)


# ===== ROUTE: Intelligence =====
@app.route('/intelligence')
def intelligence():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_page'))
    
    return render_template('intelligence.html', 
                          username=user["username"],
                          session_role=user["role"])


# ===== ROUTE: submit message =====
@app.route('/submit-message', methods=['POST'])
def submit_message():
    user = get_current_user()
    name = request.form.get('name')
    email = request.form.get('email')
    message = request.form.get('message')
    return render_template('confirmation.html', 
                          name=name, email=email, message=message,
                          username=user["username"] if user else None,
                          session_role=user["role"] if user else None)


# ===== ROUTE: Login =====
@app.route('/login', methods=['GET'])
def login_page():
    error = request.args.get('error')
    message = request.args.get('message')
    return render_template('login.html', error=error, message=message, session_role=None)


# ===== ROUTE: Login processing =====
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    users = load_users()

    if username in users and check_password_hash(users[username]["password"], password):
        session_id = str(uuid.uuid4())
        
        sessions[session_id] = {
            "username": username,
            "role": users[username]["role"],
            "login_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        response = make_response(redirect(url_for('news')))
        response.set_cookie(
            'session_token', 
            session_id, 
            httponly=True,
            samesite='Lax',
            secure=False,
            max_age=3600
        )

        log_audit(username, request.remote_addr, "SUCCESS")
        return response
    else:
        log_audit(username, request.remote_addr, "FAILED")
        return redirect(url_for('login_page', error="Invalid username or password"))


# ===== ROUTE: Registration =====
@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    errors = []
    
    if not username or not email or not password:
        errors.append("All fields are required")
    
    if password != confirm_password:
        errors.append("Passwords do not match")
    
    if len(password) < 6:
        errors.append("Password must be at least 6 characters")
    
    users = load_users()
    if username in users:
        errors.append("Username already exists")
    
    for user_data in users.values():
        if user_data.get('email') == email:
            errors.append("Email already registered")
            break
    
    if errors:
        return redirect(url_for('login_page', error=" | ".join(errors)))
    
    # Create new user
    users[username] = {
        "password": generate_password_hash(password),
        "role": "user",
        "email": email,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    save_users(users)
    
    # Assign default token for new user
    assign_user_token(username, "readonly")
    
    log_audit(username, request.remote_addr, "REGISTERED")
    
    return redirect(url_for('login_page', message="Account created! Please login."))


# ===== ROUTE: Profile Page =====
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_page'))
    
    users_data = load_users()
    user_info = users_data.get(user["username"], {})
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if check_password_hash(user_info["password"], current_password):
                if new_password == confirm_password and len(new_password) >= 6:
                    users_data[user["username"]]["password"] = generate_password_hash(new_password)
                    save_users(users_data)
                    flash("Password changed successfully!", "success")
                else:
                    flash("Passwords do not match or too short (min 6 chars)", "error")
            else:
                flash("Current password is incorrect", "error")
        
        elif action == 'update_profile':
            email = request.form.get('email')
            users_data[user["username"]]["email"] = email
            save_users(users_data)
            flash("Profile updated successfully!", "success")
        
        return redirect(url_for('profile'))
    
    user_token = get_user_token(user["username"])
    
    return render_template('profile.html',
                          username=user["username"],
                          email=user_info.get("email", ""),
                          role=user["role"],
                          created_at=user_info.get("created_at", "Unknown"),
                          user_token=user_token if user_token else "No token assigned",
                          session_role=user["role"])


# ===== ROUTE: Admin Users =====
@app.route('/admin/users')
def admin_users():
    user = get_current_user()
    if not user or user["role"] != "admin":
        return redirect(url_for('login_page'))
    
    users_data = load_users()
    users_list = []
    
    for username, data in users_data.items():
        token_info = USER_TOKENS.get(username, {})
        users_list.append({
            "username": username,
            "email": data.get("email", ""),
            "role": data.get("role", "user"),
            "token_role": token_info.get("role", "none"),
            "token": token_info.get("token", "none"),
            "created_at": data.get("created_at", "Unknown")
        })
    
    return render_template('admin_users.html',
                          users=users_list,
                          username=user["username"],
                          session_role=user["role"])


# ===== ROUTE: Admin - Update User Role =====
@app.route('/admin/update-role', methods=['POST'])
def admin_update_role():
    user = get_current_user()
    if not user or user["role"] != "admin":
        return redirect(url_for('login_page'))
    
    target_user = request.form.get('username')
    new_role = request.form.get('role')
    
    users_data = load_users()
    
    if target_user in users_data and target_user != user["username"]:
        users_data[target_user]["role"] = new_role
        save_users(users_data)
        
        # Update token based on new role
        if new_role == "admin":
            assign_user_token(target_user, "admin")
        elif new_role == "user":
            assign_user_token(target_user, "readonly")
        
        flash(f"Updated {target_user}'s role to {new_role}", "success")
    
    return redirect(url_for('admin_users'))


# ===== ROUTE: Admin - Assign Intelligence Token =====
@app.route('/admin/assign-token', methods=['POST'])
def admin_assign_token():
    user = get_current_user()
    if not user or user["role"] != "admin":
        return redirect(url_for('login_page'))
    
    target_user = request.form.get('username')
    token_type = request.form.get('token_type')
    
    if assign_user_token(target_user, token_type):
        flash(f"Assigned {token_type} token to {target_user}", "success")
    else:
        flash(f"Failed to assign token to {target_user}", "error")
    
    return redirect(url_for('admin_users'))


# ===== ROUTE: Admin - Delete User =====
@app.route('/admin/delete-user', methods=['POST'])
def admin_delete_user():
    user = get_current_user()
    if not user or user["role"] != "admin":
        return redirect(url_for('login_page'))
    
    target_user = request.form.get('username')
    
    if target_user == user["username"]:
        flash("You cannot delete your own account", "error")
        return redirect(url_for('admin_users'))
    
    users_data = load_users()
    
    if target_user in users_data:
        del users_data[target_user]
        save_users(users_data)
        
        # Remove from token storage
        if target_user in USER_TOKENS:
            token = USER_TOKENS[target_user]["token"]
            if token in ACTIVE_TOKENS:
                del ACTIVE_TOKENS[token]
            del USER_TOKENS[target_user]
        
        flash(f"Deleted user: {target_user}", "success")
    
    return redirect(url_for('admin_users'))


# ===== ROUTE: Logout =====
@app.route('/logout')
def logout():
    session_token = request.cookies.get('session_token')
    
    if session_token and session_token in sessions:
        del sessions[session_token]
    
    response = make_response(redirect(url_for('login_page')))
    response.set_cookie('session_token', '', expires=0)
    return response


# ===== ROUTE: Vulnerabilities Page =====
@app.route('/vulnerabilities')
def vulnerabilities():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_page'))
    
    try:
        cves = get_recent_cves(20)
        return render_template('vulnerabilities.html',
                              cves=cves,
                              username=user["username"],
                              session_role=user["role"])
    except sqlite3.Error as e:
        return render_template('vulnerabilities.html',
                              error="Unable to load CVE data. Please try again later.",
                              cves=[],
                              username=user["username"],
                              session_role=user["role"])


# ===== ROUTE: Cookie security =====
@app.route('/cookie_check')
def cookie_check():
    user = get_current_user()
    response = make_response(render_template('cookie_demo.html',
                            username=user["username"] if user else None,
                            session_role=user["role"] if user else None))
    
    response.set_cookie('js_accessible_cookie', 'JavaScript can read me!', httponly=False, samesite='Lax')
    response.set_cookie('http_only_cookie', 'JavaScript CANNOT read me - this is protected!', httponly=True, samesite='Lax')
    
    return response


# ===== ROUTE: /status =====
@app.route('/status')
def status():
    return "Application is running."


# ===== ROUTE: /info =====
@app.route('/info')
def info():
    today = datetime.now().strftime("%Y-%m-%d")
    return f"Today's date is {today}"


# ===== ROUTE: /greet =====
@app.route('/greet/<name>')
def greet(name):
    return f"Hello, {name}!"


# ===== ROUTE: /calculate/add =====
@app.route('/calculate/add/<int:num1>/<int:num2>')
def add_numbers(num1, num2):
    result = num1 + num2
    return f"The sum of {num1} and {num2} is {result}."


# ===== API ROUTE 1: Local fallback news =====
@app.route('/api/news')
def api_news():
    articles = [
        {"title": "New Malware Targets Industrial Systems", "source": "CyberDaily", "url": "#"},
        {"title": "Researchers Discover AI-Powered Phishing Campaign", "source": "TechWatch", "url": "#"},
        {"title": "Critical Zero-Day Vulnerability Found in Popular VPN", "source": "SecurityWeekly", "url": "#"},
        {"title": "Ransomware Gang Claims Major Healthcare Provider", "source": "BreachAlert", "url": "#"},
        {"title": "New EU Cybersecurity Law Takes Effect", "source": "CyberPolicy", "url": "#"},
        {"title": "Quantum Computing Threatens Current Encryption", "source": "FutureSec", "url": "#"}
    ]
    return json.dumps(articles, indent=2), 200, {'Content-Type': 'application/json'}


# ===== API ROUTE 2: Live news from NewsAPI =====
@app.route('/api/live-news')
def api_live_news():
    api_key = os.environ.get('NEWS_API_KEY')
    
    if not api_key:
        return json.dumps({
            "error": True,
            "message": "NEWS_API_KEY not found.",
            "articles": []
        }), 200, {'Content-Type': 'application/json'}
    
    url = f"https://newsapi.org/v2/everything?q=cybersecurity&language=en&pageSize=12&apiKey={api_key}"
    
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            return json.dumps({
                "error": True,
                "message": f"NewsAPI returned status code: {response.status_code}",
                "articles": []
            }), 200, {'Content-Type': 'application/json'}
        
        news_data = response.json()
        
        if news_data.get('status') == 'error':
            return json.dumps({
                "error": True,
                "message": news_data.get('message', 'NewsAPI error'),
                "articles": []
            }), 200, {'Content-Type': 'application/json'}
        
        articles = []
        for article in news_data.get('articles', []):
            if article.get('title') and article.get('title') != '[Removed]':
                articles.append({
                    "title": article.get('title', 'No title'),
                    "source": article.get('source', {}).get('name', 'Unknown source'),
                    "url": article.get('url', '#'),
                    "publishedAt": article.get('publishedAt', ''),
                    "description": article.get('description', 'No description available')
                })
        
        return json.dumps({
            "error": False,
            "totalResults": news_data.get('totalResults', 0),
            "articles": articles
        }, indent=2), 200, {'Content-Type': 'application/json'}
        
    except requests.exceptions.Timeout:
        return json.dumps({
            "error": True,
            "message": "Request timed out.",
            "articles": []
        }), 200, {'Content-Type': 'application/json'}
    except requests.exceptions.ConnectionError:
        return json.dumps({
            "error": True,
            "message": "Network error.",
            "articles": []
        }), 200, {'Content-Type': 'application/json'}
    except requests.exceptions.RequestException as e:
        return json.dumps({
            "error": True,
            "message": f"Failed to fetch news: {str(e)}",
            "articles": []
        }), 200, {'Content-Type': 'application/json'}


# ===== API ROUTE 3: Intelligence Feed =====
@app.route('/api/intelligence-feed', methods=['GET'])
def intelligence_feed():
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        return json.dumps({
            "error": "Missing authorization header",
            "message": "Please provide Authorization: Bearer <token>"
        }), 401, {'Content-Type': 'application/json'}
    
    if not auth_header.startswith('Bearer '):
        return json.dumps({
            "error": "Invalid authorization format",
            "message": "Use: Authorization: Bearer <token>"
        }), 401, {'Content-Type': 'application/json'}
    
    token = auth_header.split(' ')[1]
    
    if token not in ACTIVE_TOKENS:
        return json.dumps({
            "error": "Invalid or expired token",
            "message": "The provided token is not valid."
        }), 403, {'Content-Type': 'application/json'}
    
    user_info = ACTIVE_TOKENS[token]
    role = user_info["role"]
    username = user_info["user"]
    
    if role == "admin":
        intelligence_data = {
            "success": True,
            "role": role,
            "user": username,
            "reports": [
                {
                    "id": 1,
                    "title": "APT28 Activity Report",
                    "severity": "HIGH",
                    "summary": "Russian state-sponsored actors targeting government networks.",
                    "indicators": ["IP: 185.158.31.132", "Domain: malicious.ru"],
                    "mitre_techniques": ["T1566", "T1190"]
                },
                {
                    "id": 2,
                    "title": "Ransomware Campaign Analysis",
                    "severity": "CRITICAL",
                    "summary": "LockBit 3.0 variant spreading via RDP brute force.",
                    "indicators": ["IP: 45.155.205.233", "Hash: a3f5c2b1"],
                    "mitre_techniques": ["T1110", "T1486"]
                },
                {
                    "id": 3,
                    "title": "Phishing Infrastructure Takedown",
                    "severity": "MEDIUM",
                    "summary": "Coordinated takedown of 150+ phishing domains.",
                    "indicators": ["Domain: secure-login[.]com"],
                    "mitre_techniques": ["T1566.002"]
                }
            ],
            "message": f"Welcome {username}! Full intelligence report attached."
        }
    elif role == "analyst":
        intelligence_data = {
            "success": True,
            "role": role,
            "user": username,
            "reports": [
                {
                    "id": 1,
                    "title": "Phishing Campaign Trends",
                    "severity": "MEDIUM",
                    "summary": "Increase in QR code phishing attacks this quarter."
                },
                {
                    "id": 2,
                    "title": "Vulnerability Summary",
                    "severity": "HIGH",
                    "summary": "Critical RCE in popular web framework patched."
                }
            ],
            "message": f"Analyst view: 2 reports available."
        }
    elif role == "readonly":
        intelligence_data = {
            "success": True,
            "role": role,
            "user": username,
            "reports": [
                {
                    "id": 1,
                    "title": "Public Threat Brief",
                    "severity": "LOW",
                    "summary": "General threat landscape overview."
                }
            ],
            "message": f"Read-only access: Limited report available."
        }
    else:
        return json.dumps({
            "error": "Unknown role",
            "message": "Your token has an unrecognized role."
        }), 403, {'Content-Type': 'application/json'}
    
    return json.dumps(intelligence_data, indent=2), 200, {'Content-Type': 'application/json'}


# ===== Run the application =====
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
