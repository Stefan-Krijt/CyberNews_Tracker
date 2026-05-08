# ===== IMPORTS =====
from flask import Flask, render_template, request, redirect, url_for, make_response
from datetime import datetime   # Imports datetime for getting current date
import uuid     # Generating unique session IDs


app = Flask(__name__)   # Create the Flask application instance


# ===== SERVER-SIDE SESSION STORAGE =====
sessions = {}   # Stores all active sessions on the server
                # Structure: {session_id: {"username": "...", "role": "...", "login_time": "..."}}


# ===== SIMPLE USER DATABASE =====
users = {
    "Stefan": {"password": "password123", "role": "admin"},
    "Alice": {"password": "alice123", "role": "user"}
}


# ===== HELPER FUNCTION =====
# Extracts session_token from cookie and returns user data if valid
def get_current_user():
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
    
    return redirect(url_for('user_dashboard'))


# ===== ROUTE: User Dashboard (regular users only) =====
@app.route('/user-dashboard')
def user_dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_page'))
    
    # Check role - regular users only
    if user["role"] not in ["user", "admin"]:  
        return "Access Denied", 403
    
    articles = [
        {"title": "New AI Breakthrough", "summary": "Researchers develop self-improving models.", "date": "2025-11-03"},
        {"title": "Cyberattack on Major Bank", "summary": "Millions of accounts affected in latest data breach.", "date": "2025-11-02"},
        {"title": "Flask 3.0 Released", "summary": "The new version simplifies async route handling.", "date": "2025-11-01"}
    ]
    last_updated = datetime.now().strftime("%Y-%m-%d %H:%M")

    return render_template("user_dashboard.html", 
                          username=user["username"], 
                          role=user["role"],
                          articles=articles, 
                          last_updated=last_updated,
                          session_role=user["role"]) 


# ===== ROUTE: Admin Dashboard (admin users only) =====
@app.route('/admin-dashboard')
def admin_dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_page'))
    
    # Check role - admin only
    if user["role"] != "admin":
        return "Access Denied: Admin dashboard requires 'admin' role.", 403
    
    # Admin sees additional information (e.g., all active sessions)
    articles = [
        {"title": "New AI Breakthrough", "summary": "Researchers develop self-improving models.", "date": "2025-11-03"},
        {"title": "Cyberattack on Major Bank", "summary": "Millions of accounts affected.", "date": "2025-11-02"},
        {"title": "Flask 3.0 Released", "summary": "The new version simplifies async routing.", "date": "2025-11-01"}
    ]
    last_updated = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    # Admin sees list of active sessions (server-side data)
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
                          session_role=user["role"] if user else None)


# ===== ROUTE: submit message =====
@app.route('/submit-message', methods=['POST'])
def submit_message():
    user = get_current_user()
    name = request.form.get('name')
    email = request.form.get('email')
    message = request.form.get('message')
    return render_template('confirmation.html', 
                          name=name, email=email, message=message,
                          session_role=user["role"] if user else None)


# ===== ROUTE: Login page =====
@app.route('/login', methods=['GET'])
def login_page():
    error = request.args.get('error')
    return render_template('login.html', error=error, session_role=None)


# ===== ROUTE: Login processing (handles form submission) =====
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Check if user exists and password matches
    if username in users and users[username]["password"] == password:
        session_id = str(uuid.uuid4())  # Generate unique session ID
        
        sessions[session_id] = {    # Store session data server-side
            "username": username,
            "role": users[username]["role"],
            "login_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Create response with session cookie
        response = make_response(redirect(url_for('news')))
        response.set_cookie(
            'session_token', 
            session_id, 
            httponly=True,      # Cannot be accessed by JavaScript (security)
            samesite='Lax',     # CSRF protection
            secure=False,       # Set to True if using HTTPS (false for development)
            max_age=3600        # Expires after 1 hour
        )
        return response
    else:
        return redirect(url_for('login_page', error="Invalid username or password"))


# ===== ROUTE: Logout =====
@app.route('/logout')
def logout():
    session_token = request.cookies.get('session_token')    # Get session token from cookie
    
    if session_token and session_token in sessions:     # Remove session from server-side storage
        del sessions[session_token]
    
    response = make_response(redirect(url_for('login_page')))   # Clear the cookie by setting it to expire immediately
    response.set_cookie('session_token', '', expires=0)
    return response


# ===== ROUTE: Cookie security =====
@app.route('/cookie_check')
def cookie_check():
    user = get_current_user()
    response = make_response(render_template('cookie_demo.html',
                            session_role=user["role"] if user else None))
    
    # Cookie 1 - Accessible by JavaScript (httponly=False)
    response.set_cookie(
        'js_accessible_cookie',
        'JavaScript can read me!',
        httponly=False,     # JavaScript CAN access this
        samesite='Lax'
    )
    
    # Cookie 2 - NOT accessible by JavaScript (httponly=True)
    response.set_cookie(
        'http_only_cookie',
        'JavaScript CANNOT read me - this is protected!',
        httponly=True,      # JavaScript CANNOT access this
        samesite='Lax'
    )
    
    return response


# ===== ROUTE: /status page =====
@app.route('/status')
def status():
    return "Application is running."


# ===== ROUTE: /info page (with currentdate) =====
@app.route('/info')
def info():
    today = datetime.now().strftime("%Y-%m-%d")     # Get today's date and format it as YYYY-MM-DD
    return f"Today's date is {today}"


# ===== ROUTE: /greet page (dynamic) =====
@app.route('/greet/<name>')
def greet(name):
    return f"Hello, {name}!"


# ===== ROUTE: /calculate/add page (with two numbers) =====
@app.route('/calculate/add/<int:num1>/<int:num2>')
def add_numbers(num1, num2):
    result = num1 + num2
    return f"The sum of {num1} and {num2} is {result}."


# ===== Run the application =====
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)