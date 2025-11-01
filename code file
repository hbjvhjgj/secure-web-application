# app.py
"""
Secure demo Flask app (single file)
Features:
- User registration & login with bcrypt (passlib)
- Strong password validation (WTForms + custom checks)
- Input validation & sanitization
- Session management (Flask-Login)
- Data storage in SQLite (passwords hashed)
- Field encryption using AES-256-GCM (cryptography)
- Audit / activity logs (DB table)
- Profile update page
- File upload validation (images/pdf only)
- Secure error handling (no stack traces returned to clients)
- Minimal HTML templates via render_template_string so only one file required

Run:
  1) pip install -r requirements.txt
  2) export FLASK_APP=app.py
     export SECRET_KEY='choose_a_strong_secret'
     export AES_KEY_HEX='<64-hex-chars>'   # 32 bytes hex for AES-256
  3) flask run
Visit http://127.0.0.1:5000
"""

import os
import sqlite3
import secrets
import re
from datetime import datetime, timedelta

from flask import (
    Flask, g, render_template_string, request, redirect,
    url_for, flash, send_from_directory, jsonify
)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, FileField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, Optional, ValidationError
from werkzeug.utils import secure_filename
from passlib.hash import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin

# --- Configuration ---
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_ROOT, 'app.sqlite3')
UPLOAD_FOLDER = os.path.join(APP_ROOT, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# AES key: expect 64 hex chars (32 bytes)
AES_KEY_HEX = os.environ.get('AES_KEY_HEX')
AES_KEY = None
if AES_KEY_HEX:
    try:
        AES_KEY = bytes.fromhex(AES_KEY_HEX)
        if len(AES_KEY) != 32:
            print("AES_KEY_HEX is not 32 bytes")
            AES_KEY = None
    except Exception:
        AES_KEY = None

# --- DB helpers ---
def get_db():
    db = getattr(g, '_db', None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    cursor = db.cursor()
    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email TEXT,
      extra_encrypted BLOB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      failed_logins INTEGER DEFAULT 0,
      locked_until TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      meta TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_db', None)
    if db is not None:
        db.close()

# --- User class for flask-login ---
class User(UserMixin):
    def __init__(self, id_, username):
        self.id = id_
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    if row:
        return User(row['id'], row['username'])
    return None

# --- Security helpers ---
def log_action(user_id, action, meta=''):
    try:
        db = get_db()
        db.execute("INSERT INTO audit_log (user_id, action, meta) VALUES (?, ?, ?)", (user_id, action, meta))
        db.commit()
    except Exception:
        # never leak audit errors to users
        print("Audit log failed", action)

def encrypt_field(plaintext: str):
    if not AES_KEY or plaintext is None:
        return None
    aesgcm = AESGCM(AES_KEY)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce + ct  # store nonce + ciphertext

def decrypt_field(blob):
    if not AES_KEY or blob is None:
        return None
    aesgcm = AESGCM(AES_KEY)
    nonce, ct = blob[:12], blob[12:]
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode('utf-8')
    except Exception:
        return None

# --- Validators ---
def password_strength_check(form, field):
    p = field.data or ''
    if len(p) < 10:
        raise ValidationError('Password must be at least 10 characters')
    if not re.search(r'\d', p):
        raise ValidationError('Password must include a digit')
    if not re.search(r'[A-Z]', p):
        raise ValidationError('Password must include an uppercase letter')
    if not re.search(r'[a-z]', p):
        raise ValidationError('Password must include a lowercase letter')
    if not re.search(r'[^A-Za-z0-9]', p):
        raise ValidationError('Password must include a symbol')

# --- Forms ---
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField('Password', validators=[DataRequired(), password_strength_check])
    confirm = PasswordField('Confirm Password', validators=[DataRequired()])
    email = StringField('Email', validators=[Optional(), Email()])
    extra = TextAreaField('Extra (optional)', validators=[Optional(), Length(max=500)])
    submit = SubmitField('Register')

    def validate_username(self, field):
        db = get_db()
        row = db.execute("SELECT id FROM users WHERE username = ?", (field.data,)).fetchone()
        if row:
            raise ValidationError("Username already exists")

    def validate_confirm(self, field):
        if field.data != self.password.data:
            raise ValidationError("Passwords do not match")

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ProfileForm(FlaskForm):
    email = StringField('Email', validators=[Optional(), Email()])
    extra = TextAreaField('Extra (optional)', validators=[Optional(), Length(max=500)])
    submit = SubmitField('Update')

class UploadForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    submit = SubmitField('Upload')

# --- Helpers for files ---
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Routes & Views (minimal templates) ---
BASE_HTML = """
<!doctype html>
<title>Secure Demo</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
<div class="container">
  <header>
    <h1>Secure Demo App</h1>
    <nav>
      {% if current_user.is_authenticated %}
        <a href="{{ url_for('dashboard') }}">Dashboard</a> |
        <a href="{{ url_for('profile') }}">Profile</a> |
        <a href="{{ url_for('upload') }}">Upload</a> |
        <a href="{{ url_for('audit') }}">Audit</a> |
        <a href="{{ url_for('logout') }}">Logout</a>
      {% else %}
        <a href="{{ url_for('index') }}">Home</a> |
        <a href="{{ url_for('register') }}">Register</a> |
        <a href="{{ url_for('login') }}">Login</a>
      {% endif %}
    </nav>
    <hr>
  </header>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for cat, msg in messages %}
        <div class="message {{ cat }}">{{ msg }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <main>
    {{ body|safe }}
  </main>
</div>
"""

@app.route('/')
def index():
    body = "<p>Welcome. Use Register/Login to explore security features.</p>"
    return render_template_string(BASE_HTML, body=body)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        email = form.email.data.strip() if form.email.data else None
        extra = form.extra.data.strip() if form.extra.data else None

        pw_hash = bcrypt.using(rounds=12).hash(password)
        enc = encrypt_field(extra) if extra else None
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, email, extra_encrypted) VALUES (?, ?, ?, ?)",
                (username, pw_hash, email, enc)
            )
            db.commit()
            log_action(None, 'register', f'username={username}')
            flash('Registered successfully. Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username exists', 'error')
        except Exception:
            flash('Internal server error', 'error')
    body = render_template_string("""
    <h2>Register</h2>
    <form method="post">
      {{ form.hidden_tag() }}
      <label>Username</label>{{ form.username() }}
      <label>Password</label>{{ form.password() }}
      <label>Confirm</label>{{ form.confirm() }}
      <label>Email (optional)</label>{{ form.email() }}
      <label>Extra (optional)</label>{{ form.extra(cols=40, rows=3) }}
      <p>{{ form.submit() }}</p>
    </form>
    """, form=form)
    return render_template_string(BASE_HTML, body=body)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        db = get_db()
        row = db.execute("SELECT id, password_hash, failed_logins, locked_until FROM users WHERE username = ?", (username,)).fetchone()
        # Generic "invalid" response to avoid username enumeration
        if not row:
            log_action(None, 'login_failed', f'username={username}')
            flash('Invalid credentials', 'error')
            return redirect(url_for('login'))

        # check lockout
        if row['locked_until']:
            locked_until = datetime.fromisoformat(row['locked_until'])
            if datetime.utcnow() < locked_until:
                flash('Account temporarily locked. Try later.', 'error')
                return redirect(url_for('login'))
            else:
                # reset lock
                db.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (row['id'],))
                db.commit()

        if bcrypt.verify(password, row['password_hash']):
            user = User(row['id'], username)
            login_user(user)
            db.execute("UPDATE users SET failed_logins = 0 WHERE id = ?", (row['id'],))
            db.commit()
            log_action(row['id'], 'login_success', f'username={username}')
            flash('Logged in', 'success')
            return redirect(url_for('dashboard'))
        else:
            # increment failed logins and optionally lock account
            failed = row['failed_logins'] + 1
            locked_until = None
            if failed >= 5:
                locked_until = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
            db.execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?", (failed, locked_until, row['id']))
            db.commit()
            log_action(row['id'], 'login_failed', f'username={username}')
            flash('Invalid credentials', 'error')
            return redirect(url_for('login'))

    body = render_template_string("""
    <h2>Login</h2>
    <form method="post">
      {{ form.hidden_tag() }}
      <label>Username</label>{{ form.username() }}
      <label>Password</label>{{ form.password() }}
      <p>{{ form.submit() }}</p>
    </form>
    """, form=form)
    return render_template_string(BASE_HTML, body=body)

@app.route('/logout')
@login_required
def logout():
    uid = current_user.id
    logout_user()
    log_action(uid, 'logout', '')
    flash('Logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    row = db.execute("SELECT username, email, extra_encrypted, created_at FROM users WHERE id = ?", (current_user.id,)).fetchone()
    extra = decrypt_field(row['extra_encrypted']) if row['extra_encrypted'] else None
    body = render_template_string("""
    <h2>Dashboard</h2>
    <p><strong>Username:</strong> {{ username }}</p>
    <p><strong>Email:</strong> {{ email or 'N/A' }}</p>
    <p><strong>Extra (decrypted):</strong> {{ extra or '(none)' }}</p>
    <p><strong>Created:</strong> {{ created }}</p>
    """, username=row['username'], email=row['email'], extra=extra, created=row['created_at'])
    return render_template_string(BASE_HTML, body=body)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    db = get_db()
    if form.validate_on_submit():
        email = form.email.data.strip() if form.email.data else None
        extra = form.extra.data.strip() if form.extra.data else None
        enc = encrypt_field(extra) if extra else None
        try:
            if enc:
                db.execute("UPDATE users SET email = ?, extra_encrypted = ? WHERE id = ?", (email, enc, current_user.id))
            else:
                db.execute("UPDATE users SET email = ? WHERE id = ?", (email, current_user.id))
            db.commit()
            log_action(current_user.id, 'profile_update', '')
            flash('Profile updated', 'success')
            return redirect(url_for('dashboard'))
        except Exception:
            flash('Internal server error', 'error')
    else:
        # pre-fill
        row = db.execute("SELECT email, extra_encrypted FROM users WHERE id = ?", (current_user.id,)).fetchone()
        if row:
            form.email.data = row['email']
            form.extra.data = decrypt_field(row['extra_encrypted']) if row['extra_encrypted'] else ''
    body = render_template_string("""
    <h2>Profile</h2>
    <form method="post">
      {{ form.hidden_tag() }}
      <label>Email</label>{{ form.email() }}
      <label>Extra (optional)</label>{{ form.extra(cols=40, rows=3) }}
      <p>{{ form.submit() }}</p>
    </form>
    """, form=form)
    return render_template_string(BASE_HTML, body=body)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        f = request.files.get('file')
        if not f or f.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('upload'))
        filename = secure_filename(f.filename)
        if not allowed_file(filename):
            flash('Invalid file type', 'error')
            return redirect(url_for('upload'))
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        f.save(path)
        log_action(current_user.id, 'file_upload', filename)
        flash('File uploaded', 'success')
        return redirect(url_for('dashboard'))
    body = render_template_string("""
    <h2>Upload</h2>
    <form method="post" enctype="multipart/form-data">
      {{ form.hidden_tag() }}
      {{ form.file() }}
      <p>{{ form.submit() }}</p>
    </form>
    <p>Allowed: {{ allowed }}</p>
    """, form=form, allowed=", ".join(ALLOWED_EXTENSIONS))
    return render_template_string(BASE_HTML, body=body)

@app.route('/audit')
@login_required
def audit():
    db = get_db()
    rows = db.execute("SELECT action, meta, created_at FROM audit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 50", (current_user.id,)).fetchall()
    lines = "<h2>Audit (your actions)</h2><ul>"
    for r in rows:
        lines += f"<li>[{r['created_at']}] {r['action']} — {r['meta']}</li>"
    lines += "</ul>"
    return render_template_string(BASE_HTML, body=lines)

# serve uploads for demo (in production restrict access)
@app.route('/uploads/<filename>')
@login_required
def uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- Error handling ---
@app.errorhandler(400)
def bad_request(e):
    return render_template_string(BASE_HTML, body="<p>Bad request</p>"), 400

@app.errorhandler(404)
def not_found(e):
    return render_template_string(BASE_HTML, body="<p>Not found</p>"), 404

@app.errorhandler(413)
def file_too_large(e):
    flash('File too large (max 2MB)', 'error')
    return redirect(request.url or url_for('upload'))

@app.errorhandler(Exception)
def handle_exception(e):
    # Log to server console but return generic message to client
    app.logger.error("Unhandled exception: %s", str(e))
    return render_template_string(BASE_HTML, body="<p>Internal server error</p>"), 500

# --- Init DB & run ---
if __name__ == '__main__':
    init_db()
    print("AES_KEY set:", bool(AES_KEY))
    app.run(debug=False)
