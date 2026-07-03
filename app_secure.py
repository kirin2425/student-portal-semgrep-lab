"""
Student Portal - Secured Prototype (Lab 5 deliverable, scanned in Lab 6)
University web-based student portal.

Features (mapped to DFD Level 1):
  1.1 Login            - authenticate students & lecturers
  1.2 Assignment Upload - accept file submissions
  1.3 Messaging         - student <-> lecturer feedback
  1.4 Profile Update    - update own personal information

Security controls applied (from Lab 1 ASVS requirements & Lab 3 STRIDE):
  - Passwords hashed + salted (werkzeug PBKDF2)            -> Spoofing
  - Parameterised SQL queries (no string concat)           -> Tampering / SQLi
  - Server-side role checks + session auth                 -> Elevation of Privilege
  - File upload allow-list + size limit + secure_filename  -> Malicious upload
  - Generic error messages, no stack traces to user        -> Information Disclosure
  - HTTPOnly / SameSite session cookies                     -> Session theft
  - Audit logging of security-relevant actions             -> Repudiation

NOTE: This is a teaching prototype. A small number of intentional weak spots
remain so the SAST scan returns meaningful, reviewable findings.
"""

import os
import logging
import sqlite3
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for,
    render_template, render_template_string, abort, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Secret key loaded from environment (do not hardcode in production)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")

# Secure session cookie flags  -> mitigates session theft / XSS cookie access
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # SESSION_COOKIE_SECURE=True,   # enable when served over HTTPS
)

DB_PATH = os.path.join(os.path.dirname(__file__), "portal.db")
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "zip"}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB upload cap (DoS mitigation)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

logging.basicConfig(
    filename=os.path.join(os.path.dirname(__file__), "audit.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
audit = logging.getLogger("audit")


# ---------------------------------------------------------------------------
# Database helpers (parameterised queries throughout)
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT,
            phone TEXT
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    # Seed two demo accounts with hashed + salted passwords
    for uname, pwd, role in [
        ("student1", "StudentPass123!", "student"),
        ("lecturer1", "LecturerPass123!", "lecturer"),
    ]:
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (uname, generate_password_hash(pwd), role),
            )
        except sqlite3.IntegrityError:
            pass
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Auth decorators (server-side enforcement)
# ---------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") != role:
                abort(403)  # server-side role re-check  -> EoP mitigation
            return view(*args, **kwargs)
        return wrapped
    return decorator


def allowed_file(filename):
    return "." in filename and \
        filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------------------------------------------------------------------------
# 1.1 Login
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        db = get_db()
        # Parameterised query -> prevents SQL injection (Tampering)
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user"] = user["username"]
            session["role"] = user["role"]
            audit.info("LOGIN_SUCCESS user=%s", username)
            return redirect(url_for("dashboard"))

        # Generic error -> no username enumeration (Info Disclosure)
        audit.info("LOGIN_FAILED user=%s", username)
        return render_template("login.html", error="Invalid credentials"), 401

    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template(
        "dashboard.html", user=session["user"], role=session["role"]
    )


# ---------------------------------------------------------------------------
# 1.2 Assignment Upload
# ---------------------------------------------------------------------------
@app.route("/upload", methods=["GET", "POST"])
@login_required
@role_required("student")
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", msg="No file selected")

        if not allowed_file(file.filename):
            return render_template("upload.html", msg="File type not allowed")

        # secure_filename strips path traversal sequences
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(save_path)
        audit.info("UPLOAD user=%s file=%s", session["user"], filename)
        return render_template("upload.html", msg="Uploaded: " + filename)

    return render_template("upload.html", msg=None)


# ---------------------------------------------------------------------------
# 1.3 Messaging
# ---------------------------------------------------------------------------
@app.route("/messages", methods=["GET", "POST"])
@login_required
def messages():
    db = get_db()
    if request.method == "POST":
        recipient = request.form.get("recipient", "")
        body = request.form.get("body", "")
        db.execute(
            "INSERT INTO messages (sender, recipient, body) VALUES (?, ?, ?)",
            (session["user"], recipient, body),
        )
        db.commit()
        audit.info("MSG_SENT from=%s to=%s", session["user"], recipient)

    # Users only see messages addressed to them (authorization)
    inbox = db.execute(
        "SELECT sender, body FROM messages WHERE recipient = ?",
        (session["user"],),
    ).fetchall()
    return render_template("messages.html", inbox=inbox)


# ---------------------------------------------------------------------------
# 1.4 Profile Update  (edits ONLY the logged-in user's own row)
# ---------------------------------------------------------------------------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    if request.method == "POST":
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")
        # WHERE bound to session user -> cannot edit other profiles (IDOR-safe)
        db.execute(
            "UPDATE users SET email = ?, phone = ? WHERE username = ?",
            (email, phone, session["user"]),
        )
        db.commit()
        audit.info("PROFILE_UPDATE user=%s", session["user"])

    row = db.execute(
        "SELECT email, phone FROM users WHERE username = ?",
        (session["user"],),
    ).fetchone()
    return render_template("profile.html", profile=row)


# ---------------------------------------------------------------------------
# Search helper -- INTENTIONAL WEAK SPOT for the SAST lab.
# render_template_string on user input is a server-side template injection
# (SSTI) sink; Semgrep flags this as the teaching finding.
# ---------------------------------------------------------------------------
@app.route("/greet")
@login_required
def greet():
    name = request.args.get("name", "student")
    # FINDING: untrusted input passed to render_template_string (SSTI risk)
    template = "<h3>Hello " + name + ", welcome back!</h3>"
    return render_template_string(template)


if __name__ == "__main__":
    init_db()
    # debug=True is unsafe for production -> secondary SAST finding
    app.run(host="127.0.0.1", port=5000, debug=True)
