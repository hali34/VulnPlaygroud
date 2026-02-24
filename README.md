# 🏦 VulnPlayground

> **Deliberately vulnerable Flask banking application covering all OWASP Top 10 (2021) categories.**
> Built as a hands-on appsec/pentest portfolio and training tool.
> **⚠️ For local educational use only — never deploy to the internet.**

---

## What Is VulnPlayground?

VulnPlayground is a fake online banking application with 12 purposefully broken security controls — one for each OWASP Top 10 category (with extras for A01 and A03). Every vulnerability has a hidden flag in `FLAG{...}` format that you discover through real exploitation, not by reading source code. Progress is tracked on a `/exercises` challenge board.

---

## Quick Start

```bash
# 1. Navigate to the project directory
cd VulnPlayground

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate          # Linux / macOS
# venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install flask requests

# 4. Run the application
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

---

## Default Credentials

| Username | Password  | Role  |
|----------|-----------|-------|
| admin    | admin123  | admin |
| alice    | password  | user  |
| bob      | bob123    | user  |
| charlie  | charlie   | user  |

---

## Challenges at a Glance

| #   | Category                       | Challenge                         | Difficulty |
|-----|--------------------------------|-----------------------------------|------------|
| A01 | Broken Access Control          | IDOR — read any user's note       | 🟢 Easy   |
| A01 | Broken Access Control          | Session cookie forgery → admin    | 🟡 Medium |
| A02 | Cryptographic Failures         | Crack MD5 password hash           | 🟢 Easy   |
| A03 | Injection — SQLi               | UNION-based dump of hidden table  | 🟡 Medium |
| A03 | Injection — Stored XSS         | Steal admin session cookie        | 🟢 Easy   |
| A03 | Injection — Command Injection  | Read flag via OS command          | 🟢 Easy   |
| A04 | Insecure Design                | Negative transfer → drain balance | 🟢 Easy   |
| A05 | Security Misconfiguration      | Unauthenticated info disclosure   | 🟢 Easy   |
| A07 | Auth Failures                  | Brute-force with no lockout       | 🟡 Medium |
| A08 | Data Integrity                 | Pickle deserialization RCE        | 🔴 Hard   |
| A09 | Logging Failures               | Confirm absence of audit trail    | 🟢 Easy   |
| A10 | SSRF                           | Reach internal-only endpoint      | 🟡 Medium |

---

## Project Structure

```
VulnPlayground/
├── app.py                  # Flask app — all vulnerabilities here
├── requirements.txt        # Intentionally older package versions (A06)
├── start.sh                # One-command startup script
├── README.md               # This file
├── USAGE.md                # Step-by-step exercise walkthrough
├── EXPLOITATION_GUIDE.md   # Full guide: exploit, impact, secure fix
└── templates/
    ├── base.html
    ├── exercises.html      # Challenge tracker with hints
    ├── index.html
    ├── login.html          # SQLi target
    ├── board.html          # Stored XSS target
    ├── search.html         # UNION SQLi target
    ├── note.html           # IDOR target
    ├── admin.html          # Session forgery target
    ├── profile.html        # Crypto failures
    ├── transfer.html       # Insecure design / no CSRF
    ├── fetch.html          # SSRF
    ├── ping.html           # Command injection
    ├── prefs.html          # Pickle deserialization
    ├── stolen_cookies.html # XSS cookie capture viewer
    └── ...
```

---

## Recommended Tools

| Tool | Purpose | Install |
|------|---------|---------|
| **Burp Suite Community** | HTTP proxy, repeater, intruder | [portswigger.net](https://portswigger.net/burp) |
| **flask-unsign** | Decode/forge Flask session cookies | `pip install flask-unsign` |
| **sqlmap** | Automated SQL injection | `pip install sqlmap` |
| **OWASP ZAP** | Web app scanner | [zaproxy.org](https://www.zaproxy.org) |
| **Caido** | Modern Burp alternative | [caido.io](https://caido.io) |
| **CrackStation** | Online hash cracking | [crackstation.net](https://crackstation.net) |

---

## Documentation

- **[USAGE.md](USAGE.md)** — Full walkthrough of each challenge with step-by-step exploitation instructions, expected output, and what to submit.
- **[EXPLOITATION_GUIDE.md](EXPLOITATION_GUIDE.md)** — In-depth write-ups covering: vulnerable code, exploit method, real-world impact, and secure remediation code.

---

## Resetting Progress

To reset all captured flags and balances:

```bash
# Delete the database — it will regenerate on next start
rm VulnPlayground.db
python app.py
```

---

## A Note on A06 (Vulnerable Components)

VulnPlayground's `requirements.txt` pins older library versions intentionally. To check for known CVEs:

```bash
pip install safety
safety check -r requirements.txt
```

---

*Inspired by DVWA, OWASP WebGoat, and Juice Shop.*
