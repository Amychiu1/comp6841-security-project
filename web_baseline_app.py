"""
Baseline Vulnerable Web App (Phase 1 - Step 1)
================================================
Intentionally vulnerable Flask app for the COMP6841 security project.

Vulnerabilities included (NO protections yet - this is the baseline):
  1. SQL Injection in the /login route (raw string concatenation into SQL)
  2. Stored XSS in the /guestbook route (user input rendered without escaping)

Run:
    pip install flask
    python3 app.py

Then visit http://127.0.0.1:5000/
"""

from flask import Flask, request, render_template_string, g
import sqlite3
import os

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "vuln.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    # Fresh DB every time the app starts, so your testing is repeatable
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE users (
                        id INTEGER PRIMARY KEY,
                        username TEXT,
                        password TEXT
                   )""")
    cur.execute("""CREATE TABLE comments (
                        id INTEGER PRIMARY KEY,
                        author TEXT,
                        body TEXT
                   )""")
    cur.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                ("admin", "S3cretAdminPassw0rd!"))
    cur.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                ("alice", "alice123"))
    conn.commit()
    conn.close()


# ---------- HOME ----------
HOME_HTML = """
<h1>Vulnerable Demo App - Phase 1 Baseline</h1>
<ul>
  <li><a href="/login">Login page (SQLi target)</a></li>
  <li><a href="/guestbook">Guestbook (XSS target)</a></li>
</ul>
"""


@app.route("/")
def home():
    return HOME_HTML


# ---------- LOGIN (SQL INJECTION) ----------
LOGIN_HTML = """
<h1>Login</h1>
<form method="POST">
  Username: <input type="text" name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
{% if message %}<p><strong>{{ message }}</strong></p>{% endif %}
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    message = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABLE: raw string concatenation, no parameterisation.
        # This is the exact line you will screenshot and analyse.
        query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(
            username, password
        )

        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(query)
            row = cur.fetchone()
        except sqlite3.OperationalError as e:
            row = None
            message = "SQL error (useful for error-based injection): {}".format(e)

        if row:
            message = "Login successful! Welcome, {}".format(row[1])
        elif not message:
            message = "Login failed."

    return render_template_string(LOGIN_HTML, message=message)


# ---------- GUESTBOOK (STORED XSS) ----------
GUESTBOOK_HTML = """
<h1>Guestbook</h1>
<form method="POST">
  Name: <input type="text" name="author"><br>
  Message: <textarea name="body"></textarea><br>
  <input type="submit" value="Post">
</form>
<hr>
{% for c in comments %}
  <p><strong>{{ c[1] | safe }}</strong> says: {{ c[2] | safe }}</p>
{% endfor %}
"""


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    db = get_db()
    cur = db.cursor()

    if request.method == "POST":
        author = request.form.get("author", "")
        body = request.form.get("body", "")
        # VULNERABLE: stored directly, rendered later with | safe (no escaping)
        cur.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        db.commit()

    cur.execute("SELECT * FROM comments ORDER BY id DESC")
    comments = cur.fetchall()
    return render_template_string(GUESTBOOK_HTML, comments=comments)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
