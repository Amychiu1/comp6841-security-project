"""
Phase 1 - Step 3: "Proper Protection" Version
=================================================
This version replaces the naive blacklist approach with industry-standard
defences:

  1. SQLi -> Parameterised queries (data is never concatenated into SQL text;
     the DB driver keeps code and data completely separate)
  2. XSS  -> Output auto-escaping (Jinja2's default behaviour - we simply
     REMOVED the `| safe` filter that was disabling it. No input filtering
     needed at all.)

Try the exact same bypass payloads that worked in Step 2 and see what
happens now.

Run:
    python3 app_fixed.py
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


HOME_HTML = """
<h1>Vulnerable Demo App - "Proper Protection" Layer</h1>
<ul>
  <li><a href="/login">Login page (SQLi - parameterised query)</a></li>
  <li><a href="/guestbook">Guestbook (XSS - auto-escaped output)</a></li>
</ul>
"""


@app.route("/")
def home():
    return HOME_HTML


# ---------- LOGIN with PARAMETERISED QUERY ----------
LOGIN_HTML = """
<h1>Login (Fixed)</h1>
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

        # FIX: username/password are passed as bound parameters (the "?"
        # placeholders). SQLite treats them purely as DATA - they can never
        # be interpreted as part of the SQL command, no matter what
        # characters they contain.
        query = "SELECT * FROM users WHERE username = ? AND password = ?"

        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(query, (username, password))
            row = cur.fetchone()
        except sqlite3.OperationalError as e:
            row = None
            message = "SQL error: {}".format(e)

        if row:
            message = "Login successful! Welcome, {}".format(row[1])
        elif not message:
            message = "Login failed."

    return render_template_string(LOGIN_HTML, message=message)


# ---------- GUESTBOOK with AUTO-ESCAPED OUTPUT ----------
# NOTE the `| safe` filters from the previous versions are GONE here.
# Jinja2 escapes HTML-special characters by default on every {{ }} - this
# is the fix. No input filtering / sanitisation needed.
GUESTBOOK_HTML = """
<h1>Guestbook (Fixed)</h1>
<form method="POST">
  Name: <input type="text" name="author"><br>
  Message: <textarea name="body"></textarea><br>
  <input type="submit" value="Post">
</form>
<hr>
{% for c in comments %}
  <p><strong>{{ c[1] }}</strong> says: {{ c[2] }}</p>
{% endfor %}
"""


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    db = get_db()
    cur = db.cursor()

    if request.method == "POST":
        author = request.form.get("author", "")
        body = request.form.get("body", "")
        # Stored EXACTLY as typed - no input filtering at all.
        # Safety comes entirely from output-side escaping above.
        cur.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        db.commit()

    cur.execute("SELECT * FROM comments ORDER BY id DESC")
    comments = cur.fetchall()
    return render_template_string(GUESTBOOK_HTML, comments=comments)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5002, debug=True)
