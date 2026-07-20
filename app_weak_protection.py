"""
Phase 1 - Step 2: "Weak Protection" Version
=============================================
This version adds NAIVE protections - the kind a junior developer might add
without fully understanding the vulnerability class. Your job in this step
is to try to BYPASS these protections and document what works / what doesn't.

Protections added:
  1. SQLi: blacklist filter that rejects input containing certain keywords
  2. XSS: blacklist filter that strips <script> tags (naively)

These are DELIBERATELY incomplete - that's the point of this exercise.
Run:
    python3 app_weak_protection.py
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
<h1>Vulnerable Demo App - "Weak Protection" Layer</h1>
<ul>
  <li><a href="/login">Login page (SQLi - naive keyword blacklist)</a></li>
  <li><a href="/guestbook">Guestbook (XSS - naive tag stripping)</a></li>
</ul>
"""


@app.route("/")
def home():
    return HOME_HTML


# ---------- LOGIN with NAIVE SQLi "protection" ----------
LOGIN_HTML = """
<h1>Login (Protected v1)</h1>
<form method="POST">
  Username: <input type="text" name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
{% if message %}<p><strong>{{ message }}</strong></p>{% endif %}
"""

# Naive blacklist: case-sensitive, only checks a few exact keywords.
# Think about how you would defeat this before reading further.
SQL_BLACKLIST = ["OR", "UNION", "--", "DROP", "SELECT"]


def naive_sql_filter(value):
    for bad_word in SQL_BLACKLIST:
        if bad_word in value:
            return False
    return True


@app.route("/login", methods=["GET", "POST"])
def login():
    message = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if not naive_sql_filter(username) or not naive_sql_filter(password):
            message = "Blocked: suspicious input detected."
        else:
            # Still vulnerable underneath - the ONLY defence is the blacklist above.
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
                message = "SQL error: {}".format(e)

            if row:
                message = "Login successful! Welcome, {}".format(row[1])
            elif not message:
                message = "Login failed."

    return render_template_string(LOGIN_HTML, message=message)


# ---------- GUESTBOOK with NAIVE XSS "protection" ----------
GUESTBOOK_HTML = """
<h1>Guestbook (Protected v1)</h1>
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


def naive_xss_filter(value):
    # Non-recursive, case-sensitive removal of exact "<script>" / "</script>".
    # Think about what payloads this does NOT catch.
    value = value.replace("<script>", "").replace("</script>", "")
    return value


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    db = get_db()
    cur = db.cursor()

    if request.method == "POST":
        author = request.form.get("author", "")
        body = request.form.get("body", "")
        body = naive_xss_filter(body)
        cur.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        db.commit()

    cur.execute("SELECT * FROM comments ORDER BY id DESC")
    comments = cur.fetchall()
    return render_template_string(GUESTBOOK_HTML, comments=comments)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5001, debug=True)
