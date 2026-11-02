"""Deliberately vulnerable test application for SentinelGate lab use.

Run:  python -m testapp.app   (serves on http://127.0.0.1:5000)

WARNING: THIS APPLICATION IS INTENTIONALLY VULNERABLE. It reflects user input,
has no login lockout, reads arbitrary files, and exposes an admin panel.
Only run against localhost in a controlled lab. Never expose to a network.
"""

from __future__ import annotations

import os

from flask import Flask, abort, request

app = Flask(__name__)

FILES_DIR = os.path.join(os.path.dirname(__file__), "files")
os.makedirs(FILES_DIR, exist_ok=True)

WARNING_BANNER = (
    "DELIBERATELY VULNERABLE - lab use only. "
    "Do not deploy to production or expose to any network."
)


@app.get("/")
def home():
    return (
        "<h1>SentinelGate Test App</h1>"
        "<p>" + WARNING_BANNER + "</p>"
        "<ul>"
        "<li><a href='/search?q=hello'>/search?q=</a> (reflects input)</li>"
        "<li>/login (POST, no lockout)</li>"
        "<li>/file?name=sample.txt (reads a file)</li>"
        "<li>/admin</li>"
        "</ul>"
    )


@app.get("/search")
def search():
    """Reflects the q parameter back (reflected XSS vector)."""
    q = request.args.get("q", "")
    return f"<h1>Search results for: {q}</h1><p>{WARNING_BANNER}</p>"


@app.post("/login")
def login():
    """No lockout, no rate limiting on this endpoint by itself."""
    _username = request.form.get("username", "")
    _password = request.form.get("password", "")
    return f"<h1>Login attempted for {_username}</h1><p>{WARNING_BANNER}</p>"


@app.get("/file")
def read_file():
    """Reads a file from ./testapp/files (path traversal vector)."""
    name = request.args.get("name", "sample.txt")
    path = os.path.join(FILES_DIR, name)
    if not os.path.isfile(path):
        abort(404)
    with open(path, encoding="utf-8", errors="replace") as fh:
        content = fh.read()
    return f"<pre>{content}</pre><p>{WARNING_BANNER}</p>"


@app.get("/admin")
def admin():
    return f"<h1>Admin panel</h1><p>{WARNING_BANNER}</p>"


if __name__ == "__main__":
    # nosec: lab-only dev server bound to localhost.
    app.run(host="127.0.0.1", port=5000, debug=False)  # noqa: S104