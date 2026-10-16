import os
import sqlite3
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("NSCEN_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    # লোকাল পরীক্ষার জন্য; অনলাইনে পরিবেশ ভেরিয়েবল সেট করুন
    app.config["SECRET_KEY"] = os.urandom(32).hex()

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("NSCEN_HTTPS", "0") == "1"
app.config["WTF_CSRF_TIME_LIMIT"] = 3600

CSRFProtect(app)
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nscen.db")


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','agent')),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT DEFAULT '',
            email TEXT DEFAULT '',
            company TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    con.commit()
    return con


def user_count():
    con = db()
    count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    con.close()
    return count


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    con = db()
    user = con.execute(
        "SELECT id, username, role FROM users WHERE id = ?", (uid,)
    ).fetchone()
    con.close()
    return user


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if user["role"] != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if user_count() > 0:
        return redirect(url_for("login"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(username) < 3:
            flash("Username কমপক্ষে ৩ অক্ষরের হতে হবে।", "error")
        elif len(password) < 12:
            flash("Password কমপক্ষে ১২ অক্ষরের দিন।", "error")
        elif password != confirm:
            flash("দুটি Password মিলছে না।", "error")
        else:
            con = db()
            con.execute(
                "INSERT INTO users(username, password_hash, role) VALUES (?, ?, 'admin')",
                (username, generate_password_hash(password))
            )
            con.commit()
            con.close()
            flash("Admin অ্যাকাউন্ট তৈরি হয়েছে। এখন Login করুন।", "success")
            return redirect(url_for("login"))
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))
    if user_count() == 0:
        return redirect(url_for("setup"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        con = db()
        user = con.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        con.close()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash("স্বাগতম, " + user["username"], "success")
            destination = request.args.get("next", "")
            if not destination.startswith("/") or destination.startswith("//"):
                destination = url_for("dashboard")
            return redirect(destination)
        flash("Username অথবা Password ভুল।", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("আপনি Logout করেছেন।", "success")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    con = db()
    count = con.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
    con.close()
    return render_template("index.html", customer_count=count, user=current_user())


@app.route("/crm")
@login_required
def customers():
    q = request.args.get("q", "").strip()
    con = db()
    if q:
        like = "%" + q + "%"
        rows = con.execute("""
            SELECT * FROM customers
            WHERE name LIKE ? OR phone LIKE ? OR email LIKE ? OR company LIKE ?
            ORDER BY id DESC
        """, (like, like, like, like)).fetchall()
    else:
        rows = con.execute(
            "SELECT * FROM customers ORDER BY id DESC"
        ).fetchall()
    con.close()
    return render_template(
        "customers.html", customers=rows, q=q, user=current_user()
    )


@app.route("/crm/add", methods=["GET", "POST"])
@login_required
def add_customer():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("গ্রাহকের নাম দিতে হবে।", "error")
            return redirect(url_for("add_customer"))
        con = db()
        con.execute("""
            INSERT INTO customers(name, phone, email, company, notes)
            VALUES (?, ?, ?, ?, ?)
        """, (
            name, request.form.get("phone", "").strip(),
            request.form.get("email", "").strip(),
            request.form.get("company", "").strip(),
            request.form.get("notes", "").strip()
        ))
        con.commit()
        con.close()
        flash("গ্রাহক যোগ হয়েছে।", "success")
        return redirect(url_for("customers"))
    return render_template("customer_form.html", customer=None, user=current_user())


@app.route("/crm/<int:cid>/edit", methods=["GET", "POST"])
@admin_required
def edit_customer(cid):
    con = db()
    customer = con.execute(
        "SELECT * FROM customers WHERE id = ?", (cid,)
    ).fetchone()
    con.close()
    if customer is None:
        abort(404)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("গ্রাহকের নাম দিতে হবে।", "error")
            return redirect(url_for("edit_customer", cid=cid))
        con = db()
        con.execute("""
            UPDATE customers SET name=?, phone=?, email=?, company=?, notes=?
            WHERE id=?
        """, (
            name, request.form.get("phone", "").strip(),
            request.form.get("email", "").strip(),
            request.form.get("company", "").strip(),
            request.form.get("notes", "").strip(), cid
        ))
        con.commit()
        con.close()
        flash("গ্রাহকের তথ্য আপডেট হয়েছে।", "success")
        return redirect(url_for("customers"))
    return render_template("customer_form.html", customer=customer, user=current_user())


@app.route("/crm/<int:cid>/delete", methods=["POST"])
@admin_required
def delete_customer(cid):
    con = db()
    con.execute("DELETE FROM customers WHERE id = ?", (cid,))
    con.commit()
    con.close()
    flash("গ্রাহক ডিলিট করা হয়েছে।", "success")
    return redirect(url_for("customers"))


@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def manage_users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "agent")
        if len(username) < 3:
            flash("Username কমপক্ষে ৩ অক্ষরের হতে হবে।", "error")
        elif len(password) < 12:
            flash("Password কমপক্ষে ১২ অক্ষরের হতে হবে।", "error")
        elif role not in ("admin", "agent"):
            flash("Role সঠিক নয়।", "error")
        else:
            try:
                con = db()
                con.execute(
                    "INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), role)
                )
                con.commit()
                con.close()
                flash("নতুন User তৈরি হয়েছে।", "success")
                return redirect(url_for("manage_users"))
            except sqlite3.IntegrityError:
                flash("এই Username আগে থেকেই আছে।", "error")
    con = db()
    users = con.execute(
        "SELECT id, username, role, created_at FROM users ORDER BY id"
    ).fetchall()
    con.close()
    return render_template("users.html", users=users, user=current_user())


@app.errorhandler(403)
def forbidden(error):
    return render_template("403.html"), 403


if __name__ == "__main__":
    db().close()
    app.run(host="127.0.0.1", port=8082, debug=False)
