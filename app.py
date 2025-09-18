from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
import sqlite3, hashlib, os, qrcode, random, csv
from datetime import datetime, timedelta
from functools import wraps
# ---------------- App Setup ----------------
app = Flask(__name__)
app.secret_key = "supersecretkey"

# Ensure QR codes folder exists
os.makedirs("static/qr_codes", exist_ok=True)


# ---------------- Database Setup ----------------
def init_db():
    conn = sqlite3.connect("crops.db")
    c = conn.cursor()

    # Crops table
    c.execute("""
        CREATE TABLE IF NOT EXISTS crops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farmer_name TEXT,
            crop_name TEXT,
            variety TEXT,
            location TEXT,
            harvest_date TEXT,
            quantity INTEGER,
            price REAL,
            total REAL,
            data_hash TEXT,
            qr_code_path TEXT,
            status TEXT DEFAULT 'Pending',
            user_id INTEGER,
            rejected_date TEXT
        )
    """)

    # Users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()


init_db()


def get_db_connection():
    conn = sqlite3.connect("crops.db")
    conn.row_factory = sqlite3.Row
    return conn


# ---------------- Decorators ----------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Admin access only!")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper


# ---------------- Routes ----------------
@app.route("/")
def home_redirect():
    return redirect(url_for("login"))


@app.route("/index")
@login_required
def index():
    return render_template("index.html")


# ---------------- User Signup ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # Basic validations
        if not name or not email or not password:
            flash("All fields are required!")
            return redirect(url_for("signup"))

        if password != confirm:
            flash("Passwords do not match!")
            return redirect(url_for("signup"))

        hashed_pw = hashlib.sha256(password.encode()).hexdigest()

        try:
            with get_db_connection() as conn:
                conn.execute(
                    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                    (name, email, hashed_pw),
                )
                conn.commit()
            flash("Account created successfully! Please login.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already exists. Please use another.")
            return redirect(url_for("signup"))

    return render_template("user_signup.html")

# ---------------- User Login ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db_connection()
        row = conn.execute(
            "SELECT id FROM users WHERE email=? AND password=?", (email, hashed_pw)
        ).fetchone()
        conn.close()

        if row:
            session["user_id"] = row["id"]
            flash("Login successful!")
            return redirect(url_for("index"))
        else:
            flash("Invalid email or password.")
            return redirect(url_for("login"))

    return render_template("user_login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("login"))


@app.route("/about")
def about():
    return render_template("about.html")


# ---------------- Farmer Crop Registration ----------------
@app.route("/register", methods=["GET", "POST"])
@login_required
def register():
    if request.method == "POST":
        farmer_name = request.form["farmer_name"]
        crop_name = request.form["crop_name"]
        variety = request.form["crop_variety"]
        location = request.form["location"]
        harvest_date = request.form["harvest_date"]
        quantity = int(request.form["quantity"])
        price = float(request.form["price"])
        total = quantity * price

        data_string = f"{farmer_name}{crop_name}{variety}{location}{harvest_date}{quantity}{price}"
        data_hash = hashlib.sha256(data_string.encode()).hexdigest()

        conn = get_db_connection()
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO crops 
            (farmer_name, crop_name, variety, location, harvest_date, quantity, price, total, data_hash, qr_code_path, status, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                farmer_name,
                crop_name,
                variety,
                location,
                harvest_date,
                quantity,
                price,
                total,
                data_hash,
                "",
                "Pending",
                session["user_id"],
            ),
        )
        crop_id = c.lastrowid
        conn.commit()
        conn.close()

        # Generate QR Code
        qr_img = qrcode.make(data_hash)
        qr_path = f"static/qr_codes/crop_{crop_id}.png"
        qr_img.save(qr_path)

        conn = get_db_connection()
        conn.execute("UPDATE crops SET qr_code_path=? WHERE id=?", (qr_path, crop_id))
        conn.commit()
        conn.close()

        return redirect(url_for("display_qr", crop_id=crop_id))

    return render_template("farmer_register.html")


@app.route("/my_catlog")
@login_required
def my_catlog():
    conn = get_db_connection()
    crops = conn.execute(
        "SELECT * FROM crops WHERE user_id=?", (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template("my_catlog.html", crops=crops)

# ---------------- Consumer Scan ----------------
@app.route("/scan")
def scan():
    return render_template("consumer_scan.html")


@app.route("/verify_crop", methods=["POST"])
def verify_crop():
    entered_hash = request.form["crop_id"].strip()

    conn = get_db_connection()
    crop = conn.execute("SELECT * FROM crops WHERE data_hash=?", (entered_hash,)).fetchone()
    conn.close()

    if not crop:
        return render_template("consumer_scan.html", error="No crop found for this hash.")

    # Hide rejected crops after 30 days
    if crop["status"] == "Rejected" and crop["rejected_date"]:
        rejected_date = datetime.strptime(crop["rejected_date"], "%Y-%m-%d")
        if datetime.now() > rejected_date + timedelta(days=30):
            return render_template("consumer_scan.html", error="No crop found for this hash.")

    return render_template("consumer_scan.html", crop=crop, verified=True)


# ---------------- Admin Login + OTP ----------------
@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        if username == "admin" and password == "admin123":
            otp = str(random.randint(100000, 999999))
            session["pending_admin"] = True
            session["generated_otp"] = otp
            return render_template("otp_verify.html", otp=otp)
        else:
            flash("Invalid credentials")
            return render_template("admin_login.html")

    return render_template("admin_login.html")


@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    entered_otp = request.form["otp"].strip()
    if session.get("pending_admin") and entered_otp == session.get("generated_otp"):
        session.pop("pending_admin", None)
        session.pop("generated_otp", None)
        session["admin_logged_in"] = True
        return redirect(url_for("admin_dashboard"))
    else:
        flash("Invalid OTP")
        return render_template("otp_verify.html")


@app.route("/admin_logout")
@admin_required
def admin_logout():
    session.pop("admin_logged_in", None)
    flash("Admin logged out.")
    return redirect(url_for("admin_login"))


# ---------------- Admin Dashboard ----------------
@app.route("/admin_dashboard")
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    crops = conn.execute("SELECT * FROM crops").fetchall()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return render_template("admin_dashboard.html", crops=crops, users=users)


# ---------------- Admin Actions ----------------
@app.route("/approve_crop/<int:crop_id>")
@admin_required
def approve_crop(crop_id):
    conn = get_db_connection()
    conn.execute("UPDATE crops SET status='Approved' WHERE id=?", (crop_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_dashboard"))


@app.route("/reject_crop/<int:crop_id>")
@admin_required
def reject_crop(crop_id):
    rejected_on = datetime.now().strftime("%Y-%m-%d")
    conn = get_db_connection()
    conn.execute("UPDATE crops SET status='Rejected', rejected_date=? WHERE id=?", (rejected_on, crop_id))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_dashboard"))


@app.route("/delete_crop/<int:crop_id>")
@admin_required
def delete_crop(crop_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM crops WHERE id=?", (crop_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_dashboard"))


@app.route("/delete_user/<int:user_id>")
@admin_required
def delete_user(user_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_dashboard"))


@app.route("/export/<string:table>")
@admin_required
def export_table(table):
    filename = f"{table}.csv"

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(f"SELECT * FROM {table}")
    rows = c.fetchall()
    headers = [desc[0] for desc in c.description]
    conn.close()

    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows([tuple(row) for row in rows])

    return send_file(filename, as_attachment=True)


# ---------------- Display QR ----------------
@app.route("/display_qr/<int:crop_id>")
def display_qr(crop_id):
    conn = get_db_connection()
    crop = conn.execute("SELECT * FROM crops WHERE id=?", (crop_id,)).fetchone()
    conn.close()
    if not crop:
        return "Crop not found", 404
    return render_template("qr_display.html", crop=crop)


# ---------------- Run ----------------
if __name__ == "__main__":
    app.run(debug=True)
