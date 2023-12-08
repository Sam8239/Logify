from flask import (
    Flask,
    flash,
    redirect,
    url_for,
    session,
    render_template,
    request,
)
from authlib.integrations.flask_client import OAuth
import sqlite3

from requests_oauthlib import OAuth2Session

app = Flask(__name__)
app.secret_key = "hfdshf4r3fhfds"

oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id="733206789517-gov8spukuv8ou0k1nf192qjskmmlh14e.apps.googleusercontent.com",
    client_secret="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",
    redirect_uri="http://localhost:5000/login/authorized",
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
)


def create_user_table():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL DEFAULT 'normal'
        )
    """
    )
    conn.commit()
    conn.close()


# To add admin user
def add_admin_user():
    email = "coolshubham1999@gmail.com"  # Add your email
    role = "admin"

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user WHERE email = ?", (email,))
    user = cursor.fetchone()
    if not user:
        # Set the role when signing up
        cursor.execute("INSERT INTO user (email, role) VALUES (?, ?)", (email, role))
        conn.commit()
        user_id = cursor.lastrowid
        cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
    conn.close()


def create_user(email, role="normal"):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user WHERE email = ?", (email,))
    user = cursor.fetchone()
    if not user:
        # Set the role when signing up
        cursor.execute("INSERT INTO user (email, role) VALUES (?, ?)", (email, role))
        conn.commit()
        user_id = cursor.lastrowid
        cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
    conn.close()
    user = list(user)
    return user


def get_user(email):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        user = list(user)
    return user


@app.route("/")
def index():
    if "google_token" in session:
        try:
            # Create an OAuth2Session with the access token
            oauth_session = OAuth2Session(
                client_id=google.client_id, token=session["google_token"]
            )

            # Make a request to the userinfo endpoint
            user_info = oauth_session.get(
                "https://www.googleapis.com/oauth2/v2/userinfo"
            )

            # Check if the request was successful
            user_info.raise_for_status()

            # Get the user in the database
            user = get_user(user_info.json()["email"])

            return redirect(url_for("dashboard", role=user[2]))
        except Exception as e:
            return f"Error during user info retrieval: {str(e)}"
    else:
        return render_template("index.html")


@app.route("/sign_up", methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        email = request.form.get("email")

        # Check if the user with the same email already exists
        existing_user = get_user(email)

        if existing_user:
            flash(
                "User with this email already exists. Please use a different email or Sign in."
            )
            return redirect(url_for("sign_up"))
        else:
            create_user(email)
            flash(
                "Your account with Email: "
                + email
                + " has been created. You can Sign in now."
            )
            return redirect(url_for("sign_in"))
    return render_template("sign_up.html")


@app.route("/add_users", methods=["GET", "POST"])
def add_users():
    if request.method == "POST":
        email = request.form.get("email")
        role = request.form.get("role")

        # Check if the user with the same email already exists
        existing_user = get_user(email)

        if existing_user:
            flash(
                "User with this email already exists. Please use a different email or Sign in."
            )
        else:
            create_user(email, role)
            flash("User with Email: " + email + "has been created.")
    return render_template("add_users.html")


@app.route("/sign_in")
def sign_in():
    return render_template("sign_in.html")


# Google Sign In
@app.route("/login")
def login():
    return google.authorize_redirect(redirect_uri=url_for("authorized", _external=True))


# Google Sign Out
@app.route("/logout")
def logout():
    session.pop("google_token", None)
    session.pop("user_info", None)
    return redirect(url_for("index"))


# Dashboard as per Role
@app.route("/dashboard")
def dashboard():
    # Retrieve user information from the session
    user_info = session.get("user_info")

    if user_info:
        role = get_user(user_info["email"])[2]  # Get user role from db
        return render_template("dashboard.html", user_info=user_info, role=role)

    else:
        flash("User information not found. Please sign in.")
        return redirect(url_for("sign_in"))


# Checking OAuth Authorization with Google
@app.route("/login/authorized")
def authorized():
    try:
        # Fetch the access token from the Google OAuth server
        try:
            token = google.authorize_access_token()
        except Exception as e:
            return f"Error during token retrieval: {str(e)}"

        nonce = session.pop("google_nonce", None)

        # Use the access token and nonce to get user information from the ID token
        user_info = google.parse_id_token(token, nonce=nonce)

        user = get_user(user_info["email"])

        if user:
            session["user_info"] = user_info
            session["google_token"] = token
            return redirect(url_for("dashboard"))
        else:
            # If user doesn't exist, redirect to sign up
            flash("User not found. Please sign up.")
            return redirect(url_for("sign_up"))

    except Exception as e:
        return f"Error: {str(e)}"


if __name__ == "__main__":
    create_user_table()
    add_admin_user()
    app.run(debug=True)
