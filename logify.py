import json
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    flash,
    redirect,
    url_for,
    session,
)
from authlib.integrations.flask_client import OAuth
from requests_oauthlib import OAuth2Session
from flask_socketio import SocketIO

from datetime import datetime
from elasticsearch import Elasticsearch
import sqlite3
import re
import csv
from io import StringIO
import os
from dotenv import load_dotenv


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
socketio = SocketIO(app)

# SQLite Database Configuration
SQLITE_DATABASE_FILE = "logs.db"

# Elasticsearch Configuration
ELASTICSEARCH_INDEX = "logs_index"
ELASTICSEARCH_HOST = "localhost"
ELASTICSEARCH_PORT = 9200
ELASTICSEARCH_SCHEME = "http"
ELASTICSEARCH_CLIENT = Elasticsearch(
    [
        {
            "host": ELASTICSEARCH_HOST,
            "port": ELASTICSEARCH_PORT,
            "scheme": ELASTICSEARCH_SCHEME,
        }
    ]
)

# Google Authentication Setup
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.getenv("CLIENT_ID"),
    client_secret=os.getenv("CLIENT_SECRET"),
    redirect_uri="http://localhost:5000/login/authorized",
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
)


# Functions Starts
# Log Ingestor Function Starts
# Create SQLite Database for Logs
def create_sqlite_database():
    try:
        conn = sqlite3.connect(SQLITE_DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                level TEXT,
                message TEXT,
                resourceId TEXT,
                traceId TEXT,
                spanId TEXT,
                commit_hash TEXT,
                metadata TEXT
            )
        """
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error creating SQLite database: {e}")
    finally:
        if conn:
            conn.close()


def insert_log_entry_sqlite(log_entry):
    try:
        conn = sqlite3.connect(SQLITE_DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO logs (
                timestamp, level, message, resourceId, traceId, spanId, commit_hash, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                log_entry["timestamp"],
                log_entry["level"],
                log_entry["message"],
                log_entry["resourceId"],
                log_entry["traceId"],
                log_entry["spanId"],
                log_entry["commit_hash"],
                json.dumps(log_entry["metadata"]),
            ),
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error inserting log entry into SQLite database: {e}")
    finally:
        if conn:
            conn.close()


def index_log_entry_elasticsearch(log_entry):
    try:
        ELASTICSEARCH_CLIENT.index(index=ELASTICSEARCH_INDEX, body=log_entry)
    except Exception as e:
        print(f"Error indexing log entry into Elasticsearch: {e}")


def insert_log_entries(log_entries):
    for log_entry in log_entries:
        insert_log_entry_sqlite(log_entry)
        index_log_entry_elasticsearch(log_entry)


# Log Ingestor Function Ends


# Create SQLite Database for Users
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


# Create Users
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


# Get User
def get_user(email):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        user = list(user)
    return user


# Remove User
def remove_user(email):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM user WHERE email = ?", (email,))
    conn.commit()
    conn.close()


# Query Interface Function Sarts
# SQLite Query Logs
def query_logs_sqlite(filters, page, page_size):
    try:
        conn = sqlite3.connect(SQLITE_DATABASE_FILE)
        cursor = conn.cursor()

        # Constructing the SQL query based on filters
        query = "SELECT * FROM logs"
        conditions = []
        values = []

        for key, value in filters.items():
            # To handle nested JSON
            if key == "metadata.parentResourceId" and value:
                conditions.append('JSON_EXTRACT(metadata, "$.parentResourceId") = ?')
                values.append(value)

            # Skip empty values
            elif value and key not in [
                "start_timestamp",
                "end_timestamp",
                "start_date",
                "end_date",
            ]:
                conditions.append(f"{key} = ?")
                values.append(value)

        # Handle Timestamp Range and Date Range Queries
        if (
            "start_timestamp" in filters
            and "end_timestamp" in filters
            or "start_date" in filters
            and "end_date" in filters
            and filters["start_date"]
            and filters["end_date"]
        ):
            if (
                "start_timestamp" in filters
                and "end_timestamp" in filters
                and "start_date" in filters
                and "end_date" in filters
                and filters["start_date"]
                and filters["end_date"]
            ):
                start_timestamp, end_timestamp = (
                    max(
                        filters["start_timestamp"],
                        datetime.strptime(
                            filters["start_date"], "%Y-%m-%d"
                        ).isoformat(),
                    ),
                    min(
                        filters["end_timestamp"],
                        datetime.strptime(filters["end_date"], "%Y-%m-%d").isoformat(),
                    ),
                )
            elif (
                "start_date" in filters
                and "end_date" in filters
                and filters["start_date"]
                and filters["end_date"]
            ):
                start_timestamp, end_timestamp = (
                    datetime.strptime(filters["start_date"], "%Y-%m-%d").isoformat(),
                    datetime.strptime(filters["end_date"], "%Y-%m-%d").isoformat(),
                )
            else:
                start_timestamp, end_timestamp = (
                    filters["start_timestamp"],
                    filters["end_timestamp"],
                )
            conditions.append("? <= timestamp AND timestamp <= ?")
            values.extend([start_timestamp, end_timestamp])

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        # Count total records
        count_query = f"SELECT COUNT(*) FROM logs {'' if not conditions else 'WHERE ' + ' AND '.join(conditions)}"
        cursor.execute(count_query, tuple(values))
        total_records = cursor.fetchone()[0]

        # Apply pagination
        query += f" LIMIT ? OFFSET ?"
        values.extend([page_size, (page - 1) * page_size])
        cursor.execute(query, tuple(values))
        paginated_results = cursor.fetchall()

        return (
            total_records,
            [
                {
                    "timestamp": col[1],
                    "level": col[2],
                    "message": col[3],
                    "resourceId": col[4],
                    "traceId": col[5],
                    "spanId": col[6],
                    "commit_hash": col[7],
                    "metadata": json.loads(col[8]),
                }
                for col in paginated_results
            ],
        )

    except sqlite3.Error as e:
        print(f"Error querying logs from SQLite: {e}")
        return 0, []

    finally:
        if conn:
            conn.close()


# Elasticsearch Query Logs
def query_logs_elasticsearch(filters, page, page_size):
    try:
        query_body = {"query": {"bool": {"must": []}}}

        for key, value in filters.items():
            # Skip empty values to avoid unnecessary match conditions
            if value:
                query_body["query"]["bool"]["must"].append({"match": {key: value}})

        # Only perform the search if there are valid match conditions
        if query_body["query"]["bool"]["must"]:
            result = ELASTICSEARCH_CLIENT.search(
                index=ELASTICSEARCH_INDEX,
                body=query_body,
                size=page_size,
                from_=((page - 1) * page_size),
            )
            hits = result["hits"]["hits"]
            total_records = result["hits"]["total"]["value"]

            return (
                total_records,
                [
                    {
                        key: (
                            {"parentResourceId": value}
                            if key == "metadata.parentResourceId"
                            else value
                        )
                        for key, value in hit["_source"].items()
                    }
                    for hit in hits
                ],
            )

        else:
            print("No valid match conditions, skipping search.")
            return 0, []

    except Exception as e:
        print(f"Error querying logs from Elasticsearch: {e}")
        return 0, []


# Hybrid Query Logs
def query_logs(filters, page, page_size):
    try:
        len_filters = len(list(filter(lambda x: x != "", filters.values())))
        # If no filters then return empty array

        if not len_filters:
            return 0, []

        # If more than 1 filters query from SQLite
        elif (
            len_filters > 1
            or "start_timestamp" in filters
            and "end_timestamp" in filters
            or "start_date" in filters
            and "end_date" in filters
            and filters["start_date"]
            and filters["end_date"]
        ):
            return query_logs_sqlite(filters, page, page_size)

        # If only 1 filter then query from Elastic Search
        else:
            return query_logs_elasticsearch(filters, page, page_size)

    except Exception as e:
        print(f"Error querying logs: {e}")
        return 0, []


# Full Text Search
def full_text_search(query, filters):
    # Generalized regular expressions for different query patterns
    patterns = {
        re.compile(r'.*level.*"([^"]+)"', re.IGNORECASE): "level",
        re.compile(r'.*message.*"([^"]+)"', re.IGNORECASE): "message",
        re.compile(r'.*resourceid.*"([^"]+)"', re.IGNORECASE): "resourceId",
        re.compile(
            r'.*timestamp.*"([^"]+)"+.*and.*"([^"]+)"', re.IGNORECASE
        ): "timestamp_range",
    }

    for pattern, key in patterns.items():
        match = re.search(pattern, query)
        if match:
            if key == "timestamp_range":
                # For timestamp range, match two groups
                start_timestamp, end_timestamp = match.groups()
                filters["start_timestamp"] = start_timestamp
                filters["end_timestamp"] = end_timestamp
            else:
                value = match.group(1)
                filters[key] = value.lower()

    return filters


# Compare Values Between Filters Only For Common Keys
def are_values_different(filters1, filters2):
    common_keys = set(filters1) & set(filters2)
    return any(
        filters1[key] != filters2[key] and filters1[key] != "" and filters2[key] != ""
        for key in common_keys
    )


# Merge Filters from Full Text and Filters Search
def merge_filters(filters1, filters2):
    return {
        key: filters1.get(key, filters2.get(key, ""))
        or filters2.get(key, filters1.get(key, ""))
        for key in set(filters1) | set(filters2)
    }


def export_to_csv(results):
    csv_data = StringIO()
    csv_writer = csv.writer(csv_data)

    # Write header
    header = [
        "timestamp",
        "level",
        "message",
        "resourceId",
        "traceId",
        "spanId",
        "commit_hash",
        "metadata",
    ]
    csv_writer.writerow(header)

    # Write data
    for result in results:
        row = [
            result.get("timestamp", ""),
            result.get("level", ""),
            result.get("message", ""),
            result.get("resourceId", ""),
            result.get("traceId", ""),
            result.get("spanId", ""),
            result.get("commit_hash", ""),
            json.dumps(result.get("metadata", {})),
        ]
        csv_writer.writerow(row)

    return csv_data.getvalue()


# Query Interface Function Ends
# Functions Ends


# Routes Starts
# Index
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


# Privacy Policy
@app.route("/privacy_policy")
def privacy_policy():
    return render_template("privacy_policy.html")


# Terms of Service
@app.route("/terms_of_service")
def terms_of_service():
    return render_template("terms_of_service.html")


# Sign up
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


# Sign in
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


# Add Users
@app.route("/add_users", methods=["GET", "POST"])
def add_users():
    if request.method == "POST":
        email = request.form.get("email")
        role = request.form.get("role")

        # Check if the user with the same email already exists
        existing_user = get_user(email)

        if existing_user:
            flash(
                f"User with email {email} already exists. Please use a different email or Sign in."
            )
        else:
            create_user(email, role)
            flash(f"User with Email: {email} has been created.")
    return render_template("add_users.html")


# Remove Users
@app.route("/remove_users", methods=["GET", "POST"])
def remove_users():
    if request.method == "POST":
        email = request.form.get("email")

        # Check if the user with the same email already exists
        existing_user = get_user(email)

        if not existing_user:
            flash(
                f"User with email {email} doest not exist. Please use a different email."
            )
        else:
            remove_user(email)
            flash(f"User with Email: {email} has been removed.")
    return render_template("remove_users.html")


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


# Log Ingestor Starts
@app.route("/log_ingestor")
def log_ingestor():
    return render_template("log_ingestor.html")


# Ingest Logs
@app.route("/ingest", methods=["POST"])
def ingest_log():
    data = request.get_json()

    # Add timestamp to the log entry
    timestamp = datetime.utcnow().isoformat()

    # Construct log entry
    log_entry = {
        "timestamp": timestamp,
        "level": data["level"],
        "message": data["message"],
        "resourceId": data["resourceId"],
        "traceId": data["traceId"],
        "spanId": data["spanId"],
        "commit_hash": data["commit_hash"],
        "metadata": data.get("metadata", {}),
    }

    insert_log_entries([log_entry])

    return jsonify({"status": "success", "log": log_entry})


# Log Ingestor Ends


# Query Interface Starts
@app.route("/query_interface")
def query_interface():
    return render_template("query_interface.html")


# Export Logs
@app.route("/export")
def export_logs():
    # Check if the request method is GET
    if request.method == "GET":
        # Extract filters from the query parameters
        filters = request.args.to_dict()

        # Initialize page and page size
        page = 1
        page_size = 1000  # Choose a reasonable page size

        # Initialize the list to store all results
        all_results = []

        # Fetch results in chunks until no more records
        while True:
            total_records, results = query_logs(filters, page, page_size)

            if not results:
                break  # No more records to fetch

            all_results.extend(results)
            page += 1

        # Export to CSV using all_results
        csv_data = export_to_csv(all_results)

        # Save CSV data to a temporary file
        temp_file_path = "temp_export.csv"
        with open(temp_file_path, "w") as temp_file:
            temp_file.write(csv_data)

        # Send the file for download
        response = send_file(
            temp_file_path,
            as_attachment=True,
            download_name="exported_logs.csv",
            mimetype="text/csv",
        )

        return response
    else:
        # Handle other request methods if needed
        return "Method Not Allowed", 405


# Query Interface Search
@app.route("/search", methods=["POST"])
def search_logs():
    query_text = request.form.get("query_text")
    # Filters from fields other than 'Full Text Search' field
    form_filters = {
        key: request.form.get(key).lower()
        for key in request.form
        if key != "query_text" and key != "page"
    }

    # Extract text_search_filters if query_text is provided
    if query_text:
        form_filters_copy = {key: "" for key in form_filters}

        # Filters from 'Full Text Search' field
        text_search_filters = full_text_search(query_text, form_filters_copy)

        # Checking if any value in both filters is different
        if are_values_different(form_filters, text_search_filters):
            return jsonify(results=[], com="error")
        else:
            filters = merge_filters(text_search_filters, form_filters)

    else:
        filters = form_filters

    page = int(request.form.get("page", 1))
    page_size = 10  # Number of records per page

    total_records, results = query_logs(filters, page, page_size)

    return jsonify(
        results=results,
        query_text=query_text,
        filters=filters,
        com="success",
        currentPage=page,
        pageSize=page_size,
        totalRecords=total_records,
        totalPages=(total_records + page_size - 1) // page_size,
        exportUrl="/export",
    )


# Query Interface Ends
# Routes Ends

if __name__ == "__main__":
    create_sqlite_database()
    create_user_table()
    create_user("coolshubham1999@gmail.com", "admin")
    socketio.run(app, port=5000, debug="true", allow_unsafe_werkzeug=True)
