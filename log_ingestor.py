from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from elasticsearch import Elasticsearch
import sqlite3
import datetime
import json

app = Flask(__name__)
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


@app.route("/ingest", methods=["POST"])
def ingest_log():
    data = request.get_json()

    # Add timestamp to the log entry
    timestamp = datetime.datetime.utcnow().isoformat()

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


if __name__ == "__main__":
    create_sqlite_database()
    socketio.run(app, port=3000)
