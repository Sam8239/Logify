import json
import os
import sys
from flask import Flask, render_template, request, jsonify, send_file

from flask_socketio import SocketIO, emit
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    current_user,
)
from datetime import datetime
from elasticsearch import Elasticsearch
import sqlite3
import re
import csv
from io import StringIO

app = Flask(__name__)
socketio = SocketIO(app)
login_manager = LoginManager(app)

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


# Mock User class for demonstration purposes
class User(UserMixin):
    def __init__(self, id):
        self.id = id


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


# Create SQLite Database Table
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
                        key: {"parentResourceId": value}
                        if key == "metadata.parentResourceId"
                        else value
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


# Merge Two Filters
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


# Flask Login Protected Route for Demonstration Purposes
@app.route("/protected")
@login_required
def protected():
    return "Logged in as: " + current_user.id + " (protected route)"


@app.route("/")
def index():
    return render_template("index.html")


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


if __name__ == "__main__":
    create_sqlite_database()
    socketio.run(app, port=3001)
