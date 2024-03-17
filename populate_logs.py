import requests
import json
from datetime import datetime
import time

# Log ingestor endpoint
ingestor_url = "https://logify-x2tq.onrender.com/ingest"

# Sample log data
log_data = {
    "level": "info",
    "message": "Application started",
    "resourceId": "server-1234",
    "timestamp": "",
    "traceId": "abc-xyz-123",
    "spanId": "span-456",
    "commit_hash": "5e5342f",
    "metadata": {"parentResourceId": "server-0987"},
}

# Number of logs to generate
num_logs = 10

# Send logs to the log ingestor
for _ in range(num_logs):
    # Update timestamp for each log
    log_data["timestamp"] = datetime.utcnow().isoformat() + "Z"

    try:
        response = requests.post(ingestor_url, json=log_data)
        if response.status_code == 200:
            print("Log ingested successfully.")
        else:
            print(f"Failed to ingest log. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error sending log: {e}")
