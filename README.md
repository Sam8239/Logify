<p align="center">
  <img src="/banner/banner.png" />
</p>

# Logify - Log Management Application

**Logify** is a versatile logging application designed for efficient log management. It seamlessly integrates Elasticsearch and SQLite databases to ingest, store, and query logs. The app provides a user-friendly interface with robust search functionalities, allowing users to explore logs based on various criteria. Additionally, it offers export features for convenient data retrieval and analysis.

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Features

### Log Ingestor

#### Functionality:

- Receives log entries via HTTP POST requests to the `/ingest` endpoint.
- Stores log entries in both SQLite and Elasticsearch for persistence and search capabilities.

#### Database Configuration:

- SQLite database configuration is specified in the `SQLITE_DATABASE_FILE` variable.
- Elasticsearch configuration includes host, port, scheme, and client initialization.

#### SQLite Database:

- The `create_sqlite_database` function creates a table named `logs` with columns for various log attributes.
- Log entries are inserted into SQLite using `insert_log_entry_sqlite`.

#### Elasticsearch Indexing:

- Log entries are indexed into Elasticsearch using `index_log_entry_elasticsearch`.

#### API Endpoint:

- The `/ingest` endpoint receives JSON log entries and processes them.

### Query Interface

#### Functionality:

- Allows users to search and export logs based on specified filters.
- Filters include timestamp range, log level, message, resourceId, traceId, and more.

#### Database Configuration:

- Similar to the log ingestor, it uses SQLite for local storage and Elasticsearch for search capabilities.

#### SQLite Database:

- The `create_sqlite_database` function creates a table named `logs` with columns similar to the log ingestor.
- The `query_logs_sqlite` function queries logs from SQLite based on specified filters.

#### Elasticsearch Querying:

- The `query_logs_elasticsearch` function queries logs from Elasticsearch based on specified filters.

#### Hybrid Querying:

- The `query_logs` function decides whether to query logs from SQLite or Elasticsearch based on the number of filters and their types.

#### Full Text Search:

- The `full_text_search` function extracts filters from the provided query text using regular expressions.

#### Exporting Logs:

- The `/export` endpoint allows exporting logs to a CSV file.

### Search Interface:

- The `/search` endpoint handles user searches, both regular and full-text, returning paginated results.

### Export Feature:

- The `/export` endpoint is used for exporting the logs.

## Getting Started

### Prerequisites

- Python (version 3.10)
- Flask
- SQLite
- Elasticsearch

### Installation

#### 1. Clone the repository:

```bash
git clone https://github.com/yourusername/logify.git
cd logify
```
#### 2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Follow these steps to run and interact with the Logify application:

### 1. Run the App:
 
```bash
python logify.py
```

### 2. Access the App:
Access the app at http://localhost:5000.

## Contributing

If you'd like to contribute to the project:

-  Fork the repository on GitHub.
-  Clone your fork of the repository.
-  Create a new branch for your feature or bug fix.
-  Make changes and commit them to your branch.
-  Push your changes to your fork.
-  Open a pull request on the original repository.

Feel free to explore additional features, functionalities, or configurations based on your requirements.

## License
This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/Sam8239/Log-Ingestor-and-Query-Interface/blob/main/LICENSE.md) file for details.
