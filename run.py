import concurrent.futures
import subprocess

log_ingestor = "log_ingestor.py"
query_interface = "query_interface.py"

# Replace with elasticsearch.bat location
elastic_search = r"C:\Users\cools\OneDrive\Desktop\Log Ingestor and Query Interface\elasticsearch\bin\elasticsearch.bat"


def run_command(command):
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running {command}: {e}")


# Create a ThreadPoolExecutor with max_workers set to the number of processes you want to run concurrently
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
    # Submit each command to the executor
    future_log_ingestor = executor.submit(run_command, ["python", log_ingestor])
    future_query_interface = executor.submit(run_command, ["python", query_interface])
    future_elastic_search = executor.submit(run_command, [elastic_search])

    # Wait for all tasks to complete
    concurrent.futures.wait(
        [future_log_ingestor, future_query_interface, future_elastic_search]
    )
