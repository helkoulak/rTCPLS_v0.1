import subprocess
import re
import fire


def run_client_dt(iterations=10):
    """
    Run the client command multiple times and calculate the average time taken to download.

    Args:
        iterations (int): Number of times to run the client command.
    """
    result_file_path = "/home/helkoulak/Documents/r-tcpls-v-0-1/output.txt"  # Adjust the file path based on your setup
    run_client_command = [
        "./target/release/client_tcpls_mp_dt",
        "--cafile", "test-ca/rsa/server.crt",
        "-p", "8443",
        "10.0.0.1"
    ]

    # Change to the working directory
    working_dir = "/home/helkoulak/Documents/r-tcpls-v-0-1/"

    results = []

    for i in range(iterations):
        print(f"Running iteration {i + 1}/{iterations}...")
        try:
            # Run the CLI command
            subprocess.run(run_client_command, cwd=working_dir, check=True)

            # Read the result from the file
            try:
                with open(result_file_path, 'r') as file:
                    data = file.read()

                    # Extract the relevant result (e.g., a numeric value) from the file
                    match = re.search(r"Time taken to download (\d+) Bytes is ([\d.]+)(s|ms|µs)", data)
                    if match:
                        bytes_downloaded = int(match.group(1))
                        time_taken = float(match.group(2))
                        time_unit = match.group(3)

                        # Convert time based on the unit
                        if time_unit == 'ms':
                            time_taken /= 1000  # Convert milliseconds to seconds
                        elif time_unit == 'µs':
                            time_taken /= 1_000_000  # Convert microseconds to seconds
                        results.append(time_taken)
                        print(f"Iteration {i + 1}: {bytes_downloaded} Bytes in {time_taken} seconds")
                    else:
                        print(f"No valid result found in the file for iteration {i + 1}")
            except FileNotFoundError:
                print(f"Result file not found for iteration {i + 1}")
                continue
        except subprocess.CalledProcessError as e:
            print(f"Error running command in iteration {i + 1}: {e}")
            continue

    if results:
        # Calculate the average
        average = sum(results) / len(results)
        print(f"Results: {results}")
        print(f"Average download time: {average:.2f} seconds.")
    else:
        print("No results to calculate the average.")


if __name__ == "__main__":
    # Use fire to expose the function to the command line
    fire.Fire(run_client_dt)
