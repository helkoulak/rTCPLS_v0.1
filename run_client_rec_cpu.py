import subprocess
import re
import fire


def run_client_rec_cpu(iter=10, report_file="perf.txt"):
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

    cpupower_set_command = [
        "sudo",
        "cpupower",
        "-c", "0",
        "frequency-set",
        "-d", "2799MHz",
        "-u", "2800MHz",
        "-g", "performance"
    ]
    subprocess.run(cpupower_set_command, check=True)

    task_set_command = ["taskset", "-c", "0", "perf", "stat", "-e", "cycles"] + run_client_command

    cpupower_unset_command = [
        "sudo",
        "cpupower",
        "-c", "0",
        "frequency-set",
        "-d", "400MHz",
        "-u", "4200MHz",
        "-g", "powersave"
    ]

    working_dir = "/home/helkoulak/Documents/r-tcpls-v-0-1/"
    with open(f"{working_dir}/{report_file}", "w") as file:
        file.write("")

    results = {
        "cycles": [],
        "user_time": [],
        "sys_time": [],
        "wall_time": [],
    }

    for i in range(iter):
        print(f"Running iteration {i + 1}/{iter}...")
        try:
            # Run the CLI command
            result = subprocess.run(task_set_command, cwd=working_dir,  text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

            # Read the result from the file
            # Read the report file and parse the time

            with open(f"{working_dir}/{report_file}", "a") as file:
                file.write(f"Iteration {i + 1}:\n")
                file.write(result.stderr)
                file.write("\n\n")

            stderr_output = result.stderr
            cycles_match = re.search(r"([\d.,]+)\s+cycles", stderr_output)
            user_time_match = re.search(r"([\d.,]+)\s+seconds user", stderr_output)
            sys_time_match = re.search(r"([\d.,]+)\s+seconds sys", stderr_output)
            wall_time_match = re.search(r"([\d.,]+)\s+seconds time elapsed", stderr_output)

            if cycles_match and user_time_match and sys_time_match and wall_time_match:
                # Parse values and append to results
                cycles = int(cycles_match.group(1).replace(".", "").replace(",", ""))
                user_time = float(user_time_match.group(1).replace(",", "."))
                sys_time = float(sys_time_match.group(1).replace(",", "."))
                wall_time = float(wall_time_match.group(1).replace(",", "."))

                results["cycles"].append(cycles)
                results["user_time"].append(user_time)
                results["sys_time"].append(sys_time)
                results["wall_time"].append(wall_time)

                print(
                    f"Iteration {i + 1} Results: {cycles} cycles, {user_time:.9f}s user, {sys_time:.9f}s sys, {wall_time:.9f}s wall")
            else:
                print(f"Failed to parse results for iteration {i + 1}")

        except subprocess.CalledProcessError as e:
            print(f"Error running command in iteration {i + 1}: {e}")
            continue

            # Calculate and print averages
    if results["cycles"]:
        avg_cycles = sum(results["cycles"]) / len(results["cycles"])
        avg_user_time = sum(results["user_time"]) / len(results["user_time"])
        avg_sys_time = sum(results["sys_time"]) / len(results["sys_time"])
        avg_wall_time = sum(results["wall_time"]) / len(results["wall_time"])

        print("\n=== Final Averages ===")
        print(f"Average Cycles: {avg_cycles:.2f}")
        print(f"Average User Time: {avg_user_time:.9f} seconds")
        print(f"Average System Time: {avg_sys_time:.9f} seconds")
        print(f"Average Wall Time: {avg_wall_time:.9f} seconds")
    else:
        print("No valid results to calculate averages.")

    subprocess.run(cpupower_unset_command, check=True)

if __name__ == "__main__":
    # Use fire to expose the function to the command line
    fire.Fire(run_client_rec_cpu)
