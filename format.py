import re
import argparse

def parse_benchmark_file(filepath, benchmark_name_prefix):
    """
    Parses a benchmark data file and extracts user counts and times.

    Args:
        filepath (str): The path to the benchmark data file.
        benchmark_name_prefix (str): The prefix of the benchmark name
                                     (e.g., "BenchmarkNewKeyPair/NewKeyPair-" or
                                      "BenchmarkRegisterUser/RegisterUser-").

    Returns:
        dict: A dictionary mapping user counts (int) to times (int, ns/op).
    """
    data = {}
    # Regex to match lines like:
    # BenchmarkName/BenchmarkName-USERS-THREADS       ITERATIONS    TIME ns/op    BYTES B/op    ALLOCS allocs/op
    # We are interested in USERS and TIME
    # Example: BenchmarkNewKeyPair/NewKeyPair-4-32         	    1029	   1008926 ns/op ...
    # Example: BenchmarkRegisterUser/RegisterUser-4-32         	     200	   5894125 ns/op ...
    regex = re.compile(rf"^{re.escape(benchmark_name_prefix)}(\d+)-\d+\s+\d+\s+(\d+)\s+ns/op.*")
    try:
        with open(filepath, 'r') as f:
            for line in f:
                match = regex.match(line.strip())
                if match:
                    users = int(match.group(1))
                    time_ns = int(match.group(2))
                    data[users] = time_ns
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return None
    return data

def main():
    parser = argparse.ArgumentParser(
        description="Combines benchmark data from NewKeyPair and RegisterUser files."
    )
    parser.add_argument("keypair_file", help="Path to the NewKeyPair benchmark data file.")
    parser.add_argument("reguser_file", help="Path to the RegisterUser benchmark data file.")
    parser.add_argument("output_file", help="Path to the output TSV file.")

    args = parser.parse_args()

    keypair_data = parse_benchmark_file(args.keypair_file, "BenchmarkNewKeyPair/NewKeyPair-")
    reguser_data = parse_benchmark_file(args.reguser_file, "BenchmarkRegisterUser/RegisterUser-")

    if keypair_data is None or reguser_data is None:
        return # Error message already printed by parse_benchmark_file

    combined_data = []
    header = f"#{'Users':<10}{'NewKeyPair_ns':<15}{'RegisterUser_ns':<15}"

    # Iterate through user counts found in reguser_data (or keypair_data, order doesn't strictly matter here
    # as we will sort later, but using reguser_data as the primary loop ensures we have its time)
    for users, reg_time in reguser_data.items():
        if users in keypair_data:
            kp_time = keypair_data[users]
            combined_data.append((users, kp_time, reg_time))

    # Sort by the number of users (the first element in each tuple)
    combined_data.sort(key=lambda x: x[0])

    try:
        with open(args.output_file, 'w') as f:
            f.write(header + "\n")
            for entry in combined_data:
                f.write(f"{entry[0]:<10}{entry[1]:<15}{entry[2]:<15}\n")
        print(f"Combined benchmark data written to '{args.output_file}'")
    except IOError:
        print(f"Error: Could not write to output file {args.output_file}")

if __name__ == "__main__":
    main()
    
# python3 format.py new-keypair.data reg-user.data key-reg.data