import os
import hashlib
import csv
import argparse
from tqdm import tqdm

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for file {file_path}: {e}")
        return None

def load_baseline(baseline_csv):
    baseline_data = {}
    try:
        with open(baseline_csv, mode='r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                file_path = os.path.join(row['directory'], row['filename'])
                baseline_data[file_path] = row['file_hash']
    except Exception as e:
        print(f"Error loading baseline CSV {baseline_csv}: {e}")
    return baseline_data

def compare_with_baseline(directory, baseline_data):
    discrepancies = []
    all_files = []

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)

    for file_path in tqdm(all_files, desc="Comparing files", unit="file"):
        current_hash = calculate_sha256(file_path)
        if file_path in baseline_data:
            if current_hash != baseline_data[file_path]:
                discrepancies.append((file_path, "Hash mismatch", baseline_data[file_path], current_hash))
            del baseline_data[file_path]  # Remove matched file from baseline
        else:
            discrepancies.append((file_path, "New file", None, current_hash))

    for remaining_file in baseline_data.keys():
        discrepancies.append((remaining_file, "File missing", baseline_data[remaining_file], None))

    return discrepancies

def generate_report(discrepancies, report_csv):
    """Generate a report of discrepancies and save it to a CSV file."""
    try:
        with open(report_csv, mode='w', newline='') as csvfile:
            fieldnames = ["file_path", "issue", "baseline_hash", "current_hash"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for discrepancy in discrepancies:
                writer.writerow({
                    "file_path": discrepancy[0],
                    "issue": discrepancy[1],
                    "baseline_hash": discrepancy[2],
                    "current_hash": discrepancy[3]
                })
        print(f"Comparison report generated and saved to {report_csv}")
    except Exception as e:
        print(f"Error generating report CSV {report_csv}: {e}")

def print_overview(discrepancies):
    """Print a basic overview of the discrepancies to the terminal."""
    total_files = len(discrepancies)
    hash_mismatches = len([d for d in discrepancies if d[1] == "Hash mismatch"])
    new_files = len([d for d in discrepancies if d[1] == "New file"])
    missing_files = len([d for d in discrepancies if d[1] == "File missing"])

    print("\nDiscrepancy Overview:")
    print(f"Total discrepancies: {total_files}")
    print(f"Hash mismatches: {hash_mismatches}")
    print(f"New files: {new_files}")
    print(f"Missing files: {missing_files}")

def find_baseline_file(directory):
    directory_name = os.path.basename(os.path.normpath(directory))
    expected_baseline_file = f"baseline-{directory_name}.csv"
    if os.path.isfile(expected_baseline_file):
        return expected_baseline_file
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare files in a directory with a baseline CSV")
    parser.add_argument("-d", "--directory", help="Path to the directory to scan")
    parser.add_argument("-b", "--baseline", help="Path to the baseline CSV file")
    parser.add_argument("-r", "--report", default="comparison_report.csv", help="Output CSV file for the comparison report")

    args = parser.parse_args()

    if not args.directory:
        args.directory = input("Please provide the path to the directory to scan: ")
        
    directory_to_scan = args.directory

    if not args.baseline:
        found_baseline = find_baseline_file(directory_to_scan)
        if found_baseline:
            use_found = input(f"Found baseline file '{found_baseline}'. Do you want to use this file? (y/n): ")
            if use_found.lower() == 'y':
                args.baseline = found_baseline
            else:
                args.baseline = input("Please provide the path to the baseline CSV file: ")
        else:
            args.baseline = input("Please provide the path to the baseline CSV file: ")

    baseline_csv_file = args.baseline
    report_csv_file = args.report

    baseline_data = load_baseline(baseline_csv_file)
    discrepancies = compare_with_baseline(directory_to_scan, baseline_data)
    generate_report(discrepancies, report_csv_file)
    print_overview(discrepancies)
