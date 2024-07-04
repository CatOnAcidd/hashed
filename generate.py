import os
import hashlib
import csv
import datetime
import argparse
import ctypes
from ctypes import wintypes
from tqdm import tqdm

def get_username_from_sid(sid):
    try:
        name = ctypes.create_unicode_buffer(1024)
        domain = ctypes.create_unicode_buffer(1024)
        name_size = wintypes.DWORD(1024)
        domain_size = wintypes.DWORD(1024)
        sid_name_use = wintypes.DWORD()

        if ctypes.windll.advapi32.LookupAccountSidW(
            None, sid, name, ctypes.byref(name_size), domain, ctypes.byref(domain_size), ctypes.byref(sid_name_use)
        ):
            return f"{domain.value}\\{name.value}"
    except Exception as e:
        print(f"Error converting SID to username: {e}")
    return None

def get_file_owner(file_path):
    OWNER_SECURITY_INFORMATION = 0x00000001
    sec_desc = ctypes.c_void_p()
    sid = ctypes.c_void_p()
    is_defaulted = wintypes.BOOL()

    try:
        res = ctypes.windll.advapi32.GetNamedSecurityInfoW(
            file_path, 1, OWNER_SECURITY_INFORMATION, ctypes.byref(sid), None, None, None, ctypes.byref(sec_desc)
        )
        if res != 0:
            raise ctypes.WinError(res)

        res = ctypes.windll.advapi32.GetSecurityDescriptorOwner(sec_desc, ctypes.byref(sid), ctypes.byref(is_defaulted))
        if not res:
            raise ctypes.WinError()

        username = get_username_from_sid(sid)
    except Exception as e:
        print(f"Error getting file owner: {e}")
        username = None
    finally:
        if sec_desc:
            ctypes.windll.kernel32.LocalFree(sec_desc)

    return username

def get_file_info(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for file {file_path}: {e}")
        file_hash = None

    try:
        stat_info = os.stat(file_path)
        last_modified_date = datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        user_name = get_file_owner(file_path)
        file_size = stat_info.st_size
        directory = os.path.dirname(file_path)
        filename = os.path.basename(file_path)
    except Exception as e:
        print(f"Error getting metadata for file {file_path}: {e}")
        last_modified_date = None
        user_name = None
        file_size = None
        directory = None
        filename = None

    return {
        "filename": filename,
        "file_hash": file_hash,
        "last_modified_date": last_modified_date,
        "user_name": user_name,
        "file_size": file_size,
        "directory": directory
    }

def generate_baseline(directory, output_csv):
    file_info_list = []

    if not os.path.isdir(directory):
        print(f"Error: The directory '{directory}' does not exist or is not accessible.")
        return

    all_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)

    for file_path in tqdm(all_files, desc="Processing files", unit="file"):
        file_info = get_file_info(file_path)
        file_info_list.append(file_info)

    try:
        with open(output_csv, 'w', newline='') as csvfile:
            fieldnames = ["filename", "file_hash", "last_modified_date", "user_name", "file_size", "directory"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for file_info in file_info_list:
                writer.writerow(file_info)
        print(f"Baseline generated and saved to {output_csv}")
    except Exception as e:
        print(f"Error writing to CSV file {output_csv}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a baseline of SHA-256 values for files in a directory")
    parser.add_argument("-d", "--directory", help="Path to the directory to scan")
    parser.add_argument("-o", "--output", help="Output CSV file name")
    
    args = parser.parse_args()
    
    if not args.directory:
        args.directory = input("Please provide the path to the directory to scan: ")
        
    directory_to_scan = args.directory
    
    if not args.output:
        directory_name = os.path.basename(os.path.normpath(directory_to_scan))
        script_directory = os.path.dirname(os.path.abspath(__file__))
        default_output = os.path.join(script_directory, f"baseline-{directory_name}.csv")
        user_output = input(f"Please provide the output path and filename (press Enter to accept default: {default_output}): ")
        args.output = user_output if user_output else default_output
    
    output_csv_file = args.output

    generate_baseline(directory_to_scan, output_csv_file)
