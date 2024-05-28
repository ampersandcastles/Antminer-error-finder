import paramiko
import re
import json
import csv
from datetime import datetime

# Load credentials from a JSON file
def load_credentials(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Load error keywords and types from a JSON file
def load_error_keywords(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)['error_keywords']

# Regex patterns for ASIC chip errors and power-off messages
asic_pattern = re.compile(r"Chain\[(\d+)\]: find (\d+) asic, times \d+")
power_off_pattern = re.compile(r"Chain (\d+) only find (\d+) asic, will power off hash board (\d+)")
eeprom_error_pattern = re.compile(r"Data load fail for chain (\d+)\.")
chip_bin_pattern = re.compile(r"No chip bin, chain = (\d+)")

# Function to read IP addresses from a file
def read_ips(file_path):
    with open(file_path, 'r') as file:
        ips = file.readlines()
    return [ip.strip() for ip in ips]

# Function to check log files for keywords and ASIC errors
def check_logs(ip, ssh_client, worker_id, current_date):
    logs = []
    asic_errors = set()  # Using set to avoid duplicate errors
    results = []  # Using list to avoid duplicate entries
    try:
        print(f"Checking logs on {ip}")
        stdin, stdout, stderr = ssh_client.exec_command("find /var/log/ -type f")
        log_files = stdout.readlines()
        for log_file in log_files:
            log_file = log_file.strip()
            print(f"Checking file: {log_file}")  # Debug statement
            
            # Read the log file content directly
            stdin, stdout, stderr = ssh_client.exec_command(f"cat {log_file}")
            log_content = stdout.read().decode('utf-8', errors='ignore')
            print(f"Content of {log_file}: {log_content[:500]}")  # Debug statement to show part of the log content
            
            # Track unique errors within this log file
            seen_errors = set()
            for keyword, error_type in error_keywords.items():
                if keyword in log_content and (log_file, error_type, keyword) not in seen_errors:
                    print(f"Found keyword '{keyword}' in {log_file}")  # Debug statement
                    logs.append((log_file, error_type, keyword))
                    seen_errors.add((log_file, error_type, keyword))

            # Check for ASIC chip errors and power-off messages
            for match in asic_pattern.finditer(log_content):
                chain, asic_count = match.groups()
                asic_count = int(asic_count)
                asic_errors.add((chain, asic_count))
                print(f"Chain {chain} has {asic_count} chips.")  # Debug statement
                
            # Check for power-off messages
            for match in power_off_pattern.finditer(log_content):
                chain, found_asic_count, board = match.groups()
                found_asic_count = int(found_asic_count)
                chain = int(chain)
                if (log_file, "ASIC Error", f"Chain {chain} has failed with {found_asic_count} ASICs found and will power off hash board {board}") not in seen_errors:
                    results.append((current_date, worker_id, ip, log_file, "ASIC Error", f"Chain {chain} has failed with {found_asic_count} ASICs found and will power off hash board {board}"))
                    seen_errors.add((log_file, "ASIC Error", f"Chain {chain} has failed with {found_asic_count} ASICs found and will power off hash board {board}"))

            # Check for EEPROM errors
            for match in eeprom_error_pattern.finditer(log_content):
                chain = match.group(1)
                if (log_file, "EEPROM Error", f"Data load fail for chain {chain}") not in seen_errors:
                    results.append((current_date, worker_id, ip, log_file, "EEPROM Error", f"Data load fail for chain {chain}"))
                    seen_errors.add((log_file, "EEPROM Error", f"Data load fail for chain {chain}"))
            
            # Check for chip bin errors
            for match in chip_bin_pattern.finditer(log_content):
                chain = match.group(1)
                if (log_file, "Chip Bin Error", f"No chip bin for chain {chain}") not in seen_errors:
                    results.append((current_date, worker_id, ip, log_file, "Chip Bin Error", f"No chip bin for chain {chain}"))
                    seen_errors.add((log_file, "Chip Bin Error", f"No chip bin for chain {chain}"))

    except Exception as e:
        print(f"Error checking logs on {ip}: {e}")
    return logs, asic_errors, results

# Function to get worker ID
def get_worker_id(ssh_client):
    try:
        print("Getting worker ID")
        stdin, stdout, stderr = ssh_client.exec_command("cat /config/cgminer.conf")
        config_content = stdout.read().decode('utf-8')
        # Extract the worker ID from the user field
        match = re.search(r'"user" *: *"[^.]*\.(\w+)"', config_content)
        if match:
            worker_id = match.group(1)
            print(f"Got Worker ID: {worker_id}")
        else:
            worker_id = "Unknown"
    except Exception as e:
        print(f"Error getting worker ID: {e}")
        worker_id = "Unknown"
    return worker_id

# Main function to iterate over IPs and check for errors
def main():
    ips = read_ips('ips.txt')
    results = []  # Using a list to collect results
    current_date = datetime.now().strftime('%Y-%m-%d')

    for ip in ips:
        print(f"Processing IP: {ip}")
        connected = False
        for os_type, creds in credentials.items():
            if connected:
                break
            for username, password in creds:
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    print(f"Trying {username}:{password} on {ip}")
                    ssh_client.connect(ip, username=username, password=password)
                    connected = True
                    worker_id = get_worker_id(ssh_client)
                    logs, asic_errors, asic_results = check_logs(ip, ssh_client, worker_id, current_date)
                    results.extend(asic_results)
                    for log in logs:
                        results.append((current_date, worker_id, ip, log[0], log[1], log[2]))
                    
                    unique_asic_errors = {}  # Using a dictionary to store chain and failed check count.
                    for chain, asic_count in asic_errors:
                        failed_checks = unique_asic_errors.get(chain, 0) + 1
                        unique_asic_errors[chain] = failed_checks
                        if asic_count == 0 and failed_checks == 3:
                            results.append((current_date, worker_id, ip, log[0], "ASIC Error", f"Chain {chain} has 3 failed checks with {asic_count} ASICs found"))
                    
                    ssh_client.close()
                    break
                except Exception as e:
                    print(f"Connection failed for {ip} with {username}:{password} - {e}")
                    ssh_client.close()

    # Write results to CSV
    csv_file = 'results.csv'
    print(f"Writing results to {csv_file}")
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Date", "Worker ID", "IP Address", "Log File", "Error Type", "Error Message"])
        for result in results:
            writer.writerow(result)
    print("Done")

if __name__ == "__main__":
    # Load credentials and error keywords
    CREDENTIALS_FILE = 'credentials.json'
    ERRORS_FILE = 'errors.json'
    credentials = load_credentials(CREDENTIALS_FILE)
    error_keywords = load_error_keywords(ERRORS_FILE)
    
    main()
