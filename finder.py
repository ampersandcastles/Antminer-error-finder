import paramiko
import csv
import re
import json

# Load credentials from a JSON file
def load_credentials(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Load error keywords from a JSON file
def load_error_keywords(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)['error_keywords']

# Define paths to the configuration files
CREDENTIALS_FILE = 'credentials.json'
ERRORS_FILE = 'errors.json'

# Load credentials and error keywords
credentials = load_credentials(CREDENTIALS_FILE)
error_keywords = load_error_keywords(ERRORS_FILE)

# Regex patterns for ASIC chip errors and power-off messages
asic_pattern = re.compile(r"Chain\[(\d+)\]: find (\d+) asic, times \d+")
power_off_pattern = re.compile(r"Chain (\d+) only find (\d+) asic, will power off hash board (\d+)")

# Function to read IP addresses from a file
def read_ips(file_path):
    with open(file_path, 'r') as file:
        ips = file.readlines()
    return [ip.strip() for ip in ips]

# Function to check log files for keywords and ASIC errors
def check_logs(ip, ssh_client, worker_id):
    logs = []
    asic_errors = set()  # Using set to avoid duplicate errors
    results = []
    try:
        print(f"Checking logs on {ip}")
        stdin, stdout, stderr = ssh_client.exec_command("find /var/log/ -type f")
        log_files = stdout.readlines()
        for log_file in log_files:
            log_file = log_file.strip()
            print(f"Checking file: {log_file}")  # Debug statement
            # Check if file should be ignored
            if log_file.endswith(('tmp', 'utmp', 'btmp', 'wtmp')):
                continue
            
            # Check if file is a binary file
            stdin, stdout, stderr = ssh_client.exec_command(f"file {log_file}")
            file_type = stdout.read().decode('utf-8')
            if 'text' not in file_type:
                continue
            
            stdin, stdout, stderr = ssh_client.exec_command(f"cat {log_file}")
            log_content = stdout.read().decode('utf-8', errors='ignore')
            print(f"Content of {log_file}: {log_content[:500]}")  # Debug statement to show part of the log content
            for keyword in error_keywords:
                if keyword in log_content:
                    logs.append((log_file, keyword))

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
                print(f"Power-off message found: Chain {chain}, ASIC count: {found_asic_count}, Board: {board}")  # Debug statement
                results.append([worker_id, ip, "ASIC Error", f"Chain {chain} has failed with {found_asic_count} ASICs found and will power off hash board {board}"])

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
        else:
            worker_id = "Unknown"
    except Exception as e:
        print(f"Error getting worker ID: {e}")
        worker_id = "Unknown"
    return worker_id

# Main function to iterate over IPs and check for errors
def main():
    ips = read_ips('ips.txt')
    results = []

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
                    logs, asic_errors, asic_results = check_logs(ip, ssh_client, worker_id)
                    results.extend(asic_results)
                    for log in logs:
                        results.append([worker_id, ip, log[0], log[1]])
                    
                    unique_asic_errors = {}  # Using a dictionary to store chain and failed check count.
                    for chain, asic_count in asic_errors:
                        for chain, asic_count in asic_errors:
                            failed_checks = unique_asic_errors.get(chain, 0) + 1 # array
                            unique_asic_errors[chain] = failed_checks
                            if asic_count == 0 and failed_checks == 3:
                                results.append([worker_id, ip, "ASIC Error", f"Chain {chain} has 3 failed checks with {asic_count} ASICs found"])
                    
                    ssh_client.close()
                    break
                except Exception as e:
                    print(f"Connection failed for {ip} with {username}:{password} - {e}")
                    ssh_client.close()
    
    # Write results to CSV
    print("Writing results to CSV")
    with open('results.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Worker ID", "IP Address", "Log File", "Error"])
        writer.writerows(results)
    print("Writing: ", results)
    print("Done")

if __name__ == "__main__":
    main()
