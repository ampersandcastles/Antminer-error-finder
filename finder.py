import paramiko
import re
import json
import csv
import logging
from datetime import datetime

# Constants for error types
ASIC_ERROR = "ASIC Error"
EEPROM_ERROR = "EEPROM Error"
CHIP_BIN_ERROR = "Chip Bin Error"

# Logging configuration
logging.basicConfig(filename='miner_logs.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

# Function to establish an SSH connection
def establish_ssh_connection(ip, username, password):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_client.connect(ip, username=username, password=password, timeout=5)
        logging.info(f"Connected to {ip} with {username}")
        return ssh_client
    except Exception as e:
        logging.error(f"Failed to connect to {ip} with {username}:{password} - {e}")
        return None

# Function to execute a command via SSH and return the output
def execute_ssh_command(ssh_client, command):
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        return stdout.read().decode('utf-8')
    except Exception as e:
        logging.error(f"Error executing command '{command}': {e}")
        return None

# Function to get worker ID
def get_worker_id(ssh_client):
    config_content = execute_ssh_command(ssh_client, "cat /config/cgminer.conf")
    if config_content:
        match = re.search(r'"user" *: *"[^.]*\.(\w+)"', config_content)
        if match:
            return match.group(1)
    return "Unknown"

# Function to check log files for keywords and ASIC errors
def check_logs(ip, ssh_client, worker_id, current_date, error_keywords):
    logs = []
    asic_errors = set()  # Using set to avoid duplicate errors
    results = []  # Using list to avoid duplicate entries
    log_files_content = execute_ssh_command(ssh_client, "find /var/log/ -type f")
    if log_files_content:
        log_files = log_files_content.splitlines()
        for log_file in log_files:
            log_content = execute_ssh_command(ssh_client, f"cat {log_file}")
            if log_content:
                seen_errors = set()
                for keyword, error_type in error_keywords.items():
                    if keyword in log_content and (log_file, error_type, keyword) not in seen_errors:
                        logs.append((log_file, error_type, keyword))
                        seen_errors.add((log_file, error_type, keyword))

                for match in asic_pattern.finditer(log_content):
                    chain, asic_count = match.groups()
                    asic_errors.add((chain, int(asic_count)))

                for match in power_off_pattern.finditer(log_content):
                    chain, found_asic_count, board = match.groups()
                    chain = int(chain)
                    found_asic_count = int(found_asic_count)
                    if (log_file, ASIC_ERROR, f"Chain {chain} has failed with {found_asic_count} ASICs found and will power off hash board {board}") not in seen_errors:
                        results.append((current_date, worker_id, ip, log_file, ASIC_ERROR, f"Chain {chain} has failed with {found_asic_count} ASICs found and will power off hash board {board}"))
                        seen_errors.add((log_file, ASIC_ERROR, f"Chain {chain} has failed with {found_asic_count} ASICs found and will power off hash board {board}"))

                for match in eeprom_error_pattern.finditer(log_content):
                    chain = match.group(1)
                    if (log_file, EEPROM_ERROR, f"Data load fail for chain {chain}") not in seen_errors:
                        results.append((current_date, worker_id, ip, log_file, EEPROM_ERROR, f"Data load fail for chain {chain}"))
                        seen_errors.add((log_file, EEPROM_ERROR, f"Data load fail for chain {chain}"))

                for match in chip_bin_pattern.finditer(log_content):
                    chain = match.group(1)
                    if (log_file, CHIP_BIN_ERROR, f"No chip bin for chain {chain}") not in seen_errors:
                        results.append((current_date, worker_id, ip, log_file, CHIP_BIN_ERROR, f"No chip bin for chain {chain}"))
                        seen_errors.add((log_file, CHIP_BIN_ERROR, f"No chip bin for chain {chain}"))
    return logs, asic_errors, results

# Function to write results to a text file in the specified format
def write_text_file(file_path, results):
    with open(file_path, 'w') as file:
        current_worker = None
        for result in results:
            date, worker_id, ip, log_file, error_type, error_message = result
            if worker_id != current_worker:
                if current_worker is not None:
                    file.write("\n")  # Add a blank line between different workers
                file.write(f"{worker_id}\n")
                current_worker = worker_id
            file.write(f"- {error_type}\n")
            file.write(f"--- {error_message}\n")
            file.write(f"-" * 80 + "\n")

# Main function to iterate over IPs and check for errors
def main():
    ips = read_ips('ips.txt')
    results = []  # Using a list to collect results
    current_date = datetime.now().strftime('%Y-%m-%d')

    for ip in ips:
        logging.info(f"Processing IP: {ip}")
        connected = False
        for os_type, creds in credentials.items():
            if connected:
                break
            for username, password in creds:
                ssh_client = establish_ssh_connection(ip, username, password)
                if ssh_client:
                    connected = True
                    worker_id = get_worker_id(ssh_client)
                    logs, asic_errors, asic_results = check_logs(ip, ssh_client, worker_id, current_date, error_keywords)
                    results.extend(asic_results)
                    for log in logs:
                        results.append((current_date, worker_id, ip, log[0], log[1], log[2]))

                    unique_asic_errors = {}  # Using a dictionary to store chain and failed check count.
                    for chain, asic_count in asic_errors:
                        failed_checks = unique_asic_errors.get(chain, 0) + 1
                        unique_asic_errors[chain] = failed_checks
                        if asic_count == 0 and failed_checks == 3:
                            results.append((current_date, worker_id, ip, "N/A", ASIC_ERROR, f"Chain {chain} has 3 failed checks with {asic_count} ASICs found"))

                    ssh_client.close()
                    break

    # Write results to CSV
    csv_file = 'results.csv'
    logging.info(f"Writing results to {csv_file}")
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Date", "Worker ID", "IP Address", "Log File", "Error Type", "Error Message"])
        for result in results:
            writer.writerow(result)
    
    # Write results to text file
    text_file = 'results.txt'
    logging.info(f"Writing results to {text_file}")
    write_text_file(text_file, results)

    logging.info("Done")

if __name__ == "__main__":
    # Load credentials and error keywords
    CREDENTIALS_FILE = 'credentials.json'
    ERRORS_FILE = 'errors.json'
    credentials = load_credentials(CREDENTIALS_FILE)
    error_keywords = load_error_keywords(ERRORS_FILE)
    
    main()
