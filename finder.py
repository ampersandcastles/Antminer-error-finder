import paramiko
import csv
import re

# Define credentials for different OS types
credentials = {
    "stock": [("miner", "miner"), ("root", "root")],
    "braiins": [("root", "root")],
    "luxos": [("root", "root")],
    "vnish": [("user", "password")]  # Replace with correct credentials
}

# List of error keywords
error_keywords = [
    "ERROR_TEMP_TOO_HIGH",
    "ERROR_HASHRATE_TOO_LOW",
    "ERROR_NETWORK_DISCONNECTED",
    "ERROR_POWER_LOST: power voltage rise or drop",
    "SWEEP_STRING",
    "_pic_write_iic failed!",
    "PLL read exceeded wait time",
    "ERROR_SOC_INIT: soc init failed",
    "fail to read 0:1",
    "fail to write 0:1"
]

# Regex pattern for ASIC chip errors
asic_pattern = re.compile(r"Chain\[(\d+)\]: find (\d+) asic, times \d+")

# Function to read IP addresses from a file
def read_ips(file_path):
    with open(file_path, 'r') as file:
        ips = file.readlines()
    return [ip.strip() for ip in ips]

# Function to check log files for keywords and ASIC errors
def check_logs(ip, ssh_client):
    logs = []
    asic_errors = {}
    correct_asic_count = {}
    try:
        print(f"Checking logs on {ip}")
        stdin, stdout, stderr = ssh_client.exec_command("find /var/log/ -type f")
        log_files = stdout.readlines()
        for log_file in log_files:
            log_file = log_file.strip()
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
            for keyword in error_keywords:
                if keyword in log_content:
                    logs.append((log_file, keyword))

            # Check for ASIC chip errors
            for match in asic_pattern.finditer(log_content):
                chain, asic_count = match.groups()
                asic_count = int(asic_count)
                if chain not in asic_errors:
                    asic_errors[chain] = []
                asic_errors[chain].append(asic_count)
                
                # Determine the correct ASIC count for each chain
                if chain not in correct_asic_count and asic_count > 0:
                    correct_asic_count[chain] = asic_count
    except Exception as e:
        print(f"Error checking logs on {ip}: {e}")
    return logs, asic_errors, correct_asic_count

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
            print("Got worker ID: ", worker_id)
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
                    logs, asic_errors, correct_asic_count = check_logs(ip, ssh_client)
                    for log in logs:
                        results.append([worker_id, ip, log[0], log[1]])
                    
                    # Check for ASIC chip errors and add to results
                    # Maybe think about this differntly. Look for "will power off hashboard" and *then* figure out why the hashboard has been powered off.
                    for chain, counts in asic_errors.items():
                        if counts.count(0) >= 3:
                            results.append([worker_id, ip, "ASIC Error", f"Chain {chain} has {counts.count(0)} failed checks with 0 ASICs found"])
                        elif chain in correct_asic_count:
                            expected_count = correct_asic_count[chain]
                            if any(count != expected_count and count > 0 for count in counts):
                                results.append([worker_id, ip, "ASIC Discrepancy", f"Chain {chain} has varying ASIC counts: {counts}"])
                    
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
    print("Done")

if __name__ == "__main__":
    main()
