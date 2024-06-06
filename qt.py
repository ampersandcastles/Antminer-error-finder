import sys
import os
import paramiko
import re
import json
import csv
import logging
from datetime import datetime
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QTextEdit, QTreeWidget, QTreeWidgetItem, QSplitter, QHBoxLayout, QPlainTextEdit
from PyQt5.QtCore import Qt

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

# Function to browse for a file
def browse_file(label):
    options = QFileDialog.Options()
    options |= QFileDialog.ReadOnly
    file_path, _ = QFileDialog.getOpenFileName(None, "Select File", "", "All Files (*);;Text Files (*.txt)", options=options)
    if file_path:
        label.setText(file_path)

# Main application class
class MinerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        main_layout = QVBoxLayout()
        
        # File path labels
        self.ips_label = QLabel("No IPs file selected")
        self.credentials_label = QLabel("No credentials file selected")
        self.errors_label = QLabel("No errors file selected")

        # Set default paths if files exist
        self.set_default_paths()
        
        # Text edit for logs
        self.logs_text = QPlainTextEdit()
        self.logs_text.setReadOnly(True)
        
        # Tree views for machines and errors
        self.machines_tree = QTreeWidget()
        self.machines_tree.setHeaderLabel("Machines")
        self.machines_tree.itemClicked.connect(self.display_errors)

        self.errors_tree = QTreeWidget()
        self.errors_tree.setHeaderLabel("Errors")

        # Buttons
        browse_ips_btn = QPushButton('Browse IPs File')
        browse_ips_btn.clicked.connect(lambda: browse_file(self.ips_label))
        
        browse_credentials_btn = QPushButton('Browse Credentials File')
        browse_credentials_btn.clicked.connect(lambda: browse_file(self.credentials_label))
        
        browse_errors_btn = QPushButton('Browse Errors File')
        browse_errors_btn.clicked.connect(lambda: browse_file(self.errors_label))
        
        start_btn = QPushButton('Start')
        start_btn.clicked.connect(self.start_process)

        # Splitter for tree views
        tree_splitter = QSplitter()
        tree_splitter.addWidget(self.machines_tree)
        tree_splitter.addWidget(self.errors_tree)

        # Splitter for the main layout and logs
        main_splitter = QSplitter(Qt.Vertical)
        main_splitter.addWidget(tree_splitter)
        main_splitter.addWidget(self.logs_text)
        main_splitter.setSizes([500, 100])  # Initial sizes: larger for the tree views, smaller for the logs

        # Add widgets to layout
        main_layout.addWidget(browse_ips_btn)
        main_layout.addWidget(self.ips_label)
        main_layout.addWidget(browse_credentials_btn)
        main_layout.addWidget(self.credentials_label)
        main_layout.addWidget(browse_errors_btn)
        main_layout.addWidget(self.errors_label)
        main_layout.addWidget(start_btn)
        main_layout.addWidget(main_splitter)
        
        self.setLayout(main_layout)
        self.setWindowTitle('Miner Error Checker')
        self.show()
    
    def set_default_paths(self):
        default_ips_path = "ips.txt"
        default_credentials_path = "credentials.json"
        default_errors_path = "errors.json"
        
        if os.path.exists(default_ips_path):
            self.ips_label.setText(default_ips_path)
        if os.path.exists(default_credentials_path):
            self.credentials_label.setText(default_credentials_path)
        if os.path.exists(default_errors_path):
            self.errors_label.setText(default_errors_path)

    def start_process(self):
        ips_path = self.ips_label.text()
        credentials_path = self.credentials_label.text()
        errors_path = self.errors_label.text()
        
        if ips_path == "No IPs file selected" or credentials_path == "No credentials file selected" or errors_path == "No errors file selected":
            self.logs_text.appendPlainText("Please select all required files.")
            return
        
        credentials = load_credentials(credentials_path)
        error_keywords = load_error_keywords(errors_path)
        ips = read_ips(ips_path)
        
        results = []
        current_date = datetime.now().strftime('%Y-%m-%d')
        
        self.machines_tree.clear()
        self.errors_tree.clear()

        for ip in ips:
            self.logs_text.appendPlainText(f"Processing IP: {ip}")
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
        
                        unique_asic_errors = {}
                        for chain, asic_count in asic_errors:
                            failed_checks = unique_asic_errors.get(chain, 0) + 1
                            unique_asic_errors[chain] = failed_checks
                            if asic_count == 0 and failed_checks == 3:
                                results.append((current_date, worker_id, ip, "N/A", ASIC_ERROR, f"Chain {chain} has 3 failed checks with {asic_count} ASICs found"))
        
                        self.add_machine_item(ip, worker_id, results)
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
        
        self.logs_text.appendPlainText("Process completed. Results saved to results.csv and results.txt.")

    def add_machine_item(self, ip, worker_id, results):
        machine_item = QTreeWidgetItem([f"{worker_id} ({ip})"])
        machine_item.setData(0, 1, results)  # Store results in the item for later retrieval
        self.machines_tree.addTopLevelItem(machine_item)

    def display_errors(self, item, column):
        self.errors_tree.clear()
        results = item.data(0, 1)  # Retrieve stored results from the item
        if results:
            for result in results:
                date, worker_id, ip, log_file, error_type, error_message = result
                error_item = QTreeWidgetItem([f"{error_type}: {error_message}"])
                self.errors_tree.addTopLevelItem(error_item)

# Main function to run the PyQt5 application
def main():
    app = QApplication(sys.argv)
    ex = MinerApp()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
# lol