import os
import platform
import shutil
import subprocess
import psutil
import threading
import time 
import datetime
import requests
from os.path import exists
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import hashlib

# Define global monitoring_threads variable
monitoring_threads = []

# Configuration
startup_path = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\E-Guard.exe"
source_path = f'{os.getcwd()}\\GUI\\E-Guard.exe'

black_list = []
white_list = []

# Update monitored directories to existing paths
black_list = []
white_list = []
monitored_directories = ["C:\\"]

cpu_threshold = 80
memory_threshold = 80

# VirusTotal API key
VT_API_KEY = "57806df5ab73126fa09e8d0d792981fbe799a645d59c9912a2309a962c7c8998"

# Clear the log file when the script starts
def clear_log_file():
    with open("e_guard.log", "w"):
        pass

def start_logging():
    # Configure logging
    logging.basicConfig(filename="e_guard.log", level=logging.INFO, 
                        format='%(asctime)s:%(levelname)s:%(message)s')

def initialize():
    clear_log_file()
    start_logging()

class MyHandler(FileSystemEventHandler):
    def on_modified(self, event):
        logging.info(f'Modified file: {event.src_path}')
        analyze_behavior(event.src_path)
        
    def on_created(self, event):
        logging.info(f'Created file: {event.src_path}')
        analyze_behavior(event.src_path)
        
    def on_deleted(self, event):
        logging.info(f'Deleted file: {event.src_path}')
        analyze_behavior(event.src_path)

def add_to_startup():
    if not exists(startup_path):
        try:
            shutil.copy(source_path, startup_path)
            if exists(startup_path):
                logging.info("Program successfully added to startup.")
            else:
                logging.error("Error: Program did not load into startup folder.")
        except Exception as e:
            logging.error(f"Error: {e}")
    else:
        logging.error("Error: Program already exists in startup.")

def remove_from_startup():
    if exists(startup_path):
        try:
            os.remove(startup_path)
            if not exists(startup_path):
                logging.info("File removed successfully.")
            else:
                logging.error("Error: File was not removed from startup.")
        except Exception as e:
            logging.error(f"Error: {e}")
    else:
        logging.error("Error: Program does not exist in startup directory.")

def scan_network():
    while True:
        proc = subprocess.Popen('netstat -ano -p tcp | findstr "587 465 2525"', shell=True, stdout=subprocess.PIPE)
        out, _ = proc.communicate()
        output = out.decode()

        if "ESTABLISHED" in output:
            process_info = parse_netstat_output(output)
            handle_process(process_info)

        time.sleep(1)

def parse_netstat_output(output):
    my_list = list(filter(None, output.split()))
    pid = my_list[-1]
    port = my_list[-3].split(":")[-1]

    cmd_output = subprocess.getoutput(f'tasklist /fi "pid eq {pid}"')
    process_name = cmd_output.split()[13]
    return {'pid': pid, 'port': port, 'process_name': process_name}

def handle_process(process_info):
    pid = int(process_info['pid'])
    process_name = process_info['process_name']
    port = process_info['port']

    if process_name not in white_list:
        logging.warning("KEYLOGGER DETECTED!")
        p = psutil.Process(pid)

        if process_name in black_list:
            p.kill()
            logging.info("Blacklist application found running. Process automatically terminated.")
        else:
            p.suspend()
            logging.info(f"Information on application identified as a potential threat:\n"
                         f"Application name: {process_name}\nProcess ID (PID): {pid}\n"
                         f"Trying to communicate on port {port}\n")

            while True:
                is_safe = input("Would you like to whitelist this application? (Y/N): ").lower()
                if is_safe == 'n':
                    p.kill()
                    black_list.append(process_name)
                    logging.info("Process terminated and added to blacklist.")
                    break
                elif is_safe == 'y':
                    p.resume()
                    white_list.append(process_name)
                    logging.info("Process resumed and added to whitelist.")
                    break

def check_file_for_malware(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': VT_API_KEY}

    with open(file_path, 'rb') as file:
        files = {'file': file}
        response = requests.post(url, files=files, params=params)

    if response.status_code == 200:
        logging.info(f'Successfully submitted file {file_path} for scanning.')
        time.sleep(10)  # VirusTotal API requires a delay before retrieving scan results
        retrieve_scan_report(response.json()['resource'])
    else:
        logging.error(f'Error submitting file {file_path} for scanning: {response.text}')

def retrieve_scan_report(resource):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VT_API_KEY, 'resource': resource}

    response = requests.get(url, params=params)
    if response.status_code == 200:
        report = response.json()
        logging.info(f'Scan report for {report["resource"]}:')
        for antivirus, result in report['scans'].items():
            logging.info(f'{antivirus}: {result["result"]}')
    else:
        logging.error(f'Error retrieving scan report for {resource}: {response.text}')

def monitor_resources():
    while True:
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()
        memory_usage = memory_info.percent

        if cpu_usage > cpu_threshold:
            logging.warning(f"High CPU usage detected: {cpu_usage}%")

        if memory_usage > memory_threshold:
            logging.warning(f"High Memory usage detected: {memory_usage}%")

        time.sleep(5)

def get_file_metadata(file_path):
    try:
        # Get file metadata
        stat_info = os.stat(file_path)
        metadata = {
            'size': stat_info.st_size,
            'last_accessed': datetime.datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            'last_modified': datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            'creation_time': datetime.datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            'permissions': stat_info.st_mode,
            'owner': (stat_info.st_uid, stat_info.st_gid),
            'file_type': 'File' if os.path.isfile(file_path) else 'Directory'
        }
        if platform.system() == 'Windows':
            metadata['extension'] = os.path.splitext(file_path)[1]
        return metadata
    except Exception as e:
        logging.error(f"An error occurred while getting metadata for file: {file_path} - {e}")
        return None
    
def check_file_access(pid):
    sensitive_files = [
        'C:\\Windows\\System32\\config\\SAM',
        'C:\\Windows\\System32\\config\\SECURITY',
        'C:\\Windows\\System32\\config\\SYSTEM',
        'C:\\Windows\\System32\\config\\SOFTWARE',
        'C:\\Windows\\System32\\config\\DEFAULT',
        'C:\\Users\\Administrator\\NTUSER.DAT',
        'C:\\Users\\<username>\\NTUSER.DAT',  # Replace <username> with actual usernames
        'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp',
        'C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\History',
        'C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files',
        'C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\Cookies'
    ]

    try:
        pid = int(pid)  # Convert pid to integer
        process = psutil.Process(pid)
        files_accessed = {}

        # Get files accessed by the process
        for file in process.open_files():
            files_accessed[file.path] = get_file_metadata(file.path)
        
        # Check for sensitive directories
        sensitive_dirs = ['C:\\Windows\\System32', 'C:\\Users\\<username>\\AppData']
        for dir in sensitive_dirs:
            for root, _, files in os.walk(dir):
                for file in files:
                    sensitive_files.append(os.path.join(root, file))

        # Check if any accessed files are in the sensitive files list
        for file, details in files_accessed.items():
            if any(sensitive_file.lower() in file.lower() for sensitive_file in sensitive_files):
                logging.warning(f'Sensitive file accessed: {file} by PID: {pid}')
                logging.info(f'File details: Size - {details["size"]} bytes, Last Accessed - {details["last_accessed"]}, Last Modified - {details["last_modified"]}, Creation Time - {details["creation_time"]}, Permissions - {details["permissions"]}, Owner - {details["owner"]}, Type - {details["file_type"]}')
                if 'extension' in details:
                    logging.info(f'File Extension: {details["extension"]}')
                return True, details

        return False, {}
    except psutil.NoSuchProcess:
        logging.error(f"No such process with PID: {pid}")
        return False, {}
    except psutil.AccessDenied:
        logging.error(f"Access denied to process with PID: {pid}")
        return False, {}
    except psutil.ZombieProcess:
        logging.error(f"Zombie process with PID: {pid}")
        return False, {}
    except Exception as e:
        logging.error(f"An error occurred while checking file access for PID: {pid} - {e}")
        return False, {}

def integrate_vulnerability_databases():
    try:
        # Fetch CVE data from the NVD API
        response = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0')
        
        # Check if the request was successful
        if response.status_code == 200:
            cve_data = response.json()
            cves = cve_data.get('vulnerabilities', [])
            
            # Check if any CVEs were found
            if cves:
                with open("vulnerability_results.log", "a") as log_file:
                    log_file.write("CVEs found in the NVD database:\n")
                    for cve in cves:
                        cve_id = cve.get('cve', {}).get('id')
                        description = cve.get('cve', {}).get('descriptions', [{}])[0].get('value')
                        severity = cve.get('cve', {}).get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity')
                        
                        # Write CVE details to the log file
                        log_file.write(f"CVE ID: {cve_id}, Description: {description}, Severity: {severity}\n")
            else:
                with open("vulnerability_results.log", "a") as log_file:
                    log_file.write("No CVEs found in the NVD database.\n")
        else:
            with open("vulnerability_results.log", "a") as log_file:
                log_file.write(f"Failed to fetch CVE data from NVD. Status Code: {response.status_code}\n")
    
    except requests.RequestException as e:
        # Handle exceptions related to the requests library
        with open("vulnerability_results.log", "a") as log_file:
            log_file.write(f"RequestException occurred: {e}\n")
    except KeyError as e:
        # Handle missing keys in the JSON response
        with open("vulnerability_results.log", "a") as log_file:
            log_file.write(f"KeyError: Missing key in the response data - {e}\n")
    except Exception as e:
        # Handle any other exceptions
        with open("vulnerability_results.log", "a") as log_file:
            log_file.write(f"An error occurred: {e}\n")

def analyze_behavior(file_path):
    if not os.path.exists(file_path):
        logging.warning(f'File not found: {file_path}')
        return
    
    try:
        # Example: Analyze file contents, access patterns, etc.
        suspicious_keywords = ['password', 'credit card', 'social security', 'login', 'ssn', 'bank account']
        suspicious_extensions = ['.exe', '.dll', '.sys', '.bat']
        
        # Check for suspicious keywords in file contents
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            contents = file.read()
            for keyword in suspicious_keywords:
                if keyword in contents.lower():
                    logging.warning(f'Suspicious keyword "{keyword}" found in file: {file_path}')
                    break
        
        # Check for suspicious file extensions
        if os.path.splitext(file_path)[1] in suspicious_extensions:
            logging.warning(f'Suspicious file extension found: {os.path.splitext(file_path)[1]}')
        
        # Perform additional analysis based on specific threat behaviors
        try:
            # Calculate MD5 hash of the file
            md5_hash = calculate_hash(file_path)
            # Check if the file's MD5 hash is in a blacklist of known malicious hashes
            if is_blacklisted(md5_hash):
                logging.warning(f'Suspicious file with MD5 hash {md5_hash} detected: {file_path}')
        except Exception as e:
            logging.error(f'Error analyzing file {file_path}: {e}')
    except PermissionError:
        logging.error(f'Permission denied: Unable to access file {file_path}')
    except Exception as e:
        logging.error(f'An error occurred while analyzing file {file_path}: {e}')

def calculate_hash(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as file:
        while True:
            data = file.read(65536)  # Read in 64kb chunks
            if not data:
                break
            hasher.update(data)
    return hasher.hexdigest()

def is_blacklisted(md5_hash):
    # Example implementation: Check if the MD5 hash is in a blacklist of known malicious hashes
    # Placeholder implementation - Replace with actual blacklist lookup
    blacklist = ['d41d8cd98f00b204e9800998ecf8427e', '0cc175b9c0f1b6a831c399e269772661']
    return md5_hash in blacklist

class FileMonitorThread(threading.Thread):
    def __init__(self, event_handler):
        super().__init__()
        self.event_handler = event_handler
        self.observer = Observer()

    def run(self):
        for directory in monitored_directories:
            self.observer.schedule(self.event_handler, directory, recursive=True)
        
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

def start_monitoring():
    initialize()

    network_thread = threading.Thread(target=scan_network)
    resource_thread = threading.Thread(target=monitor_resources)
    file_monitor_thread = FileMonitorThread(MyHandler())

    # Append threads to the global monitoring_threads list
    global monitoring_threads
    monitoring_threads.append(network_thread)
    monitoring_threads.append(resource_thread)
    monitoring_threads.append(file_monitor_thread)

    network_thread.start()
    resource_thread.start()
    file_monitor_thread.start()

def stop_monitoring():
    global monitoring_threads
    for thread in monitoring_threads:
        thread.do_run = False
        if isinstance(thread, FileMonitorThread):
            thread.observer.stop()
    monitoring_threads = []

