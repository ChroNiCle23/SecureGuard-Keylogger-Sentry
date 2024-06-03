# SecureGuard-Keylogger-Sentry
"SecureGuard Keylogger Sentry" is a comprehensive security tool tailored for network administrators, system administrators, forensic analysts, and cybersecurity analysts. It offers a suite of features to bolster system defenses, including monitoring keylogging activities, scanning network traffic, tracking system resources, and assessing vulnerabilities. With its ability to provide real-time alerts, detailed logs, and proactive threat detection, SecureGuard enables users to identify and respond to security threats effectively, ensuring the integrity and security of networked environments.

# Requirement
System Requirements:

Python 3.5+
Internet connection for network scanning and VirusTotal API usage
Windows operating system (for startup functionalities)

Dependencies:

1. Flask
2. Watchdog
3. Psutil
4. Requests
5. Python Bootstrap (optional for frontend styling)

# Installation 
1. Check the Python version
   ```
   python3 --version
   ```
3. If Python is not installed or you have lower version, You can download Python from the official website: https://www.python.org/downloads/
4. Flask is used in this project to create the web application interface for SecureGuard Keylogger Sentry.
   ```
   pip install flask
   pip install Flask-RESTful
   ```
5. Watchdog is used to monitor changes in directories and files, allowing the system to react to any suspicious activities.
   ```
   pip install watchdog
   ```
6. SecureGuard Keylogger Sentry utilizes Psutil to monitor system resources, detect high CPU/memory usage, and identify potentially malicious processes.
   ```
   pip install psutil
   ```
8. Requests is utilized to interact with external services, such as the VirusTotal API for file scanning and retrieving vulnerability data.
   ```
   pip install requests
   ```
9. Bootstrap enhances the user experience and aesthetics of SecureGuard Keylogger Sentry's web application.
    ```
   pip install flask-bootstrap
   ```
10. Git Clone
    ```
    https://github.com/ChroNiCle23/SecureGuard-Keylogger-Sentry.git
    ```
11. Configuration:
    ```
    Replace VT_API_KEY in monitor.py with your VirusTotal API key.
    Ensure that you have Python 3.5+ installed.
    ```

# Usage
1. Starting the Application
   ```
   python e_guard.py
   ```
2. Accessing the Control Panel:
   ```
   Open a web browser and go to http://localhost:5000/. You will see the Control Panel of SecureGuard Keylogger Sentry.
   ```
Functionality:

1. Add to Startup: Adds the monitoring tool to system startup.
2. Remove from Startup: Removes the monitoring tool from system startup.
3. Start Monitoring: Initiates monitoring of system resources and file events.
4. Stop Monitoring: Stops monitoring of system resources and file events.
5. View Logs: Displays real-time logs of monitored file events.
6. Check Vulnerabilities: Checks for vulnerabilities using CVE data from NVD.
7. Check File Access: Checks file access permissions for a specified process ID



   
