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
11. Git Clone
12. 

# Usage
