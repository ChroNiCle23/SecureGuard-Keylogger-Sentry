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
3. If Python is not installed or you have lower version, You can download Python from the official website:
   ```
    https://www.python.org/downloads/
   ```
5. Flask is used in this project to create the web application interface for SecureGuard Keylogger Sentry.
   ```
   pip install flask
   pip install Flask-RESTful
   ```
6. Watchdog is used to monitor changes in directories and files, allowing the system to react to any suspicious activities.
   ```
   pip install watchdog
   ```
7. SecureGuard Keylogger Sentry utilizes Psutil to monitor system resources, detect high CPU/memory usage, and identify potentially malicious processes.
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
3. Functionality:
   ```
   Add to Startup: Adds the monitoring tool to system startup.
   Remove from Startup: Removes the monitoring tool from system startup.
   Start Monitoring: Initiates monitoring of system resources and file events.
   Stop Monitoring: Stops monitoring of system resources and file events.
   View Logs: Displays real-time logs of monitored file events.
   Check Vulnerabilities: Checks for vulnerabilities using CVE data from NVD.
   Check File Access: Checks file access permissions for a specified process ID
   ```
# Screenshots
![image](https://github.com/ChroNiCle23/SecureGuard-Keylogger-Sentry/assets/161189544/0ecdaf30-ab4f-457d-be46-9ace69870de1)
![image](https://github.com/ChroNiCle23/SecureGuard-Keylogger-Sentry/assets/161189544/02aa18c5-904f-46b2-b2ba-62d288690332)
![image](https://github.com/ChroNiCle23/SecureGuard-Keylogger-Sentry/assets/161189544/83162d62-5e98-42a6-b966-f72af4209023)
![image](https://github.com/ChroNiCle23/SecureGuard-Keylogger-Sentry/assets/161189544/00dd79bf-68f5-4909-b334-b9869f8bb778)
![image](https://github.com/ChroNiCle23/SecureGuard-Keylogger-Sentry/assets/161189544/98154169-7489-48d7-96c4-cfbd3486fe31)






   
