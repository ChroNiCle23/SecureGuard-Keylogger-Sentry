from flask import Flask, render_template, redirect, url_for, request, jsonify
from monitor import integrate_vulnerability_databases, analyze_behavior
import threading
import monitor
import os

app = Flask(__name__)

monitoring_thread = None
vulnerability_data = None  # Variable to store vulnerability data

# Function to clear vulnerability_results.log
def clear_vulnerability_log():
    log_file_path = 'vulnerability_results.log'
    if os.path.exists(log_file_path):
        os.remove(log_file_path)

# Call the function to clear vulnerability_results.log when the code starts
clear_vulnerability_log()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add-to-startup')
def add_to_startup():
    monitor.add_to_startup()
    return redirect(url_for('index'))

@app.route('/remove-from-startup')
def remove_from_startup():
    monitor.remove_from_startup()
    return redirect(url_for('index'))

@app.route('/start-monitoring')
def start_monitoring():
    global monitoring_thread
    if monitoring_thread is None or not monitoring_thread.is_alive():
        monitoring_thread = threading.Thread(target=monitor.start_monitoring)
        monitoring_thread.start()
    return redirect(url_for('index'))

@app.route('/stop-monitoring')
def stop_monitoring():
    monitor.stop_monitoring()
    global monitoring_thread
    if monitoring_thread is not None:
        monitoring_thread.join()
        monitoring_thread = None
    return redirect(url_for('index'))

@app.route('/view-logs')
def view_logs():
    log_content = read_log_file('e_guard.log')  # Read from e_guard.log
    return render_template('logs.html', log_content=log_content)

@app.route('/check-vulnerabilities')
def check_vulnerabilities():
    clear_vulnerability_log()  # Clear vulnerability_results.log
    integrate_vulnerability_databases()  # Call the function to fetch CVE data and log it
    return redirect(url_for('vulnerability_results'))

@app.route('/vulnerability_results')
def vulnerability_results():
    log_content = read_log_file('vulnerability_results.log')  # Read from vulnerability_results.log
    return render_template('vulnerability_results.html', log_content=log_content)




def read_log_file(log_file_path):
    with open(log_file_path, 'r') as log_file:
        log_content = log_file.read()
    return log_content

if __name__ == '__main__':
    app.run(debug=True)
