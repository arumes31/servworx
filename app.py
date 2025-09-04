from flask import Flask, request, render_template, redirect, url_for, session
import os
import json
import hashlib
import threading
import time
import requests
import subprocess
import datetime
import builtins
import signal
import sys

app = Flask(__name__)
app.secret_key = os.urandom(24)
CONFIG_FILE = '/app/config/config.json'
STATUS_FILE = '/app/config/status.json'
DEFAULT_CONFIG = {
    'users': {'admin': hashlib.sha256('changeme'.encode()).hexdigest()},
    'services': [
        {
            'name': 'Service1',
            'website_url': 'http://example.com',
            'container_names': 'service1',
            'retries': 15,
            'interval': 120,
            'grace_period': 3600,
            'accepted_status_codes': [200]
        }
    ]
}
DEFAULT_STATUS = {
    'services': [
        {'name': 'Service1', 'status': 'Unknown', 'last_failure': None, 'down_since': None, 'up_since': None, 'last_stable_status': 'Unknown'}
    ]
}

# Add custom zip filter to Jinja2
app.jinja_env.filters['zip'] = builtins.zip

# Global variable to track monitoring threads
monitoring_threads = []
stop_monitoring_flag = threading.Event()

# ANSI color codes
COLOR_GREEN = '\033[92m'  # User actions
COLOR_BLUE = '\033[94m'   # System actions (container start/stop)
COLOR_YELLOW = '\033[93m' # Service status (Checking, Up)
COLOR_RED = '\033[91m'    # Errors or restarts, Down status
COLOR_RESET = '\033[0m'

# Helper function to format duration in human-readable form
def format_duration(seconds):
    if seconds is None or seconds <= 0:
        return "0 seconds"
    days = seconds // (24 * 3600)
    seconds %= (24 * 3600)
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if seconds > 0 or not parts:
        parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")
    return ", ".join(parts)

# Initialize config and status files
if not os.path.exists(CONFIG_FILE):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(DEFAULT_CONFIG, f)
if not os.path.exists(STATUS_FILE):
    with open(STATUS_FILE, 'w') as f:
        json.dump(DEFAULT_STATUS, f)

def log_action(username, action, log_type='user'):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if log_type == 'user':
        color = COLOR_GREEN
    elif log_type == 'system':
        color = COLOR_BLUE
    elif log_type == 'status':
        color = COLOR_YELLOW if 'Down' not in action else COLOR_RED
    elif log_type == 'error':
        color = COLOR_RED
    else:
        color = COLOR_RESET
    print(f"{color}[{timestamp}] {username}: {action}{COLOR_RESET}")
    sys.stdout.flush()

def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        log_action("System", f"Failed to load config: {str(e)}", log_type='error')
        return DEFAULT_CONFIG

def save_config(config):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
    except Exception as e:
        log_action("System", f"Failed to save config: {str(e)}", log_type='error')
        raise

def load_status():
    try:
        with open(STATUS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        log_action("System", f"Failed to load status: {str(e)}", log_type='error')
        return DEFAULT_STATUS

def save_status(status):
    try:
        with open(STATUS_FILE, 'w') as f:
            json.dump(status, f)
    except Exception as e:
        log_action("System", f"Failed to save status: {str(e)}", log_type='error')
        raise

def check_website(url, accepted_status_codes):
    try:
        response = requests.head(url, timeout=5, verify=False)
        if response.status_code in accepted_status_codes:
            return True, f"Website returned status {response.status_code} (accepted)"
        else:
            return False, f"Website returned status {response.status_code} (not accepted)"
    except requests.RequestException as e:
        return False, f"Website is unreachable: {str(e)}"

def restart_containers(container_names, service_name):
    log_action("System", f"Restarting Docker containers for {service_name}", log_type='error')
    containers = container_names.split(',')
    for container in containers:
        container = container.strip()
        print(f"Executing 'docker restart {container}'")
        sys.stdout.flush()
        subprocess.run(['docker', 'restart', container])
        print(f"Completed 'docker restart {container}'")
        sys.stdout.flush()
    last_restart = int(time.time())
    status = load_status()
    for s in status['services']:
        if s['name'] == service_name:
            s['last_failure'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_action("System", f"Updated last_failure for {service_name} to {s['last_failure']}", log_type='system')
    save_status(status)
    return last_restart

def monitor_service(service, status_lock):
    name = service['name']
    url = service['website_url']
    container_names = service['container_names']
    retries = service['retries']
    interval = service['interval']
    grace_period = service['grace_period']
    accepted_status_codes = service.get('accepted_status_codes', [200])
    last_restart_file = f"/app/config/last_restart_{name}.txt"

    # Read last restart time
    if os.path.exists(last_restart_file):
        with open(last_restart_file, 'r') as f:
            last_restart = int(f.read().strip())
    else:
        last_restart = 0

    while not stop_monitoring_flag.is_set():
        current_time = int(time.time())
        time_since_last_restart = current_time - last_restart
        restart_allowed = time_since_last_restart >= grace_period
        remaining_grace = grace_period - time_since_last_restart if time_since_last_restart < grace_period else 0

        with status_lock:
            status = load_status()
            for s in status['services']:
                if s['name'] == name:
                    s['status'] = 'Checking'
                    log_action("System", f"Service {name} status: Checking", log_type='status')
            save_status(status)

        success = False
        for i in range(1, retries + 1):
            if stop_monitoring_flag.is_set():
                break
            success, message = check_website(url, accepted_status_codes)
            with status_lock:
                status = load_status()
                for s in status['services']:
                    if s['name'] == name:
                        old_status = s.get('last_stable_status', s['status'])
                        s['status'] = 'Up' if success else 'Down'
                        if s['status'] != old_status:
                            if s['status'] == 'Down' and old_status == 'Up':
                                s['down_since'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                s['up_since'] = None
                                s['last_failure'] = s['down_since']
                                log_action("System", f"Updated down_since for {name} to {s['down_since']}", log_type='system')
                            elif s['status'] == 'Up' and old_status == 'Down':
                                s['up_since'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                s['down_since'] = None
                                log_action("System", f"Updated up_since for {name} to {s['up_since']}", log_type='system')
                        s['last_stable_status'] = s['status']
                        log_action("System", f"Service {name} status: {s['status']}", log_type='status')
                save_status(status)

            print(f"{name}: {message}")
            sys.stdout.flush()
            if success:
                break
            elif i < retries:
                print(f"{name}: Retry {i}/{retries} failed, retrying in {interval} seconds...")
                sys.stdout.flush()
                for _ in range(interval):
                    if stop_monitoring_flag.is_set():
                        break
                    time.sleep(1)

        if not success and not stop_monitoring_flag.is_set():
            print(f"{name}: Max retries ({retries}) reached.")
            sys.stdout.flush()
            if restart_allowed:
                last_restart = restart_containers(container_names, name)
                with open(last_restart_file, 'w') as f:
                    f.write(str(last_restart))
            else:
                print(f"{name}: Restart not allowed yet. Remaining grace period: {remaining_grace} seconds.")
                sys.stdout.flush()
                log_action("System", f"Service {name}: Restart not allowed, remaining grace period: {remaining_grace} seconds", log_type='error')
                sys.stdout.flush()

        if not stop_monitoring_flag.is_set():
            print(f"{name}: Sleeping {interval} sec...")
            sys.stdout.flush()
            for _ in range(interval):
                if stop_monitoring_flag.is_set():
                    break
                time.sleep(1)

def stop_monitoring():
    global monitoring_threads
    stop_monitoring_flag.set()
    for thread in monitoring_threads:
        thread.join(timeout=1.0)  # Short timeout to avoid long waits
    monitoring_threads = []
    stop_monitoring_flag.clear()
    log_action("System", "Monitoring threads stopped", log_type='system')

def start_monitoring():
    global monitoring_threads
    config = load_config()
    status = load_status()
    status_lock = threading.Lock()

    # Rebuild status['services'] to match config['services'] order
    config_service_names = [service['name'] for service in config['services']]
    new_status_services = []
    existing_status = {s['name']: s for s in status['services']}

    for name in config_service_names:
        if name in existing_status:
            # Ensure all fields are present
            status_entry = existing_status[name]
            status_entry.setdefault('down_since', None)
            status_entry.setdefault('up_since', None)
            status_entry.setdefault('last_stable_status', status_entry.get('status', 'Unknown'))
            new_status_services.append(status_entry)
        else:
            new_status_services.append({
                'name': name,
                'status': 'Unknown',
                'last_failure': None,
                'down_since': None,
                'up_since': None,
                'last_stable_status': 'Unknown'
            })
            log_action("System", f"Initialized status for new service: {name}", log_type='system')
    status['services'] = new_status_services
    save_status(status)
    log_action("System", f"Rebuilt status.json to match config.json: {config_service_names}", log_type='system')

    # Start a thread for each service
    for service in config['services']:
        thread = threading.Thread(target=monitor_service, args=(service, status_lock), daemon=True)
        monitoring_threads.append(thread)
        thread.start()
    log_action("System", "Monitoring threads started", log_type='system')

def handle_shutdown(signum, frame):
    log_action("System", f"Received signal {signum}, servworx container stopping", log_type='system')
    stop_monitoring()
    sys.exit(0)

# Register signal handlers for container stop
signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)

# Log container start and initialize monitoring
log_action("System", "servworx container started", log_type='system')
start_monitoring()

@app.route('/')
def index():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('config'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        config = load_config()
        
        if username in config['users']:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if config['users'][username] == hashed_password:
                session['logged_in'] = True
                session['username'] = username
                log_action(username, "Logged in", log_type='user')
                # Force password change on first login
                if username == 'admin' and hashed_password == hashlib.sha256('changeme'.encode()).hexdigest():
                    return redirect(url_for('change_password'))
                return redirect(url_for('config'))
            else:
                log_action(username, "Failed login attempt (invalid password)", log_type='error')
                error = 'Invalid password'
        else:
            log_action(username, "Failed login attempt (invalid username)", log_type='error')
            error = 'Invalid username'
    return render_template('login.html', error=error)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    username = session.get('username', 'unknown')
    error = None
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password == confirm_password:
            config = load_config()
            config['users'][username] = hashlib.sha256(new_password.encode()).hexdigest()
            save_config(config)
            log_action(username, "Changed password", log_type='user')
            return redirect(url_for('config'))
        else:
            log_action(username, "Failed password change (passwords do not match)", log_type='error')
            error = 'Passwords do not match'
    
    return render_template('change_password.html', error=error)

@app.route('/config', methods=['GET'])
def config():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    username = session.get('username', 'unknown')
    log_action(username, "Accessed configuration page", log_type='user')
    config = load_config()
    status = load_status()
    
    # Calculate durations and time to restart for each service
    current_time = int(time.time())
    for service, s in zip(config['services'], status['services']):
        s['down_for'] = None
        s['up_for'] = None
        s['time_to_restart'] = format_duration(service['interval'] * service['retries'])
        if s['down_since']:
            try:
                down_since_time = int(datetime.datetime.strptime(s['down_since'], '%Y-%m-%d %H:%M:%S').timestamp())
                s['down_for'] = format_duration(current_time - down_since_time)
            except ValueError:
                s['down_for'] = "Invalid timestamp"
        if s['up_since']:
            try:
                up_since_time = int(datetime.datetime.strptime(s['up_since'], '%Y-%m-%d %H:%M:%S').timestamp())
                s['up_for'] = format_duration(current_time - up_since_time)
            except ValueError:
                s['up_for'] = "Invalid timestamp"
    
    return render_template('config.html', services=config['services'], status=status)

@app.route('/update_service/<int:index>', methods=['POST'])
def update_service(index):
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    username = session.get('username', 'unknown')
    log_action(username, f"Reached update service endpoint for index {index} with raw form data: {dict(request.form)}", log_type='user')
    try:
        config = load_config()
        action = request.form.get('action')
        
        if action == 'delete':
            if 0 <= index < len(config['services']):
                deleted_service_name = config['services'][index]['name']
                config['services'].pop(index)
                save_config(config)
                status = load_status()
                status['services'] = [s for s in status['services'] if s['name'] != deleted_service_name]
                save_status(status)
                log_action(username, f"Deleted service: {deleted_service_name}", log_type='user')
                log_action("System", f"Removed status for service: {deleted_service_name}", log_type='system')
                # Stop and restart monitoring threads
                stop_monitoring()
                start_monitoring()
                return redirect(url_for('config'))
            else:
                log_action(username, f"Invalid service index {index} for deletion", log_type='error')
                return render_template('config.html', services=config['services'], status=load_status(), error=f"Invalid service index: {index}")
        
        elif action == 'update':
            if 0 <= index < len(config['services']):
                # Validate form data
                required_fields = ['name', 'website_url', 'container_names', 'retries', 'interval', 'grace_period', 'accepted_status_codes']
                for field in required_fields:
                    if field not in request.form:
                        raise ValueError(f"Missing required field: {field}")
                
                # Validate numeric inputs
                retries = int(request.form['retries'])
                interval = int(request.form['interval'])
                grace_period = int(request.form['grace_period'])
                if retries < 1 or interval < 1 or grace_period < 1:
                    raise ValueError(f"Service {index}: Retries, interval, and grace period must be positive integers")
                
                # Parse comma-separated status codes, default to [200] if empty
                status_codes = request.form['accepted_status_codes']
                if not status_codes.strip():
                    log_action(username, f"Service {index}: Empty accepted_status_codes, defaulting to [200]", log_type='user')
                    accepted_status_codes = [200]
                else:
                    accepted_status_codes = [int(code.strip()) for code in status_codes.split(',') if code.strip()]
                    if not accepted_status_codes:
                        log_action(username, f"Service {index}: No valid accepted_status_codes, defaulting to [200]", log_type='user')
                        accepted_status_codes = [200]
                
                # Update the service
                old_service_name = config['services'][index]['name']
                config['services'][index] = {
                    'name': request.form['name'],
                    'website_url': request.form['website_url'],
                    'container_names': request.form['container_names'],
                    'retries': retries,
                    'interval': interval,
                    'grace_period': grace_period,
                    'accepted_status_codes': accepted_status_codes
                }
                save_config(config)
                # Update status if service name changed
                status = load_status()
                for s in status['services']:
                    if s['name'] == old_service_name:
                        s['name'] = request.form['name']
                        log_action("System", f"Updated status name from {old_service_name} to {s['name']}", log_type='system')
                save_status(status)
                log_action(username, f"Configuration validated for service {index}, saving to file", log_type='user')
                log_action(username, f"Updated service {index} successfully", log_type='user')
                # Stop and restart monitoring threads
                stop_monitoring()
                start_monitoring()
                return redirect(url_for('config'))
            else:
                log_action(username, f"Invalid service index {index} for update", log_type='error')
                return render_template('config.html', services=config['services'], status=load_status(), error=f"Invalid service index: {index}")
        else:
            raise ValueError("Invalid action specified")
    except Exception as e:
        log_action(username, f"Failed to process service {index}: {str(e)}", log_type='error')
        return render_template('config.html', services=config['services'], status=load_status(), error=str(e))

@app.route('/add_service', methods=['POST'])
def add_service():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    username = session.get('username', 'unknown')
    log_action(username, "Received add service request", log_type='user')
    try:
        config = load_config()
        new_service_name = f'Service{len(config["services"]) + 1}'
        config['services'].append({
            'name': new_service_name,
            'website_url': 'http://example.com',
            'container_names': '',
            'retries': 15,
            'interval': 120,
            'grace_period': 3600,
            'accepted_status_codes': [200]
        })
        save_config(config)
        status = load_status()
        status['services'].append({
            'name': new_service_name,
            'status': 'Unknown',
            'last_failure': None,
            'down_since': None,
            'up_since': None,
            'last_stable_status': 'Unknown'
        })
        save_status(status)
        log_action(username, f"Added new service: {new_service_name}", log_type='user')
        log_action("System", f"Initialized status for new service: {new_service_name}", log_type='system')
        # Stop and restart monitoring threads
        stop_monitoring()
        start_monitoring()
        return redirect(url_for('config'))
    except Exception as e:
        log_action(username, f"Failed to add service: {str(e)}", log_type='error')
        return render_template('config.html', services=config['services'], status=load_status(), error=str(e))

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    session.pop('logged_in', None)
    session.pop('username', None)
    log_action(username, "Logged out", log_type='user')
    return redirect(url_for('login'))