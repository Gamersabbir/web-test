# web.py - Modified for Remote Control
import requests
import json
import threading
import time
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, session
from datetime import datetime
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'asuwishmynigga_secure_key_2024'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# Database setup
def init_db():
    conn = sqlite3.connect('bot_control.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create bot_servers table
    c.execute('''CREATE TABLE IF NOT EXISTS bot_servers
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT,
                  ip_address TEXT,
                  port INTEGER DEFAULT 8080,
                  api_key TEXT,
                  status TEXT DEFAULT 'offline',
                  last_seen TIMESTAMP,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create command_log table
    c.execute('''CREATE TABLE IF NOT EXISTS command_log
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  bot_server_id INTEGER,
                  action TEXT,
                  data TEXT,
                  status TEXT,
                  response TEXT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create default admin user if not exists
    c.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                  ('admin', 'admin123'))
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Configuration
DEFAULT_BOT_SERVERS = [
    {"name": "PC-1", "ip": "192.168.1.100", "port": 8080, "api_key": "key123"},
    {"name": "PC-2", "ip": "192.168.1.101", "port": 8080, "api_key": "key456"},
]

class BotControlManager:
    def __init__(self):
        self.active_servers = {}
        self.bot_configs = {}
        self.load_configs()
        
    def load_configs(self):
        """Load bot configurations"""
        try:
            # Load bot servers from database
            conn = sqlite3.connect('bot_control.db')
            c = conn.cursor()
            c.execute("SELECT * FROM bot_servers")
            servers = c.fetchall()
            
            for server in servers:
                server_id, name, ip, port, api_key, status, last_seen, created_at = server
                self.active_servers[name] = {
                    'ip': ip,
                    'port': port,
                    'api_key': api_key,
                    'status': status,
                    'last_seen': last_seen
                }
            
            conn.close()
        except Exception as e:
            print(f"Error loading configs: {e}")
            
        # Load bot configurations
        try:
            with open('ALL_BOT.json', 'r') as f:
                config = json.load(f)
                self.bot_configs = config.get("bots", [])
        except FileNotFoundError:
            print("ERROR: ALL_BOT.json file not found!")
            self.bot_configs = []
        except json.JSONDecodeError:
            print("ERROR: Invalid JSON format in ALL_BOT.json!")
            self.bot_configs = []
    
    def discover_bot_servers(self):
        """Automatically discover bot servers on network"""
        discovered_servers = []
        
        # Try common IP ranges
        base_ips = ["192.168.1.", "192.168.0.", "10.0.0."]
        ports = [8080, 8081, 8082]
        
        for base_ip in base_ips:
            for i in range(1, 255):
                for port in ports:
                    ip = f"{base_ip}{i}"
                    if self.check_server_status(ip, port):
                        discovered_servers.append({
                            "ip": ip,
                            "port": port,
                            "name": f"Auto-Discovered-{ip}"
                        })
        
        return discovered_servers
    
    def check_server_status(self, ip, port, timeout=2):
        """Check if bot server is online"""
        try:
            url = f"http://{ip}:{port}/status"
            response = requests.get(url, timeout=timeout)
            return response.status_code == 200
        except:
            return False
    
    def send_command_to_server(self, server_info, command_data):
        """Send command to specific bot server"""
        try:
            ip = server_info.get('ip')
            port = server_info.get('port', 8080)
            api_key = server_info.get('api_key', '')
            
            url = f"http://{ip}:{port}/command"
            
            # Add API key if exists
            if api_key:
                command_data['api_key'] = api_key
            
            response = requests.post(url, json=command_data, timeout=10)
            
            # Log the command
            self.log_command(server_info.get('name'), command_data, response)
            
            return {
                "status": "success",
                "server": server_info.get('name'),
                "response": response.json() if response.status_code == 200 else None,
                "status_code": response.status_code
            }
        except requests.exceptions.ConnectionError:
            return {"status": "error", "error": f"Could not connect to {server_info.get('name')}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def broadcast_command(self, command_data):
        """Send command to all active bot servers"""
        results = []
        
        for server_name, server_info in self.active_servers.items():
            if server_info.get('status') == 'online':
                result = self.send_command_to_server(server_info, command_data)
                results.append({
                    "server": server_name,
                    "result": result
                })
        
        return results
    
    def send_smart_command(self, bot_id, action, data=None):
        """Smart command routing to appropriate server"""
        # Find which server has this bot
        target_server = None
        
        for server_name, server_info in self.active_servers.items():
            if server_info.get('status') == 'online':
                # Check if bot exists on this server
                try:
                    url = f"http://{server_info['ip']}:{server_info['port']}/status"
                    response = requests.get(url, timeout=2)
                    if response.status_code == 200:
                        server_status = response.json()
                        if bot_id in server_status.get('bots', []):
                            target_server = server_info
                            break
                except:
                    continue
        
        if target_server:
            command_data = {
                "action": action,
                "bot_id": bot_id,
                **(data or {})
            }
            return self.send_command_to_server(target_server, command_data)
        else:
            return {"status": "error", "error": f"Bot {bot_id} not found on any active server"}
    
    def log_command(self, server_name, command_data, response):
        """Log command to database"""
        try:
            conn = sqlite3.connect('bot_control.db')
            c = conn.cursor()
            
            c.execute('''INSERT INTO command_log 
                         (bot_server_id, action, data, status, response, timestamp)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                     (1, command_data.get('action'), 
                      json.dumps(command_data), 
                      'success' if response.status_code == 200 else 'error',
                      response.text if response else 'No response',
                      datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error logging command: {e}")
    
    def get_available_bots(self):
        """Get list of all available bots from all servers"""
        all_bots = []
        
        for server_name, server_info in self.active_servers.items():
            if server_info.get('status') == 'online':
                try:
                    url = f"http://{server_info['ip']}:{server_info['port']}/status"
                    response = requests.get(url, timeout=2)
                    if response.status_code == 200:
                        server_data = response.json()
                        bots = server_data.get('bots', [])
                        
                        for bot_id in bots:
                            all_bots.append({
                                "id": bot_id,
                                "server": server_name,
                                "server_ip": server_info['ip'],
                                "status": "online"
                            })
                except:
                    continue
        
        return all_bots

# Initialize bot manager
bot_manager = BotControlManager()

# Authentication middleware
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('bot_control.db')
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ? AND password = ?", 
                  (username, password))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Renders the main control panel page."""
    bots = bot_manager.bot_configs
    available_bots = bot_manager.get_available_bots()
    active_servers = bot_manager.active_servers
    
    return render_template('index.html', 
                         bots=bots, 
                         available_bots=available_bots,
                         active_servers=active_servers,
                         username=session.get('username'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard with statistics"""
    conn = sqlite3.connect('bot_control.db')
    c = conn.cursor()
    
    # Get stats
    c.execute("SELECT COUNT(*) FROM command_log WHERE status = 'success'")
    success_commands = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM command_log WHERE status = 'error'")
    error_commands = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM bot_servers WHERE status = 'online'")
    online_servers = c.fetchone()[0]
    
    c.execute("SELECT action, COUNT(*) as count FROM command_log GROUP BY action ORDER BY count DESC LIMIT 10")
    popular_actions = c.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html',
                         success_commands=success_commands,
                         error_commands=error_commands,
                         online_servers=online_servers,
                         popular_actions=popular_actions,
                         username=session.get('username'))

@app.route('/servers')
@login_required
def servers():
    """Manage bot servers"""
    conn = sqlite3.connect('bot_control.db')
    c = conn.cursor()
    c.execute("SELECT * FROM bot_servers ORDER BY status DESC, name")
    servers_list = c.fetchall()
    conn.close()
    
    return render_template('servers.html', servers=servers_list)

@app.route('/add_server', methods=['POST'])
@login_required
def add_server():
    """Add new bot server"""
    name = request.form.get('name')
    ip = request.form.get('ip')
    port = request.form.get('port', 8080)
    api_key = request.form.get('api_key', '')
    
    # Check if server is online
    is_online = bot_manager.check_server_status(ip, port)
    
    conn = sqlite3.connect('bot_control.db')
    c = conn.cursor()
    c.execute('''INSERT INTO bot_servers (name, ip_address, port, api_key, status, last_seen)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (name, ip, port, api_key, 'online' if is_online else 'offline', 
               datetime.now().isoformat() if is_online else None))
    conn.commit()
    conn.close()
    
    # Reload bot manager configs
    bot_manager.load_configs()
    
    flash(f'Server {name} added successfully!', 'success')
    return redirect(url_for('servers'))

@app.route('/discover_servers')
@login_required
def discover_servers():
    """Auto-discover bot servers"""
    discovered = bot_manager.discover_bot_servers()
    return jsonify({"discovered": discovered})

@app.route('/api/command', methods=['POST'])
@login_required
def api_command():
    """API endpoint for sending commands"""
    try:
        data = request.json
        action = data.get('action')
        bot_id = data.get('bot_id')
        server_name = data.get('server_name')
        
        if not action or not bot_id:
            return jsonify({"status": "error", "error": "Missing parameters"}), 400
        
        # Prepare command data
        command_data = {"action": action, "bot_id": bot_id}
        
        # Add additional data based on action
        if action == "emote":
            command_data["emote_id"] = data.get('emote_id')
            command_data["player_ids"] = data.get('player_ids', [])
        elif action == "join_squad":
            command_data["team_code"] = data.get('team_code')
        elif action == "quick_invite":
            command_data["player_id"] = data.get('player_id')
        elif action == "send_message":
            command_data["message"] = data.get('message')
            command_data["chat_type"] = data.get('chat_type', 0)
        
        # Send command
        if server_name:
            # Send to specific server
            server_info = bot_manager.active_servers.get(server_name)
            if server_info:
                result = bot_manager.send_command_to_server(server_info, command_data)
            else:
                result = {"status": "error", "error": "Server not found"}
        else:
            # Smart routing
            result = bot_manager.send_smart_command(bot_id, action, data)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/action', methods=['POST'])
@login_required
def handle_action():
    """Handles all form submissions from the new UI."""
    try:
        action = request.form.get('action')
        payload_str = request.form.get('payload')
        bot_uid = request.form.get('bot_uid', '')
        server_selection = request.form.get('server_selection', 'auto')
        
        if not action or payload_str is None:
            flash('Invalid request from client.', 'danger')
            return redirect(url_for('index'))
        
        # Parse payload
        data = json.loads(payload_str)
        
        # Find bot name from UID
        bot_name = "Unknown Bot"
        for bot in bot_manager.bot_configs:
            if bot['uid'] == bot_uid:
                bot_name = bot['name']
                break
        
        # Prepare command
        command_data = {
            "action": action,
            "bot_id": bot_name,
            "user": session.get('username')
        }
        
        # Add action-specific data
        if action == 'emote':
            command_data.update(data)
            if not command_data.get('emote_id') or not command_data.get('player_ids'):
                raise ValueError("Emote ID and Player IDs are required.")
            
            flash_msg = f"Sending emote {command_data['emote_id']} to {len(command_data['player_ids'])} player(s) using {bot_name}..."
            
        elif action == 'emote_batch':
            if not isinstance(data, list):
                raise ValueError("A list of assignments is required for emote_batch.")
            command_data['assignments'] = data
            flash_msg = f"Sending batch of {len(command_data['assignments'])} assigned emotes using {bot_name}..."
            
        elif action == 'join_squad':
            command_data.update(data)
            if not command_data.get('team_code'):
                raise ValueError("Team Code is required.")
            flash_msg = f"Attempting to join squad {command_data.get('team_code')} using {bot_name}..."
            
        elif action == 'quick_invite':
            command_data.update(data)
            if not command_data.get('player_id'):
                raise ValueError("Your Main Account UID is required.")
            flash_msg = f'Creating squad and sending invite using {bot_name}...'
            
        elif action == 'leave_squad':
            command_data.update(data)
            flash_msg = f'Telling {bot_name} to leave squad...'
        
        else:
            flash(f'Unknown action: {action}', 'danger')
            return redirect(url_for('index'))
        
        # Send command based on server selection
        result = None
        if server_selection == 'auto':
            # Smart routing
            result = bot_manager.send_smart_command(bot_name, action, data)
        elif server_selection == 'broadcast':
            # Broadcast to all servers
            results = bot_manager.broadcast_command(command_data)
            result = {"status": "broadcast", "results": results}
            flash_msg = f"Broadcasted command to {len(results)} servers"
        else:
            # Specific server
            server_info = bot_manager.active_servers.get(server_selection)
            if server_info:
                result = bot_manager.send_command_to_server(server_info, command_data)
            else:
                flash(f'Server {server_selection} not found!', 'danger')
                return redirect(url_for('index'))
        
        # Handle response
        if result and result.get('status') == 'success':
            flash(f'{flash_msg} - Success!', 'success')
        elif result and result.get('status') == 'broadcast':
            flash(flash_msg, 'info')
        else:
            error_msg = result.get('error', 'Unknown error') if result else 'No response'
            flash(f'Command failed: {error_msg}', 'danger')
        
    except requests.exceptions.ConnectionError:
        flash('Could not connect to bot servers. Make sure main.py is running on target PCs!', 'danger')
    except (ValueError, json.JSONDecodeError) as e:
        flash(f'Invalid data provided: {e}', 'danger')
    except Exception as e:
        flash(f'An unexpected error occurred: {e}', 'danger')
    
    return redirect(url_for('index'))

@app.route('/api/status')
@login_required
def api_status():
    """Get system status"""
    available_bots = bot_manager.get_available_bots()
    server_status = {}
    
    for server_name, server_info in bot_manager.active_servers.items():
        server_status[server_name] = {
            "status": server_info.get('status'),
            "ip": server_info.get('ip'),
            "port": server_info.get('port'),
            "last_seen": server_info.get('last_seen')
        }
    
    return jsonify({
        "status": "online",
        "available_bots": available_bots,
        "servers": server_status,
        "total_bots": len(available_bots),
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/bots')
@login_required
def api_bots():
    """Get all bot configurations"""
    return jsonify({
        "configs": bot_manager.bot_configs,
        "available": bot_manager.get_available_bots()
    })

@app.route('/history')
@login_required
def command_history():
    """View command history"""
    conn = sqlite3.connect('bot_control.db')
    c = conn.cursor()
    c.execute('''SELECT cl.*, bs.name as server_name 
                 FROM command_log cl 
                 LEFT JOIN bot_servers bs ON cl.bot_server_id = bs.id 
                 ORDER BY cl.timestamp DESC LIMIT 100''')
    history = c.fetchall()
    conn.close()
    
    return render_template('history.html', history=history)

def run_flask_app():
    # Start server discovery in background
    def discover_background():
        while True:
            bot_manager.load_configs()
            time.sleep(60)  # Check every minute
    
    # Start discovery thread
    discovery_thread = threading.Thread(target=discover_background, daemon=True)
    discovery_thread.start()
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

if __name__ == '__main__':
    print("🌐 Multi-PC Bot Control Panel")
    print("📡 Server: http://0.0.0.0:5000")
    print("🔧 Features:")
    print("  • Multi-PC Support")
    print("  • Auto Server Discovery")
    print("  • Smart Command Routing")
    print("  • Command History")
    print("  • User Authentication")
    print("\n✅ Ready to receive commands from any device!")
    
    # Run Flask app
    run_flask_app()
