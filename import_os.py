import os
import socket
import re
import sqlite3
import hmac
import requests
from flask import Flask, request, jsonify, make_response, render_template

app = Flask(__name__)


@app.route('/')
def home():
    # Render a simple HTML test UI (templates/index.html)
    return render_template('index.html')


def _is_valid_hostname(name: str) -> bool:
    # Validate IP addresses
    try:
        import ipaddress

        ipaddress.ip_address(name)
        return True
    except Exception:
        pass

    # Basic hostname validation (not a full RFC implementation)
    if len(name) > 253:
        return False
    if name.endswith('.'):
        name = name[:-1]
    allowed = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
    return all(allowed.match(x) for x in name.split('.'))


@app.route('/ping', methods=['GET'])
def ping():
    """Safe reachability check using a TCP connection instead of shell ping.
    Query parameter: 'host' (hostname or IP)."""
    host = request.args.get('host', '')
    if not host:
        return jsonify({'error': 'host parameter required'}), 400
    if not _is_valid_hostname(host):
        return jsonify({'error': 'invalid host'}), 400

    try:
        with socket.create_connection((host, 80), timeout=3):
            return jsonify({'host': host, 'reachable': True})
    except Exception as e:
        return jsonify({'host': host, 'reachable': False, 'error': str(e)})


# Credentials must be provided via environment variables
USERNAME = os.environ.get('APP_USERNAME')
PASSWORD = os.environ.get('APP_PASSWORD')


@app.route('/login', methods=['POST'])
def login():
    if not USERNAME or not PASSWORD:
        return jsonify({'error': 'authentication not configured'}), 500
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    if hmac.compare_digest(username, USERNAME) and hmac.compare_digest(password, PASSWORD):
        return jsonify({'status': 'login successful'})
    return jsonify({'status': 'login failed'}), 401


@app.route('/deserialize_json', methods=['POST'])
def deserialize_json():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({'error': 'invalid JSON'}), 400
    return jsonify({'received': data})


@app.route('/requests_example', methods=['GET'])
def requests_example():
    try:
        resp = requests.get('https://example.com', timeout=5)
        resp.raise_for_status()
        content_type = resp.headers.get('Content-Type', 'text/plain')
        return make_response(resp.content, 200, {'Content-Type': content_type})
    except requests.RequestException as e:
        return jsonify({'error': 'failed to fetch remote resource', 'detail': str(e)}), 502


@app.route('/user', methods=['GET'])
def get_user():
    user_id = request.args.get('id', '')
    if not user_id:
        return jsonify({'error': 'id parameter required'}), 400
    user = run_query(user_id)
    if user is None:
        return jsonify({'user': None}), 404
    return jsonify({'user': user})


def run_query(user_id: str):
    db_path = os.path.join(os.path.dirname(__file__), 'app.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT)')
    cur.execute('INSERT OR IGNORE INTO users (id, name) VALUES (?, ?)', ('1', 'Alice'))
    cur.execute('INSERT OR IGNORE INTO users (id, name) VALUES (?, ?)', ('2', 'Bob'))
    cur.execute('SELECT id, name FROM users WHERE id = ?', (user_id,))
    row = cur.fetchone()
    conn.commit()
    conn.close()
    if row:
        return dict(row)
    return None


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)