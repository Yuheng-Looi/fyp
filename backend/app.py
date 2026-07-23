from flask import Flask, request, jsonify
import sqlite3
import json
import os
import datetime

app = Flask(__name__)
DB_PATH = 'victim_db.sqlite'
LOG_PATH = 'security_evidence.log'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    ''')
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'SuperSecretAdmin123!')")
        cursor.execute("INSERT INTO users (username, password) VALUES ('user1', 'password123')")
        conn.commit()
    conn.close()

def log_security_evidence(event_type, src_ip):
    log_entry = {
        "event": event_type,
        "src_ip": src_ip,
        "timestamp": datetime.datetime.now().isoformat()
    }
    # Log to the global security_evidence.log path for consistency
    global_log_path = '/home/fyp2025/fyp/backend/security_evidence.log'
    try:
        with open(global_log_path, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        print(f"Failed to write to security evidence log: {e}")

@app.route('/')
def index():
    return jsonify({"status": "running", "service": "Victim Server API"})

@app.route('/query', methods=['GET'])
def query_db():
    query_param = request.args.get('q', '')
    src_ip = request.remote_addr

    # Simple SQL Injection detection
    sqli_keywords = ["'", "UNION", "SELECT", "OR", "--", "#", "/*"]
    is_sqli = any(kw in query_param.upper() for kw in sqli_keywords)

    if is_sqli:
        log_security_evidence("unauthorized_query", src_ip)
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(f"SELECT username FROM users WHERE username = '{query_param}'")
            results = cursor.fetchall()
            conn.close()
            return jsonify({"results": results, "warning": "Potential SQL injection detected and logged!"})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username LIKE ?", (f"%{query_param}%",))
        results = cursor.fetchall()
        conn.close()
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/credentials', methods=['GET'])
def credentials():
    src_ip = request.remote_addr
    log_security_evidence("unauthorized_credential_query", src_ip)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT username, password FROM users")
        results = [{"username": r[0], "password": r[1]} for r in cursor.fetchall()]
        conn.close()
        return jsonify({"credentials": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=80)
    args = parser.parse_args()
    init_db()
    app.run(host='0.0.0.0', port=args.port)
