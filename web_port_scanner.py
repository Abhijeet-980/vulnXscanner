from flask import Flask, render_template_string, request
import socket
import threading
import queue
from datetime import datetime

app = Flask(__name__)

# Common ports and services
common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 143, 161, 389, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443, 9200]

port_services = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MS RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS/SMB", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP Alternate", 8443: "HTTPS Alternate",
    9200: "Elasticsearch"
}

port_threats = {
    22: "SSH: Frequently targeted by brute-force attacks. Use key-based authentication.",
    80: "HTTP: Unencrypted web traffic. Vulnerable to interception.",
    443: "HTTPS: Generally secure, but depends on proper TLS configuration.",
    3389: "RDP: High-risk for ransomware. Disable if not needed.",
    445: "SMB: Known for exploits like EternalBlue. Block externally.",
    21: "FTP: Transmits credentials in plain text. Use SFTP instead.",
    23: "Telnet: Completely unencrypted. Replace with SSH.",
}

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        banner = ""

        # Try to get initial banner
        try:
            data = sock.recv(1024)
            if data:
                banner += data.decode('utf-8', errors='ignore').strip()
        except:
            pass

        # For web ports, send GET request
        if port in [80, 443, 8080, 8443]:
            try:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                response = sock.recv(2048)
                if response:
                    decoded = response.decode('utf-8', errors='ignore').strip()
                    banner += ("\n\n" + decoded) if banner else decoded
            except:
                pass

        sock.close()
        return banner[:500] if banner else "No banner grabbed"
    except:
        return "No banner grabbed"

def scan_target(target_ip, port_range):
    ports_to_scan = {
        "common": common_ports,
        "1-1024": list(range(1, 1025)),
        "1-10000": list(range(1, 10001))
    }[port_range]

    results = []
    q = queue.Queue()
    for port in ports_to_scan:
        q.put(port)

    def worker():
        while not q.empty():
            port = q.get()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((target_ip, port)) == 0:
                    service = port_services.get(port, "Unknown")
                    banner = grab_banner(target_ip, port)
                    results.append((port, service, banner))
                sock.close()
            except:
                pass
            q.task_done()

    for _ in range(60):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
    q.join()

    results.sort(key=lambda x: x[0])
    return results

def resolve_target(target):
    target = target.strip()
    try:
        socket.inet_aton(target)
        return target, target
    except:
        try:
            ip = socket.gethostbyname(target)
            return ip, target
        except:
            return None, target

# Clean & Professional HTML Template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureScan Pro - Port Scanner</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #121212;
            color: #e0e0e0;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 1px solid #333;
        }
        h1 {
            color: #00bfff;
            font-size: 2.8rem;
            margin: 0;
        }
        .subtitle {
            color: #aaa;
            font-size: 1.2rem;
            margin-top: 10px;
        }
        .warning {
            background: #330000;
            color: #ffcccc;
            padding: 15px;
            border-radius: 8px;
            margin: 30px 0;
            border-left: 4px solid #ff4444;
            font-weight: bold;
        }
        .form-card {
            background: #1e1e1e;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            margin-bottom: 40px;
        }
        label {
            display: block;
            margin: 20px 0 8px;
            font-weight: 600;
            color: #00bfff;
        }
        input, select {
            width: 100%;
            padding: 12px;
            background: #2d2d2d;
            border: 1px solid #444;
            border-radius: 8px;
            color: white;
            font-size: 1rem;
        }
        input:focus, select:focus {
            outline: none;
            border-color: #00bfff;
            box-shadow: 0 0 0 2px rgba(0,191,255,0.3);
        }
        button {
            margin-top: 25px;
            width: 100%;
            padding: 14px;
            background: #00bfff;
            color: black;
            font-weight: bold;
            border: none;
            border-radius: 8px;
            font-size: 1.1rem;
            cursor: pointer;
        }
        button:hover {
            background: #009fd9;
        }
        .results {
            background: #1e1e1e;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        .info {
            background: #002b36;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .port-item {
            background: #252525;
            padding: 20px;
            margin: 15px 0;
            border-radius: 10px;
            border-left: 4px solid #00bfff;
        }
        .open-port {
            color: #4ade80;
            font-weight: bold;
            font-size: 1.2rem;
        }
        .threat {
            background: #330000;
            color: #ff9999;
            padding: 12px;
            border-radius: 6px;
            margin-top: 12px;
            font-size: 0.95rem;
        }
        code {
            background: #000;
            padding: 12px;
            border-radius: 6px;
            display: block;
            overflow-x: auto;
            margin: 10px 0;
            font-size: 0.9rem;
        }
        footer {
            text-align: center;
            margin-top: 60px;
            color: #666;
            font-size: 0.9rem;
        }
        .no-ports {
            text-align: center;
            padding: 40px;
            color: #4ade80;
            font-size: 1.3rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SecureScan Pro</h1>
            <p class="subtitle">Professional Network Port Scanner</p>
        </header>

        <div class="warning">
            Use only on systems you own or have explicit permission to scan.<br>
            Examples: 127.0.0.1, scanme.nmap.org, github.com
        </div>

        <div class="form-card">
            <form method="post">
                <label>Target (IP or Domain Name)</label>
                <input type="text" name="target" placeholder="e.g., scanme.nmap.org" required value="{{ original_target }}">

                <label>Scan Range</label>
                <select name="range">
                    <option value="common">Common Ports (Fast)</option>
                    <option value="1-1024">Ports 1-1024</option>
                    <option value="1-10000">Ports 1-10000 (Thorough)</option>
                </select>

                <button type="submit">Start Scan</button>
            </form>
        </div>

        {% if results is not none %}
            <div class="results">
                {% if resolved_ip %}
                    <div class="info">
                        <strong>Scanned Target:</strong> {{ original_target }} → <strong>IP:</strong> {{ resolved_ip }}
                    </div>
                {% else %}
                    <div class="warning">Could not resolve domain name.</div>
                {% endif %}

                {% if results %}
                    <h2 style="color:#4ade80; text-align:center;">{{ results|length }} Open Ports Found</h2>
                    {% for port, service, banner in results %}
                        <div class="port-item">
                            <div class="open-port">Port {{ port }} — {{ service }}</div>
                            {% if "No banner" not in banner %}
                                <p><strong>Service Banner:</strong><br>
                                <code>{{ banner }}</code></p>
                            {% endif %}
                            <div class="threat">
                                <strong>Security Note:</strong> {{ port_threats.get(port, "Open port increases attack surface. Restrict access if possible.") }}
                            </div>
                        </div>
                    {% endfor %}
                {% else %}
                    {% if resolved_ip %}
                        <div class="no-ports">
                            <h2>No Open Ports Detected</h2>
                            <p>The target appears secure or protected by a firewall.</p>
                        </div>
                    {% endif %}
                {% endif %}
            </div>
        {% endif %}

        <footer>
            SecureScan Pro • Educational & Security Testing Tool • 2025
        </footer>
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    original_target = ""
    resolved_ip = None

    if request.method == 'POST':
        original_target = request.form['target'].strip()
        port_range = request.form['range']

        resolved_ip, _ = resolve_target(original_target)

        if resolved_ip:
            results = scan_target(resolved_ip, port_range)
        else:
            results = []

    return render_template_string(
        HTML_TEMPLATE,
        results=results,
        original_target=original_target,
        resolved_ip=resolved_ip,
        port_threats=port_threats
    )

if __name__ == '__main__':
    print("SecureScan Pro is starting...")
    print("Open your browser: http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=False)