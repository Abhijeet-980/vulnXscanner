# NetScan Pro - Fixed Professional Version (No More Server Errors!)

from flask import Flask, render_template_string, request
import socket
import threading
from datetime import datetime
import queue

app = Flask(__name__)

# === Port & Service Data ===
common_ports = [22, 80, 443, 3389, 445, 21, 23, 25, 53, 110, 135, 137, 138, 139, 143, 161, 162, 389, 3306, 5432, 5900, 8080, 8443, 9200]

port_services = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MS RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS/SMB", 143: "IMAP", 161: "SNMP", 162: "SNMP Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP Alternate", 8443: "HTTPS Alternate",
    9200: "Elasticsearch",
}

port_threats = {
    22: "SSH: Highly targeted for brute-force attacks and exploits. Keep updated!",
    80: "HTTP: Unencrypted traffic. Vulnerable to MITM and web exploits.",
    443: "HTTPS: Secure if TLS is modern, but web app flaws remain possible.",
    3389: "RDP: Top target for ransomware (BlueKeep, brute-force). Disable if unused!",
    445: "SMB: EternalBlue vulnerability led to WannaCry. Patch immediately!",
    21: "FTP: Sends passwords in plaintext. Extremely risky.",
    23: "Telnet: Fully unencrypted. Disable immediately!",
}

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        if port in [80, 443, 8080, 8443]:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
            banner += "\n" + sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        if banner:
            return banner[:300]
    except:
        pass
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

    for _ in range(50):
        t = threading.Thread(target=worker)
        t.daemon = True
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
            resolved_ip = socket.gethostbyname(target)
            return resolved_ip, target
        except:
            return None, target

# === Fixed Professional HTML Template (No strftime error!) ===
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetScan Pro - Advanced Port Scanner</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0f0f1a;
            --card: #1a1a2e;
            --text: #e0e0ff;
            --accent: #00d4ff;
            --success: #00ff9d;
            --warning: #ff6b6b;
            --border: #33334d;
        }
        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #0f0f1a 0%, #16213e 100%);
            color: var(--text);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }
        .container { max-width: 1000px; margin: 40px auto; }
        header { text-align: center; margin-bottom: 40px; }
        h1 {
            font-size: 2.8rem;
            background: linear-gradient(90deg, #00d4ff, #00ff9d);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin: 0;
        }
        .subtitle { color: #8888aa; font-size: 1.1rem; }
        .warning-box {
            background: rgba(255, 107, 107, 0.15);
            border: 1px solid var(--warning);
            padding: 16px;
            border-radius: 12px;
            margin: 20px 0;
            font-size: 0.95rem;
        }
        .scan-card {
            background: var(--card);
            border-radius: 16px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
            margin-bottom: 30px;
        }
        label {
            display: block;
            margin: 20px 0 8px;
            font-weight: 600;
            color: var(--accent);
        }
        input, select {
            width: 100%;
            padding: 14px;
            background: #16213e;
            border: 1px solid var(--border);
            border-radius: 10px;
            color: white;
            font-size: 1rem;
        }
        input:focus, select:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.2);
        }
        button {
            margin-top: 25px;
            width: 100%;
            padding: 16px;
            background: linear-gradient(90deg, #00d4ff, #00ff9d);
            color: black;
            font-weight: bold;
            font-size: 1.1rem;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.3s;
        }
        button:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(0, 212, 255, 0.3);
        }
        .result-info {
            background: rgba(0, 212, 255, 0.1);
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            border-left: 4px solid var(--accent);
        }
        .port-card {
            background: #16213e;
            border-radius: 12px;
            padding: 20px;
            margin: 15px 0;
            border: 1px solid var(--border);
            transition: all 0.3s;
        }
        .port-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        }
        .open { color: var(--success); font-weight: bold; }
        .threat {
            background: rgba(255, 107, 107, 0.15);
            padding: 12px;
            border-radius: 8px;
            margin-top: 12px;
            border-left: 4px solid var(--warning);
        }
        footer {
            text-align: center;
            margin-top: 60px;
            color: #666;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>NetScan Pro</h1>
            <p class="subtitle">Advanced Network Port Scanner • Banner Grabbing • Threat Insights</p>
        </header>

        <div class="warning-box">
            ⚠️ <strong>Ethical Use Only:</strong> Scan only systems you own or have explicit permission to test.<br>
            Examples: 127.0.0.1, scanme.nmap.org, yourdomain.com
        </div>

        <div class="scan-card">
            <form method="post">
                <label>🎯 Target (IP or Domain)</label>
                <input type="text" name="target" placeholder="e.g., google.com or 127.0.0.1" required value="{{ original_target }}">

                <label>📊 Scan Intensity</label>
                <select name="range">
                    <option value="common">Quick Scan (Common Ports)</option>
                    <option value="1-1024">Standard Scan (1-1024)</option>
                    <option value="1-10000">Deep Scan (1-10000)</option>
                </select>

                <button type="submit">🚀 Launch Scan</button>
            </form>
        </div>

        {% if results is not none %}
            <div class="scan-card">
                {% if resolved_ip %}
                    <div class="result-info">
                        <strong>Target:</strong> {{ original_target }} → <strong>IP:</strong> {{ resolved_ip }}
                    </div>
                {% else %}
                    <div class="warning-box">❌ Could not resolve "{{ original_target }}" to an IP.</div>
                {% endif %}

                {% if results %}
                    <h2 style="color: var(--success); margin-top: 30px;">{{ results|length }} Open Ports Detected</h2>
                    {% for port, service, banner in results %}
                        <div class="port-card">
                            <h3><span class="open">Port {{ port }}/TCP • OPEN</span> — {{ service }}</h3>
                            {% if "No banner" not in banner %}
                                <p><strong>Service Banner:</strong><br>
                                <code style="background:#0f0f1a; padding:10px; border-radius:8px; display:block; overflow-x:auto; white-space: pre-wrap;">{{ banner }}</code></p>
                            {% endif %}
                            <div class="threat">
                                <strong>⚠️ Security Alert:</strong> {{ port_threats.get(port, "Open port increases attack surface. Monitor and restrict access.") }}
                            </div>
                        </div>
                    {% endfor %}
                {% else %}
                    {% if resolved_ip %}
                        <div style="text-align:center; padding:40px; color:#00ff9d;">
                            <h2>🔒 No open ports found</h2>
                            <p>The target appears secure or protected by a firewall.</p>
                        </div>
                    {% endif %}
                {% endif %}
            </div>
        {% endif %}

        <footer>
            NetScan Pro • Educational & Security Testing Tool • Built with Python Flask • 2025
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
    print("🚀 NetScan Pro is starting... (Fixed Version)")
    print("Open your browser: http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=False)