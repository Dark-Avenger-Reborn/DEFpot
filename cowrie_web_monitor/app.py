from flask import Flask, render_template, Response
import time
import re
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)

LOGFILE = "../cowrie/var/log/cowrie/cowrie.log"

seen_ips = set()
logged_in_users = defaultdict(str)
connection_times = {}
confirmed_scanners = set()

def tail_log():
    with open(LOGFILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            parsed = parse_line(line)
            if parsed:
                yield f"data: {parsed}\n\n"

def parse_line(line):
    meta_match = re.match(r".*?\[(.*?),(.*?),([\d\.]+)\]", line)
    if not meta_match:
        return None
    _, conn_id, ip = meta_match.groups()

    timestamp_match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    log_time = datetime.strptime(timestamp_match.group(1), "%Y-%m-%dT%H:%M:%S") if timestamp_match else datetime.now()

    if "New connection:" in line:
        if ip not in seen_ips:
            seen_ips.add(ip)
            connection_times[ip] = log_time
            return f"{ip} connected (possible scan)"

    login_match = re.search(r"login attempt \[b?'?(.+?)'?/b?'?.*?'?\] succeeded", line)
    if login_match:
        user = login_match.group(1)
        logged_in_users[ip] = user
        return f"{ip} logged in as {user} via SSH"

    cmd_match = re.search(r"CMD: (.+)", line)
    if cmd_match:
        command = cmd_match.group(1)
        return f"{ip} ran: {command}"

    lost_match = re.search(r"Connection lost after ([\d\.]+) seconds", line)
    if lost_match:
        duration = float(lost_match.group(1))
        if duration < 1.0 and ip not in logged_in_users and ip not in confirmed_scanners:
            confirmed_scanners.add(ip)
            return f"{ip} is scanning ports (connection lasted {duration:.1f}s)"

    return None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/stream")
def stream():
    return Response(tail_log(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True, threaded=True)
