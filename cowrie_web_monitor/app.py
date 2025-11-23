from flask import Flask, render_template, Response, send_from_directory
import time
import re
import requests
from datetime import datetime
from collections import defaultdict
import os
import queue
import threading

app = Flask(__name__)

LOGFILE = "../cowrie/var/log/cowrie/cowrie.log"
WEBHOOK_PATH = "../webhook_url.txt"
IMAGES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "images"))
previous_webhook = ""


seen_ips = set()
logged_in_users = defaultdict(str)
connection_times = {}
confirmed_scanners = set()

# Queue for parsed events so SSE clients can read events produced by the
# background tailer thread. Centralizing parsing in the tailer ensures
# webhooks are sent even with no connected web clients.
event_queue = queue.Queue()

# Read webhook URL once at start (fail silently if missing)
def get_webhook_url():
    try:
        with open(WEBHOOK_PATH, "r") as f:
            url = f.read().strip()
            if url.startswith("http"):
                return url
    except Exception:
        pass
    return None

WEBHOOK_URL = get_webhook_url()

def send_discord_webhook(title, description, color=0x3498db):
    # Debug print to help diagnose duplicate sends: show process & thread.
    try:
        print(f"[webhook-send] pid={os.getpid()} thread={threading.current_thread().name} title={title!r}")
    except Exception:
        pass

    if not WEBHOOK_URL:
        try:
            print("[webhook-send] no WEBHOOK_URL configured; skipping HTTP POST")
        except Exception:
            pass
        return  # Fail silently
    payload = {
        "embeds": [
            {
                "title": title,
                "description": description,
                "color": color,
                "timestamp": datetime.utcnow().isoformat()
            }
        ]
    }
    try:
        if previous_webhook == payload:
            return
        previous_webhook = payload
        requests.post(WEBHOOK_URL, json=payload, timeout=3)
    except Exception:
        pass  # Fail silently

def tail_log():
    # Read parsed events from the shared queue. This blocks until the
    # background tailer produces new events.
    while True:
        parsed = event_queue.get()
        try:
            yield f"data: {parsed}\n\n"
        finally:
            event_queue.task_done()


def _background_tail():
    """Background thread: tails the log file, parses lines and puts
    parsed messages into `event_queue`. This is what sends webhooks
    regardless of whether any clients are connected to the SSE stream.
    """
    try:
        with open(LOGFILE, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                parsed = parse_line(line)
                if parsed:
                    # parse_line already triggers webhook sending.
                    # Put the parsed message into the queue for SSE clients.
                    event_queue.put(parsed)
    except Exception:
        # Fail silently to avoid crashing the app; could be logged.
        return

def parse_line(line):
    meta_match = re.match(r".*?\[(.*?),(.*?),([\d\.]+)\]", line)
    if not meta_match:
        return None
    protocol, conn_id, ip = meta_match.groups()

    # Determine protocol name & colors
    if "Telnet" in protocol:
        proto_name = "Telnet"
        proto_color = 0xffa500  # orange
    elif "SSH" in protocol:
        proto_name = "SSH"
        proto_color = 0x2ecc71  # green
    else:
        proto_name = protocol
        proto_color = 0x3498db  # default blue

    timestamp_match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    log_time = datetime.strptime(timestamp_match.group(1), "%Y-%m-%dT%H:%M:%S") if timestamp_match else datetime.now()

    # New connection
    if "New connection:" in line:
        if ip not in seen_ips:
            seen_ips.add(ip)
            connection_times[ip] = log_time
            msg = f"{ip} connected to {proto_name} (possible scan)"
            send_discord_webhook("New Connection", msg, color=proto_color)
            return msg

    # Login success
    login_match = re.search(r"login attempt \[b?'?(.+?)'?/b?'?.*?'?\] succeeded", line)
    if login_match:
        user = login_match.group(1)
        logged_in_users[ip] = user
        msg = f"{ip} logged in as **{user}** via {proto_name}"
        send_discord_webhook("Login Success", msg, color=proto_color)
        return msg

    # Command execution
    cmd_match = re.search(r"CMD: (.+)", line)
    if cmd_match:
        command = cmd_match.group(1)
        msg = f"{ip} ran {proto_name} command: `{command}`"
        send_discord_webhook("Command Executed", msg, color=proto_color)
        return msg

    # Scanner detection and disconnect logging
    lost_match = re.search(r"Connection lost after ([\d\.]+) seconds", line)
    if lost_match:
        duration = float(lost_match.group(1))
        if duration < 1.0:
            confirmed_scanners.add(ip)
            msg = f"{ip} is likely scanning {proto_name} (connection lasted {duration:.1f}s)"
            send_discord_webhook("Scanner Detected", msg, color=0xe74c3c)
            return msg
        else:
            msg = f"{ip} disconnected from {proto_name} after {duration:.1f}s"
            send_discord_webhook("Session Ended", msg, color=0x95a5a6)  # grey
            return msg

    return None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/stream")
def stream():
    return Response(tail_log(), mimetype="text/event-stream")

@app.route("/logo.png")
def logo_png():
    return send_from_directory(IMAGES_DIR, "logo.png")

if __name__ == "__main__":
    # Start background tailer so webhooks are sent even with no clients.
    # When running with the Flask debug reloader, the process is started
    # twice. Only start the tailer in the reloader child process to avoid
    # duplicate threads.
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        tailer_thread = threading.Thread(target=_background_tail, name="log-tailer", daemon=True)
        tailer_thread.start()
    app.run(host="0.0.0.0", port=8080, debug=True, threaded=True)