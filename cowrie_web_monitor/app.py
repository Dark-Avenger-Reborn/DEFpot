import os
import re
import time
import queue
import json
import threading
from datetime import datetime
from collections import defaultdict

import requests
from flask import Flask, render_template, Response, send_from_directory

app = Flask(__name__)

LOGFILE = "../cowrie/var/log/cowrie/cowrie.log"
WEBHOOK_PATH = "../webhook_url.txt"
IMAGES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "images"))

# -----------------------------
# STATE
# -----------------------------
seen_ips = set()
logged_in_users = defaultdict(str)
connection_times = {}
confirmed_scanners = set()

# SSE queue
event_queue = queue.Queue(maxsize=500)

# Webhook queue (async)
webhook_queue = queue.Queue(maxsize=200)

# GeoIP cache
geo_cache = {}

# ----------------------------------------------------
# CONFIG
# ----------------------------------------------------
GEO_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,query,isp,org,as,reverse"

DISCORD_RATE_LIMIT_SECONDS = 1.2  # safe small delay

# ----------------------------------------------------
# UTIL
# ----------------------------------------------------

def get_webhook_url():
    try:
        with open(WEBHOOK_PATH, "r") as f:
            u = f.read().strip()
            return u if u.startswith("http") else None
    except:
        return None

WEBHOOK_URL = get_webhook_url()


# -----------------------------
# GEO LOOKUP
# -----------------------------

def geo_lookup(ip):
    """Cached lookup for IP geolocation."""
    if ip in geo_cache:
        return geo_cache[ip]

    try:
        r = requests.get(GEO_API_URL.format(ip=ip), timeout=2)
        data = r.json()

        if data.get("status") == "success":
            geo_cache[ip] = data
            return data
    except:
        pass

    # fallback minimal
    geo_cache[ip] = {"country": "Unknown", "city": "Unknown", "org": "Unknown"}
    return geo_cache[ip]


# -----------------------------
# ASYNC WEBHOOK WORKER
# -----------------------------

def webhook_worker():
    """Pulls from webhook_queue and posts to Discord with rate-limit protection."""
    while True:
        embed = webhook_queue.get()
        if not WEBHOOK_URL:
            time.sleep(1)
            webhook_queue.task_done()
            continue

        try:
            requests.post(WEBHOOK_URL, json=embed, timeout=4)
        except Exception:
            pass

        time.sleep(DISCORD_RATE_LIMIT_SECONDS)
        webhook_queue.task_done()


def enqueue_webhook(title, description, color=0x3498db, fields=None):
    """Adds embed to async queue."""
    embed = {
        "embeds": [
            {
                "title": title,
                "description": description,
                "color": color,
                "timestamp": datetime.utcnow().isoformat(),
                "fields": fields or []
            }
        ]
    }

    try:
        webhook_queue.put_nowait(embed)
    except queue.Full:
        # drop oldest
        try:
            webhook_queue.get_nowait()
            webhook_queue.put_nowait(embed)
        except:
            pass


# ----------------------------------------------------
# PARSE LOG LINES
# ----------------------------------------------------

def parse_line(line):
    try:
        meta = re.search(r"\[(.*?),(.*?),([\d\.]+)\]", line)
        if not meta:
            return None

        protocol_raw, conn_id, ip = meta.groups()

        if "Telnet" in protocol_raw:
            proto = "Telnet"
            color = 0xffa500
        elif "SSH" in protocol_raw:
            proto = "SSH"
            color = 0x2ecc71
        else:
            proto = protocol_raw
            color = 0x3498db

        ts = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
        log_time = datetime.strptime(ts.group(1), "%Y-%m-%dT%H:%M:%S") if ts else datetime.utcnow()

        # Geo info
        geo = geo_lookup(ip)
        location = f"{geo.get('city')}, {geo.get('country')}"
        org = geo.get("org")

        # CONNECTION EVENT
        if "New connection:" in line:
            if ip not in seen_ips:
                seen_ips.add(ip)
                connection_times[ip] = log_time
                msg = f"{ip} connected to {proto}"
                enqueue_webhook(
                    "New Connection",
                    msg,
                    color,
                    fields=[
                        {"name": "Location", "value": location, "inline": True},
                        {"name": "Org/ISP", "value": org, "inline": True},
                    ]
                )
                return msg

        # LOGIN
        login = re.search(r"login attempt \[b?'?(.+?)'?/.*?\] succeeded", line)
        if login:
            user = login.group(1)
            logged_in_users[ip] = user
            msg = f"{ip} logged in as **{user}** via {proto}"
            enqueue_webhook(
                "Login Success",
                msg,
                color,
                fields=[
                    {"name": "Location", "value": location, "inline": True},
                    {"name": "Username", "value": user, "inline": True}
                ]
            )
            return msg

        # COMMAND
        cmd = re.search(r"CMD: (.+)", line)
        if cmd:
            command = cmd.group(1).strip()
            msg = f"{ip} ran {proto} command: `{command}`"
            enqueue_webhook(
                "Command Executed",
                msg,
                color,
                fields=[
                    {"name": "Command", "value": f"`{command}`", "inline": False},
                    {"name": "Location", "value": location, "inline": True},
                ]
            )
            return msg

        # DISCONNECT / SCAN
        lost = re.search(r"Connection lost after ([\d\.]+) seconds", line)
        if lost:
            duration = float(lost.group(1))
            if duration < 1.0:
                msg = f"{ip} is likely scanning {proto} (lasted {duration:.1f}s)"
                enqueue_webhook(
                    "Scanner Detected",
                    msg,
                    0xe74c3c,
                    fields=[
                        {"name": "Scan Duration", "value": f"{duration:.1f}s", "inline": True},
                        {"name": "Location", "value": location, "inline": True},
                    ]
                )
            else:
                msg = f"{ip} disconnected from {proto} after {duration:.1f}s"
                enqueue_webhook(
                    "Session Ended",
                    msg,
                    0x95a5a6,
                    fields=[
                        {"name": "Session Length", "value": f"{duration:.1f}s", "inline": True},
                        {"name": "Location", "value": location, "inline": True},
                    ]
                )
            return msg

    except:
        return None

    return None


# ----------------------------------------------------
# LOG TAILER WITH ROTATION HANDLING
# ----------------------------------------------------

def open_follow(filename):
    f = open(filename, "r")
    inode = os.fstat(f.fileno()).st_ino
    f.seek(0, os.SEEK_END)
    return f, inode


def _background_tail():
    f, inode = open_follow(LOGFILE)

    while True:
        line = f.readline()

        if not line:
            try:
                new_inode = os.stat(LOGFILE).st_ino
                if new_inode != inode:
                    f.close()
                    f, inode = open_follow(LOGFILE)
            except:
                pass
            time.sleep(0.05)
            continue

        parsed = parse_line(line)
        if parsed:
            try:
                event_queue.put_nowait(parsed)
            except queue.Full:
                event_queue.get_nowait()
                event_queue.put_nowait(parsed)


# ----------------------------------------------------
# SSE STREAM
# ----------------------------------------------------

def tail_log():
    while True:
        msg = event_queue.get()
        yield f"data: {msg}\n\n"
        event_queue.task_done()


# ----------------------------------------------------
# FLASK ROUTES
# ----------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/stream")
def stream():
    return Response(tail_log(), mimetype="text/event-stream")

@app.route("/logo.png")
def logo_png():
    return send_from_directory(IMAGES_DIR, "logo.png")


# ----------------------------------------------------
# STARTUP
# ----------------------------------------------------

if __name__ == "__main__":

    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":

        t1 = threading.Thread(target=_background_tail, daemon=True)
        t1.start()

        t2 = threading.Thread(target=webhook_worker, daemon=True)
        t2.start()

    app.run(host="0.0.0.0", port=8080, debug=True, threaded=True)
