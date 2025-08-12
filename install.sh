#!/bin/bash

# Dependencies
sudo apt update && sudo apt install -y git python3-venv libssl-dev libffi-dev build-essential libpython3-dev libevent-dev

# Install Website Dependencies
pip install -r cowrie_web_monitor/requirements.txt

cd cowrie

# Setup virtual environment
python3 -m venv cowrie-env
source cowrie-env/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create systemd service file
cat <<EOF | sudo tee /etc/systemd/system/cowrie.service > /dev/null
[Unit]
Description=Cowrie SSH/Telnet Honeypot
After=network.target

[Service]
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/bin/cowrie start --nodaemon
ExecStop=$(pwd)/bin/cowrie stop
ExecReload=$(pwd)/bin/cowrie restart --nodaemon
Restart=on-failure
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start Cowrie
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable cowrie
sudo systemctl start cowrie

echo "✅ Cowrie installed and running as a systemd service."