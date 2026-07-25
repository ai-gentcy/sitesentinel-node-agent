#!/bin/sh
# Site Sentinel Pi agent installer. Run as root from this directory:
#   sudo ./install.sh
# The agent generates its key on first start and logs its registration hash —
# add that hash in the backoffice (Nodes -> Add node) to activate the node:
#   journalctl -u sitesentinel-agent | grep "Registration hash"
set -eu

mkdir -p /opt/sitesentinel /etc/sitesentinel
cp sitesentinel-agent.py /opt/sitesentinel/sitesentinel-agent.py
chmod 755 /opt/sitesentinel/sitesentinel-agent.py

if [ ! -f /etc/sitesentinel/agent.env ]; then
  cp agent.env.example /etc/sitesentinel/agent.env
  chmod 600 /etc/sitesentinel/agent.env
fi

cp sitesentinel-agent.service /etc/systemd/system/sitesentinel-agent.service
systemctl daemon-reload
systemctl enable --now sitesentinel-agent

echo ">> Installed. Registration hash (add it in the backoffice):"
sleep 2
journalctl -u sitesentinel-agent --no-pager | grep "Registration hash" | tail -1 || echo ">> (not logged yet — run: journalctl -u sitesentinel-agent -f)"
