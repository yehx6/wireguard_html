#!/bin/bash
# WireGuard Manager - install script
# Run as root on the WireGuard server

set -e

INSTALL_DIR="/opt/wg-manager"
SERVICE_FILE="/etc/systemd/system/wg-manager.service"
WG_INTERFACE="${WG_INTERFACE:-wg0}"
PORT="${PORT:-5000}"

echo "==> Installing WireGuard Manager"
echo "    Interface : $WG_INTERFACE"
echo "    Port      : $PORT"
echo "    Directory : $INSTALL_DIR"
echo ""

# ── Check root ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run as root (sudo bash install.sh)"
  exit 1
fi

# ── Check WireGuard ───────────────────────────────────────────────────────────
if ! command -v wg &>/dev/null; then
  echo "ERROR: wg not found. Install WireGuard first."
  exit 1
fi

if [ ! -f "/etc/wireguard/${WG_INTERFACE}.conf" ]; then
  echo "WARNING: /etc/wireguard/${WG_INTERFACE}.conf not found."
  echo "         Make sure WireGuard is configured before using this app."
fi

# ── Install Python + dependencies ─────────────────────────────────────────────
echo "==> Installing Python dependencies…"
if command -v apt-get &>/dev/null; then
  apt-get install -y python3 python3-pip python3-venv --quiet
elif command -v dnf &>/dev/null; then
  dnf install -y python3 python3-pip --quiet
elif command -v yum &>/dev/null; then
  yum install -y python3 python3-pip --quiet
fi

# ── Copy files ────────────────────────────────────────────────────────────────
echo "==> Copying files to $INSTALL_DIR…"
mkdir -p "$INSTALL_DIR"
cp app.py "$INSTALL_DIR/"
cp -r templates "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"

# ── Create venv ───────────────────────────────────────────────────────────────
echo "==> Creating Python virtual environment…"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

# ── Systemd service ───────────────────────────────────────────────────────────
echo "==> Creating systemd service…"
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=WireGuard Web Manager
After=network.target wg-quick@${WG_INTERFACE}.service
Wants=wg-quick@${WG_INTERFACE}.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment=WG_INTERFACE=${WG_INTERFACE}
Environment=WG_CONFIG_DIR=/etc/wireguard
Environment=PORT=${PORT}
ExecStart=${INSTALL_DIR}/venv/bin/python3 app.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wg-manager
systemctl restart wg-manager

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "✓ WireGuard Manager installed and started!"
echo ""
echo "  Access via SSH tunnel:"
echo "  ssh -L ${PORT}:127.0.0.1:${PORT} user@your-server"
echo "  Then open: http://127.0.0.1:${PORT}"
echo ""
echo "  Service commands:"
echo "  systemctl status wg-manager"
echo "  journalctl -u wg-manager -f"
echo ""
echo "  To change interface: WG_INTERFACE=wg1 bash install.sh"
echo "  To change port:      PORT=8080 bash install.sh"
