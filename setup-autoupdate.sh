#!/usr/bin/env bash
# ตั้ง auto-update ของบอท FT: เช็ก GitHub (repo ft-bo-worker) ทุก 2 นาที แล้วอัปเอง
# แยกขาดจาก K36 — ชื่อ timer/service ขึ้นต้น ft-bo-update
# รันครั้งเดียว:  sudo bash /opt/ft-bo-worker/setup-autoupdate.sh
set -euo pipefail
chmod +x /opt/ft-bo-worker/autoupdate.sh

cat > /etc/systemd/system/ft-bo-update.service <<'UNIT'
[Unit]
Description=FT bot auto-update from GitHub
After=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/ft-bo-worker/autoupdate.sh
UNIT

cat > /etc/systemd/system/ft-bo-update.timer <<'UNIT'
[Unit]
Description=Check GitHub for FT bot updates every 2 min

[Timer]
OnBootSec=1min
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now ft-bo-update.timer
echo "=============================================="
echo " ตั้ง auto-update ของบอท FT เรียบร้อย"
echo " ต่อไปแค่ push ขึ้น GitHub repo: ft-bo-worker"
echo " VPS จะอัปเฉพาะบอท FT ให้เอง (ไม่แตะบอท K36)"
echo "=============================================="
systemctl status ft-bo-update.timer --no-pager || true
