#!/usr/bin/env bash
# ตั้งบอท FT ให้รันตลอด + เปิดเองตอนรีบูต (service: ft-bo-worker)
# แยกขาดจากบอท K36 เดิม (k36-bo-worker) — คนละ service คนละโฟลเดอร์
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "ต้องรันด้วย sudo"; exit 1; fi
DIR="$(cd "$(dirname "$0")" && pwd)"
[ -f "$DIR/.env" ] || { echo "ไม่พบ $DIR/.env — สร้างก่อน (cp .env.example .env แล้วเติมค่า)"; exit 1; }

cat > /etc/systemd/system/ft-bo-worker.service <<UNIT
[Unit]
Description=FT บอทหลังบ้าน
After=network-online.target k36-singbox.service
Wants=network-online.target
Requires=k36-singbox.service

[Service]
WorkingDirectory=$DIR
EnvironmentFile=$DIR/.env
ExecStart=$(command -v node) $DIR/index.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now ft-bo-worker.service
sleep 2
systemctl --no-pager --lines=12 status ft-bo-worker.service || true
echo
echo "ดู log สด: sudo journalctl -u ft-bo-worker -f"
