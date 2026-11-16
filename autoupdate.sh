#!/usr/bin/env bash
# FT บอท: ดึงโค้ดล่าสุดจาก GitHub repo ft-bo-worker ถ้าต่างจากเดิม → ทับแล้วรีสตาร์ท
# แยกขาดจากบอท K36 (คนละ repo คนละโฟลเดอร์ คนละ service) — ไม่แตะ .env
set -euo pipefail
DIR=/opt/ft-bo-worker
REPO=linef1832-dev/ft-bo-worker
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -sL "https://codeload.github.com/$REPO/tar.gz/refs/heads/main" | tar xz --strip-components=1 -C "$TMP"
changed=0
for f in index.js package.json autoupdate.sh; do
  if [ -f "$TMP/$f" ] && ! cmp -s "$TMP/$f" "$DIR/$f"; then
    cp "$TMP/$f" "$DIR/$f"; changed=1
  fi
done
chmod +x "$DIR/autoupdate.sh" 2>/dev/null || true
if [ "$changed" = "1" ]; then
  systemctl restart ft-bo-worker
  echo "$(date -u +%FT%TZ) FT: มีโค้ดใหม่ → อัปแล้วรีสตาร์ท"
else
  echo "$(date -u +%FT%TZ) FT: ไม่มีอะไรเปลี่ยน"
fi
