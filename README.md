# FT บอทหลังบ้าน (แยกจาก K36)

บอทตัวที่ 2 บน VPS เดิม — แยกขาดจากบอท K36 ทุกอย่าง:

| | บอท K36 เดิม | บอท FT (ตัวนี้) |
|---|---|---|
| โฟลเดอร์ | `/opt/k36-bo-worker` | `/opt/ft-bo-worker` |
| service | `k36-bo-worker` | `ft-bo-worker` |
| auto-update | `k36-bo-update` | `ft-bo-update` |
| GitHub repo | `k36-bo-worker` | `ft-bo-worker` |
| Supabase | ของ K36 | ของ FT |
| proxy (sing-box) | ใช้ร่วมกัน `k36-singbox` | ใช้ร่วมกัน `k36-singbox` |

แก้บอท FT = push repo `ft-bo-worker` → อัปเฉพาะ FT, ไม่กระทบ K36
แก้บอท K36 = push repo `k36-bo-worker` → อัปเฉพาะ K36, ไม่กระทบ FT

## ติดตั้งครั้งแรก (บน VPS)
```
sudo mkdir -p /opt/ft-bo-worker
cd /opt/ft-bo-worker
sudo curl -sL https://codeload.github.com/linef1832-dev/ft-bo-worker/tar.gz/refs/heads/main | sudo tar xz --strip-components=1
sudo cp .env.example .env
sudo nano .env          # เติม SUPABASE_URL / SUPABASE_KEY / PROXY_URL (BO_PRIVATE_KEY เว้นไว้ก่อน)
sudo bash setup-service.sh
sudo bash setup-autoupdate.sh
```

## คำสั่งที่ใช้บ่อย
- ดู log:   `sudo journalctl -u ft-bo-worker -f`
- รีสตาร์ท: `sudo systemctl restart ft-bo-worker`
- สถานะ:    `sudo systemctl status ft-bo-worker`
