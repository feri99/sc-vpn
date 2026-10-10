# VPN Panel Uninstaller

Script uninstaller untuk menghapus semua komponen yang diinstal oleh **Alrescha79 VPN Panel**.

## ✨ Fitur

- **Uninstall Lengkap**: Menghapus semua komponen VPN Panel
- **Progress Tracking**: Menampilkan progress real-time
- **Konfirmasi Keamanan**: Meminta konfirmasi sebelum eksekusi
- **Clean Removal**: Menghapus files, services, dan konfigurasi

## 📁 File Script

### 1. `uninstall.sh`

Script utama untuk uninstall VPN Panel

## 🚀 Cara Penggunaan

### Uninstall Langsung

```bash
wget -O uninstaller.sh https://raw.githubusercontent.com/feri99/sc-vpn/main/uninstall.sh && chmod +x uninstaller.sh && sudo ./uninstaller.sh
```

## 🗑️ Yang Dihapus

### Services

- ✅ Xray (VMess, VLess, Trojan, Shadowsocks)
- ✅ OpenVPN
- ✅ HAProxy
- ✅ Nginx
- ✅ Dropbear SSH
- ✅ WebSocket
- ✅ UDP Custom
- ✅ BadVPN
- ✅ Limit IP/Quota services

### Konfigurasi

- ✅ `/etc/xray/` - Semua konfigurasi Xray
- ✅ `/etc/openvpn/` - Konfigurasi OpenVPN
- ✅ `/etc/haproxy/haproxy.cfg` - Konfigurasi HAProxy
- ✅ `/etc/nginx/conf.d/xray.conf` - Konfigurasi Nginx
- ✅ `/etc/default/dropbear` - Konfigurasi Dropbear

### Database & Logs

- ✅ Database pengguna (VMess, VLess, Trojan, Shadowsocks)
- ✅ Log files Xray
- ✅ Setup logs
- ✅ Access logs

### Sertifikat

- ✅ SSL certificates (Let's Encrypt)
- ✅ HAProxy certificates
- ✅ ACME certificates

### Binary & Scripts

- ✅ Menu scripts (`add-*`, `del-*`, `check-*`, `renew-*`)
- ✅ Gotop monitoring tool
- ✅ UDP custom binary
- ✅ BadVPN binary
- ✅ WebSocket script

### System Configuration

- ✅ Systemd service files
- ✅ Cron jobs
- ✅ IPTables rules
- ✅ Sysctl configurations
- ✅ Security limits
- ✅ Swap file (jika dibuat oleh setup)

### Repository

- ✅ Nginx repository
- ✅ HAProxy repository
- ✅ Repository keys

## ⚠️ Peringatan

### 🚨 PENTING - BACA SEBELUM MENGGUNAKAN

1. **TIDAK DAPAT DIBATALKAN**: Proses uninstall tidak dapat dibatalkan setelah dijalankan
2. **BACKUP DULU**: Selalu buat backup sebelum uninstall jika Anda ingin restore nanti
3. **ROOT ACCESS**: Script harus dijalankan dengan privilese root
4. **DATA HILANG**: Semua data pengguna dan konfigurasi akan terhapus

### 🔒 Keamanan

- Script meminta konfirmasi eksplisit sebelum eksekusi
- Menampilkan daftar lengkap yang akan dihapus
- Progress tracking untuk monitoring proses
- Error handling untuk mencegah kerusakan sistem

### 🖥️ Kompatibilitas

- ✅ Ubuntu 20.04, 22.04, 24.04
- ✅ Debian 10, 11, 12, 13
- ✅ Tested dengan Alrescha79 VPN Panel setup script

## 🔄 Restore dari Backup

Jika Anda memiliki backup dan ingin restore:

1. **Install VPN Panel baru** di server target
2. **Stop semua services**:

   ```bash
   systemctl stop vmess@config vless@config trojan@config shadowsocks@config
   systemctl stop haproxy nginx openvpn dropbear
   ```

3. **Extract backup**:

   ```bash
   tar -xzf vpn_backup_YYYYMMDD_HHMMSS.tar.gz
   cd vpn_backup_YYYYMMDD_HHMMSS
   ```

4. **Copy konfigurasi**:

   ```bash
   cp -r etc/xray/* /etc/xray/
   cp -r etc/openvpn/* /etc/openvpn/
   # Copy konfigurasi lainnya sesuai kebutuhan
   ```

5. **Restart services**:

   ```bash
   systemctl restart vmess@config vless@config trojan@config shadowsocks@config
   systemctl restart haproxy nginx openvpn
   ```

## 📞 Support

Jika mengalami masalah:

- 💬 **Telegram**: [@Alrescha79](https://t.me/Alrescha79)
- 📧 **Email**: anggun@cakson.my.id
- 🐛 **Issues**: [GitHub Issues](https://github.com/feri99/sc-vpn/issues)

## 📄 Lisensi

Copyright (C) 2025 [Alrescha79](https://github.com/feri99). All rights reserved.

---
