# SentinelGate Deployment Guide

This guide covers deploying SentinelGate in various environments: local development, Docker, and production.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development Deployment](#local-development-deployment)
3. [Docker Deployment](#docker-deployment)
4. [Production Deployment](#production-deployment)
5. [Configuration](#configuration)
6. [Monitoring & Maintenance](#monitoring--maintenance)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Minimum Requirements
- **OS**: Windows 10/11, Ubuntu 20.04+, macOS 12+
- **Python**: 3.12 or 3.13
- **RAM**: 4 GB (8 GB recommended)
- **Disk**: 2 GB free space
- **Network**: Internet access for package installation

### Optional
- **Docker**: 24.0+ and Docker Compose v2
- **Redis**: 7.0+ (for distributed deployments)
- **nmap**: For port scanning features
- **Suricata**: 7.0+ (for network IDS integration)
- **Wazuh**: 4.x (for SIEM integration)

---

## Local Development Deployment

### Step 1: Clone and Setup

```powershell
# Clone repository
git clone https://github.com/yourusername/sentinelgate.git
cd sentinelgate

# Setup environment (creates venv, installs deps)
.\tasks.ps1 setup

# Or manually:
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Step 2: Configure Environment

```powershell
# Copy example config
copy .env.example .env

# Edit .env with your settings
notepad .env
```

Required settings:
```bash
TARGET_URL=http://127.0.0.1:5000
DASHBOARD_PASSWORD=your-secure-password-here
```

### Step 3: Train ML Model (Optional)

```powershell
# Train with synthetic baseline
python -m ml.train --synthetic --output models/iforest.joblib
```

### Step 4: Start Services

**Option A: Using demo script (easiest)**
```powershell
.\demo.ps1
```

**Option B: Manual start**
```powershell
# Terminal 1: Test app
python -m testapp.app

# Terminal 2: Gateway
python -m uvicorn gateway.main:app --host 127.0.0.1 --port 8000

# Terminal 3: Collector
python -m siem.collector --follow

# Terminal 4: Dashboard
python -m streamlit run dashboard\app.py
```

### Step 5: Verify Deployment

```powershell
# Check gateway health
curl http://localhost:8000/health

# Access dashboard
# Open browser: http://localhost:8501
# Password: admin (or your DASHBOARD_PASSWORD)
```

---

## Docker Deployment

### Step 1: Build Images

```powershell
# Build all images
.\tasks.ps1 docker-build

# Or manually
docker build -t sentinelgate:latest .
```

### Step 2: Start Stack

```powershell
# Start all services
.\tasks.ps1 docker-up

# Or manually
docker-compose up -d
```

Services started:
- **testapp**: Port 5000 (vulnerable test application)
- **gateway**: Port 8000 (main security gateway)
- **collector**: Background SIEM collector
- **dashboard**: Port 8501 (Streamlit UI)
- **redis**: Port 6379 (optional, for future use)
- **web**: Port 8080 (landing page, if implemented)

### Step 3: Check Status

```powershell
# View running containers
docker-compose ps

# View logs
docker-compose logs -f gateway
docker-compose logs -f dashboard

# Check health
curl http://localhost:8000/health
```

### Step 4: Run Attack Simulation

```powershell
# From host or inside gateway container
docker-compose exec gateway python -m simulator.run mixed --count 50
```

### Step 5: Stop Stack

```powershell
# Stop all services
.\tasks.ps1 docker-down

# Or manually
docker-compose down

# Remove volumes too
docker-compose down -v
```

---

## Production Deployment

### Architecture Options

**Option 1: Single Server (Small Team)**
```
Internet → Nginx → Gateway → Target App
                  ↓
              Collector → SQLite
                  ↓
              Dashboard
```

**Option 2: Multi-Server (Large Team)**
```
Internet → Load Balancer → Gateway Cluster → Target Apps
                              ↓
                          Redis Cluster
                              ↓
                          Collectors → PostgreSQL
                              ↓
                          Dashboard Cluster
```

### Step 1: Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3.12 python3.12-venv nginx certbot redis-server

# Create application user
sudo useradd -m -s /bin/bash sentinel
sudo su - sentinel
```

### Step 2: Deploy Application

```bash
# Clone repo
cd /opt
sudo git clone https://github.com/yourusername/sentinelgate.git
sudo chown -R sentinel:sentinel sentinelgate
cd sentinelgate

# Setup environment
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 3: Configure Production Settings

```bash
# Create production .env
cat > .env << 'EOF'
TARGET_URL=https://your-app.example.com
TRUST_PROXY=true
RATE_LIMIT=100
RATE_BURST=30
DB_PATH=/var/lib/sentinelgate/siem.db
DASHBOARD_PASSWORD=YOUR_SECURE_PASSWORD
TELEGRAM_TOKEN=YOUR_BOT_TOKEN
TELEGRAM_CHAT_ID=YOUR_CHAT_ID
NVD_API_KEY=YOUR_NVD_KEY
ABUSEIPDB_KEY=YOUR_ABUSEIPDB_KEY
EOF

# Create data directories
sudo mkdir -p /var/lib/sentinelgate /var/log/sentinelgate
sudo chown sentinel:sentinel /var/lib/sentinelgate /var/log/sentinelgate
```

### Step 4: Setup Systemd Services

**Gateway Service** (`/etc/systemd/system/sentinelgate-gateway.service`):
```ini
[Unit]
Description=SentinelGate Security Gateway
After=network.target

[Service]
Type=simple
User=sentinel
WorkingDirectory=/opt/sentinelgate
Environment="PATH=/opt/sentinelgate/.venv/bin"
ExecStart=/opt/sentinelgate/.venv/bin/uvicorn gateway.main:app --host 127.0.0.1 --port 8000 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Collector Service** (`/etc/systemd/system/sentinelgate-collector.service`):
```ini
[Unit]
Description=SentinelGate SIEM Collector
After=network.target sentinelgate-gateway.service

[Service]
Type=simple
User=sentinel
WorkingDirectory=/opt/sentinelgate
Environment="PATH=/opt/sentinelgate/.venv/bin"
ExecStart=/opt/sentinelgate/.venv/bin/python -m siem.collector --follow
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Dashboard Service** (`/etc/systemd/system/sentinelgate-dashboard.service`):
```ini
[Unit]
Description=SentinelGate Dashboard
After=network.target

[Service]
Type=simple
User=sentinel
WorkingDirectory=/opt/sentinelgate
Environment="PATH=/opt/sentinelgate/.venv/bin"
ExecStart=/opt/sentinelgate/.venv/bin/streamlit run dashboard/app.py --server.port=8501 --server.address=127.0.0.1
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and Start Services**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable sentinelgate-gateway sentinelgate-collector sentinelgate-dashboard
sudo systemctl start sentinelgate-gateway sentinelgate-collector sentinelgate-dashboard

# Check status
sudo systemctl status sentinelgate-gateway
sudo systemctl status sentinelgate-collector
sudo systemctl status sentinelgate-dashboard
```

### Step 5: Configure Nginx Reverse Proxy

**Gateway Proxy** (`/etc/nginx/sites-available/sentinelgate-gateway`):
```nginx
upstream sentinelgate_gateway {
    server 127.0.0.1:8000;
}

server {
    listen 443 ssl http2;
    server_name gateway.example.com;

    ssl_certificate /etc/letsencrypt/live/gateway.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/gateway.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    location / {
        proxy_pass http://sentinelgate_gateway;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name gateway.example.com;
    return 301 https://$server_name$request_uri;
}
```

**Dashboard Proxy** (`/etc/nginx/sites-available/sentinelgate-dashboard`):
```nginx
upstream sentinelgate_dashboard {
    server 127.0.0.1:8501;
}

server {
    listen 443 ssl http2;
    server_name dashboard.example.com;

    ssl_certificate /etc/letsencrypt/live/dashboard.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dashboard.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://sentinelgate_dashboard;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support for Streamlit
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }

    location /_stcore/stream {
        proxy_pass http://sentinelgate_dashboard/_stcore/stream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}

server {
    listen 80;
    server_name dashboard.example.com;
    return 301 https://$server_name$request_uri;
}
```

**Enable Sites**:
```bash
sudo ln -s /etc/nginx/sites-available/sentinelgate-gateway /etc/nginx/sites-enabled/
sudo ln -s /etc/nginx/sites-available/sentinelgate-dashboard /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Step 6: SSL Certificates (Let's Encrypt)

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificates
sudo certbot --nginx -d gateway.example.com
sudo certbot --nginx -d dashboard.example.com

# Auto-renewal (already configured by certbot)
sudo systemctl status certbot.timer
```

### Step 7: Firewall Configuration

```bash
# Configure UFW
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable

# Check status
sudo ufw status
```

### Step 8: Monitoring Setup

**Logrotate** (`/etc/logrotate.d/sentinelgate`):
```
/var/log/sentinelgate/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 sentinel sentinel
    sharedscripts
    postrotate
        systemctl reload sentinelgate-gateway >/dev/null 2>&1 || true
    endscript
}
```

**Health Check Script** (`/opt/sentinelgate/healthcheck.sh`):
```bash
#!/bin/bash
set -e

# Check gateway
curl -f http://localhost:8000/health || exit 1

# Check dashboard
curl -f http://localhost:8501/_stcore/health || exit 1

# Check database
sqlite3 /var/lib/sentinelgate/siem.db "SELECT COUNT(*) FROM events" > /dev/null || exit 1

echo "All health checks passed"
```

**Cron Job** (add to sentinel user's crontab):
```bash
# Health check every 5 minutes
*/5 * * * * /opt/sentinelgate/healthcheck.sh >> /var/log/sentinelgate/health.log 2>&1

# Database cleanup daily at 2 AM
0 2 * * * cd /opt/sentinelgate && .venv/bin/python -c "import sqlite3; from siem.storage import Store; conn = sqlite3.connect('/var/lib/sentinelgate/siem.db'); Store(conn).purge_retention(30); conn.close()"
```

---

## Configuration

### Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_URL` | `http://127.0.0.1:5000` | Upstream application URL |
| `TRUST_PROXY` | `false` | Trust X-Forwarded-For header |
| `RATE_LIMIT` | `60` | Requests per minute per IP |
| `RATE_BURST` | `20` | Burst allowance |
| `DB_PATH` | `logs/siem.db` | SQLite database path |
| `ALLOWED_TARGETS` | `""` | Comma-separated IPs for scanner |
| `ALLOWLIST` | `""` | IPs exempt from rate limiting |
| `DASHBOARD_PASSWORD` | `admin` | Dashboard login password |
| `TELEGRAM_TOKEN` | `""` | Telegram bot token (optional) |
| `TELEGRAM_CHAT_ID` | `""` | Telegram chat ID (optional) |
| `NVD_API_KEY` | `""` | NVD API key (optional) |
| `ABUSEIPDB_KEY` | `""` | AbuseIPDB API key (optional) |
| `ENABLE_SURICATA` | `false` | Enable Suricata integration |
| `SURICATA_EVE_PATH` | `/var/log/suricata/eve.json` | Suricata eve.json path |
| `ENABLE_WAZUH` | `false` | Enable Wazuh integration |
| `WAZUH_URL` | `https://localhost:55000` | Wazuh API URL |
| `WAZUH_USER` | `""` | Wazuh username |
| `WAZUH_PASSWORD` | `""` | Wazuh password |

### Performance Tuning

**Gateway Workers** (production):
```bash
# For 4 CPU cores:
uvicorn gateway.main:app --host 0.0.0.0 --port 8000 --workers 4
```

**Database Optimization**:
```sql
-- Run periodically
PRAGMA optimize;
VACUUM;
```

**Redis Backend** (optional, for distributed deployments):
```python
# future enhancement - currently using SQLite
```

---

## Monitoring & Maintenance

### Log Files

- **Gateway**: Check systemd journal: `sudo journalctl -u sentinelgate-gateway -f`
- **Collector**: `sudo journalctl -u sentinelgate-collector -f`
- **Dashboard**: `sudo journalctl -u sentinelgate-dashboard -f`
- **Nginx**: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`

### Metrics to Monitor

1. **Gateway Performance**
   - Requests per second
   - P95 latency (<15ms target)
   - Error rate (<1%)
   - Rate limit hits

2. **SIEM**
   - Events per second
   - Alert count (by severity)
   - Correlation rule matches
   - Database size

3. **ML Detector**
   - Anomaly detection rate
   - False positive rate
   - Model drift

4. **System Resources**
   - CPU usage (<70%)
   - Memory usage (<80%)
   - Disk space (>20% free)
   - Network I/O

### Backup Strategy

**Database Backup** (daily):
```bash
#!/bin/bash
DATE=$(date +%Y%m%d)
sqlite3 /var/lib/sentinelgate/siem.db ".backup /backups/siem-$DATE.db"
find /backups -name "siem-*.db" -mtime +30 -delete
```

**Configuration Backup**:
```bash
tar czf /backups/sentinelgate-config-$(date +%Y%m%d).tar.gz \
    /opt/sentinelgate/.env \
    /opt/sentinelgate/idps/rules.yaml \
    /opt/sentinelgate/siem/correlation.yaml
```

### Update Procedure

```bash
# Stop services
sudo systemctl stop sentinelgate-gateway sentinelgate-collector sentinelgate-dashboard

# Backup
sudo -u sentinel bash -c "cd /opt/sentinelgate && git stash"

# Update
sudo -u sentinel bash -c "cd /opt/sentinelgate && git pull"

# Reinstall dependencies
sudo -u sentinel bash -c "cd /opt/sentinelgate && source .venv/bin/activate && pip install -r requirements.txt"

# Restart services
sudo systemctl start sentinelgate-gateway sentinelgate-collector sentinelgate-dashboard

# Verify
curl http://localhost:8000/health
```

---

## Troubleshooting

### Gateway Not Starting

**Check logs**:
```bash
sudo journalctl -u sentinelgate-gateway -n 50
```

**Common issues**:
1. Port 8000 already in use: `sudo lsof -i :8000`
2. Permission denied on logs: `sudo chown sentinel:sentinel /var/log/sentinelgate`
3. Database locked: `rm /var/lib/sentinelgate/siem.db-wal && systemctl restart sentinelgate-gateway`

### Dashboard Not Accessible

**Check Streamlit**:
```bash
sudo journalctl -u sentinelgate-dashboard -n 50
```

**Common issues**:
1. Port 8501 in use: `sudo lsof -i :8501`
2. WebSocket errors: Check nginx proxy_set_header Upgrade/Connection
3. Password not working: Verify DASHBOARD_PASSWORD in .env

### High CPU/Memory Usage

**Check processes**:
```bash
top -u sentinel
```

**Solutions**:
1. Reduce gateway workers: Edit systemd service, use `--workers 2`
2. Enable log rotation: Verify `/etc/logrotate.d/sentinelgate`
3. Purge old events: Run `Store.purge_retention(7)`

### Database Growing Too Large

**Check size**:
```bash
du -h /var/lib/sentinelgate/siem.db
```

**Solutions**:
```bash
# Purge events older than 7 days
cd /opt/sentinelgate
source .venv/bin/activate
python -c "import sqlite3; from siem.storage import Store; conn = sqlite3.connect('/var/lib/sentinelgate/siem.db'); print(f'Deleted {Store(conn).purge_retention(7)} rows'); conn.close()"

# Vacuum database
sqlite3 /var/lib/sentinelgate/siem.db "VACUUM;"
```

### Rate Limiting Too Aggressive

**Adjust limits**:
```bash
# Edit .env
RATE_LIMIT=100
RATE_BURST=50

# Restart gateway
sudo systemctl restart sentinelgate-gateway
```

**Add to allowlist**:
```bash
# Edit .env
ALLOWLIST=127.0.0.1,192.168.1.100,10.0.0.0/8

# Restart gateway
sudo systemctl restart sentinelgate-gateway
```

---

## Security Hardening Checklist

- [ ] Change default DASHBOARD_PASSWORD
- [ ] Enable HTTPS with valid certificates
- [ ] Configure firewall (UFW/iptables)
- [ ] Disable root SSH access
- [ ] Enable fail2ban for SSH
- [ ] Set up automated backups
- [ ] Configure log rotation
- [ ] Enable Telegram alerts
- [ ] Review IDPS rules regularly
- [ ] Update dependencies monthly
- [ ] Monitor security advisories
- [ ] Conduct penetration testing
- [ ] Document incident response procedures

---

## Support & Resources

- **Documentation**: https://github.com/yourusername/sentinelgate/tree/master/docs
- **Issues**: https://github.com/yourusername/sentinelgate/issues
- **Security**: See SECURITY.md for reporting vulnerabilities

---

**Deployment completed!** 🚀

For questions or issues, consult the troubleshooting section or open a GitHub issue.
