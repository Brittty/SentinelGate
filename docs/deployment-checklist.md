# SentinelGate Deployment Checklist

Use this checklist to ensure a smooth deployment.

---

## Pre-Deployment

### Infrastructure
- [ ] Server provisioned (4 GB RAM, 2 vCPU minimum)
- [ ] Domain names configured (gateway.example.com, dashboard.example.com)
- [ ] DNS records pointing to server IP
- [ ] SSH access configured
- [ ] Firewall rules planned

### Dependencies
- [ ] Python 3.12+ installed
- [ ] Nginx installed
- [ ] Redis installed (optional)
- [ ] Certbot installed for SSL
- [ ] Git installed

### Configuration
- [ ] `.env` file created from `.env.example`
- [ ] `DASHBOARD_PASSWORD` changed from default
- [ ] `TARGET_URL` set to correct upstream
- [ ] `TRUST_PROXY=true` if behind load balancer
- [ ] Telegram credentials configured (if using)
- [ ] AbuseIPDB API key configured (if using)

---

## Deployment Steps

### Application Setup
- [ ] Code cloned to `/opt/sentinelgate`
- [ ] Virtual environment created
- [ ] Dependencies installed from `requirements.txt`
- [ ] ML model trained (synthetic or from real data)
- [ ] Data directories created (`/var/lib/sentinelgate`, `/var/log/sentinelgate`)
- [ ] Permissions set (`chown sentinel:sentinel`)

### Service Configuration
- [ ] systemd service files created for:
  - [ ] Gateway (`sentinelgate-gateway.service`)
  - [ ] Collector (`sentinelgate-collector.service`)
  - [ ] Dashboard (`sentinelgate-dashboard.service`)
- [ ] Services enabled: `systemctl enable`
- [ ] Services started: `systemctl start`
- [ ] Service status verified: `systemctl status`

### Web Server (Nginx)
- [ ] Virtual host configs created for gateway and dashboard
- [ ] SSL certificates obtained (Let's Encrypt)
- [ ] Security headers configured
- [ ] WebSocket support enabled for dashboard
- [ ] Nginx config tested: `nginx -t`
- [ ] Nginx reloaded: `systemctl reload nginx`

### Firewall
- [ ] UFW enabled
- [ ] Port 22 (SSH) allowed
- [ ] Port 80 (HTTP) allowed
- [ ] Port 443 (HTTPS) allowed
- [ ] Other ports blocked

---

## Post-Deployment

### Verification
- [ ] Gateway health check passes: `curl https://gateway.example.com/health`
- [ ] Dashboard accessible: `https://dashboard.example.com`
- [ ] Login to dashboard with password
- [ ] KPIs showing on dashboard
- [ ] Run test attack: `python -m simulator.run sqli --count 10`
- [ ] Verify events logged in dashboard
- [ ] Verify alerts generated
- [ ] Check rate limiting works (send 100 requests rapidly)

### Monitoring
- [ ] Logrotate configured
- [ ] Health check cron job added
- [ ] Database cleanup cron job added
- [ ] Systemd journal retention set
- [ ] Backup script created and scheduled
- [ ] Monitoring alerts configured (email/Telegram)

### Security
- [ ] SSL certificates auto-renew configured
- [ ] Default passwords changed
- [ ] SSH key-only authentication enabled
- [ ] fail2ban installed and configured
- [ ] Security headers verified: `curl -I https://gateway.example.com`
- [ ] IDPS rules reviewed and tuned
- [ ] Allowlist configured for known good IPs

### Documentation
- [ ] Deployment details documented
- [ ] Admin credentials stored securely
- [ ] Runbook created for common operations
- [ ] Incident response procedures documented
- [ ] Contact information updated

---

## Testing

### Functional Tests
- [ ] Normal traffic passes through gateway
- [ ] SQLi attack blocked (403)
- [ ] XSS attack blocked (403)
- [ ] Brute force triggers rate limit (429)
- [ ] Alert appears in dashboard
- [ ] Case can be created from alert
- [ ] Telegram notification received (if configured)

### Performance Tests
- [ ] Gateway handles 100 req/s without errors
- [ ] P95 latency < 15ms
- [ ] Dashboard loads in < 3 seconds
- [ ] Database queries fast (< 100ms)

### Load Tests (Optional)
```bash
# Install Apache Bench
sudo apt install apache2-utils

# Test gateway
ab -n 10000 -c 100 http://localhost:8000/

# Results should show < 1% errors
```

---

## Rollback Plan

If deployment fails:

1. **Stop services**:
   ```bash
   sudo systemctl stop sentinelgate-gateway sentinelgate-collector sentinelgate-dashboard
   ```

2. **Restore previous version**:
   ```bash
   cd /opt/sentinelgate
   git stash
   git checkout <previous-commit>
   ```

3. **Restart services**:
   ```bash
   sudo systemctl start sentinelgate-gateway sentinelgate-collector sentinelgate-dashboard
   ```

4. **Verify rollback**:
   ```bash
   curl http://localhost:8000/health
   ```

---

## Maintenance Schedule

### Daily
- [ ] Check service status
- [ ] Review critical alerts
- [ ] Monitor disk space

### Weekly
- [ ] Review all alerts
- [ ] Check blocked IPs
- [ ] Review false positives
- [ ] Update IDPS rules if needed

### Monthly
- [ ] Update dependencies: `pip install -U -r requirements.txt`
- [ ] Review audit findings
- [ ] Check SSL certificate expiry
- [ ] Review and tune correlation rules
- [ ] Analyze ML model performance

### Quarterly
- [ ] Security audit
- [ ] Performance review
- [ ] Backup restore test
- [ ] Disaster recovery drill

---

## Success Criteria

Deployment is successful when:

✅ All services running and healthy  
✅ Gateway proxying traffic correctly  
✅ IDPS blocking attacks  
✅ Rate limiting working  
✅ SIEM collecting events  
✅ Dashboard showing real-time data  
✅ Alerts generating correctly  
✅ SSL certificates valid  
✅ Monitoring in place  
✅ Backups configured  
✅ Documentation complete  

---

## Emergency Contacts

- **System Administrator**: _____________________
- **Security Team**: _____________________
- **On-Call Engineer**: _____________________
- **Vendor Support**: See SUPPORT.md

---

**Deployment Date**: _____________  
**Deployed By**: _____________  
**Sign-Off**: _____________
