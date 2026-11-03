# SentinelGate Integrations

This document describes how to integrate SentinelGate with external security tools.

## Suricata (Network IDS)

Suricata is an open-source network IDS/IPS that produces alerts in eve.json format.

### Installation (Ubuntu/Debian)

```bash
sudo apt-get install suricata
sudo systemctl enable suricata
sudo systemctl start suricata
```

### Configuration

Edit `/etc/suricata/suricata.yaml` to enable eve.json logging:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            metadata: yes
```

Restart Suricata:

```bash
sudo systemctl restart suricata
```

### SentinelGate Integration

Set the path in `.env`:

```bash
ENABLE_SURICATA=true
SURICATA_EVE_PATH=/var/log/suricata/eve.json
```

Run the Suricata collector:

```bash
python -m siem.suricata --eve /var/log/suricata/eve.json --follow
```

Or add to `demo.ps1` to start automatically.

---

## Wazuh (SIEM/XDR)

Wazuh is an open-source SIEM and XDR platform.

### Installation (Docker)

```bash
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
docker-compose up -d
```

Default credentials:
- API: https://localhost:55000
- Username: `wazuh`
- Password: `wazuh`

### Configuration

Edit `ossec.conf` on Wazuh server to enable JSON alerts:

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/alerts/alerts.json</location>
  </localfile>
</ossec_config>
```

### SentinelGate Integration

Set credentials in `.env`:

```bash
ENABLE_WAZUH=true
WAZUH_URL=https://localhost:55000
WAZUH_USER=wazuh
WAZUH_PASSWORD=wazuh
```

Run the Wazuh collector:

```bash
python -m siem.wazuh --url https://localhost:55000 --user wazuh --password wazuh --follow
```

The collector polls the Wazuh API every 60 seconds by default. Use `--interval` to change.

---

## Docker Compose Setup (All-in-One)

Create `docker-compose.integrations.yml`:

```yaml
version: '3.8'

services:
  suricata:
    image: jasonish/suricata:latest
    network_mode: host
    volumes:
      - ./suricata/logs:/var/log/suricata
      - ./suricata/rules:/var/lib/suricata/rules
    command: -i eth0

  wazuh:
    image: wazuh/wazuh-odfe:latest
    ports:
      - "55000:55000"
      - "1514:1514"
      - "1515:1515"
    environment:
      - INDEXER_URL=https://wazuh-indexer:9200
      - DASHBOARD_USERNAME=admin
      - DASHBOARD_PASSWORD=admin

  sentinelgate-suricata-collector:
    build: .
    depends_on:
      - suricata
    volumes:
      - ./suricata/logs:/var/log/suricata:ro
      - ./logs:/app/logs
    command: python -m siem.suricata --eve /var/log/suricata/eve.json --follow
    environment:
      - DB_PATH=/app/logs/siem.db
```

Run with:

```bash
docker-compose -f docker-compose.integrations.yml up -d
```

---

## Testing

### Generate Suricata Alerts

```bash
# Trigger a test alert
curl "http://localhost/?id=1' OR '1'='1"
```

Check eve.json:

```bash
tail -f /var/log/suricata/eve.json | grep '"event_type":"alert"'
```

### Generate Wazuh Alerts

Install a Wazuh agent and trigger a test rule:

```bash
# Failed SSH login (rule 5710)
ssh invalid@localhost
```

Check alerts:

```bash
curl -u wazuh:wazuh -k https://localhost:55000/alerts
```

---

## Troubleshooting

### Suricata

**Problem:** No alerts in eve.json

**Solution:**
1. Check Suricata is running: `systemctl status suricata`
2. Verify eve.json exists: `ls -la /var/log/suricata/eve.json`
3. Check permissions: `sudo chmod 644 /var/log/suricata/eve.json`
4. Test with a known bad request: `curl "http://localhost/?q=<script>alert(1)</script>"`

### Wazuh

**Problem:** API authentication fails

**Solution:**
1. Verify credentials in `.env`
2. Check Wazuh API is running: `curl -k https://localhost:55000`
3. Test authentication: `curl -u wazuh:wazuh -k https://localhost:55000/security/user/authenticate`

**Problem:** No alerts received

**Solution:**
1. Check agent is connected: `curl -u wazuh:wazuh -k https://localhost:55000/agents`
2. Verify alerts exist: `curl -u wazuh:wazuh -k https://localhost:55000/alerts`
3. Check last processed ID: `sqlite3 logs/siem.db "SELECT * FROM kv WHERE key='wazuh_last_id'"`

---

## Performance

- **Suricata collector**: Processes ~1000 alerts/sec
- **Wazuh collector**: Polls max 500 alerts per request (configurable)
- Both collectors use offset tracking to resume after restart
- Events are normalized to the same Event schema as gateway logs

---

## Security Notes

- Wazuh integration uses `verify=False` for SSL — use proper certificates in production
- Suricata eve.json may contain sensitive data — restrict file permissions
- Collectors run with database write access — isolate in production
- API credentials should be rotated regularly

---

## References

- [Suricata Documentation](https://suricata.io/documentation/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Suricata eve.json Format](https://suricata.readthedocs.io/en/latest/output/eve/eve-json-format.html)
- [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
