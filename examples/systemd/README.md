# Systemd Service Files

## Installation

### 1. Install easy-oidc

```bash
# Copy binary
sudo cp bin/easy-oidc /usr/local/bin/easy-oidc
sudo chmod +x /usr/local/bin/easy-oidc

# Create user
sudo useradd -r -s /usr/sbin/nologin easy-oidc

# Create config directory
sudo mkdir -p /etc/easy-oidc
sudo cp examples/config/config-google.jsonc /etc/easy-oidc/config.jsonc
sudo chown -R easy-oidc:easy-oidc /etc/easy-oidc

# Create data directory for SQLite database
sudo mkdir -p /var/lib/easy-oidc
sudo chown easy-oidc:easy-oidc /var/lib/easy-oidc
sudo chmod 700 /var/lib/easy-oidc

# Install systemd service
sudo cp examples/systemd/easy-oidc.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable easy-oidc
sudo systemctl start easy-oidc
```

### 2. Install Caddy

```bash
# Download Caddy binary
CADDY_VERSION="2.7.6"
ARCH="arm64"  # or "amd64" for x86_64
curl -L "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_${ARCH}.tar.gz" -o /tmp/caddy.tar.gz

# Extract and install
sudo tar -xzf /tmp/caddy.tar.gz -C /usr/bin caddy
sudo chmod +x /usr/bin/caddy
rm /tmp/caddy.tar.gz

# Create user
sudo useradd -r -s /usr/sbin/nologin caddy

# Create directories
sudo mkdir -p /etc/caddy
sudo mkdir -p /var/log/caddy
sudo chown caddy:caddy /var/log/caddy

# Copy Caddyfile
sudo cp examples/Caddyfile /etc/caddy/Caddyfile
sudo chown caddy:caddy /etc/caddy/Caddyfile

# Install systemd service
sudo cp examples/systemd/caddy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable caddy
sudo systemctl start caddy
```

## Caddy Automatic HTTPS

Caddy automatically:
- ✅ Obtains Let's Encrypt certificates on first request
- ✅ Redirects HTTP (port 80) to HTTPS (port 443)
- ✅ Renews certificates before expiration
- ✅ Serves on HTTPS port 443

**No manual certificate management needed!**

## Checking Status

```bash
# Check easy-oidc
sudo systemctl status easy-oidc
sudo journalctl -u easy-oidc -f

# Check Caddy
sudo systemctl status caddy
sudo journalctl -u caddy -f

# Test endpoints
curl http://auth.example.com/healthz     # Redirects to HTTPS
curl https://auth.example.com/healthz    # Returns OK
curl https://auth.example.com/.well-known/openid-configuration
```

## Logs

```bash
# easy-oidc logs (JSON format)
sudo journalctl -u easy-oidc -n 100 --no-pager

# Caddy access logs
sudo tail -f /var/log/caddy/access.log
```

## Reloading Configuration

```bash
# Reload easy-oidc (reads new config)
sudo systemctl restart easy-oidc

# Reload Caddy (no downtime)
sudo systemctl reload caddy
```

## Troubleshooting

**Port 80/443 already in use:**
```bash
sudo netstat -tlnp | grep ':80\|:443'
```

**Certificate not obtained:**
- Ensure DNS points to your server's public IP
- Check port 80 is accessible (Let's Encrypt validation)
- Check logs: `sudo journalctl -u caddy -n 50`

**easy-oidc not starting:**
- Check config: `/usr/local/bin/easy-oidc --config /etc/easy-oidc/config.jsonc --validate`
- Check secrets are accessible (AWS IAM role, env vars, etc.)
- Check logs: `sudo journalctl -u easy-oidc -n 50`
