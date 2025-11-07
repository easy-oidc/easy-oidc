#!/bin/bash
# Copyright 2025 Nadrama Pty Ltd
# SPDX-License-Identifier: Apache-2.0

set -eo pipefail

# Userdata script for Ubuntu LTS, which sets up easy-oidc and Caddy on a fresh instance.
# Variables which you can set prior to invoking this script:
# EASY_OIDC_VERSION="latest"
# EASY_OIDC_SHA512="abc123..."
# CADDY_VERSION="latest"
# CADDY_SHA512="def456..."
# OIDC_HOSTNAME="auth.example.com"
# EASY_OIDC_CONFIG='{"clients":{}}'
# SSH=false
# FIREWALL=true
# AUTO_UPDATES=true

# === DO NOT EDIT BELOW ===

# Caddyfile content
read -r -d '' CADDYFILE <<'CADDYEOF' || true
${OIDC_HOSTNAME} {
    reverse_proxy localhost:8080
    log {
        output file /var/log/caddy/access.log
    }
}
CADDYEOF

# Security configuration
SSH="${SSH:-false}"
FIREWALL="${FIREWALL:-true}"
AUTO_UPDATES="${AUTO_UPDATES:-true}"

echo "=== Starting Installation ==="

# === Configure Firewall (if enabled) ===
if [ "${FIREWALL}" = "true" ]; then
    echo "Configuring firewall..."
    # Only allow HTTP/HTTPS
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw
    ufw --force disable
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 80/tcp
    ufw allow 443/tcp
    if [ "${SSH}" = "true" ]; then
        ufw allow 22/tcp
    fi
    ufw --force enable
fi

# === Configure SSH Access ===
if [ "${SSH}" = "true" ]; then
    # Harden SSH configuration
    echo "Hardening SSH configuration..."
    cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'SSH_EOF'
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 2
SSH_EOF
    systemctl reload ssh || true
else
    echo "Disabling SSH..."
    systemctl stop ssh || true
    systemctl disable ssh || true
fi

# Auto-detect architecture
echo "Detecting architecture..."
MACHINE_ARCH=$(uname -m)
case "${MACHINE_ARCH}" in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: ${MACHINE_ARCH}"
        exit 1
        ;;
esac
echo "ARCH: ${ARCH}"

# === Install easy-oidc ===
# Resolve "latest" or empty to actual version
if [ -z "${EASY_OIDC_VERSION}" ] || [ "${EASY_OIDC_VERSION}" = "latest" ]; then
    echo "Fetching latest easy-oidc release..."
    EASY_OIDC_VERSION=$(curl -sSL https://api.github.com/repos/easy-oidc/easy-oidc/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    echo "Latest version: ${EASY_OIDC_VERSION}"
fi

echo "Installing easy-oidc ${EASY_OIDC_VERSION}..."

curl -L "https://github.com/easy-oidc/easy-oidc/releases/download/${EASY_OIDC_VERSION}/easy-oidc_${EASY_OIDC_VERSION#v}_linux_${ARCH}.tar.gz" -o /tmp/easy-oidc.tar.gz

if [ -n "${EASY_OIDC_SHA512}" ]; then
    echo "Verifying easy-oidc checksum..."
    echo "${EASY_OIDC_SHA512}  /tmp/easy-oidc.tar.gz" | sha512sum -c -
    if [ $? -ne 0 ]; then
        echo "ERROR: easy-oidc checksum verification failed"
        exit 1
    fi
fi

tar -xzf /tmp/easy-oidc.tar.gz -C /tmp
mv /tmp/easy-oidc /usr/local/bin/easy-oidc
chmod +x /usr/local/bin/easy-oidc
rm /tmp/easy-oidc.tar.gz

if ! id -u easy-oidc >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d /var/lib/easy-oidc -m easy-oidc
fi

mkdir -p /etc/easy-oidc
mkdir -p /opt/easy-oidc
chown easy-oidc:easy-oidc /var/lib/easy-oidc
chmod 700 /var/lib/easy-oidc

# === Install Caddy ===
# Resolve "latest" or empty to actual version
if [ -z "${CADDY_VERSION}" ] || [ "${CADDY_VERSION}" = "latest" ]; then
    echo "Fetching latest Caddy release..."
    CADDY_VERSION=$(curl -sSL https://api.github.com/repos/caddyserver/caddy/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    echo "Latest version: ${CADDY_VERSION}"
fi

echo "Installing Caddy ${CADDY_VERSION}..."

curl -L "https://github.com/caddyserver/caddy/releases/download/${CADDY_VERSION}/caddy_${CADDY_VERSION#v}_linux_${ARCH}.tar.gz" -o /tmp/caddy.tar.gz

if [ -n "${CADDY_SHA512}" ]; then
    echo "Verifying Caddy checksum..."
    echo "${CADDY_SHA512}  /tmp/caddy.tar.gz" | sha512sum -c -
    if [ $? -ne 0 ]; then
        echo "ERROR: Caddy checksum verification failed"
        exit 1
    fi
fi

tar -xzf /tmp/caddy.tar.gz -C /tmp caddy
mv /tmp/caddy /usr/bin/caddy
chmod +x /usr/bin/caddy
rm /tmp/caddy.tar.gz

if ! id -u caddy >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d /var/lib/caddy -m caddy
fi

mkdir -p /etc/caddy
mkdir -p /var/log/caddy
chown caddy:caddy /var/log/caddy
chown -R caddy:caddy /var/lib/caddy

# === Create configuration files ===
echo "Creating configuration files..."

# Write easy-oidc config (already a complete JSON document from Terraform)
echo "${EASY_OIDC_CONFIG}" > /etc/easy-oidc/config.jsonc
chown easy-oidc:easy-oidc /etc/easy-oidc/config.jsonc

# Write Caddyfile (expand variables)
cat > /etc/caddy/Caddyfile <<EOF
$(eval "echo \"${CADDYFILE}\"")
EOF
chown caddy:caddy /etc/caddy/Caddyfile

# === Install systemd services ===
echo "Installing systemd services..."

cat > /etc/systemd/system/easy-oidc.service <<'EOF'
[Unit]
Description=Easy OIDC Server
After=network.target

[Service]
Type=simple
User=easy-oidc
Group=easy-oidc
WorkingDirectory=/opt/easy-oidc
ExecStart=/usr/local/bin/easy-oidc --config /etc/easy-oidc/config.jsonc
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/easy-oidc
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/caddy.service <<'EOF'
[Unit]
Description=Caddy Web Server
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=/usr/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=512
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/var/lib/caddy
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# === Start services ===
echo "Starting services..."
systemctl daemon-reload
systemctl enable easy-oidc
systemctl enable caddy
systemctl start easy-oidc
systemctl start caddy

# === Log Installation Info ===
echo "=== Installation complete ==="
echo ""
echo "Configuration:"
echo "  Hostname:     ${OIDC_HOSTNAME}"
echo "  Issuer URL:   https://${OIDC_HOSTNAME}"
echo ""
echo "Status:"
systemctl status easy-oidc --no-pager || true
echo ""
systemctl status caddy --no-pager || true
echo ""
echo "Logs:"
echo "  easy-oidc: journalctl -u easy-oidc -f"
echo "  caddy:     journalctl -u caddy -f"
echo ""

# === Automatic System Updates ===
if [ "${AUTO_UPDATES}" = "true" ]; then
    echo "Enabling automatic security updates..."
    export DEBIAN_FRONTEND=noninteractive
    dpkg-reconfigure unattended-upgrades
fi
