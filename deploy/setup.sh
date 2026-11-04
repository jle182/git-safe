#!/usr/bin/env bash
# git-safe server setup for a fresh Ubuntu 24.04 box (e.g. Vultr cloud compute).
# usage:  sudo bash deploy/setup.sh [yourdomain.example]
#   no argument -> uses <server-ip>.nip.io as a free placeholder domain
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
  IP="$(hostname -I | awk '{print $1}')"
  DOMAIN="${IP}.nip.io"
fi
echo ">> site will be: https://$DOMAIN  (for a real domain, point its A record at this box first)"

echo ">> base packages"
apt-get update -qq
apt-get install -y -qq python3 git ca-certificates curl debian-keyring debian-archive-keyring apt-transport-https >/dev/null

echo ">> caddy (web server + automatic HTTPS)"
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --batch --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' >/etc/apt/sources.list.d/caddy-stable.list
apt-get update -qq && apt-get install -y -qq caddy >/dev/null

echo ">> user + files"
id -u gitsafe >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d /var/lib/git-safe -m gitsafe
mkdir -p /opt/git-safe /var/lib/git-safe
cp -r "$REPO_DIR/gitsafe" "$REPO_DIR/server" "$REPO_DIR/web" /opt/git-safe/
chown -R gitsafe:gitsafe /var/lib/git-safe

echo ">> systemd service"
cp "$REPO_DIR/deploy/git-safe.service" /etc/systemd/system/git-safe.service
systemctl daemon-reload
systemctl enable --now git-safe

echo ">> caddy config"
cat >/etc/caddy/Caddyfile <<CADDYHERE
$DOMAIN {
	reverse_proxy 127.0.0.1:8080
}
CADDYHERE
systemctl restart caddy

echo ">> firewall"
command -v ufw >/dev/null 2>&1 && { ufw allow 22/tcp >/dev/null 2>&1 || true; ufw allow 80,443/tcp >/dev/null 2>&1 || true; } || true

echo
echo "done.  site: https://$DOMAIN   (first HTTPS cert can take ~30s)"
echo "       logs: journalctl -u git-safe -f"
echo "cli:   GITSAFE_API=https://$DOMAIN git safe owner/repo"
