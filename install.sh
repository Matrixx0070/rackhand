#!/usr/bin/env bash
# ssh-mcp installer: one command on a fresh Linux VPS (run as root).
#
#   curl -fsSL https://raw.githubusercontent.com/Matrixx0070/ssh-mcp/main/install.sh | sudo bash
#
# What it does:
#   1. installs Node.js 22 if Node >= 20 is missing
#   2. puts the server in /opt/ssh-mcp and installs its dependencies
#   3. creates a random secret in /etc/ssh-mcp.env (kept if it already exists)
#   4. creates and starts the systemd service ssh-mcp (listens on 127.0.0.1 only)
#   5. puts Caddy in front of it for HTTPS on https://<public-ip-with-dashes>.sslip.io
#   6. checks that the server answers, then prints the connector URL
#
# Run it again to upgrade: hosts.json and the secret are kept, the old server.ts is backed up,
# and it is put back automatically if the new one does not answer.
#
# Settings (environment variables, all optional):
#   DOMAIN=mcp.example.com   use your own domain (its DNS A record must already point here)
#   PUBLIC_IP=203.0.113.10   skip the public-IP lookup
#   NO_CADDY=1               do not install or configure Caddy (bring your own HTTPS reverse proxy)
#   REPO=owner/name REF=main where to download the code from
#   SRC=/path/to/checkout    install from a local directory instead of downloading
#   APP=/opt/ssh-mcp SVC=ssh-mcp PORT=8787 ENVF=/etc/ssh-mcp.env STATE=/var/lib/ssh-mcp
#                            install somewhere else / under another name (each install needs its own STATE)
set -euo pipefail

REPO=${REPO:-Matrixx0070/ssh-mcp}; REF=${REF:-main}; SRC=${SRC:-}
APP=${APP:-/opt/ssh-mcp}; SVC=${SVC:-ssh-mcp}; PORT=${PORT:-8787}; ENVF=${ENVF:-/etc/$SVC.env}
STATE=${STATE:-/var/lib/$SVC}   # job logs, sessions, saved output and the audit log
NO_CADDY=${NO_CADDY:-0}; DOMAIN=${DOMAIN:-}; PUBLIC_IP=${PUBLIC_IP:-}
CADDYFILE=/etc/caddy/Caddyfile
UNIT=/etc/systemd/system/$SVC.service

say()  { printf '>> %s\n' "$*"; }
warn() { printf '!! %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (sudo bash install.sh)"
[ "$(uname -s)" = Linux ] || die "Linux only"
command -v systemctl >/dev/null && [ -d /run/systemd/system ] || die "systemd is required"
for c in curl tar; do command -v $c >/dev/null || die "$c is required (install it and run again)"; done
case "$(uname -m)" in x86_64|amd64) NARCH=x64; CARCH=amd64;; aarch64|arm64) NARCH=arm64; CARCH=arm64;; *) die "unsupported CPU: $(uname -m)";; esac

# ---------- 1. Node.js ----------
node_ok() { command -v node >/dev/null 2>&1 && [ "$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)" -ge 20 ]; }
if ! node_ok; then
  command -v xz >/dev/null || die "xz is required to unpack Node.js (apt-get install -y xz-utils  /  dnf install -y xz)"
  say "installing Node.js 22 into /usr/local"
  NF=$(curl -fsSL https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt | grep -o "node-v22[0-9.]*-linux-$NARCH\.tar\.xz" | head -1)
  [ -n "$NF" ] || die "could not find a Node.js 22 build for linux-$NARCH"
  T=$(mktemp -d)
  curl -fsSL "https://nodejs.org/dist/latest-v22.x/$NF" -o "$T/$NF"
  WANT=$(curl -fsSL https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt | awk -v f="$NF" '$2 == f {print $1}')
  [ "$(sha256sum "$T/$NF" | cut -d' ' -f1)" = "$WANT" ] || die "Node.js download does not match its published checksum"
  tar -xJf "$T/$NF" -C /usr/local --strip-components=1
  rm -rf "$T"; hash -r
  node_ok || die "Node.js install failed"
fi
NODE=$(command -v node); NPM=$(command -v npm) || die "npm not found next to node"
say "Node.js $(node -v) at $NODE"

# ---------- 2. code ----------
FRESH=1; [ -f "$APP/server.ts" ] && FRESH=0
STAGE=$(mktemp -d); trap 'rm -rf "$STAGE"' EXIT
if [ -n "$SRC" ]; then
  [ -f "$SRC/server.ts" ] || die "SRC=$SRC has no server.ts"
  cp -a "$SRC/." "$STAGE/"
else
  case "$REPO" in *__*) die "set REPO=owner/name (or SRC=/path/to/checkout)";; esac
  say "downloading $REPO@$REF"
  curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$REF" | tar -xz -C "$STAGE" --strip-components=1
fi
for f in server.ts box.sh package.json package-lock.json; do [ -s "$STAGE/$f" ] || die "the source has no $f"; done

mkdir -p "$APP"; chmod 755 "$APP"
TS=$(date -u +%Y%m%d-%H%M%S); BAK=""
if [ "$FRESH" = 0 ]; then BAK="$APP/server.ts.bak-$TS"; cp -p "$APP/server.ts" "$BAK"; say "upgrade: old server.ts kept as $BAK"; fi
for f in server.ts box.sh package.json package-lock.json tsconfig.json hosts.example.json README.md LICENSE; do
  [ -e "$STAGE/$f" ] && cp -f "$STAGE/$f" "$APP/$f"
done
for d in upgrade test; do [ -d "$STAGE/$d" ] && { mkdir -p "$APP/$d"; cp -af "$STAGE/$d/." "$APP/$d/"; }; done
[ -f "$APP/hosts.json" ] || echo '{ "local": { "local": true } }' > "$APP/hosts.json"
chmod 600 "$APP/hosts.json"
say "installing dependencies"
(cd "$APP" && "$NPM" ci --omit=dev --no-audit --no-fund --silent) || die "npm ci failed"

# ---------- 3. secret ----------
if [ ! -s "$ENVF" ]; then
  S=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  [ "${#S}" = 64 ] || die "could not generate a secret"
  (umask 077; echo "MCP_SECRET=$S" > "$ENVF")
  say "new secret written to $ENVF"
fi
chmod 600 "$ENVF"
MCP_SECRET=$(sed -n 's/^MCP_SECRET=//p' "$ENVF" | head -1)
[ "${#MCP_SECRET}" -ge 32 ] || die "$ENVF has no usable MCP_SECRET"

# ---------- 4. service ----------
# KillMode=process + OOMPolicy=continue: restarting, crashing or an out-of-memory kill of the connector
# does not take down the programs that were started through it.
RUN_HOME=$(getent passwd 0 | cut -d: -f6); RUN_HOME=${RUN_HOME:-/root}
install -d -m 700 "$STATE"      # private: it holds command output and the audit log
cat > "$UNIT" <<EOF
[Unit]
Description=ssh-mcp connector (remote MCP server)
After=network.target

[Service]
WorkingDirectory=$APP
EnvironmentFile=$ENVF
Environment=HOSTS_FILE=$APP/hosts.json
Environment=PORT=$PORT
Environment=JOBS_DIR=$STATE/jobs
Environment="HOME=$RUN_HOME"
Environment="PATH=$APP/node_modules/.bin:$(dirname "$NODE"):/usr/local/bin:/usr/bin:/bin"
ExecStart=$NODE --import tsx server.ts
Restart=always
RestartSec=1
KillMode=process
OOMPolicy=continue

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SVC" >/dev/null 2>&1 || true
systemctl restart "$SVC"

URL_LOCAL="http://127.0.0.1:$PORT/mcp/$MCP_SECRET"
tool_count() {
  curl -s -m 5 -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' "$URL_LOCAL" 2>/dev/null | grep -o '"name":"[a-z_]*"' | wc -l
}
wait_up() { local i n; for i in $(seq 1 30); do n=$(tool_count); [ "$n" -gt 0 ] && { echo "$n"; return 0; }; sleep 1; done; echo 0; return 1; }
if N=$(wait_up); then
  say "server is up: $N tools"
else
  journalctl -u "$SVC" -n 15 --no-pager >&2 || true
  if [ -n "$BAK" ]; then
    warn "the new server did not answer - putting the previous server.ts back"
    cp -pf "$BAK" "$APP/server.ts"; systemctl restart "$SVC"
    N=$(wait_up) && die "upgrade failed; the previous version is running again ($N tools)" || die "upgrade failed and the previous version does not answer either - see: journalctl -u $SVC"
  fi
  die "the server did not start - see: journalctl -u $SVC"
fi

# ---------- 5. HTTPS ----------
if [ -z "$DOMAIN" ]; then
  if [ -z "$PUBLIC_IP" ]; then
    TOK=$(curl -s -m 2 -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null || true)
    [ -n "$TOK" ] && PUBLIC_IP=$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $TOK" http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true)
    case "$PUBLIC_IP" in *[!0-9.]*|"") PUBLIC_IP=$(curl -4 -fsS -m 8 https://api.ipify.org 2>/dev/null || curl -4 -fsS -m 8 https://ifconfig.me 2>/dev/null || true);; esac
  fi
  case "$PUBLIC_IP" in *[!0-9.]*|"") PUBLIC_IP="";; esac
  [ -n "$PUBLIC_IP" ] && DOMAIN="${PUBLIC_IP//./-}.sslip.io"
fi

HTTPS_OK=0
if [ "$NO_CADDY" = 1 ]; then
  say "NO_CADDY=1: point your own HTTPS reverse proxy at 127.0.0.1:$PORT"
elif [ -z "$DOMAIN" ]; then
  warn "could not work out this machine's public IP - run again with DOMAIN=your.domain or PUBLIC_IP=x.x.x.x"
else
  BUSY=$(ss -ltnpH 'sport = :443' 2>/dev/null | grep -v caddy | grep -o 'users:(("[^"]*"' | head -1 | cut -d'"' -f2 || true)
  if [ -n "$BUSY" ]; then
    warn "port 443 is already used by '$BUSY' - not installing Caddy. Add a reverse proxy rule there:  https://$DOMAIN  ->  127.0.0.1:$PORT"
  else
    if ! command -v caddy >/dev/null; then
      say "installing Caddy"
      curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=$CARCH" -o /usr/local/bin/caddy
      chmod +x /usr/local/bin/caddy
    fi
    mkdir -p /etc/caddy /var/lib/caddy
    MARK="# ssh-mcp ($SVC)"
    if [ -f "$CADDYFILE" ] && grep -qF "$MARK" "$CADDYFILE"; then
      say "Caddyfile already has the $SVC site"
    else
      [ -f "$CADDYFILE" ] && cp -p "$CADDYFILE" "$CADDYFILE.bak-$TS"       # other sites in it are left as they are
      printf '\n%s\n%s {\n    reverse_proxy 127.0.0.1:%s\n}\n' "$MARK" "$DOMAIN" "$PORT" >> "$CADDYFILE"
    fi
    if ! systemctl cat caddy >/dev/null 2>&1; then
      cat > /etc/systemd/system/caddy.service <<EOF
[Unit]
Description=Caddy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$(command -v caddy) run --config $CADDYFILE --adapter caddyfile
ExecReload=$(command -v caddy) reload --config $CADDYFILE --adapter caddyfile
Restart=always
# certificates in /var/lib/caddy, Caddy's own saved config in /var/lib/caddy/.config (without HOME it would
# write a "caddy" folder into whatever directory it was started from)
Environment=XDG_DATA_HOME=/var/lib
Environment=HOME=/var/lib/caddy
WorkingDirectory=/var/lib/caddy
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
    fi
    systemctl enable caddy >/dev/null 2>&1 || true
    systemctl is-active --quiet caddy && systemctl reload caddy 2>/dev/null || systemctl restart caddy
    say "waiting for the HTTPS certificate for $DOMAIN (ports 80 and 443 must be open to the internet)"
    for i in $(seq 1 30); do
      code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
        -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' "https://$DOMAIN/mcp/$MCP_SECRET" 2>/dev/null || true)
      [ "$code" = 200 ] && { HTTPS_OK=1; break; }
      sleep 2
    done
    [ "$HTTPS_OK" = 1 ] || warn "https://$DOMAIN does not answer yet. Open ports 80 and 443 in the firewall / security group, then check: journalctl -u caddy -n 30"
  fi
fi

# ---------- 6. result ----------
ROLE=""
if [ -n "${TOK:-}" ]; then ROLE=$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $TOK" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null | head -1 || true); fi
case "$ROLE" in *"<"*|*" "*) ROLE="";; esac

echo
echo "=================================================================="
if [ -n "$DOMAIN" ] && [ "$NO_CADDY" != 1 ]; then
  echo " CONNECTOR URL - whoever has it has a root shell on this machine:"
  echo
  echo "   https://$DOMAIN/mcp/$MCP_SECRET"
  echo
  [ "$HTTPS_OK" = 1 ] && echo " HTTPS check: OK" || echo " HTTPS check: NOT reachable yet (see the warning above)"
else
  echo " Local endpoint (put HTTPS in front of it):"
  echo "   $URL_LOCAL"
fi
echo "=================================================================="
echo " Add it as a custom connector / remote MCP server in your AI client (see README)."
echo " More SSH hosts:  ask the assistant to add one (the add_host tool), or edit $APP/hosts.json"
echo " Logs:            journalctl -u $SVC -f"
AUDIT=$(journalctl -u "$SVC" -n 50 --no-pager -o cat 2>/dev/null | sed -n 's/^audit log: //p' | tail -1 || true)
[ -n "$AUDIT" ] && echo " Audit log:       $AUDIT   (every call the connector runs)"
echo " New secret:      delete $ENVF, run this installer again, re-add the connector"
if [ -n "$ROLE" ]; then
  echo
  echo " WARNING: this EC2 instance has the IAM role '$ROLE'."
  echo " Anyone with the URL above can use that role's AWS permissions. Check what it allows,"
  echo " and remove permissions this machine does not need."
fi
