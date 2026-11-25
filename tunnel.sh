#!/bin/bash
# Rackhand __VERSION__: connects this machine to the Rackhand connector at __URL__ as "__NAME__", through a tunnel
# that this machine opens: an SSH connection over HTTPS (port 443) that the connector's logins come back through.
# Nothing on this machine has to be reachable from outside, and nothing changes on its firewall.
#
# What it does, in this order:
#   1. checks for an OpenSSH client with a post-quantum key exchange, openssl, curl, and an SSH server on port __SSHD_PORT__
#   2. lets the connector log in as __USERNAME__: adds the connector's key to that user's ~/.ssh/authorized_keys
#   3. makes a key for the tunnel (in /etc/ssh-mcp-tunnel) and tells the connector that key and this machine's
#      SSH host keys - the link this came from works for that once, within 30 minutes of add_host
#   4. installs and starts the service ssh-mcp-tunnel, which keeps the tunnel open and reopens it when it drops
#   5. waits until the connector has logged in through the tunnel, and says so
# The tunnel can do one thing at the connector: pass the connector's connections on to 127.0.0.1:__SSHD_PORT__ here.
# Its key exchange is post-quantum only, at both ends.
#
# To undo it: systemctl disable --now ssh-mcp-tunnel; rm -r /etc/ssh-mcp-tunnel /etc/systemd/system/ssh-mcp-tunnel.service
# and remove the line "__CONNECTOR_KEY__" from ~__USERNAME__/.ssh/authorized_keys.
#
# Without root or without systemd, SSHMCP_TUNNEL_FOREGROUND=1 keeps the tunnel in the foreground instead of a service
# (SSHMCP_TUNNEL_DIR: where its files go; SSHMCP_AUTHORIZED_KEYS: the authorized_keys file to add the connector's key to).
set -euo pipefail

# Everything is in one function, so that bash has read the whole script before any of it runs (curl ... | bash).
main() {
  local url='__URL__' enroll='__ENROLL__' name='__NAME__' user='__USERNAME__' sshd_port='__SSHD_PORT__'
  local connector_key='__CONNECTOR_KEY__' tunnel_hostkey='__TUNNEL_HOSTKEY__' kex_offer='__KEX__' version='__VERSION__'
  local dir="${SSHMCP_TUNNEL_DIR:-/etc/ssh-mcp-tunnel}" foreground="${SSHMCP_TUNNEL_FOREGROUND:-}"
  local unit=/etc/systemd/system/ssh-mcp-tunnel.service code="" reply=""

  say() { printf '%s\n' "$*"; }
  die() { printf 'rackhand tunnel: %s\n' "$*" >&2; exit 1; }
  # POST to the connector; sets $code (000 when it could not be reached) and $reply
  post() {
    local out
    if ! out=$(curl -sS --proto =https --max-time 90 -X POST -H 'Content-Type: text/plain' --data-binary "$2" -w '\n%{http_code}' "$url$1" 2>&1); then
      code=000; reply=$out; return 0
    fi
    code=${out##*$'\n'}; reply=${out%$'\n'*}
  }

  say "rackhand tunnel: connecting this machine to $url as \"$name\""

  # 1. what it needs
  if [ -z "$foreground" ]; then
    [ "$(id -u)" = 0 ] || die "run it as root (curl ... | sudo bash): it installs a system service. To keep the tunnel in the foreground instead, without root: SSHMCP_TUNNEL_FOREGROUND=1"
    { command -v systemctl >/dev/null && [ -d /run/systemd/system ]; } || die "this machine does not run systemd. Run it with SSHMCP_TUNNEL_FOREGROUND=1 to keep the tunnel in the foreground instead"
  fi
  local t
  for t in ssh ssh-keygen openssl curl timeout; do command -v "$t" >/dev/null || die "$t is missing (it comes with the packages openssh-client, openssl, curl and coreutils)"; done
  # -nocommands: without it, openssl would act on a byte "Q" or "R" in the tunnel's data as a command (OpenSSL 1.1.1 and newer have it)
  [[ $(openssl s_client -help 2>&1) == *-nocommands* ]] || die "this machine's openssl ($(openssl version)) is too old for the tunnel: OpenSSL 1.1.1 or newer is needed"
  local have k kex=""
  have=$(ssh -Q kex 2>/dev/null || true)
  for k in ${kex_offer//,/ }; do grep -qxF "$k" <<<"$have" && kex="${kex:+$kex,}$k"; done
  [ -n "$kex" ] || die "this machine's SSH client ($(ssh -V 2>&1)) has none of the post-quantum key exchanges the tunnel is made with ($kex_offer). OpenSSH 9.0 and newer have one"
  local banner
  banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$sshd_port && head -1 <&3" 2>/dev/null || true)
  case "$banner" in
    SSH-2.0-*) ;;
    *) die "no SSH server answers on 127.0.0.1:$sshd_port here. Install and start one (apt-get install openssh-server), or call add_host again with the port it listens on" ;;
  esac
  say "  ok: $(ssh -V 2>&1 | cut -d, -f1), key exchange ${kex%%,*}; SSH server on port $sshd_port"

  # 2. the connector's key, for the user it logs in as
  local ak="${SSHMCP_AUTHORIZED_KEYS:-}" home="" group=""
  if [ -z "$ak" ]; then
    home=$(getent passwd "$user" | cut -d: -f6 || true)
    [ -n "$home" ] || die "there is no user $user on this machine (add_host was called with username: \"$user\")"
    group=$(id -gn "$user")
    ak="$home/.ssh/authorized_keys"
  fi
  if [ -f "$ak" ] && grep -qF "$(cut -d' ' -f2 <<<"$connector_key")" "$ak"; then
    say "  the connector's key is already in $ak"
  else
    if [ -n "$home" ] && [ ! -d "$home/.ssh" ]; then install -d -m 700 -o "$user" -g "$group" "$home/.ssh"; fi
    if [ ! -f "$ak" ]; then
      ( umask 077; : > "$ak" )
      if [ -n "$home" ]; then chown "$user:$group" "$ak"; fi
    fi
    if [ -s "$ak" ] && [ -n "$(tail -c1 "$ak")" ]; then printf '\n' >> "$ak"; fi # its last line has no line break: give it one first
    printf '%s\n' "$connector_key" >> "$ak"
    say "  added the connector's key to $ak"
  fi

  # 3. the tunnel's own key, and the enrollment
  ( umask 077; mkdir -p "$dir" )
  chmod 700 "$dir"
  [ -f "$dir/key" ] || ssh-keygen -q -t ed25519 -N '' -C "ssh-mcp-tunnel@$(uname -n)" -f "$dir/key" </dev/null
  local hostkeys
  hostkeys=$(ssh-keyscan -T 5 -p "$sshd_port" 127.0.0.1 2>/dev/null | awk '!/^#/ && NF >= 3 { print $2, $3 }' | sort -u || true)
  [ -n "$hostkeys" ] || hostkeys=$(cat /etc/ssh/ssh_host_*_key.pub 2>/dev/null | awk 'NF >= 2 { print $1, $2 }' || true)
  [ -n "$hostkeys" ] || die "could not read the host keys of the SSH server on port $sshd_port"
  local body l
  body="key $(cut -d' ' -f1,2 "$dir/key.pub")"$'\n'
  while IFS= read -r l; do body+="hostkey $l"$'\n'; done <<<"$hostkeys"
  body+="hostname $(uname -n)"$'\n'"client $(ssh -V 2>&1 | cut -d, -f1)"$'\n'
  post "/t/$enroll" "$body"
  [ "$code" = 200 ] || die "the connector did not take this machine (HTTP $code): $reply"
  local port id tuser
  port=$(sed -n 's/^port=\([0-9]\{1,5\}\)$/\1/p' <<<"$reply")
  id=$(sed -n 's/^id=\([0-9a-f]\{32\}\)$/\1/p' <<<"$reply")
  tuser=$(sed -n 's/^user=\([A-Za-z0-9_][A-Za-z0-9_.-]*\)$/\1/p' <<<"$reply")
  [ -n "$port" ] && [ -n "$id" ] && [ -n "$tuser" ] || die "unexpected answer from the connector: $reply"
  say "  the connector took it: the tunnel is to come in on its port $port"

  # the tunnel: SSH, carried over HTTPS by the helper below, host key of the connector's end pinned
  local hp=${url#https://} host tport
  host=${hp%:*}; tport=${hp##*:}
  if [ "$host" = "$hp" ]; then tport=443; fi
  printf 'ssh-mcp-tunnel %s\n' "$tunnel_hostkey" > "$dir/known_hosts"
  {
    printf '#!/bin/bash\n'
    printf '# ProxyCommand of the Rackhand tunnel (Rackhand %s): carries the SSH connection to %s over HTTPS -\n' "$version" "$url"
    printf '# TLS to the connector, one HTTP upgrade, then the bytes as they are.\n'
    printf 'host=%q; port=%q; path=%q; hostheader=%q\n' "$host" "$tport" "/t/$id" "$([ "$tport" = 443 ] && printf %s "$host" || printf %s "$host:$tport")"
    cat <<'HELPER'
# The pipeline's last part runs in this process, and its exec cat replaces it: when the connection ends, nothing else
# holds ssh's end of it open, so ssh sees the end at once (not only at its next keepalive).
shopt -s lastpipe
if [[ $host =~ ^[0-9.]+$ ]]; then name=(-noservername -verify_ip "$host"); else name=(-servername "$host" -verify_hostname "$host"); fi
{ printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: ssh-mcp-tunnel\r\nUser-Agent: ssh-mcp-tunnel\r\n\r\n' "$path" "$hostheader"; exec cat; } |
  openssl s_client -quiet -no_ign_eof -nocommands -verify_quiet -verify_return_error "${name[@]}" -connect "$host:$port" |
  { IFS= read -r status || { echo "rackhand tunnel: no answer from $host:$port" >&2; exit 1; }
    case "$status" in "HTTP/1.1 101 "*) ;; *) echo "rackhand tunnel: the connector answered: ${status%$'\r'}" >&2; exit 1 ;; esac
    while IFS= read -r line && [ -n "${line%$'\r'}" ]; do :; done
    exec cat; }
HELPER
  } > "$dir/connect"
  chmod 700 "$dir/connect"
  cat > "$dir/ssh_config" <<EOF
# Rackhand tunnel to $url, as "$name" (Rackhand $version)
Host ssh-mcp-tunnel
  User $tuser
  ProxyCommand $dir/connect
  IdentityFile $dir/key
  IdentitiesOnly yes
  IdentityAgent none
  HostKeyAlias ssh-mcp-tunnel
  UserKnownHostsFile $dir/known_hosts
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  UpdateHostKeys no
  CheckHostIP no
  HostKeyAlgorithms ssh-ed25519
  KexAlgorithms $kex
  BatchMode yes
  ExitOnForwardFailure yes
  ServerAliveInterval 15
  ServerAliveCountMax 3
  RemoteForward 127.0.0.1:$port 127.0.0.1:$sshd_port
  RequestTTY no
  ControlMaster no
  ControlPath none
  LogLevel ERROR
EOF
  local ssh_bin
  ssh_bin=$(command -v ssh)

  # 5. (in the background while the tunnel starts) wait until the connector has logged in through it
  confirm() {
    local i
    for i in $(seq 1 45); do
      post "/t/$enroll/up" ""
      case "$code" in
        200) say "$reply"; return 0 ;;
        503 | 000) sleep 2 ;;
        *) die "$reply" ;;
      esac
    done
    local hint=" - see: systemctl status ssh-mcp-tunnel; journalctl -u ssh-mcp-tunnel"
    [ -z "$foreground" ] || hint=""
    die "the tunnel did not come up within 90 seconds: $reply$hint"
  }

  if [ -n "$foreground" ]; then
    say "  running the tunnel in the foreground (Ctrl-C ends it)"
    confirm &
    while :; do
      "$ssh_bin" -F "$dir/ssh_config" -N -T ssh-mcp-tunnel </dev/null || true
      sleep "${SSHMCP_TUNNEL_RETRY:-5}"
    done
  fi

  # 4. the service
  # It starts ssh through env, not as ssh itself. On a machine with SELinux enforcing (RHEL, Fedora, ...) a unit
  # whose program is the ssh client stays in systemd's own domain (init_t), which may neither run ssh - the unit
  # fails with status=203/EXEC and loops, and that denial is not even logged - nor connect to the SSH server on
  # port 22, so the tunnel would come up and pass nothing. Started through env, it gets the domain that every
  # other third-party service runs in (unconfined_service_t). Without SELinux it makes no difference.
  local env_bin
  env_bin=$(command -v env || echo /usr/bin/env)
  cat > "$unit" <<EOF
[Unit]
Description=Rackhand tunnel to $url (as "$name")
After=network-online.target
Wants=network-online.target
# keep trying, however long the connector or the network is away
StartLimitIntervalSec=0

[Service]
ExecStart=$env_bin $ssh_bin -F $dir/ssh_config -N -T ssh-mcp-tunnel
Restart=always
RestartSec=5
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable ssh-mcp-tunnel >/dev/null 2>&1
  systemctl restart ssh-mcp-tunnel
  say "  started the service ssh-mcp-tunnel"
  confirm
}

main "$@"
