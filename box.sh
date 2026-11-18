#!/usr/bin/env bash
# box - sandbox-side client for the ssh-mcp connector. The connector serves this file at /b/<token>/cli
# with its own URL filled in. Everything goes straight from this shell to the host over HTTPS:
# no model in between, binary-safe, any size. Needs only bash, curl, tar, base64.
set -o pipefail
BOX_URL="${BOX_URL:-__BOX_URL__}"
VERSION="__BOX_VERSION__"

usage() {
  cat >&2 <<'EOF'
box - talk to the ssh-mcp connector from a sandbox shell

  box exec [-t SEC] [-C DIR] [-y] [HOST] -- COMMAND   run a command: merged output, same exit code (-y: confirm a command the server refused)
                                                 COMMAND "-" reads a script from stdin
  box put  LOCAL [HOST:]REMOTE [MODE]            upload one file (parent directories are created)
  box get  [HOST:]REMOTE [LOCAL|-]               download one file ("-" writes to stdout)
  box push LOCALDIR [HOST:]REMOTEDIR [-x PAT]... upload a directory tree as one tar stream
  box pull [HOST:]REMOTEDIR LOCALDIR [-x PAT]... download a directory tree as one tar stream
  box call TOOL [JSON]                           call any MCP tool of the connector
  box tools                                      list the connector's tools
  box install                                    copy this script onto PATH as "box"

HOST defaults to "local" (the machine the connector runs on). Remote paths are absolute.
Each command is one HTTPS request; run several at once with & or xargs -P.
EOF
  exit 2
}
die() { echo "box: $*" >&2; exit 2; }
b64u() { printf %s "$1" | base64 | tr -d '\n=' | tr '+/' '-_'; }
split() { # [HOST:]/abs/path -> H, Q
  if [[ "$1" =~ ^([A-Za-z0-9_.-]+):(/.*)$ ]]; then H="${BASH_REMATCH[1]}"; Q="${BASH_REMATCH[2]}"; else H=local; Q="$1"; fi
  [[ "$Q" == /* ]] || die "remote path must be absolute: $1"
}
mktmp() { T=$(mktemp -d) || die "mktemp failed"; trap 'rm -rf "$T"' EXIT; }
http_status() { awk 'toupper($1) ~ /^HTTP\// { s = $2 } END { print s }' "$1"; }   # last response (a proxy adds its own first)
http_header() { awk -v k="$2:" 'tolower($1) == k { v = $2 } END { gsub(/\r/, "", v); print v }' "$1"; }

cmd_exec() {
  local t=120 cwd="" host=local yes=""
  while [ $# -gt 0 ]; do
    case "$1" in
      -t) t="$2"; shift 2 ;;
      -y|--yes) yes=1; shift ;;
      -C) cwd="$2"; shift 2 ;;
      --) shift; break ;;
      -*) die "exec: unknown option $1" ;;
      *) host="$1"; shift ;;
    esac
  done
  [ $# -gt 0 ] || die "usage: box exec [-t SEC] [-C DIR] [-y] [HOST] -- COMMAND"
  mktmp
  [[ "$t" =~ ^[0-9]+$ ]] || die "exec: -t takes whole seconds"
  if [ "$*" = "-" ]; then cat > "$T/cmd"; else printf %s "$*" > "$T/cmd"; fi
  [ -s "$T/cmd" ] || die "exec: empty command"
  local q="timeout=$t" code
  [ -n "$cwd" ] && q="$q&c64=$(b64u "$cwd")"
  [ -n "$yes" ] && q="$q&confirm=1"   # run a command the server's tripwire refused
  # nothing comes back until the command has finished, so allow that much silence (plus a margin), then any size of output
  curl -sS --connect-timeout 20 -y $((t + 60)) -Y 1 -D "$T/h" -o "$T/o" -H 'Content-Type: text/plain' --data-binary @"$T/cmd" "$BOX_URL/exec/$host?$q" || die "request failed"
  if [ "$(http_status "$T/h")" = 200 ]; then
    cat "$T/o"
    code=$(http_header "$T/h" x-exit-code)
    exit "${code:-255}"
  fi
  cat "$T/o" >&2
  exit 255
}

cmd_put() {
  [ $# -ge 2 ] || die "usage: box put LOCAL [HOST:]REMOTE [MODE]"
  [ -f "$1" ] || die "no such file: $1"
  split "$2"
  local q="p64=$(b64u "$Q")"
  [ -n "${3:-}" ] && q="$q&mode=$3"
  curl -sS --fail-with-body -H 'Content-Type: application/octet-stream' -T "$1" "$BOX_URL/fs/$H?$q"
}

cmd_get() {
  [ $# -ge 1 ] || die "usage: box get [HOST:]REMOTE [LOCAL|-]"
  split "$1"
  local out="${2:-$(basename "$Q")}" url="$BOX_URL/fs/$H?p64=$(b64u "$Q")"
  if [ "$out" = - ]; then curl -sS --fail "$url"; return; fi
  [ -d "$out" ] && out="$out/$(basename "$Q")"
  curl -sS --fail -o "$out.part.$$" "$url" || { rm -f "$out.part.$$"; exit 1; }
  mv -f "$out.part.$$" "$out"
  echo "got $(wc -c < "$out" | tr -d ' ') bytes -> $out"
}

cmd_push() {
  [ $# -ge 2 ] || die "usage: box push LOCALDIR [HOST:]REMOTEDIR [-x PATTERN]..."
  local src="$1" dst="$2" ex=()
  shift 2
  while [ $# -gt 0 ]; do case "$1" in -x) ex+=("--exclude=$2"); shift 2 ;; *) die "push: unknown argument $1" ;; esac; done
  [ -d "$src" ] || die "no such directory: $src"
  split "$dst"
  tar -C "$src" "${ex[@]}" -czf - . | curl -sS --fail-with-body -H 'Content-Type: application/gzip' -T - "$BOX_URL/tar/$H?p64=$(b64u "$Q")"
}

cmd_pull() {
  [ $# -ge 2 ] || die "usage: box pull [HOST:]REMOTEDIR LOCALDIR [-x PATTERN]..."
  local src="$1" dst="$2" q=""
  shift 2
  while [ $# -gt 0 ]; do case "$1" in -x) q="$q&x64=$(b64u "$2")"; shift 2 ;; *) die "pull: unknown argument $1" ;; esac; done
  split "$src"
  mkdir -p "$dst" || die "cannot create $dst"
  curl -sS --fail "$BOX_URL/tar/$H?p64=$(b64u "$Q")$q" | tar -C "$dst" -xzf - || exit 1
  echo "pulled $H:$Q -> $dst ($(find "$dst" -type f | wc -l | tr -d ' ') files)"
}

rpc() { curl -sS --fail-with-body -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary @"$1" "$BOX_URL/mcp" | sed -n 's/^data: //p'; }

cmd_call() {
  [ $# -ge 1 ] || die "usage: box call TOOL [JSON]"
  local args="${2:-}"
  [ -n "$args" ] || args='{}'
  mktmp
  { printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s","arguments":' "$1"; printf %s "$args"; printf '}}'; } > "$T/req"
  if command -v jq >/dev/null 2>&1; then
    rpc "$T/req" | jq -r 'if .error then "RPC ERROR: " + .error.message else ((if .result.isError then "[isError] " else "" end) + ([.result.content[] | select(.type == "text") | .text] | join(""))) end'
  elif command -v python3 >/dev/null 2>&1; then
    rpc "$T/req" | python3 -c 'import json,sys
j=json.load(sys.stdin)
print("RPC ERROR: "+j["error"]["message"] if "error" in j else ("[isError] " if j["result"].get("isError") else "")+"".join(c.get("text","") for c in j["result"]["content"] if c.get("type")=="text"))'
  else
    rpc "$T/req"
  fi
}

cmd_tools() {
  mktmp
  echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' > "$T/req"
  rpc "$T/req" | grep -o '"name":"[A-Za-z0-9_]*"' | cut -d'"' -f4 | tr '\n' ' '
  echo
}

cmd_install() {
  local d
  for d in /usr/local/bin "$HOME/.local/bin" "$HOME/bin"; do
    if mkdir -p "$d" 2>/dev/null && cp "$0" "$d/box" 2>/dev/null && chmod +x "$d/box"; then
      echo "installed $d/box (version $VERSION) -> $(printf %s "$BOX_URL" | sed -E 's#/b/[^/]+#/b/<token>#')"
      case ":$PATH:" in *":$d:"*) ;; *) echo "note: $d is not on PATH; call $d/box" ;; esac
      return 0
    fi
  done
  die "no writable directory for the box command"
}

case "${1:-}" in
  exec | put | get | push | pull | call | tools | install) c="$1"; shift; "cmd_$c" "$@" ;;
  --version | -V) echo "box $VERSION" ;;
  *) usage ;;
esac
