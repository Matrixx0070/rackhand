#!/bin/bash
# deploy.sh <sha256-of-server.new.ts> [--dry-run]
#
# Safe swap + restart of the connector, to be run DETACHED from the service (systemd-run), never inside it.
#   1. UNITFIX=1 (first run only): install a unit drop-in so that a restart, a crash or an OOM kill of the
#      connector never again takes down what was started through it:
#        KillMode=process     stop/restart signals only the connector, not everything in its cgroup
#        OOMPolicy=continue   one OOM-killed process does not make systemd stop the whole unit
#        ExecStart=node ...   the connector itself is the main process (no npm/sh wrappers in between);
#                             HOME and PATH are pinned to what npm used to provide, so commands run through
#                             the connector see the same environment as before
#   2. If the unit still has KillMode=control-group, move every process that is not the connector itself
#      into its own scope first (with OOMPolicy=continue).
#   3. Swap server.new.ts into place, stop, make sure the old listener is gone, start.
#   4. Roll back automatically (file and drop-in) unless tools/list answers with the expected tools and,
#      when the new server has them, a two-step batch call runs and a bridge URL serves the box client
#      and runs a command.
# Env overrides (SVC PORT APP ENVF LOGDIR) exist so the whole script can be rehearsed on a throwaway copy.
set -u
SVC=${SVC:-ssh-mcp}; PORT=${PORT:-8787}; APP=${APP:-/opt/ssh-mcp}; ENVF=${ENVF:-/etc/ssh-mcp.env}
LOGDIR=${LOGDIR:-/opt/ssh-mcp/upgrade}; UNITFIX=${UNITFIX:-0}
EXPECT=${EXPECT:-"bash batch bridge edit exec_code list_hosts read sftp_list sftp_read sftp_write ssh_exec ssh_exec_many ssh_job ssh_jobs ssh_spawn write"}
NODE=${NODE:-/usr/local/bin/node}
DROPDIR=/etc/systemd/system/$SVC.service.d; DROPIN=$DROPDIR/10-keep-workloads.conf
cd "$APP"
SHA=${1:?sha256 of server.new.ts}; DRY=${2:-}
TS=$(date -u +%Y%m%d-%H%M%S)
LOG=$LOGDIR/deploy-$SVC-$TS${DRY:+-dryrun}.log
ln -sfn "$LOG" "$LOGDIR/deploy-latest.log"
exec >"$LOG" 2>&1
. "$ENVF"
U=http://127.0.0.1:$PORT/mcp/$MCP_SECRET
CG=/sys/fs/cgroup/system.slice/$SVC.service
SCOPE=$SVC-workloads-$TS.scope
SCG=/sys/fs/cgroup/system.slice/$SCOPE
BAK=server.ts.bak-$TS
wrote_dropin=0

say() { echo "$(date -u +%T) $*"; }
abort() {
  if [ "${wrote_dropin:-0}" = 1 ]; then rm -f "$DROPIN"; rmdir "$DROPDIR" 2>/dev/null; systemctl daemon-reload; fi
  say "RESULT: ABORTED ($*) - server.ts and the unit are untouched, $SVC not restarted"; exit 1
}
cmd() { cat /proc/$1/cmdline 2>/dev/null | tr '\0\n' '  ' | cut -c1-110; }
age() { ps -o etimes= -p "$1" 2>/dev/null | tr -d ' '; }
tools() {
  curl -s -m 5 -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' "$U" 2>/dev/null \
    | grep -o '"name":"[a-z_]*"' | sed 's/"name":"//;s/"//' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//'
}
listener() { ss -ltnpH "sport = :$PORT" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2; }
killmode() { systemctl show -p KillMode --value "$SVC"; }
incg() { grep -qs "/$SVC.service\$" "/proc/$1/cgroup"; }      # is this pid (still) a process of our unit?
smoke() {   # real calls against the new server: a batch, then the bridge end to end
  local b cli out
  case " $EXPECT " in *" batch "*)
    out=$(curl -s -m 20 -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
          -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"batch","arguments":{"host":"local","ops":[{"bash":{"command":"echo smoke-a"}},{"bash":{"command":"echo smoke-b"}}]}}}' "$U" 2>/dev/null)
    case "$out" in *"smoke-a"*"smoke-b"*"batch: 2 ok, 0 failed, 0 skipped"*) say "smoke: batch ok (2 steps in one call)";;
      *) say "smoke: batch call failed: $(echo "$out" | tail -c 200 | tr '\n' ' ')"; return 1;; esac;;
  esac
  case " $EXPECT " in *" bridge "*) ;; *) return 0;; esac
  b=$(curl -s -m 10 -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
        -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bridge","arguments":{"ttl_hours":1}}}' "$U" 2>/dev/null \
      | grep -o 'http://127\.0\.0\.1:[0-9]*/b/[0-9a-z]*\.[0-9a-f]*' | head -1)
  [ -n "$b" ] || { say "smoke: the bridge tool returned no URL"; return 1; }
  cli=$(curl -s -m 10 "$b/cli" | head -c 4000)
  case "$cli" in "#!/usr/bin/env bash"*"$b"*) ;; *) say "smoke: $b/cli did not serve the box client"; return 1;; esac
  out=$(curl -s -m 20 -D - -H 'Content-Type: text/plain' --data-binary 'echo smoke-$((40+2))' "$b/exec/local" | tr -d '\r')
  case "$out" in *"X-Exit-Code: 0"*"smoke-42"*) say "smoke: bridge ok (client served, command ran)"; return 0;; esac
  say "smoke: exec through the bridge failed: $(echo "$out" | tail -3 | tr '\n' ' ')"; return 1
}

BEFORE=$(tools)
say "start${DRY:+ (dry run)} for $SVC on :$PORT in $APP (UNITFIX=$UNITFIX); tools before: [$BEFORE]"
[ -f server.new.ts ] || abort "no server.new.ts"
[ "$(sha256sum server.new.ts | cut -d' ' -f1)" = "$SHA" ] || abort "server.new.ts checksum mismatch"
[ -r "$CG/cgroup.procs" ] || abort "no cgroup $CG"
[ -x "$NODE" ] || abort "no node at $NODE"
case " $EXPECT " in *" bridge "*) [ -s box.sh ] || abort "no box.sh next to server.ts (the bridge serves it)";; esac
case "$(cat /proc/$$/cgroup)" in *"/$SVC.service"*) abort "running inside $SVC.service";; esac
[ -z "$DRY" ] && sleep 2      # let the call that launched us return first

# --- the connector's own process chain: whoever listens on the port, up to the unit's main PID
M=$(systemctl show -p MainPID --value "$SVC"); PORTPID=$(listener)
[ -n "$M" ] && [ "$M" != 0 ] && [ -n "$PORTPID" ] || abort "cannot find main pid ($M) or listener ($PORTPID)"
KEEP=""; p=$PORTPID
for i in 1 2 3 4 5 6; do
  KEEP="$KEEP $p"
  [ "$p" = "$M" ] && break
  p=$(ps -o ppid= -p "$p" | tr -d ' ')
  [ -n "$p" ] && [ "$p" != 1 ] || break
done
[ "$p" = "$M" ] || abort "listener $PORTPID is not a descendant of main pid $M (chain:$KEEP)"
say "connector processes (will be replaced):"
for q in $KEEP; do echo "     $q $(cmd $q)"; done
others() {
  for q in $(cat $CG/cgroup.procs 2>/dev/null); do
    case " $KEEP " in *" $q "*) continue;; esac
    [ "$(awk '/^State:/{print $2}' /proc/$q/status 2>/dev/null)" = Z ] && continue
    [ -d /proc/$q ] && echo $q
  done
}
MOVE=$(others | tr '\n' ' '); n=$(echo $MOVE | wc -w)
say "other processes inside $SVC.service (started through the connector): $n; unit has KillMode=$(killmode) OOMPolicy=$(systemctl show -p OOMPolicy --value "$SVC")"
for q in $MOVE; do echo "     $q [$(ps -o etime= -p $q 2>/dev/null | tr -d ' ')] $(cmd $q)"; done
if [ -n "$DRY" ]; then say "RESULT: DRY RUN ONLY - nothing changed"; exit 0; fi

# --- 1. unit drop-in
if [ "$UNITFIX" = 1 ] && [ -e "$DROPIN" ]; then
  say "drop-in already present, leaving it alone: KillMode=$(killmode) OOMPolicy=$(systemctl show -p OOMPolicy --value "$SVC")"
elif [ "$UNITFIX" = 1 ]; then
  # npm (the old "npx tsx" start) gave the connector a HOME and put node_modules/.bin on PATH; keep both.
  CUR_HOME=$(tr '\0' '\n' < "/proc/$PORTPID/environ" 2>/dev/null | sed -n 's/^HOME=//p' | head -1)
  [ -n "$CUR_HOME" ] || CUR_HOME=$(getent passwd "$(ps -o uid= -p "$PORTPID" | tr -d ' ')" | cut -d: -f6)
  UNIT_PATH=$(systemctl show -p Environment --value "$SVC" | tr ' ' '\n' | sed -n 's/^PATH=//p' | tail -1)
  mkdir -p "$DROPDIR"
  cat > "$DROPIN" <<UNIT
# Written by /opt/ssh-mcp/upgrade/deploy.sh on $TS. Remove this file + "systemctl daemon-reload" to undo.
# Stopping, restarting or an out-of-memory kill of the connector no longer takes down what was started through it.
[Service]
ExecStart=
ExecStart=$NODE --import tsx server.ts
Environment="HOME=${CUR_HOME:-/root}"
Environment="PATH=$APP/node_modules/.bin:${UNIT_PATH:-/usr/local/bin:/usr/bin:/bin}"
KillMode=process
OOMPolicy=continue
UNIT
  wrote_dropin=1
  systemctl daemon-reload
  say "drop-in installed: KillMode=$(killmode) OOMPolicy=$(systemctl show -p OOMPolicy --value "$SVC")"
fi

# --- 2. only needed while the unit still kills its whole cgroup on stop
declare -A CMD; LONG=""
if [ "$(killmode)" = control-group ] && [ "$n" -gt 0 ]; then
  ok=0
  for try in 1 2 3 4; do
    STABLE=""; for q in $(others); do a=$(age $q); [ -n "$a" ] && [ "$a" -gt 15 ] && STABLE="$STABLE $q"; done
    ns=$(echo $STABLE | wc -w)
    [ "$ns" -eq 0 ] && break
    out=$(busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
           StartTransientUnit 'ssa(sv)a(sa(sv))' "$SCOPE" fail 3 PIDs au $ns $STABLE OOMPolicy s continue \
           Description s "Workloads started through $SVC before its upgrade" 0 2>&1) && { ok=1; say "adopted $ns long-lived processes into $SCOPE"; break; }
    say "adopt attempt $try failed: $out"
  done
  PH=""
  if [ "$ok" != 1 ]; then
    systemd-run --scope --quiet -p OOMPolicy=continue --unit="${SCOPE%.scope}" sleep 86400 </dev/null >/dev/null 2>&1 &
    PH=$!; sleep 1
  fi
  sleep 0.3
  [ -d "$SCG" ] || abort "could not create $SCOPE"
  clean=0
  for round in $(seq 1 200); do
    S=$(others)
    if [ -z "$S" ]; then clean=$((clean+1)); [ "$clean" -ge 3 ] && break; sleep 0.1; continue; fi
    clean=0
    for q in $S; do echo "$q" > "$SCG/cgroup.procs" 2>/dev/null; done
  done
  [ -n "$PH" ] && kill "$PH" 2>/dev/null
  left=$(others | tr '\n' ' ')
  [ -z "$left" ] || abort "service cgroup still holds foreign processes: $left"
  say "moved out of the service: $(wc -l < $SCG/cgroup.procs) processes (scope OOMPolicy=$(systemctl show -p OOMPolicy --value "$SCOPE"))"
fi
# whatever was started through the connector and is older than a minute must survive the restart
for q in $MOVE; do [ -d /proc/$q ] || continue; a=$(age $q); if [ -n "$a" ] && [ "$a" -gt 60 ]; then LONG="$LONG $q"; CMD[$q]=$(cmd $q); fi; done

# --- 3. swap + restart
stop_connector() {      # stop the unit and make sure nothing of the old connector still holds the port
  systemctl stop "$SVC"
  for q in $KEEP $(listener); do incg "$q" && kill -TERM "$q" 2>/dev/null; done
  for i in $(seq 1 50); do [ -z "$(listener)" ] && break; sleep 0.1; done
  for q in $KEEP $(listener); do incg "$q" && kill -KILL "$q" 2>/dev/null; done
  for i in $(seq 1 30); do [ -z "$(listener)" ] && break; sleep 0.1; done
  systemctl reset-failed "$SVC" 2>/dev/null
  [ -z "$(listener)" ] || say "WARNING: port $PORT is still held by pid $(listener) ($(cmd "$(listener)"))"
}
cp -p server.ts "$BAK"
cp -p server.new.ts server.ts.next && mv -f server.ts.next server.ts      # atomic replace
say "restarting $SVC (old main pid $M)"
stop_connector
systemctl start "$SVC"
ok=0; r0=$(systemctl show -p NRestarts --value "$SVC")
for i in $(seq 1 30); do
  sleep 2
  got=$(tools); say "try $i: [$got]"
  if [ "$got" = "$EXPECT" ]; then smoke && ok=1; break; fi
  r=$(systemctl show -p NRestarts --value "$SVC")
  if systemctl is-failed --quiet "$SVC" || [ $(( ${r:-0} - ${r0:-0} )) -ge 3 ]; then say "service is crash-looping (auto-restarts $r0 -> $r), not waiting further"; break; fi
done
survivors() {
  dead=0
  for q in $LONG; do kill -0 $q 2>/dev/null || { dead=$((dead+1)); say "DIED: $q ${CMD[$q]:-?}"; }; done
  say "long-running processes started through the connector: $(echo $LONG | wc -w) before the restart, $dead died"
}
if [ "$ok" = 1 ]; then
  rm -f server.new.ts
  survivors
  say "unit now: KillMode=$(killmode) OOMPolicy=$(systemctl show -p OOMPolicy --value "$SVC") main=$(cmd "$(systemctl show -p MainPID --value "$SVC")" | cut -c1-60)"
  say "backup of the old file: $APP/$BAK"
  say "RESULT: OK ($(echo $EXPECT | wc -w) tools live, new main pid $(systemctl show -p MainPID --value "$SVC"))"
  exit 0
fi
say "new server did not pass the checks -> rolling back"
journalctl -u "$SVC" -n 15 --no-pager
# Order matters: stop the failed instance while the drop-in (KillMode=process) is still in force, so the
# workloads that stayed inside the unit are not swept away with it; only then restore the file and the unit.
KEEP="$(systemctl show -p MainPID --value "$SVC" | grep -v '^0$')"
stop_connector
cp -p "$BAK" server.ts.next && mv -f server.ts.next server.ts
if [ "$wrote_dropin" = 1 ]; then rm -f "$DROPIN"; rmdir "$DROPDIR" 2>/dev/null; systemctl daemon-reload; say "drop-in removed: KillMode=$(killmode)"; fi
systemctl start "$SVC"
got=""
for i in $(seq 1 30); do sleep 2; got=$(tools); say "rollback try $i: [$got]"; [ -n "$got" ] && break; done
survivors
say "RESULT: ROLLED BACK to the previous server.ts ([$got])"
exit 1
