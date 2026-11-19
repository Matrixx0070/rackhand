#!/bin/bash
# rehearse.sh [all|setup|R|A|S|O|B|cleanup]
# Full rehearsal of deploy.sh against a throwaway copy of the connector as it is in production RIGHT NOW:
# the live server.ts, a copy of the live unit file (for an install older than install.sh: the old unit shape,
# with the keep-workloads drop-in when production has it), its own port and directory, and dummy workloads
# started through the old connector.
# The new build is /opt/ssh-mcp/server.new.ts (LIVE=... for another install path). The live ssh-mcp.service and its processes are never touched.
#   R  failed deploy from the current state   -> must roll back file (and unit), workloads alive
#   A  good deploy                            -> the new tool list, same command environment, workloads alive
#   S  plain restart, then a crash (kill -9)  -> workloads alive both times
#   O  out-of-memory kill inside the unit     -> only the hog dies, unit and workloads carry on
#   B  failed deploy on top of the new build  -> rolls back to the new build, workloads alive
set -u
R=/tmp/ssh-mcp-rehearsal; SVC=ssh-mcp-rehearsal; PORT=8789
UNITF=/etc/systemd/system/$SVC.service; DROPIN=$UNITF.d/10-keep-workloads.conf
CG=/sys/fs/cgroup/system.slice/$SVC.service
LIVE=${LIVE:-/opt/ssh-mcp}                 # the live install this rehearsal copies from
LIVEUNIT=/etc/systemd/system/ssh-mcp.service
PRODFIX=$LIVEUNIT.d/10-keep-workloads.conf
# A unit made by install.sh already keeps workloads alive (KillMode=process is in the unit itself), so the deploy
# has no unit to fix; an older one gets the fix (UNITFIX=1), as its first real deploy would.
if grep -qs '^KillMode=process' $LIVEUNIT; then FIX=0; else FIX=1; fi
TO=$(sed -n 's/^EXPECT=\${EXPECT:-"\(.*\)"}$/\1/p' $LIVE/upgrade/deploy.sh | wc -w)     # tools the new build must have
PATS=('sleep 8001' 'sleep 8002' 'while :; do sleep 0.4' 'sleep 8003')
part=${1:-all}
H=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')

names() { curl -s -m 5 "${H[@]}" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' $U | grep -o '"name":"[a-z_]*"' | wc -l; }
waitfor() { for i in $(seq 1 80); do [ "$(names)" = "$1" ] && return 0; sleep 0.5; done; echo "   (timed out waiting for $1 tools, have $(names))"; return 1; }
call() { # <tool> <json-arguments> -> the result text
  curl -s -m 120 "${H[@]}" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" $U \
    | sed -n 's/^data: //p' \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);console.log(j.error?("RPC ERROR: "+j.error.message):((j.result.isError?"[isError] ":"")+j.result.content.map(c=>c.text).join("")))})'
}
sshexec() { call ssh_exec "{\"host\":\"local\",\"command\":$1}" >/dev/null; }
deploy() { # <tag> [UNITFIX]
  systemd-run --quiet --unit=$SVC-deploy-$1 --collect --wait -E SVC=$SVC -E PORT=$PORT -E APP=$R -E ENVF=$R/env -E LOGDIR=$R/log -E UNITFIX=${2:-0} \
    /bin/bash $LIVE/upgrade/deploy.sh "$(sha256sum $R/server.new.ts | cut -d' ' -f1)"
  echo "deploy.sh exit: $?"; cut -c1-190 $R/log/deploy-latest.log | grep -v "Found left-over process"
}
mainpid() { systemctl show -p MainPID --value $SVC; }
unit() {
  echo "   unit: $(systemctl is-active $SVC), main pid $(mainpid), KillMode=$(systemctl show -p KillMode --value $SVC), OOMPolicy=$(systemctl show -p OOMPolicy --value $SVC), drop-in $([ -e $DROPIN ] && echo present || echo absent), tools $(names)"
  echo "   main process: $(tr '\0' ' ' < /proc/$(mainpid)/cmdline 2>/dev/null | cut -c1-90)"
}
workloads() {
  local alive=0 p
  for pat in "${PATS[@]}"; do
    p=$(pgrep -f "$pat" | head -1); [ -n "$p" ] && alive=$((alive+1))
    echo "   [$pat] pid ${p:-NONE} $([ -n "$p" ] && cut -d: -f3 /proc/$p/cgroup)"
  done
  echo "   WORKLOADS ALIVE: $alive/${#PATS[@]}"
}
envsnap() { call ssh_exec '{"host":"local","command":"echo HOME=$HOME; echo PATH=$PATH | tr : \"\\n\" | while read d; do [ -d \"${d#PATH=}\" ] && echo \"dir ${d#PATH=}\"; done; for c in node npm npx tsx tsc python3 git; do echo \"$c -> $(command -v $c)\"; done; echo cwd=$PWD; echo user=$(id -un); cd ~ && echo home-ok=$PWD"}' | sed -n '/--- stdout ---/,/--- stderr ---/p' | grep -v '^---'; }
cleanup() {
  systemctl stop $SVC 2>/dev/null
  for p in $(cat $CG/cgroup.procs 2>/dev/null); do kill -9 "$p" 2>/dev/null; done      # only this throwaway unit's cgroup
  [ -s $R/job.id ] && systemctl stop "ssh-mcp-job-$(cat $R/job.id).scope" 2>/dev/null
  for s in $(systemctl list-units --all --no-legend --plain "$SVC-workloads-*" 2>/dev/null | awk '{print $1}'); do systemctl stop "$s"; done
  tmux -L rehearsal kill-server 2>/dev/null
  pkill -f 'sleep 8001'; pkill -f 'sleep 8002'; pkill -f 'sleep 8003'; pkill -f 'while :; do sleep 0.4'
  rm -rf "$UNITF" "$UNITF.d"; systemctl daemon-reload; systemctl reset-failed $SVC 2>/dev/null
  rm -rf $R
}

if [ "$part" = all ] || [ "$part" = setup ]; then
  cleanup >/dev/null 2>&1
  ss -ltnH "sport = :$PORT" | grep -q . && { echo "port $PORT is in use - not starting the rehearsal"; exit 1; }
  mkdir -p $R/log
  cp $LIVE/server.ts $LIVE/package.json $LIVE/box.sh $R/      # the live file ...
  [ -f $LIVE/tunnel.sh ] && cp $LIVE/tunnel.sh $R/                          # (1.8: the script add_host's tunnel links serve)
  cp $LIVE/server.new.ts $R/server.good.ts                                  # ... and the new build
  ln -s $LIVE/node_modules $R/node_modules
  echo '{ "local": { "local": true } }' > $R/hosts.json
  echo "MCP_SECRET=$(openssl rand -hex 32)" > $R/env; chmod 600 $R/env             # throwaway secret
  printf 'import time\nb = []\nfor i in range(400):\n    b.append(b"x" * (8 << 20))\n    time.sleep(0.01)\nprint("allocated", len(b) * 8, "MB")\n' > $R/hog.py
  if [ "$FIX" = 0 ]; then    # the live unit itself, pointed at the rehearsal's folder, port, secret and state
    LIVEAPP=$(sed -n 's/^WorkingDirectory=//p' $LIVEUNIT | head -1)
    sed -e "s#${LIVEAPP:-/opt/ssh-mcp}#$R#g" -e "s#^Description=.*#Description=Rackhand connector (rehearsal copy - safe to delete)#" \
        -e "s#^EnvironmentFile=.*#EnvironmentFile=$R/env#" -e "s#^Environment=PORT=.*#Environment=PORT=$PORT#" \
        -e "s#^Environment=JOBS_DIR=.*#Environment=JOBS_DIR=$R/jobs#" $LIVEUNIT > $UNITF
  else
    cat > $UNITF <<EOF
[Unit]
Description=Rackhand connector (rehearsal copy - safe to delete)
After=network.target
[Service]
WorkingDirectory=$R
EnvironmentFile=$R/env
Environment=HOSTS_FILE=$R/hosts.json
Environment=PORT=$PORT
Environment=JOBS_DIR=$R/jobs
ExecStart=/usr/local/bin/npx tsx server.ts
Restart=always
Environment=PATH=/usr/local/bin:/usr/bin:/bin
EOF
    if [ -e $PRODFIX ]; then mkdir -p $UNITF.d; sed "s#$LIVE#$R#g" $PRODFIX > $DROPIN; fi      # same unit fix as production
  fi
  systemctl daemon-reload; systemctl start $SVC
fi
. $R/env
U=http://127.0.0.1:$PORT/mcp/$MCP_SECRET

if [ "$part" = all ] || [ "$part" = setup ]; then
  for i in $(seq 1 80); do [ "$(names)" -gt 0 ] && break; sleep 0.5; done
  names > $R/from
  echo "== setup: rehearsal connector (same unit shape as production) on :$PORT; new build must have $TO tools"; unit
  # workloads started THROUGH the old connector, like the real ones: a daemon, a tmux, a busy forker, a background job
  sshexec '"nohup setsid sleep 8001 >/dev/null 2>&1 &"'
  sshexec '"tmux -L rehearsal new-session -d -s r8002 \"sleep 8002\""'
  sshexec '"nohup setsid bash -c \"while :; do sleep 0.4 & sleep 0.15; done\" >/dev/null 2>&1 &"'
  call ssh_spawn '{"host":"local","command":"sleep 8003"}' | sed -n 's/^jobId: //p' > $R/job.id
  sleep 62        # let them count as long-running (>60s), like the real workloads
  echo "   processes in the rehearsal unit: $(wc -l < $CG/cgroup.procs)"; workloads
  envsnap > $R/log/env-before.txt
fi

FROM=$(cat $R/from 2>/dev/null)
if [ "$part" = all ] || [ "$part" = R ]; then
  echo; echo "== R. failed deploy from the current state (a build that crashes at startup, UNITFIX=$FIX)"
  printf 'throw new Error("rehearsal: broken build");\n' > $R/server.new.ts
  deploy r $FIX
  echo "   expect: $FROM tools again, unit exactly as at setup, 4/4 alive"; unit; workloads
fi

if [ "$part" = all ] || [ "$part" = A ]; then
  echo; echo "== A. good deploy of the new build (UNITFIX=$FIX)"
  cp $R/server.good.ts $R/server.new.ts
  deploy a $FIX
  echo "   expect: $TO tools, KillMode=process, OOMPolicy=continue, $([ $FIX = 1 ] && echo "drop-in present" || echo "no drop-in needed"), node start, 4/4 alive"; unit; workloads
  echo "   a batch through the new build:"; call batch "{\"host\":\"local\",\"cwd\":\"$R\",\"ops\":[{\"write\":{\"file_path\":\"$R/b.txt\",\"content\":\"one\\n\"}},{\"edit\":{\"file_path\":\"$R/b.txt\",\"old_string\":\"one\",\"new_string\":\"two\"}},{\"bash\":{\"command\":\"cat b.txt; false\"}},{\"bash\":{\"command\":\"echo never\"}}]}" | grep '^===' | sed 's/^/      /'
  envsnap > $R/log/env-after.txt
  if diff $R/log/env-before.txt $R/log/env-after.txt >/dev/null; then echo "   command environment before/after: IDENTICAL"; sed 's/^/      /' $R/log/env-after.txt
  else echo "   command environment CHANGED:"; diff $R/log/env-before.txt $R/log/env-after.txt | sed 's/^/      /'; fi
  [ -e $DROPIN ] && { echo "   drop-in:"; grep -v '^#' $DROPIN | sed 's/^/      /'; }
fi

if [ "$part" = all ] || [ "$part" = S ]; then
  echo; echo "== S. plain 'systemctl restart', then a crash of the connector (kill -9)"
  m=$(mainpid); systemctl restart $SVC; waitfor $TO
  echo "   after restart (main $m -> $(mainpid)):"; workloads
  m=$(mainpid); kill -9 "$m"; sleep 1; waitfor $TO
  echo "   after kill -9 of pid $m (auto-restarted as $(mainpid), NRestarts=$(systemctl show -p NRestarts --value $SVC)):"; workloads
fi

if [ "$part" = all ] || [ "$part" = O ]; then
  echo; echo "== O. out-of-memory kill inside the unit (memory capped at 350M for this test, hog started through the connector)"
  m=$(mainpid); k0=$(sed -n 's/^oom_kill //p' $CG/memory.events)
  systemctl set-property --runtime $SVC MemoryMax=350M MemorySwapMax=0
  echo "   hog: $(call bash "{\"host\":\"local\",\"command\":\"python3 $R/hog.py\",\"timeout\":90000}" | tr '\n' ' ' | cut -c1-160)"
  sleep 2
  echo "   kernel OOM kills in this unit: $k0 -> $(sed -n 's/^oom_kill //p' $CG/memory.events); systemd: $(journalctl -u $SVC --since '-2min' --no-pager -o cat | grep -i 'oom' | tail -1 | cut -c1-120)"
  echo "   expect: unit still active with the same main pid ($m), 4/4 alive"; unit; workloads
  systemctl set-property --runtime $SVC MemoryMax=infinity MemorySwapMax=infinity
fi

if [ "$part" = all ] || [ "$part" = B ]; then
  echo; echo "== B. failed deploy on top of the new build"
  printf 'throw new Error("rehearsal: broken build");\n' > $R/server.new.ts
  deploy b $FIX
  echo "   expect: $TO tools (the good new build is back), unit as after A, 4/4 alive"; unit; workloads
fi

if [ "$part" = all ] || [ "$part" = cleanup ]; then
  echo; echo "== cleanup"
  cleanup
  echo "rehearsal leftovers: units $(systemctl list-units --all --no-legend "$SVC*" | wc -l), unit file $([ -e $UNITF ] && echo exists || echo removed), processes $(pgrep -f 'sleep 800[1-3]|while :; do sleep 0.4' | wc -l), dir $([ -e $R ] && echo exists || echo removed)"
  echo "live connector: $(systemctl is-active ssh-mcp), main pid $(systemctl show -p MainPID --value ssh-mcp), KillMode=$(systemctl show -p KillMode --value ssh-mcp), processes in its cgroup: $(wc -l < /sys/fs/cgroup/system.slice/ssh-mcp.service/cgroup.procs)"
fi
