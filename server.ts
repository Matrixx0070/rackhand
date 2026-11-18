// SSH connector as a remote MCP server.
// Claude -> HTTPS -> this server (on your VPS) -> SSH/SFTP -> any host in hosts.json
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { Client, type ConnectConfig } from "ssh2";
import { exec, spawn } from "node:child_process";
import { readFileSync, promises as fs } from "node:fs";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { dirname } from "node:path";
import { PassThrough, Transform, type Readable, type Writable } from "node:stream";

const PORT = Number(process.env.PORT ?? 8787);
const SECRET = process.env.MCP_SECRET ?? "";
const HOSTS_FILE = process.env.HOSTS_FILE ?? "./hosts.json";
const MAX_OUT = 100_000;
const JOBS_DIR = process.env.JOBS_DIR ?? "/var/lib/ssh-mcp/jobs"; // ssh_spawn: <jobId>.log / .exit / .pid / .cmd / .sh
const MAX_PAYLOAD = 64 * 1024; // bytes of command/code sent inline (base64) in one shell argument
const VERSION = "1.3.0";
// Sent to the client at initialize; clients put it in front of the model. Keep it short: it costs tokens in every conversation.
const INSTRUCTIONS = `Remote shell and files on the hosts from list_hosts ("local" = the machine this connector runs on).
Every tool call is a round trip, so do as much as possible per call:
- batch: several bash / read / write / edit steps in ONE call, in order, stopping at the first failure. Prefer it for any multi-step work (change files, then build or test, then look at the result).
- read / write / edit take \`files\` / \`edits\` arrays: many files in one call.
- ssh_exec_many: up to 10 independent commands at the same time.
- bash: join steps with && or newlines instead of separate calls; pass quiet: true when only success or failure matters (the full output stays in a file on the host); use run_in_background plus ssh_job (wait) for anything that takes more than a minute.
- bridge: large, binary or many files, moved directly from a sandbox shell.
bash starts in the home directory unless cwd or a session is given.`;

if (SECRET.length < 32) throw new Error("Set MCP_SECRET (>=32 random chars)");

type HostCfg = {
  local?: boolean;
  host?: string;
  port?: number;
  username?: string;
  privateKeyPath?: string;
  passphraseEnv?: string;
  passwordEnv?: string;
  hostFingerprint?: string; // "SHA256:..." from ssh-keygen -lf
};

const loadHosts = (): Record<string, HostCfg> => JSON.parse(readFileSync(HOSTS_FILE, "utf8"));
const trunc = (s: string, max = MAX_OUT) => (s.length > max ? s.slice(0, max) + `\n…[truncated ${s.length - max} chars]` : s);

function getHost(name: string): HostCfg {
  const cfg = loadHosts()[name];
  if (!cfg) throw new Error(`Unknown host "${name}". Known: ${Object.keys(loadHosts()).join(", ")}`);
  return cfg;
}

function connect(cfg: HostCfg): Promise<Client> {
  const opts: ConnectConfig = {
    host: cfg.host,
    port: cfg.port ?? 22,
    username: cfg.username,
    readyTimeout: 15_000,
    keepaliveInterval: 10_000,
  };
  if (cfg.privateKeyPath) opts.privateKey = readFileSync(cfg.privateKeyPath);
  if (cfg.passphraseEnv) opts.passphrase = process.env[cfg.passphraseEnv];
  if (cfg.passwordEnv) opts.password = process.env[cfg.passwordEnv];
  if (cfg.hostFingerprint) {
    const want = cfg.hostFingerprint.replace(/^SHA256:/, "").replace(/=+$/, "");
    opts.hostVerifier = (key: Buffer) =>
      createHash("sha256").update(key).digest("base64").replace(/=+$/, "") === want;
  }
  return new Promise((resolve, reject) => {
    const c = new Client();
    c.on("ready", () => resolve(c)).on("error", reject).connect(opts);
  });
}

type ExecResult = { code: number | null; stdout: string; stderr: string };

async function runCommand(name: string, command: string, timeoutSec: number): Promise<ExecResult> {
  const cfg = getHost(name);
  if (cfg.local) {
    return new Promise((resolve) => {
      exec(command, { timeout: timeoutSec * 1000, maxBuffer: 10 * 1024 * 1024, shell: "/bin/bash" },
        (err, stdout, stderr) => resolve({ code: err ? (typeof err.code === "number" ? err.code : 1) : 0, stdout, stderr }));
    });
  }
  const conn = await connect(cfg);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { conn.end(); reject(new Error(`Timed out after ${timeoutSec}s`)); }, timeoutSec * 1000);
    conn.exec(command, (err, stream) => {
      if (err) { clearTimeout(timer); conn.end(); return reject(err); }
      let stdout = "", stderr = "";
      stream.on("data", (d: Buffer) => (stdout += d));
      stream.stderr.on("data", (d: Buffer) => (stderr += d));
      stream.on("close", (code: number | null) => { clearTimeout(timer); conn.end(); resolve({ code, stdout, stderr }); });
    });
  });
}

async function withSftp<T>(name: string, fn: (sftp: import("ssh2").SFTPWrapper) => Promise<T>): Promise<T> {
  const conn = await connect(getHost(name));
  try {
    const sftp = await new Promise<import("ssh2").SFTPWrapper>((res, rej) => conn.sftp((e, s) => (e ? rej(e) : res(s))));
    return await fn(sftp);
  } finally {
    conn.end();
  }
}

async function readRemote(name: string, path: string): Promise<Buffer> {
  if (getHost(name).local) return fs.readFile(path);
  return withSftp(name, (s) => new Promise((res, rej) => s.readFile(path, (e, d) => (e ? rej(e) : res(d)))));
}

async function writeRemote(name: string, path: string, data: Buffer, mode?: number): Promise<void> {
  if (getHost(name).local) return fs.writeFile(path, data, mode ? { mode } : undefined);
  return withSftp(name, (s) => new Promise((res, rej) => s.writeFile(path, data, mode ? { mode } : {}, (e) => (e ? rej(e) : res()))));
}

async function listRemote(name: string, path: string): Promise<string> {
  if (getHost(name).local) {
    const r = await runCommand(name, `ls -la -- ${JSON.stringify(path)}`, 30);
    return r.stdout || r.stderr;
  }
  return withSftp(name, (s) => new Promise((res, rej) =>
    s.readdir(path, (e, list) => (e ? rej(e) : res(list.map((f) => f.longname).join("\n"))))));
}

type Block = { type: "text"; text: string } | { type: "image"; data: string; mimeType: string };
type ToolOut = { content: Block[]; isError?: boolean };
const text = (t: string) => ({ content: [{ type: "text" as const, text: t }] });
const fail = (e: unknown) => ({ isError: true, content: [{ type: "text" as const, text: `Error: ${(e as Error).message}` }] });

// ───────── v1.1: batch exec, background jobs, code runner. Everything below runs through runCommand. ─────────

const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`; // single-quote for sh/bash
const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");

// Run a bash script on a host. `bash -c` makes it independent of the remote login shell; user
// payloads (commands, code) travel base64-encoded inside the script, so nothing needs escaping.
const runScript = (name: string, script: string, timeoutSec: number) => runCommand(name, `bash -c ${shq(script)}`, timeoutSec);

function checkPayload(what: string, s: string) {
  const n = Buffer.byteLength(s);
  if (n > MAX_PAYLOAD) throw new Error(`${what} too large (${n} bytes, max ${MAX_PAYLOAD}). Upload it with sftp_write and run the file instead.`);
}

const newJobId = () => // e.g. 20261116-183414-a1b2c3 (UTC, sorts chronologically)
  `${new Date().toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15)}-${randomBytes(3).toString("hex")}`;

// Where state lives on the target host: $D = jobs dir (falls back to ~/.ssh-mcp/jobs when not writable).
const DIR_LIB = `
D=${shq(JOBS_DIR)}
mkdir -p "$D" 2>/dev/null
if [ ! -d "$D" ] || [ ! -w "$D" ]; then D="$HOME/.ssh-mcp/jobs"; mkdir -p "$D" || { echo "cannot create jobs dir $D" >&2; exit 97; }; fi
chmod 700 "$D" 2>/dev/null
`;

// Shell helpers shared by all job scripts. Jobs live in $D as <jobId>.cmd/.sh/.pid/.log/.exit.
const JOB_LIB = `${DIR_LIB}mt() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0; }
iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "$1"; }
alive() { # <pid> <jobId>: is that pid still this job's wrapper (guards against pid reuse)?
  [ -n "$1" ] || return 1
  if [ -r "/proc/$1/cmdline" ]; then tr '\\0' ' ' < "/proc/$1/cmdline" | grep -qF -- "$2.sh"
  elif [ -d /proc/1 ]; then return 1
  else ps -o args= -p "$1" 2>/dev/null | grep -qF -- "$2.sh"; fi
}
jstate() { # <jobId> -> st=running|exited|lost, rc, pid
  pid=$(cat "$D/$1.pid" 2>/dev/null); rc=""
  if [ -f "$D/$1.exit" ]; then st=exited
  elif alive "$pid" "$1"; then st=running
  elif [ -f "$D/$1.exit" ]; then st=exited
  else st=lost; fi
  if [ "$st" = exited ]; then rc=$(cat "$D/$1.exit" 2>/dev/null); fi
}
jprint() { # <jobId>
  jstate "$1"
  s=$(mt "$D/$1.cmd")
  echo "job: $1"
  echo "state: $st"
  if [ "$st" = exited ]; then e=$(mt "$D/$1.exit"); echo "exit: $rc"; fi
  echo "pid: \${pid:-?}"
  echo "started: $(iso "$s")"
  case "$st" in
    exited) echo "ended: $(iso "$e")"; echo "elapsed: $((e - s))s" ;;
    running) echo "elapsed: $(( $(date +%s) - s ))s" ;;
    lost) echo "note: no exit record and the process is gone (killed -9, out of memory, or reboot)" ;;
  esac
  echo "log: $D/$1.log ($(wc -c < "$D/$1.log" 2>/dev/null | tr -d ' ') bytes)"
  echo "command: $(head -c 200 "$D/$1.cmd" | tr '\\n\\t' '  ' | sed 's/ *$//')"
}
need() { [ -f "$D/$1.cmd" ] || { echo "No such job: $1 (jobs dir: $D)" >&2; exit 96; }; }
`;

// Launch <command> detached: setsid + nohup under bash, stdout+stderr -> .log, exit code -> .exit.
// The wrapper traps TERM so that after a kill it still records the exit code (143).
// cdExpr (optional) is a shell expression printing the directory the job should start in.
const spawnScript = (id: string, command: string, cdExpr?: string) => `${JOB_LIB}
id=${shq(id)}
[ ! -e "$D/$id.cmd" ] || { echo "job id $id already exists, try again" >&2; exit 94; }
${cdExpr ? `printf 'cd -- %q || exit 96\\n' "$(${cdExpr})" > "$D/$id.cmd"; printf %s ${shq(b64(command))} | base64 -d >> "$D/$id.cmd"` : `printf %s ${shq(b64(command))} | base64 -d > "$D/$id.cmd"`} || { echo "cannot write $D/$id.cmd" >&2; exit 98; }
cat > "$D/$id.sh" <<'SSH_MCP_WRAPPER'
D="$1"; id="$2"
echo "$$" > "$D/$id.pid"
trap ":" TERM
bash "$D/$id.cmd" > "$D/$id.log" 2>&1 < /dev/null
rc=$?
echo "$rc" > "$D/$id.exit.tmp" && mv -f "$D/$id.exit.tmp" "$D/$id.exit"
SSH_MCP_WRAPPER
: > "$D/$id.log"
pre=""
command -v nohup >/dev/null 2>&1 && pre="nohup"
command -v setsid >/dev/null 2>&1 && pre="setsid $pre"
# Under systemd, put the job in its own scope so it outlives a restart of the service that launched it and a
# logout with KillUserProcesses=yes. OOMPolicy=continue: if the kernel OOM-kills one process of the job,
# systemd must not take the rest of the job down with it (the default for a scope is to stop everything).
sr="systemd-run --scope --quiet --no-ask-password"
if [ -d /run/systemd/system ] && command -v systemd-run >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
  if timeout 5 $sr -p OOMPolicy=continue true >/dev/null 2>&1; then pre="$pre $sr --collect -p OOMPolicy=continue --unit=ssh-mcp-job-$id"
  elif timeout 5 $sr true >/dev/null 2>&1; then pre="$pre $sr --collect --unit=ssh-mcp-job-$id"; fi
fi
$pre bash "$D/$id.sh" "$D" "$id" </dev/null >/dev/null 2>&1 &
i=0; while [ ! -s "$D/$id.pid" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i+1)); done
[ -s "$D/$id.pid" ] || { echo "job $id did not start (jobs dir: $D)" >&2; exit 95; }
echo "jobId: $id"
echo "pid: $(cat "$D/$id.pid")"
echo "log: $D/$id.log"
`;

type JobAction = "status" | "tail" | "wait" | "kill";
function jobScript(id: string, action: JobAction, bytes: number, timeoutSec: number): string {
  const head = `${JOB_LIB}\nid=${shq(id)}\nneed "$id"\n`;
  const tail = `echo "--- log (last ${bytes} bytes) ---"\ntail -c ${bytes} "$D/$id.log" 2>/dev/null\n`;
  if (action === "status") return `${head}jprint "$id"\n`;
  if (action === "tail") return `${head}jprint "$id"\n${tail}`;
  if (action === "wait") return `${head}
while [ ! -f "$D/$id.exit" ] && [ "$SECONDS" -lt ${timeoutSec} ]; do
  alive "$(cat "$D/$id.pid" 2>/dev/null)" "$id" || break
  sleep 1
done
jprint "$id"
[ "$st" = running ] && echo "note: still running after ${timeoutSec}s - call wait again"
${tail}`;
  return `${head}
jstate "$id"
if [ "$st" = running ]; then
  sig() { kill "-$1" -- "-$pid" 2>/dev/null || kill "-$1" "$pid" 2>/dev/null; systemctl kill --signal="$1" "ssh-mcp-job-$id.scope" >/dev/null 2>&1; return 0; }
  sig TERM
  i=0; while alive "$pid" "$id" && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i+1)); done
  if alive "$pid" "$id"; then
    sig KILL; sleep 0.3
    [ -f "$D/$id.exit" ] || echo 137 > "$D/$id.exit"
    echo "kill: SIGTERM ignored for 5s, sent SIGKILL"
  else
    echo "kill: terminated with SIGTERM"
  fi
else
  echo "kill: nothing to do (state: $st)"
fi
jprint "$id"
`;
}

const jobsScript = (limit: number) => `${JOB_LIB}
printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' JOB STATE EXIT ELAPSED STARTED COMMAND
n=0
for f in $(ls -1 "$D" 2>/dev/null | grep '\\.cmd$' | sort -r | head -n ${limit}); do
  id="\${f%.cmd}"
  jstate "$id"
  s=$(mt "$D/$id.cmd")
  case "$st" in
    exited) el="$(( $(mt "$D/$id.exit") - s ))s" ;;
    running) el="$(( $(date +%s) - s ))s" ;;
    *) el="-" ;;
  esac
  printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$id" "$st" "\${rc:--}" "$el" "$(iso "$s")" "$(head -c 100 "$D/$id.cmd" | tr '\\n\\t' '  ' | sed 's/ *$//')"
  n=$((n+1))
done
[ "$n" -gt 0 ] || echo "(no jobs)"
echo "total: $(ls -1 "$D" 2>/dev/null | grep -c '\\.cmd$') job(s) in $D"
`;

const INTERPRETERS = { python: ["python3", "py"], node: ["node", "js"], bash: ["bash", "sh"] } as const;
type Language = keyof typeof INTERPRETERS;

// Write <code> to a private temp dir and run it; `timeout` (when present) kills the whole process
// group at the limit, so partial output is still returned (exit 124).
function codeScript(language: Language, code: string, timeoutSec: number): string {
  const [bin, ext] = INTERPRETERS[language];
  return `d=$(mktemp -d "\${TMPDIR:-/tmp}/ssh-mcp-code.XXXXXXXX") || { echo "mktemp failed" >&2; exit 99; }
trap 'rm -rf "$d"' EXIT
f="$d/code.${ext}"
printf %s ${shq(b64(code))} | base64 -d > "$f" || { echo "cannot write $f" >&2; exit 98; }
command -v ${bin} >/dev/null 2>&1 || { echo "${bin}: not found on this host" >&2; exit 127; }
if command -v timeout >/dev/null 2>&1; then timeout -k 5 ${timeoutSec} ${bin} "$f" < /dev/null; else ${bin} "$f" < /dev/null; fi
`;
}

// ───────── v1.2: the four tools a Claude sandbox has (bash / read / write / edit), bulk-capable, and a bridge ─────────
// so a sandbox shell can reach this server directly: files and commands at network speed, no model in between.

// Script prelude for the state directory on the target host: $R = parent of the jobs dir, with sessions/
// (remembered working directories) and out/ (outputs too big to return). Also a sane HOME and PATH.
const STATE_LIB = `
[ -n "\${HOME:-}" ] || HOME=$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6); export HOME="\${HOME:-/}"
case ":$PATH:" in *:/usr/sbin:*) ;; *) PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin" ;; esac
${DIR_LIB}R=$(dirname "$D"); mkdir -p "$R/sessions" "$R/out" 2>/dev/null; chmod 700 "$R/sessions" "$R/out" 2>/dev/null
`;

const OUT_HEAD = 60_000, OUT_TAIL = 38_000; // bash: what comes back of an oversized output; the rest stays in a file on the host

// How much of a command's output comes back: normally the start and the end of at most `budget` bytes;
// quiet = only the end (more of it after a failure). Whatever is cut stays in full in a file on the host.
type OutLimit = { head: number; tail: number; errHead: number; errTail: number };
const outLimit = (budget: number, quiet: boolean): OutLimit => {
  if (quiet) return { head: 0, tail: Math.min(2000, budget), errHead: 0, errTail: Math.min(8000, budget) };
  const head = Math.floor(budget * OUT_HEAD / (OUT_HEAD + OUT_TAIL));
  return { head, tail: budget - head, errHead: head, errTail: budget - head };
};

// Run <command> the way the sandbox Bash tool does: stdout+stderr merged in order, optional start directory,
// optional named session that remembers the working directory, hard timeout that still returns partial output.
// Tool form: the script prints the text to show (oversized output cut, footer lines for a failure) and
// "rc=<exit code>" on its stderr. noteMove: note [cwd: ...] only when the command itself changed directory
// (batch), instead of whenever the session's directory differs from before (bash tool).
// raw form (bridge): the script prints one header line "rc=<exit code> size=<bytes>" and then the whole output.
function bashScript(o: { command: string; timeoutSec: number; cwd?: string; session?: string; raw?: boolean; keep?: OutLimit; noteMove?: boolean }): string {
  const k = o.keep ?? outLimit(OUT_HEAD + OUT_TAIL, false);
  return `${STATE_LIB}
S=${o.session ? `"$R/sessions/${o.session}.cwd"` : `""`}
prev="$HOME"; if [ -n "$S" ] && [ -s "$S" ]; then prev=$(cat "$S"); fi
[ -d "$prev" ] || prev="$HOME"
cd "$prev" 2>/dev/null
${o.cwd ? `cd -- ${shq(o.cwd)} 2>/dev/null || { echo "No such directory: "${shq(o.cwd)} >&2; exit 96; }` : ""}
start=$PWD
O=$(mktemp "$R/out/XXXXXXXX") || { echo "cannot create an output file in $R/out" >&2; exit 97; }
N="$O.cwd"
${o.raw ? `trap 'rm -f "$O" "$N"' EXIT` : ""}
find "$R/out" -type f -mtime +3 -delete 2>/dev/null
find "$R/sessions" -type f -name 'tmp+*' -mmin +120 -delete 2>/dev/null
T=""; command -v timeout >/dev/null 2>&1 && T="timeout -k 5 ${o.timeoutSec}"
$T bash -c 'trap "pwd > \\"$1\\"" EXIT; eval "$(printf %s "$2" | base64 -d)"' _ "$N" ${shq(b64(o.command))} > "$O" 2>&1 < /dev/null
rc=$?
size=$(wc -c < "$O" | tr -d ' ')
new=""; if [ -s "$N" ]; then new=$(cat "$N"); fi; rm -f "$N"
${o.raw ? `printf 'rc=%s size=%s\\n' "$rc" "$size"
cat "$O"
exit 0` : `nl=0; if [ "$size" -gt 0 ] && [ "$(tail -c 1 "$O" | wc -l | tr -d ' ')" = 0 ]; then nl=1; fi
if [ "$rc" = 0 ]; then H=${k.head}; L=${k.tail}; else H=${k.errHead}; L=${k.errTail}; fi
if [ "$size" -le $((H + L)) ]; then cat "$O"; rm -f "$O"
else
  if [ "$H" -gt 0 ]; then head -c "$H" "$O"; echo; fi
  printf '...[%d bytes omitted - full output saved on the host: %s]...\\n' "$((size - H - L))" "$O"; tail -c "$L" "$O"
fi
F=""
if { [ "$rc" = 124 ] || [ "$rc" = 137 ]; } && [ -n "$T" ] && [ "$SECONDS" -ge ${o.timeoutSec} ]; then F="[timed out after ${o.timeoutSec}s - exit code: $rc]"
elif [ "$rc" != 0 ]; then F="[exit code: $rc]"; fi
if [ -n "$S" ] && [ -n "$new" ]; then
  if [ "$new" != "${o.noteMove ? "$start" : "$prev"}" ]; then F="\${F:+$F
}[cwd: $new]"; fi
  printf %s "$new" > "$S"
fi
if [ -n "$F" ]; then [ "$nl" = 1 ] && echo; printf %s "$F"; fi
echo "rc=$rc" >&2
exit 0`}
`;
}

// Read text files as numbered lines (cat -n style) with ONE command for the whole batch; every file gets
// the same share of the output budget. Records are separated by a random boundary line.
function readScript(files: { file_path: string; offset: number; limit: number }[], boundary: string, budget: number): string {
  return `rd() {
  printf '\\n%s %s\\n' ${shq(boundary)} "$1"
  f=$4
  if [ ! -e "$f" ]; then echo "ERR File does not exist: $f"; return; fi
  if [ -d "$f" ]; then echo "ERR Path is a directory, not a file: $f"; return; fi
  if [ ! -r "$f" ]; then echo "ERR Permission denied: $f"; return; fi
  if [ "$(head -c 8192 -- "$f" | wc -c)" != "$(head -c 8192 -- "$f" | tr -d '\\000' | wc -c)" ]; then
    echo "ERR Binary file ($(wc -c < "$f" | tr -d ' ') bytes): $f - inspect it with bash (file, xxd) or fetch it through the bridge"; return
  fi
  echo OK
  awk -v s="$2" -v n="$3" -v budget=${budget} '
    NR < s { next }
    NR >= s + n { more = 1; exit }
    { l = $0; if (length(l) > 2000) l = substr(l, 1, 2000) "... [line truncated]"
      out += length(l) + 8
      if (out > budget && last) { more = 1; cut = 1; exit }
      printf "%6d\\t%s\\n", NR, l; last = NR }
    END {
      if (NR == 0) print "(empty file)"
      else if (!last && !more) printf "[offset %d is past the end of the file (%d lines)]\\n", s, NR
      else if (more) printf "[lines %d-%d shown%s; more follow - continue with offset=%d]\\n", s, last, (cut ? ", output budget reached" : ""), last + 1
    }' "$f"
}
${files.map((f, i) => `rd ${i} ${f.offset} ${f.limit} ${shq(f.file_path)}`).join("\n")}
`;
}

const IMAGE_TYPES: Record<string, string> = { png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp" };
const MAX_IMAGE = 4 * 1024 * 1024;
const imageType = (p: string): string | undefined => IMAGE_TYPES[p.slice(p.lastIndexOf(".") + 1).toLowerCase()];
const errText = (e: unknown, p: string) => ((e as NodeJS.ErrnoException).code === "ENOENT" || /no such file/i.test((e as Error).message) ? `File does not exist: ${p}` : (e as Error).message);

// Node's mkdir({ recursive: true }) spins forever on paths the kernel refuses with ENOENT although the parent
// exists (anything under /proc, for one), so walk up by hand: at most two mkdir calls per level.
async function mkdirp(dir: string): Promise<void> {
  try { await fs.mkdir(dir); } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "EEXIST") return;
    if (code !== "ENOENT" || dirname(dir) === dir) throw e;
    await mkdirp(dirname(dir));
    await fs.mkdir(dir).catch((e2) => { if ((e2 as NodeJS.ErrnoException).code !== "EEXIST") throw e2; });
  }
}

// File access for a bulk operation: local = fs, remote = ONE SSH connection and SFTP session for the whole batch.
type Fx = { read(p: string): Promise<Buffer>; write(p: string, data: Buffer, mode?: number): Promise<void>; mkdirs(dirs: string[]): Promise<void>; close(): void };
async function openFx(name: string): Promise<Fx> {
  const cfg = getHost(name);
  if (cfg.local) {
    return {
      read: (p) => fs.readFile(p),
      write: async (p, data, mode) => { await fs.writeFile(p, data); if (mode !== undefined) await fs.chmod(p, mode); },
      mkdirs: async (dirs) => { await Promise.allSettled(dirs.map(mkdirp)); },
      close: () => {},
    };
  }
  const conn = await connect(cfg);
  const sftp = await new Promise<import("ssh2").SFTPWrapper>((res, rej) => conn.sftp((e, s) => (e ? rej(e) : res(s)))).catch((e) => { conn.end(); throw e; });
  return {
    read: (p) => new Promise((res, rej) => sftp.readFile(p, (e, d) => (e ? rej(e) : res(d)))),
    write: (p, data, mode) => new Promise((res, rej) => sftp.writeFile(p, data, (e) => {
      if (e) return rej(e);
      if (mode === undefined) return res();
      sftp.chmod(p, mode, (e2) => (e2 ? rej(e2) : res()));
    })),
    mkdirs: (dirs) => new Promise((res) => {
      if (!dirs.length) return res();
      conn.exec(`mkdir -p -- ${dirs.map(shq).join(" ")}`, (e, st) => { if (e) return res(); st.on("close", () => res()); st.resume(); st.stderr.resume(); });
    }),
    close: () => conn.end(),
  };
}

type EditItem = { file_path: string; old_string: string; new_string: string; replace_all?: boolean };
function applyEdit(src: string, e: EditItem): { text: string; count: number; at: number } {
  if (e.old_string === "") throw new Error("old_string is empty - use write to create or replace a whole file");
  if (e.old_string === e.new_string) throw new Error("old_string and new_string are identical");
  const count = src.split(e.old_string).length - 1;
  if (count === 0) throw new Error("old_string not found - it must match the file exactly, including whitespace and line breaks");
  if (count > 1 && !e.replace_all) throw new Error(`old_string matches ${count} places - add surrounding context to make it unique, or set replace_all`);
  return { text: e.replace_all ? src.split(e.old_string).join(e.new_string) : src.replace(e.old_string, () => e.new_string), count, at: src.indexOf(e.old_string) };
}
// A few numbered lines around a position, in the same format as read.
function snippet(textNow: string, at: number, changedLines: number): string {
  const lines = textNow.split("\n");
  const ln = textNow.slice(0, at).split("\n").length; // 1-based line of the change
  const from = Math.max(1, ln - 3), to = Math.min(lines.length, ln + changedLines + 2);
  return `--- lines ${from}-${to} after the edit ---\n` + lines.slice(from - 1, to).map((l, i) => `${String(from + i).padStart(6)}\t${l}`).join("\n") + "\n";
}

// Run a script on a host with streaming stdin/stdout (bridge endpoints): local = child process in its own
// process group, remote = ssh exec. If whoever reads stdout goes away, or stdin breaks off before its end,
// the script is stopped (aborted: true) - otherwise it would wait forever on a pipe nobody serves.
type StreamResult = { code: number | null; stderr: string; aborted: boolean };
function streamExec(name: string, script: string, stdin: Readable | null, stdout: Writable): Promise<StreamResult> {
  const cfg = getHost(name);
  return new Promise<StreamResult>((resolve, reject) => {
    let stderr = "", aborted = false, settled = false, kill = () => {};
    const abort = () => { if (settled || aborted) return; aborted = true; kill(); setTimeout(() => finish(null), 5000).unref(); };
    const inClosed = () => { if (!stdin!.readableEnded) abort(); };
    const cleanup = () => { settled = true; stdout.off("close", abort); stdin?.off("close", inClosed); };
    const finish = (code: number | null) => { if (settled) return; cleanup(); resolve({ code, stderr, aborted }); };
    const fail = (e: unknown) => { if (settled) return; cleanup(); reject(e); };
    const onErr = (d: Buffer) => { if (stderr.length < 65536) stderr += d; };
    if (stdout.destroyed || (stdin && stdin.destroyed && !stdin.readableEnded)) return resolve({ code: null, stderr, aborted: true });
    stdout.once("close", abort);
    stdin?.once("close", inClosed);
    if (cfg.local) {
      const child = spawn("/bin/bash", ["-c", script], { stdio: [stdin ? "pipe" : "ignore", "pipe", "pipe"], detached: true });
      const signal = (sig: NodeJS.Signals) => { try { process.kill(-child.pid!, sig); } catch { /* already gone */ } };
      kill = () => { signal("SIGTERM"); setTimeout(() => signal("SIGKILL"), 2000).unref(); }; // TERM first: lets the script's EXIT trap clean up
      child.on("error", fail);
      child.stderr!.on("data", onErr);
      child.stdout!.pipe(stdout, { end: false });
      if (stdin) { child.stdin!.on("error", () => {}); stdin.pipe(child.stdin!); }
      child.on("close", finish);
      return;
    }
    connect(cfg).then((conn) => {
      kill = () => conn.destroy();
      if (aborted) { conn.destroy(); return finish(null); }
      conn.exec(`bash -c ${shq(script)}`, (err, stream) => {
        if (err) { conn.end(); return fail(err); }
        stream.stderr.on("data", onErr);
        stream.pipe(stdout, { end: false });
        if (stdin) stdin.pipe(stream); else stream.end();
        stream.on("close", (code: number | null) => { conn.end(); finish(code ?? null); });
      });
    }, fail);
  });
}

// Bridge tokens: "<expiry, base36>.<hmac>" - stateless, signed with MCP_SECRET, so only this server can mint them.
const bridgeSig = (exp: number) => createHmac("sha256", SECRET).update(`bridge:${exp}`).digest("hex").slice(0, 32);
function mintBridgeToken(ttlSec: number): { exp: number; token: string } {
  const exp = Math.floor(Date.now() / 1000) + ttlSec;
  return { exp, token: `${exp.toString(36)}.${bridgeSig(exp)}` };
}
function bridgeTokenOk(token: string): boolean {
  const m = /^([0-9a-z]{1,12})\.([0-9a-f]{32})$/.exec(token);
  if (!m) return false;
  const exp = parseInt(m[1], 36);
  return exp > Date.now() / 1000 && timingSafeEqual(Buffer.from(m[2]), Buffer.from(bridgeSig(exp)));
}

function buildServer(base = "", viaBridge = false): McpServer {
  const server = new McpServer({ name: "ssh-connector", version: VERSION }, { instructions: INSTRUCTIONS });

  server.registerTool("list_hosts", {
    description: "List SSH hosts this connector can reach.",
    inputSchema: {},
  }, async () => {
    const h = loadHosts();
    return text(Object.entries(h).map(([k, v]) => v.local ? `${k}: (this VPS)` : `${k}: ${v.username}@${v.host}:${v.port ?? 22}`).join("\n"));
  });

  server.registerTool("ssh_exec", {
    description: "Run a shell command on a named host. Returns exit code, stdout, stderr.",
    inputSchema: {
      host: z.string().describe("Host name from list_hosts"),
      command: z.string().describe("Shell command to run"),
      timeout_sec: z.number().int().min(1).max(1800).default(120),
    },
  }, async ({ host, command, timeout_sec }) => {
    try {
      const r = await runCommand(host, command, timeout_sec);
      return text(`exit: ${r.code}\n--- stdout ---\n${trunc(r.stdout)}\n--- stderr ---\n${trunc(r.stderr)}`);
    } catch (e) { return fail(e); }
  });

  server.registerTool("sftp_read", {
    description: "Read a file from a host (utf8 text, or base64 for binary).",
    inputSchema: {
      host: z.string(),
      path: z.string(),
      encoding: z.enum(["utf8", "base64"]).default("utf8"),
    },
  }, async ({ host, path, encoding }) => {
    try { return text(trunc((await readRemote(host, path)).toString(encoding))); } catch (e) { return fail(e); }
  });

  server.registerTool("sftp_write", {
    description: "Write a file on a host (overwrites).",
    inputSchema: {
      host: z.string(),
      path: z.string(),
      content: z.string(),
      encoding: z.enum(["utf8", "base64"]).default("utf8"),
      mode: z.string().regex(/^[0-7]{3,4}$/).optional().describe("Octal, e.g. 0644"),
    },
  }, async ({ host, path, content, encoding, mode }) => {
    try {
      const buf = Buffer.from(content, encoding);
      await writeRemote(host, path, buf, mode ? parseInt(mode, 8) : undefined);
      return text(`Wrote ${buf.length} bytes to ${host}:${path}`);
    } catch (e) { return fail(e); }
  });

  server.registerTool("sftp_list", {
    description: "List a directory on a host.",
    inputSchema: { host: z.string(), path: z.string().default(".") },
  }, async ({ host, path }) => {
    try { return text(await listRemote(host, path)); } catch (e) { return fail(e); }
  });

  // ── v1.1 tools ──────────────────────────────────────────────────────────────

  server.registerTool("ssh_exec_many", {
    description: "Run up to 10 shell commands concurrently on one host. Returns one block per id: exit code, stdout, stderr, duration.",
    inputSchema: {
      host: z.string().describe("Host name from list_hosts"),
      commands: z.array(z.object({
        id: z.string().min(1).max(64).regex(/^[^\r\n]+$/).describe("Your label for this command; echoed in its result block"),
        command: z.string().describe("Shell command to run"),
        timeout_sec: z.number().int().min(1).max(1800).default(120),
      })).min(1).max(10).describe("1-10 commands, run in parallel"),
    },
  }, async ({ host, commands }) => {
    try {
      getHost(host);
      const dup = commands.find((c, i) => commands.findIndex((o) => o.id === c.id) !== i);
      if (dup) throw new Error(`Duplicate id "${dup.id}"`);
      const max = Math.floor(MAX_OUT / commands.length); // the MAX_OUT budget is shared across blocks
      const t0 = Date.now();
      const ms: number[] = [];
      const done = await Promise.allSettled(commands.map((c, i) =>
        runCommand(host, c.command, c.timeout_sec).finally(() => { ms[i] = Date.now() - t0; })));
      return text(done.map((d, i) => {
        const head = `=== [${commands[i].id}] `, dur = ` | ${(ms[i] / 1000).toFixed(2)}s ===`;
        return d.status === "fulfilled"
          ? `${head}exit: ${d.value.code}${dur}\n--- stdout ---\n${trunc(d.value.stdout, max)}\n--- stderr ---\n${trunc(d.value.stderr, max)}`
          : `${head}error: ${(d.reason as Error).message}${dur}`;
      }).join("\n\n"));
    } catch (e) { return fail(e); }
  });

  server.registerTool("ssh_spawn", {
    description: "Start a long-running shell command in the background on a host (bash under setsid/nohup) and return a jobId immediately. " +
      `Output goes to ${JOBS_DIR}/<jobId>.log and the exit code to <jobId>.exit. Follow up with ssh_job (status | tail | wait | kill) or ssh_jobs.`,
    inputSchema: {
      host: z.string().describe("Host name from list_hosts"),
      command: z.string().min(1).describe("Shell command (bash) to run in the background"),
    },
  }, async ({ host, command }) => {
    try {
      checkPayload("command", command);
      const id = newJobId();
      const r = await runScript(host, spawnScript(id, command), 60);
      if (r.code !== 0) throw new Error(`spawn failed (exit ${r.code}): ${(r.stderr || r.stdout).trim()}`);
      return text(`${r.stdout.trim()}\nnext: ssh_job { host: "${host}", jobId: "${id}", action: "tail" | "wait" | "status" | "kill" }`);
    } catch (e) { return fail(e); }
  });

  server.registerTool("ssh_job", {
    description: "Inspect or control a background job started with ssh_spawn. status: state (running | exited | lost) and exit code. " +
      "tail: status plus the last `bytes` of the log. wait: block until the job exits or timeout_sec passes, then status plus log tail. " +
      "kill: SIGTERM the job's process group, SIGKILL after 5s.",
    inputSchema: {
      host: z.string().describe("Host the job was started on"),
      jobId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/).describe("jobId returned by ssh_spawn"),
      action: z.enum(["status", "tail", "wait", "kill"]),
      bytes: z.number().int().min(1).max(MAX_OUT).default(8192).describe("tail/wait: how many bytes of the log end to return"),
      timeout_sec: z.number().int().min(1).max(1800).default(60).describe("wait: maximum seconds to block"),
    },
  }, async ({ host, jobId, action, bytes, timeout_sec }) => {
    try {
      const r = await runScript(host, jobScript(jobId, action, bytes, timeout_sec), action === "wait" ? timeout_sec + 30 : 60);
      if (r.code !== 0) throw new Error((r.stderr || r.stdout).trim() || `exit ${r.code}`);
      return text(trunc(r.stdout));
    } catch (e) { return fail(e); }
  });

  server.registerTool("ssh_jobs", {
    description: "List background jobs on a host, newest first: jobId, state (running | exited | lost), exit code, elapsed time, start time, command.",
    inputSchema: {
      host: z.string().describe("Host name from list_hosts"),
      limit: z.number().int().min(1).max(500).default(50).describe("Show at most this many jobs"),
    },
  }, async ({ host, limit }) => {
    try {
      const r = await runScript(host, jobsScript(limit), 60);
      if (r.code !== 0) throw new Error((r.stderr || r.stdout).trim() || `exit ${r.code}`);
      return text(trunc(r.stdout));
    } catch (e) { return fail(e); }
  });

  server.registerTool("exec_code", {
    description: "Write a code snippet to a temp file on a host and run it with python3, node or bash. Returns exit code, stdout, stderr.",
    inputSchema: {
      host: z.string().describe("Host name from list_hosts"),
      language: z.enum(["python", "node", "bash"]),
      code: z.string().min(1).describe("Source code to run"),
      timeout_sec: z.number().int().min(1).max(1800).default(120),
    },
  }, async ({ host, language, code, timeout_sec }) => {
    try {
      checkPayload("code", code);
      const t0 = Date.now();
      const r = await runScript(host, codeScript(language, code, timeout_sec), timeout_sec + 15);
      const note = (r.code === 124 || r.code === 137) && Date.now() - t0 >= timeout_sec * 1000 ? ` (timed out after ${timeout_sec}s)` : "";
      return text(`exit: ${r.code}${note}\n--- stdout ---\n${trunc(r.stdout)}\n--- stderr ---\n${trunc(r.stderr)}`);
    } catch (e) { return fail(e); }
  });

  // ── v1.2 tools: bash / read / write / edit mirror the sandbox's own tools (same parameter names, plus host) ──

  const bashShape = {
    host: z.string().describe("Host name from list_hosts"),
    command: z.string().min(1).describe("Shell command (bash)"),
    timeout: z.number().int().min(1000).max(1_800_000).default(120_000).describe("Milliseconds before the command is killed (default 120000, max 1800000)"),
    cwd: z.string().optional().describe("Directory to run in: absolute, or relative to the session directory"),
    session: z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/).optional().describe("Any name; calls that share it share a working directory that `cd` changes. Use one per conversation"),
    run_in_background: z.boolean().default(false).describe("Start it as a background job and return a jobId at once"),
    quiet: z.boolean().default(false).describe("Return only the end of the output (last ~2 KB, ~8 KB after a failure); the full output is kept in a file on the host. Use it when only success or failure matters"),
    description: z.string().optional().describe("What the command does (for the transcript; not used by the server)"),
  };
  // ok = the command ran and exited 0. budget = most bytes of output to return. inBatch: see bashScript's noteMove.
  const runBash = async ({ host, command, timeout, cwd, session, run_in_background, quiet }: z.infer<z.ZodObject<typeof bashShape>>, budget = OUT_HEAD + OUT_TAIL, inBatch = false): Promise<{ out: ToolOut; ok: boolean }> => {
    try {
      checkPayload("command", command);
      if (run_in_background) {
        const id = newJobId();
        const cdExpr = cwd ? `printf %s ${shq(cwd)}` : session ? `cat "$(dirname "$D")/sessions/${session}.cwd" 2>/dev/null || printf %s ~` : "printf %s ~";
        const r = await runScript(host, spawnScript(id, command, cdExpr), 60);
        if (r.code !== 0) throw new Error(`spawn failed (exit ${r.code}): ${(r.stderr || r.stdout).trim()}`);
        return { out: text(`${r.stdout.trim()}\nnext: ssh_job { host: "${host}", jobId: "${id}", action: "tail" | "wait" | "status" | "kill" }`), ok: true };
      }
      const sec = Math.ceil(timeout / 1000);
      const r = await runScript(host, bashScript({ command, timeoutSec: sec, cwd, session, keep: outLimit(budget, quiet), noteMove: inBatch }), sec + 20);
      if (r.code !== 0) throw new Error((r.stderr || r.stdout).trim() || `exit ${r.code}`);
      return { out: text(r.stdout === "" ? "(no output)" : r.stdout), ok: /^rc=0$/m.test(r.stderr) };
    } catch (e) { return { out: fail(e), ok: false }; }
  };
  server.registerTool("bash", {
    description: "Run a shell command on a host: the remote twin of the local Bash tool. stdout and stderr come back merged, in order; a non-zero exit adds an [exit code: N] line. " +
      "Working directory: pass `cwd`, or pass the same `session` name on every call to make `cd` persist between calls; with neither, each call starts in the home directory. " +
      "Output over ~100 KB is cut in the middle and kept in full in a file on the host (read it with `read`). Use run_in_background for long jobs, then ssh_job.",
    inputSchema: bashShape,
  }, async (a) => (await runBash(a)).out);

  const readShape = {
    host: z.string().describe("Host name from list_hosts"),
    file_path: z.string().optional().describe("Absolute path of the file to read"),
    offset: z.number().int().min(1).optional().describe("First line to return (1-based)"),
    limit: z.number().int().min(1).max(20000).optional().describe("Number of lines to return (default 2000)"),
    files: z.array(z.object({
      file_path: z.string().describe("Absolute path"),
      offset: z.number().int().min(1).optional(),
      limit: z.number().int().min(1).max(20000).optional(),
    })).min(1).max(20).optional().describe("Several files in one call; they share the output budget"),
  };
  const readTool = async ({ host, file_path, offset, limit, files }: z.infer<z.ZodObject<typeof readShape>>, budget = MAX_OUT): Promise<ToolOut> => {
    try {
      if ((file_path === undefined) === (files === undefined)) throw new Error("Pass either file_path (one file) or files (several)");
      const list = files ?? [{ file_path: file_path!, offset, limit }];
      for (const f of list) if (!f.file_path.startsWith("/")) throw new Error(`file_path must be absolute: ${f.file_path}`);
      type Out = { err: string } | { body: string } | { data: string; mimeType: string; bytes: number };
      const out: Out[] = new Array(list.length);
      const texts = list.map((f, i) => ({ f, i })).filter(({ f }) => !imageType(f.file_path));
      const images = list.map((f, i) => ({ f, i })).filter(({ f }) => imageType(f.file_path));
      await Promise.all([
        (async () => { // all text files with one command
          if (!texts.length) return;
          const boundary = `@@${randomBytes(12).toString("hex")}@@`;
          const reqs = texts.map(({ f }) => ({ file_path: f.file_path, offset: f.offset ?? 1, limit: f.limit ?? 2000 }));
          const r = await runScript(host, readScript(reqs, boundary, Math.floor(Math.max(1000, budget - 2000) / texts.length)), 120);
          if (r.code !== 0) throw new Error((r.stderr || r.stdout).trim() || `exit ${r.code}`);
          for (const part of r.stdout.split(`\n${boundary} `).slice(1)) {
            const a = part.indexOf("\n"), b = part.indexOf("\n", a + 1);
            const status = part.slice(a + 1, b < 0 ? undefined : b);
            out[texts[Number(part.slice(0, a))].i] = status === "OK" ? { body: b < 0 ? "" : part.slice(b + 1) } : { err: status.replace(/^ERR /, "") };
          }
        })(),
        (async () => { // images over one connection
          if (!images.length) return;
          const fx = await openFx(host);
          try {
            await Promise.all(images.map(async ({ f, i }) => {
              try {
                const buf = await fx.read(f.file_path);
                if (buf.length > MAX_IMAGE) throw new Error(`Image is ${buf.length} bytes (limit ${MAX_IMAGE}): ${f.file_path} - downscale it first, or fetch it through the bridge`);
                out[i] = { data: buf.toString("base64"), mimeType: imageType(f.file_path)!, bytes: buf.length };
              } catch (e) { out[i] = { err: errText(e, f.file_path) }; }
            }));
          } finally { fx.close(); }
        })(),
      ]);
      for (let i = 0; i < list.length; i++) out[i] ??= { err: `No result for ${list[i].file_path}` };
      if (!files) { // single file: same shape as the local Read tool
        const o = out[0];
        if ("err" in o) throw new Error(o.err);
        if ("data" in o) return { content: [{ type: "text" as const, text: `${list[0].file_path} (${o.mimeType}, ${o.bytes} bytes)` }, { type: "image" as const, data: o.data, mimeType: o.mimeType }] };
        return text(trunc(o.body, budget));
      }
      const content: ({ type: "text"; text: string } | { type: "image"; data: string; mimeType: string })[] = [];
      let buf: string[] = [];
      const flush = () => { if (buf.length) { content.push({ type: "text", text: trunc(buf.join("\n"), budget) }); buf = []; } };
      out.forEach((o, i) => {
        const p = list[i].file_path;
        if ("data" in o) { buf.push(`=== ${p} (${o.mimeType}, ${o.bytes} bytes) ===`); flush(); content.push({ type: "image", data: o.data, mimeType: o.mimeType }); }
        else buf.push(`=== ${p} ===\n${"err" in o ? `ERROR: ${o.err}\n` : o.body}`);
      });
      flush();
      return { content, isError: out.every((o) => "err" in o) };
    } catch (e) { return fail(e); }
  };
  server.registerTool("read", {
    description: "Read files on a host: the remote twin of the local Read tool, and bulk-capable. Text comes back as numbered lines (cat -n style); use offset/limit for long files. " +
      "Images (png, jpg, gif, webp) come back as images. Pass file_path for one file, or `files` for up to 20 files read in one call.",
    inputSchema: readShape,
  }, (a) => readTool(a));

  const writeShape = {
    host: z.string().describe("Host name from list_hosts"),
    file_path: z.string().optional().describe("Absolute path of the file to write"),
    content: z.string().optional().describe("Full new content of the file"),
    files: z.array(z.object({
      file_path: z.string().describe("Absolute path"),
      content: z.string(),
      mode: z.string().regex(/^[0-7]{3,4}$/).optional().describe("Octal, e.g. 0644"),
    })).min(1).max(50).optional().describe("Several files in one call"),
  };
  const writeTool = async ({ host, file_path, content, files }: z.infer<z.ZodObject<typeof writeShape>>): Promise<ToolOut> => {
    try {
      const single = file_path !== undefined || content !== undefined;
      if (single === (files !== undefined) || (single && (file_path === undefined || content === undefined))) throw new Error("Pass either file_path + content (one file) or files (several)");
      const list: { file_path: string; content: string; mode?: string }[] = files ?? [{ file_path: file_path!, content: content! }];
      for (const f of list) if (!f.file_path.startsWith("/")) throw new Error(`file_path must be absolute: ${f.file_path}`);
      const fx = await openFx(host);
      try {
        await fx.mkdirs([...new Set(list.map((f) => dirname(f.file_path)))]);
        const res = await Promise.allSettled(list.map(async (f) => {
          const data = Buffer.from(f.content, "utf8");
          await fx.write(f.file_path, data, f.mode ? parseInt(f.mode, 8) : undefined);
          return data.length;
        }));
        const lines = res.map((r, i) => r.status === "fulfilled" ? `Wrote ${r.value} bytes to ${host}:${list[i].file_path}` : `ERROR ${list[i].file_path}: ${(r.reason as Error).message}`);
        const ok = res.filter((r) => r.status === "fulfilled") as PromiseFulfilledResult<number>[];
        if (!files) { if (!ok.length) throw new Error(lines[0].replace(/^ERROR /, "")); return text(lines[0]); }
        const failed = res.length - ok.length;
        lines.push(`${ok.length} files written, ${ok.reduce((n, r) => n + r.value, 0)} bytes${failed ? `, ${failed} failed` : ""}`);
        return { content: [{ type: "text" as const, text: lines.join("\n") }], isError: failed > 0 };
      } finally { fx.close(); }
    } catch (e) { return fail(e); }
  };
  server.registerTool("write", {
    description: "Create or overwrite files on a host: the remote twin of the local Write tool, and bulk-capable. Pass file_path + content for one file, or `files` for up to 50 files written in parallel in one call. " +
      "Parent directories are created; an existing file keeps its mode and owner. For large or binary files use the bridge instead.",
    inputSchema: writeShape,
  }, (a) => writeTool(a));

  const editShape = {
    host: z.string().describe("Host name from list_hosts"),
    file_path: z.string().optional().describe("Absolute path of the file to change"),
    old_string: z.string().optional().describe("Exact text to replace"),
    new_string: z.string().optional().describe("Text to put in its place"),
    replace_all: z.boolean().optional().describe("Replace every occurrence instead of requiring a unique match"),
    edits: z.array(z.object({
      file_path: z.string().describe("Absolute path"),
      old_string: z.string(),
      new_string: z.string(),
      replace_all: z.boolean().optional(),
    })).min(1).max(50).optional().describe("Several edits in one call"),
  };
  const editTool = async ({ host, file_path, old_string, new_string, replace_all, edits }: z.infer<z.ZodObject<typeof editShape>>): Promise<ToolOut> => {
    try {
      const single = file_path !== undefined || old_string !== undefined || new_string !== undefined;
      if (single === (edits !== undefined) || (single && (file_path === undefined || old_string === undefined || new_string === undefined))) {
        throw new Error("Pass either file_path + old_string + new_string (one edit) or edits (several)");
      }
      const list: EditItem[] = edits ?? [{ file_path: file_path!, old_string: old_string!, new_string: new_string!, replace_all }];
      const byFile = new Map<string, { e: EditItem; n: number }[]>();
      list.forEach((e, i) => {
        if (!e.file_path.startsWith("/")) throw new Error(`file_path must be absolute: ${e.file_path}`);
        byFile.set(e.file_path, [...(byFile.get(e.file_path) ?? []), { e, n: i + 1 }]);
      });
      const fx = await openFx(host);
      try {
        const res = await Promise.all([...byFile].map(async ([p, items]) => {
          try {
            const raw = await fx.read(p).catch((e) => { throw new Error(errText(e, p)); });
            let t = raw.toString("utf8");
            if (!Buffer.from(t, "utf8").equals(raw)) throw new Error("file is not valid UTF-8 text");
            let reps = 0, at = -1, changed = 1;
            for (const { e, n } of items) {
              try {
                const r = applyEdit(t, e);
                if (at < 0) { at = r.at; changed = e.new_string.split("\n").length; }
                t = r.text; reps += r.count;
              } catch (err) { throw new Error(edits ? `edit #${n}: ${(err as Error).message}` : (err as Error).message); }
            }
            await fx.write(p, Buffer.from(t, "utf8"));
            return { p, ok: true as const, n: items.length, reps, snip: snippet(t, at, changed) };
          } catch (err) { return { p, ok: false as const, msg: (err as Error).message }; }
        }));
        if (!edits) {
          const r = res[0];
          if (!r.ok) throw new Error(`${r.msg} (${host}:${r.p})`);
          return text(`Edited ${host}:${r.p}: ${r.reps} replacement${r.reps === 1 ? "" : "s"}\n${r.snip}`);
        }
        const failed = res.filter((r) => !r.ok).length;
        const lines = res.map((r) => r.ok ? `OK ${host}:${r.p}: ${r.n} edit${r.n === 1 ? "" : "s"} (${r.reps} replacement${r.reps === 1 ? "" : "s"})` : `FAILED ${host}:${r.p} (not modified): ${r.msg}`);
        lines.push(`${res.length - failed} file${res.length - failed === 1 ? "" : "s"} changed${failed ? `, ${failed} left untouched` : ""}`);
        return { content: [{ type: "text" as const, text: lines.join("\n") }], isError: failed > 0 };
      } finally { fx.close(); }
    } catch (e) { return fail(e); }
  };
  server.registerTool("edit", {
    description: "Replace exact text in files on a host: the remote twin of the local Edit tool, and bulk-capable. old_string must match exactly and be unique in the file unless replace_all is set. " +
      "Pass file_path/old_string/new_string for one edit, or `edits` for up to 50 edits across files in one call: edits to the same file apply in order, and a file is written only if all of its edits succeed.",
    inputSchema: editShape,
  }, (a) => editTool(a));

  // ── v1.3: batch - several of the four tools above in one call. Each call from a model costs seconds of round trip
  // and thinking; the work itself takes milliseconds. So let one call carry a whole sequence of steps. ──
  const KINDS = ["bash", "read", "write", "edit"] as const;
  const opShape = z.object({
    bash: z.object(bashShape).omit({ host: true }).optional().describe("Run a command: arguments of the bash tool"),
    read: z.object(readShape).omit({ host: true }).optional().describe("Read files: arguments of the read tool"),
    write: z.object(writeShape).omit({ host: true }).optional().describe("Write files: arguments of the write tool"),
    edit: z.object(editShape).omit({ host: true }).optional().describe("Replace text in files: arguments of the edit tool"),
  });
  server.registerTool("batch", {
    description: "Run several steps on one host in ONE call: the fastest way to do multi-step work, because every separate tool call is a round trip. " +
      "Each op is exactly one of {bash}, {read}, {write}, {edit}, with the arguments of the tool of that name (without host). Ops run in order; the batch stops at the first failure " +
      "(non-zero exit, timeout, failed edit, missing file) and skips the rest, unless stop_on_error is false. A `cd` in one bash op carries to the later bash ops of the batch. " +
      "Returns one block per op and a summary line; the ops share the ~100 KB output budget.",
    inputSchema: {
      host: z.string().describe("Host name from list_hosts; every op runs there"),
      ops: z.array(opShape).min(1).max(30).describe("Steps to run, in order. Each is exactly one of {bash}, {read}, {write}, {edit}"),
      stop_on_error: z.boolean().default(true).describe("Stop at the first failed op and skip the rest (default). false: run them all"),
      cwd: z.string().optional().describe("Directory the first bash op starts in (default: home, or where the session is)"),
      session: z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/).optional().describe("Named bash session to use and update (as in bash). Default: a private one for this batch"),
    },
  }, async ({ host, ops, stop_on_error, cwd, session }): Promise<ToolOut> => {
    try {
      getHost(host);
      const kinds = ops.map((op, i) => {
        const k = KINDS.filter((x) => op[x] !== undefined);
        if (k.length !== 1) throw new Error(`op #${i + 1}: give exactly one of bash, read, write, edit (got ${k.length ? k.join(" + ") : "none"})`);
        return k[0];
      });
      const per = Math.max(3000, Math.floor((MAX_OUT - 2000) / ops.length)); // bytes of output each op may return
      const sess = session ?? `tmp+${randomBytes(6).toString("hex")}`;        // "+" cannot occur in a caller's session name
      const oneLine = (t: string) => { const l = t.trim().split("\n")[0]; return l.length > 80 ? `${l.slice(0, 77)}...` : l; };
      const content: Block[] = [];
      const say = (t: string) => { const last = content[content.length - 1]; if (last?.type === "text") last.text += t; else content.push({ type: "text", text: t }); };
      let okN = 0, failN = 0, skipN = 0, firstBash = true;
      const t0 = Date.now();
      for (let i = 0; i < ops.length; i++) {
        const op = ops[i], kind = kinds[i];
        const label = kind === "bash" ? oneLine(op.bash!.description ?? op.bash!.command)
          : kind === "read" ? op.read!.file_path ?? `${op.read!.files?.length ?? 0} files`
          : kind === "write" ? op.write!.file_path ?? `${op.write!.files?.length ?? 0} files`
          : op.edit!.file_path ?? `${op.edit!.edits?.length ?? 0} edits`;
        const head = `=== [${i + 1}/${ops.length}] ${kind} ${label} | `;
        if (failN > 0 && stop_on_error) { skipN++; say(`${head}skipped ===\n`); continue; }
        const s0 = Date.now();
        let out: ToolOut, ok: boolean;
        if (kind === "bash") {
          const a = op.bash!;
          const r = await runBash({ ...a, host, cwd: a.cwd ?? (firstBash ? cwd : undefined), session: a.session ?? sess }, per - 300, true);
          firstBash = false; out = r.out; ok = r.ok;
        } else {
          out = kind === "read" ? await readTool({ ...op.read!, host }, per) : kind === "write" ? await writeTool({ ...op.write!, host }) : await editTool({ ...op.edit!, host });
          ok = !out.isError;
        }
        if (ok) okN++; else failN++;
        say(`${head}${ok ? "ok" : "FAILED"} | ${((Date.now() - s0) / 1000).toFixed(2)}s ===\n`);
        for (const c of out.content) {
          if (c.type === "image") { content.push(c); continue; }
          const t = trunc(c.text, per + 1000);
          say(t === "" || t.endsWith("\n") ? t : `${t}\n`);
        }
      }
      say(`=== batch: ${okN} ok, ${failN} failed, ${skipN} skipped | ${((Date.now() - t0) / 1000).toFixed(2)}s ===`);
      return { content, isError: failN > 0 };
    } catch (e) { return fail(e); }
  });

  server.registerTool("bridge", {
    description: "Open a direct path from your own sandbox shell to this server, so files and command output move at network speed without passing through the model. " +
      "Returns a time-limited URL and a one-line installer for the `box` command (exec, put, get, push, pull, call). Use it for bulk transfers, whole directories, binaries, and scripted sequences of commands.",
    inputSchema: { ttl_hours: z.number().min(1).max(168).default(12).describe("How long the URL stays valid") },
  }, async ({ ttl_hours }) => {
    // A bridge URL must expire when it says it does, so it cannot be used to mint its own successor.
    if (viaBridge) return fail(new Error("A bridge URL cannot create another one - call the bridge tool through the connector itself"));
    const { exp, token } = mintBridgeToken(Math.round(ttl_hours * 3600));
    const url = `${base}/b/${token}`;
    return text([
      `Bridge URL (valid until ${new Date(exp * 1000).toISOString().slice(0, 16)}Z): ${url}`,
      "",
      "Install the client in your sandbox shell:",
      `  curl -fsS '${url}/cli' -o /tmp/box && bash /tmp/box install`,
      "",
      "Then, from that shell (HOST defaults to local; write HOST:/path for another host):",
      "  box exec -- 'uname -a; df -h /'          run a command: merged output, same exit code (`box exec -- -` reads a script from stdin)",
      "  box put ./file /remote/path [MODE]        upload one file, any size, binary-safe",
      "  box get /remote/path ./file               download one file (- writes to stdout)",
      "  box push ./dir /remote/dir [-x PATTERN]   upload a directory tree as one stream",
      "  box pull /remote/dir ./dir [-x PATTERN]   download a directory tree as one stream",
      "  box call TOOL '{json}'                    call any tool of this connector (ssh_spawn, edit, ...)",
      "Each command is one HTTPS request; run several at once with & or xargs -P for parallel transfers.",
    ].join("\n"));
  });

  return server;
}

const app = express();
const json = express.json({ limit: "20mb" }); // only on the MCP routes: bridge uploads must arrive unparsed

// Public base URL of this server as the caller reached it (the bridge tool hands it out); PUBLIC_URL overrides.
const publicBase = (req: express.Request) =>
  (process.env.PUBLIC_URL ?? `${String(req.headers["x-forwarded-proto"] ?? req.protocol).split(",")[0]}://${String(req.headers["x-forwarded-host"] ?? req.headers.host).split(",")[0]}`).replace(/\/+$/, "");

// Stateless Streamable HTTP: fresh server + transport per request.
const mcpHandler = async (req: express.Request, res: express.Response) => {
  const server = buildServer(publicBase(req), typeof (req.params as Record<string, string>).token === "string");
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => { transport.close(); server.close(); });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error(e);
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null });
  }
};
app.post(`/mcp/${SECRET}`, json, mcpHandler);
app.all(`/mcp/${SECRET}`, (_req, res) => { res.status(405).set("Allow", "POST").end(); });

// ── v1.2 bridge: /b/<token>/... lets a sandbox shell use this server directly (see the `bridge` tool). ──
// Same trust level as the secret path, but time-limited and only mintable through an authenticated MCP call.
const bridge = express.Router({ mergeParams: true });
const qstr = (v: unknown) => (typeof v === "string" ? v : undefined);
const qval = (req: express.Request, k64: string, k: string) => { const a = qstr(req.query[k64]); return a !== undefined ? Buffer.from(a, "base64url").toString("utf8") : qstr(req.query[k]); };
const qlist = (v: unknown): string[] => (Array.isArray(v) ? v : v === undefined ? [] : [v]).filter((x): x is string => typeof x === "string");
const plain = (res: express.Response, status: number, msg: string) => { res.status(status).type("text/plain").send(msg.endsWith("\n") ? msg : `${msg}\n`); };
const hostOf = (req: express.Request, res: express.Response): string | null => {
  const h = String(req.params.host);
  if (h in loadHosts()) return h;
  plain(res, 404, `Unknown host "${h}"`);
  return null;
};
const absPath = (req: express.Request, res: express.Response): string | null => {
  const p = qval(req, "p64", "path");
  if (p && p.startsWith("/")) return p;
  plain(res, 400, "an absolute path is required (p64=<base64url> or path=<urlencoded>)");
  return null;
};
const guarded = (fn: (req: express.Request, res: express.Response) => Promise<void>) => async (req: express.Request, res: express.Response) => {
  try { await fn(req, res); } catch (e) { console.error(e); if (res.headersSent) res.destroy(); else plain(res, 500, (e as Error).message); }
};

bridge.post("/mcp", json, mcpHandler);

bridge.get("/cli", (req, res) => {
  const script = readFileSync(new URL("./box.sh", import.meta.url), "utf8");
  const token = (req.params as Record<string, string>).token; // from the parent route /b/:token (mergeParams)
  res.type("text/plain").send(script.replaceAll("__BOX_URL__", `${publicBase(req)}/b/${token}`).replaceAll("__BOX_VERSION__", VERSION));
});

// GET /fs/<host>?p64=<path>  ->  the file's bytes
bridge.get("/fs/:host", guarded(async (req, res) => {
  const host = hostOf(req, res); if (!host) return;
  const p = absPath(req, res); if (!p) return;
  const st = await runScript(host, `f=${shq(p)}; [ -f "$f" ] && [ -r "$f" ] && wc -c < "$f"`, 30);
  if (st.code !== 0) return plain(res, 404, `No such readable file: ${host}:${p}`);
  const size = Number(st.stdout.trim());
  res.status(200).set({ "Content-Type": "application/octet-stream", "Content-Length": String(size) });
  const r = await streamExec(host, `head -c ${size} -- ${shq(p)}`, null, res);
  if (r.aborted || r.code !== 0) return void res.destroy(); // the client sees a broken transfer, never a silently short file
  res.end();
}));

// PUT /fs/<host>?p64=<path>[&mode=0644]  <-  request body becomes the file (parent directories are created).
// The bytes land next to the target and are renamed over it only when all of them arrived, so an interrupted
// upload never damages an existing file. An existing file keeps its mode and owner unless mode is given.
bridge.put("/fs/:host", guarded(async (req, res) => {
  const host = hostOf(req, res); if (!host) return;
  const p = absPath(req, res); if (!p) return;
  const mode = qstr(req.query.mode);
  if (mode !== undefined && !/^[0-7]{3,4}$/.test(mode)) return plain(res, 400, "mode must be octal, e.g. 0644");
  const want = req.headers["content-length"];
  if (want === undefined || !/^\d+$/.test(want)) return plain(res, 411, "Content-Length is required");
  const out = new PassThrough(); let wrote = ""; out.on("data", (d) => (wrote += d));
  const r = await streamExec(host, `f=${shq(p)}; if [ -L "$f" ]; then f=$(readlink -f -- "$f") || exit 1; fi
[ ! -d "$f" ] || { echo "Path is a directory: $f" >&2; exit 1; }
t="$f.part.$$"; trap 'rm -f -- "$t"' EXIT
mkdir -p -- "$(dirname -- "$f")" && cat > "$t" || exit 1
n=$(wc -c < "$t" | tr -d ' ')
[ "$n" = ${Number(want)} ] || { echo "incomplete upload: $n of ${Number(want)} bytes arrived" >&2; exit 3; }
if [ -e "$f" ]; then chown --reference="$f" -- "$t" 2>/dev/null; chmod --reference="$f" -- "$t" 2>/dev/null; fi
${mode ? `chmod ${mode} -- "$t" || exit 1` : ":"}
mv -f -- "$t" "$f" && echo "$n"`, req, out);
  if (r.aborted) return void res.destroy();
  if (r.code !== 0) return plain(res, 500, r.stderr.trim() || `write failed (exit ${r.code})`);
  plain(res, 200, `wrote ${wrote.trim()} bytes to ${host}:${p}`);
}));

// GET /tar/<host>?p64=<dir>[&x64=<exclude pattern>...]  ->  the directory tree as tar.gz
bridge.get("/tar/:host", guarded(async (req, res) => {
  const host = hostOf(req, res); if (!host) return;
  const dir = absPath(req, res); if (!dir) return;
  const ex = [...qlist(req.query.x), ...qlist(req.query.x64).map((x) => Buffer.from(x, "base64url").toString("utf8"))];
  const chk = await runScript(host, `[ -d ${shq(dir)} ] && [ -r ${shq(dir)} ]`, 30);
  if (chk.code !== 0) return plain(res, 404, `No such readable directory: ${host}:${dir}`);
  res.status(200).set({ "Content-Type": "application/gzip" });
  const r = await streamExec(host, `tar -C ${shq(dir)} ${ex.map((x) => `--exclude=${shq(x)}`).join(" ")} -czf - .`, null, res);
  // tar exits 1 when a file changed while it was read (the archive is still good); anything worse breaks the transfer
  if (r.aborted || r.code === null || r.code > 1) { if (!r.aborted) console.error(`tar ${host}:${dir} failed (exit ${r.code}): ${r.stderr.trim()}`); return void res.destroy(); }
  res.end();
}));

// PUT /tar/<host>?p64=<dir>  <-  a tar.gz stream, unpacked into the directory (created if missing)
bridge.put("/tar/:host", guarded(async (req, res) => {
  const host = hostOf(req, res); if (!host) return;
  const dir = absPath(req, res); if (!dir) return;
  const r = await streamExec(host, `d=${shq(dir)}; mkdir -p -- "$d" && tar -C "$d" --no-same-owner -xzf -`, req, new PassThrough().resume());
  if (r.aborted) return void res.destroy();
  if (r.code !== 0) return plain(res, 500, r.stderr.trim() || `unpack failed (exit ${r.code})`);
  plain(res, 200, `unpacked into ${host}:${dir}`);
}));

// POST /exec/<host>[?timeout=<sec>&c64=<cwd>]  body = command  ->  merged output of any size, streamed;
// the command's exit code is in the X-Exit-Code header.
bridge.post("/exec/:host", express.text({ type: () => true, limit: "1mb" }), guarded(async (req, res) => {
  const host = hostOf(req, res); if (!host) return;
  const command = typeof req.body === "string" ? req.body : "";
  if (!command.trim()) return plain(res, 400, "the request body must be the command to run");
  if (Buffer.byteLength(command) > MAX_PAYLOAD) return plain(res, 413, `command too large (max ${MAX_PAYLOAD} bytes) - upload it as a script and run that`);
  const t = Math.min(1800, Math.max(1, Math.floor(Number(qstr(req.query.timeout) ?? 120)) || 120));
  // The script answers with one header line, "rc=<exit code> size=<bytes>", then the output itself.
  let head: Buffer | null = Buffer.alloc(0), started = false;
  const body = new Transform({
    transform(chunk: Buffer, _enc, cb) {
      if (head === null) return cb(null, chunk);
      head = Buffer.concat([head, chunk]);
      const nl = head.indexOf(10);
      const m = nl < 0 ? null : /^rc=(-?\d+) size=(\d+)$/.exec(head.subarray(0, nl).toString("latin1"));
      if (!m) return cb(nl < 0 && head.length < 64 ? null : new Error("unexpected output from the exec script"));
      started = true;
      res.status(200).set({ "Content-Type": "text/plain; charset=utf-8", "Content-Length": m[2], "X-Exit-Code": m[1] });
      const rest = head.subarray(nl + 1);
      head = null;
      cb(null, rest);
    },
  });
  body.on("error", () => {});
  res.once("close", () => { if (!res.writableFinished) body.destroy(); }); // client gone: stop the script
  body.pipe(res);
  const r = await streamExec(host, bashScript({ command, timeoutSec: t, cwd: qval(req, "c64", "cwd"), raw: true }), null, body);
  if (!started) { body.unpipe(res); return res.destroyed ? undefined : plain(res, 500, r.stderr.trim() || `exec failed (exit ${r.code})`); }
  if (r.aborted || r.code !== 0) return void res.destroy();
  body.end();
}));

app.use("/b/:token", (req, res, next) => { if (bridgeTokenOk(String(req.params.token))) next(); else res.status(404).end(); }, bridge);

app.use((_req, res) => { res.status(404).end(); });

app.listen(PORT, "127.0.0.1", () => console.log(`ssh-mcp listening on 127.0.0.1:${PORT}`));
