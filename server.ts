// SSH connector as a remote MCP server.
// Claude -> HTTPS -> this server (on your VPS) -> SSH/SFTP -> any host in hosts.json
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { Client, type ClientChannel, type ConnectConfig, type ParsedKey, type SFTPWrapper } from "ssh2";
import { exec, execFile, spawn } from "node:child_process";
import { readFileSync, constants as fsc, promises as fs } from "node:fs";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import { homedir, hostname, userInfo } from "node:os";
import { createServer as netServer, type Socket } from "node:net";
import type { IncomingMessage } from "node:http";
import { dirname, join, resolve as resolvePath } from "node:path";
import { Duplex, PassThrough, Transform, type Readable, type Writable } from "node:stream";
import { createRequire } from "node:module";

// ssh2 is CommonJS and Node cannot see its `utils` as a named export, so it is taken from the module object.
const sshUtils = (createRequire(import.meta.url)("ssh2") as typeof import("ssh2")).utils;

const PORT = Number(process.env.PORT ?? 8787);
const SECRET = process.env.MCP_SECRET ?? "";
const HOSTS_FILE = process.env.HOSTS_FILE ?? "./hosts.json";
const MAX_OUT = 100_000;
const JOBS_DIR = process.env.JOBS_DIR ?? "/var/lib/ssh-mcp/jobs"; // ssh_spawn: <jobId>.log / .exit / .pid / .cmd / .sh
const MAX_PAYLOAD = 64 * 1024; // bytes of command/code sent inline (base64) in one shell argument
const VERSION = "1.9.0";
// Sent to the client at initialize; clients put it in front of the model. Keep it short: it costs tokens in every conversation.
const INSTRUCTIONS = `Remote shell and files on the hosts from list_hosts ("local" = the machine this connector runs on).
Every tool call is a round trip, so do as much as possible per call:
- batch: several bash / read / write / edit steps in ONE call, in order, stopping at the first failure. Prefer it for any multi-step work (change files, then build or test, then look at the result).
- read / write / edit take \`files\` / \`edits\` arrays: many files in one call.
- ssh_exec_many: up to 10 independent commands at the same time.
- bash: join steps with && or newlines instead of separate calls; pass quiet: true when only success or failure matters (the full output stays in a file on the host); use run_in_background plus ssh_job (wait) for anything that takes more than a minute.
- bridge: large, binary or many files, moved directly from a sandbox shell.
- audit: the log of every call made through this connector, from any chat or client.
- add_host: connect another server (it tells you what to do on that server); tunnel: true for one this connector cannot reach.
A few catastrophic commands (deleting /, formatting a disk, powering off) are refused unless the call says confirm: true; only pass it when the user really wants that.
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
  pq?: boolean;             // v1.6: true = post-quantum key exchange on the wire (see below); false = add_host found it impossible
  pqWhy?: string;           //       ... and why
  pqVia?: string;           //       where that server's SSH is as the server itself sees it ("ip:port"), when it is not 127.0.0.1:<port>
  tunnel?: { id: string; key: string; to: number }; // v1.8: the host comes in through a tunnel it opens itself (see below): id = the
                            //       secret part of its address here, key = its tunnel key ("ssh-ed25519 AAAA..."), to = its SSH port there
};

const loadHosts = (): Record<string, HostCfg> => JSON.parse(readFileSync(HOSTS_FILE, "utf8"));
const trunc = (s: string, max = MAX_OUT) => (s.length > max ? s.slice(0, max) + `\n…[truncated ${s.length - max} chars]` : s);

function getHost(name: string): HostCfg {
  const cfg = loadHosts()[name];
  if (!cfg) throw new Error(`Unknown host "${name}". Known: ${Object.keys(loadHosts()).join(", ")}`);
  return cfg;
}

// ── v1.6: post-quantum key exchange for remote hosts ────────────────────────────────────────────
// ssh2, the SSH library used here, has no post-quantum key exchange; OpenSSH has had one since 9.0. So for a host
// marked "pq": true the connection that crosses the network is made by this machine's `ssh`: key exchange
// restricted to the post-quantum ones, host key pinned, and all it does is carry bytes to that server's own SSH
// port (ssh -W). The ssh2 connection - commands, SFTP, everything - runs inside it, so whatever is recorded on the
// wire is protected by the outer key exchange. add_host decides this per host and writes it down; a host that was
// added as post-quantum never falls back to a classical connection by itself.
//   PQ_SSH=off      never do this: every host is connected to as in 1.5
//   PQ_SSH=require  refuse every remote host that is not post-quantum
const PQ_MODE: "auto" | "off" | "require" = /^(off|0|false|no)$/i.test(process.env.PQ_SSH ?? "") ? "off" : /^(require|required|only)$/i.test(process.env.PQ_SSH ?? "") ? "require" : "auto";
const PQ_KEX = ["mlkem768x25519-sha256", "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com"]; // best first
type HostKey = { fp: string; type: string; blob: Buffer };
type PqFail = { pqFail: true; kind: "nossh" | "nokex" | "forward" | "noroute" | "hostkey" | "innerkey" | "auth" | "down" | "other"; why: string };
type Carried = { client: Client; kex: string };
const pqFail = (kind: PqFail["kind"], why: string): PqFail => ({ pqFail: true, kind, why });
const isPqFail = (e: unknown): e is PqFail => typeof e === "object" && e !== null && (e as PqFail).pqFail === true;
const fingerprintOf = (key: Buffer) => `SHA256:${createHash("sha256").update(key).digest("base64").replace(/=+$/, "")}`;
const samePin = (fp: string) => `SHA256:${fp.replace(/^SHA256:/, "").replace(/=+$/, "")}`;
const keyTypeOf = (key: Buffer) => { const n = key.length >= 4 ? key.readUInt32BE(0) : 0; return n > 0 && n < 64 && key.length >= 4 + n ? key.subarray(4, 4 + n).toString("latin1") : "unknown"; };

// The post-quantum key exchanges this machine's OpenSSH client knows: [] when it has none, or there is no client.
let pqClient: Promise<string[]> | null = null;
const pqHere = (): Promise<string[]> => (pqClient ??= new Promise<string[]>((res) => execFile("ssh", ["-Q", "kex"], { timeout: 10_000 }, (err, out) => {
  const have = err ? [] : String(out).split("\n").map((l) => l.trim()), list = PQ_KEX.filter((k) => have.includes(k));
  if (!list.length) pqClient = null; // ask again next time: a client can be installed later
  res(list);
})));

// The host key a server presents, and nothing else: the connection is dropped before any login is tried.
function presentedKey(host: string, port: number, username: string): Promise<HostKey | { err: string }> {
  return new Promise((done) => {
    const c = new Client();
    let got: HostKey | undefined, settled = false;
    const finish = (r: HostKey | { err: string }) => { if (settled) return; settled = true; clearTimeout(timer); c.destroy(); done(r); };
    const timer = setTimeout(() => finish(got ?? { err: "timed out after 20 s" }), 20_000);
    c.on("error", (e: Error) => finish(got ?? { err: e.message }));
    c.on("close", () => finish(got ?? { err: "the connection was closed" }));
    c.connect({
      host, port, username, readyTimeout: 15_000,
      hostVerifier: (key: Buffer) => { got = { fp: fingerprintOf(key), type: keyTypeOf(key), blob: Buffer.from(key) }; setImmediate(() => finish(got!)); return false; },
    });
  });
}
// The full host key behind a pinned fingerprint: OpenSSH's known_hosts needs the key itself. It is asked from the
// server once per start and checked against the pin (add_host puts it here directly).
const pqKeys = new Map<string, HostKey>();
const pqKeyId = (host: string, port: number, fp: string) => `${host}:${port}:${samePin(fp)}`;
async function pinnedKey(cfg: HostCfg): Promise<HostKey> {
  const port = cfg.port ?? 22, id = pqKeyId(cfg.host!, port, cfg.hostFingerprint!), known = pqKeys.get(id);
  if (known) return known;
  const got = await presentedKey(cfg.host!, port, cfg.username ?? "");
  if ("err" in got) throw pqFail("down", got.err);
  if (got.fp !== samePin(cfg.hostFingerprint!)) throw pqFail("hostkey", "");
  pqKeys.set(id, got);
  return got;
}
async function knownHosts(alias: string, key: HostKey): Promise<string> {
  let last: unknown;
  for (const dir of [join(dirname(JOBS_DIR), "pq"), join(homedir(), ".ssh-mcp", "pq")]) {
    try {
      const file = join(dir, alias), line = `${alias} ${key.type} ${key.blob.toString("base64")}\n`;
      if ((await fs.readFile(file, "utf8").catch(() => "")) === line) return file;
      await mkdirp(dir);
      await fs.chmod(dir, 0o700);
      const tmp = `${file}.${randomBytes(4).toString("hex")}.tmp`;
      await fs.writeFile(tmp, line, { mode: 0o600 });
      await fs.rename(tmp, file);
      return file;
    } catch (e) { last = e; }
  }
  throw new Error(`cannot write the known-hosts file for the post-quantum connection: ${(last as Error).message}`);
}
// At most three connections to one server are being set up at a time: each is, for a moment, two connections that
// have not logged in yet, and sshd starts dropping those at ten (MaxStartups).
const pqGates = new Map<string, { busy: number; waiting: (() => void)[] }>();
async function pqGate<T>(id: string, fn: () => Promise<T>): Promise<T> {
  const g = pqGates.get(id) ?? { busy: 0, waiting: [] };
  pqGates.set(id, g);
  if (g.busy >= 3) await new Promise<void>((go) => g.waiting.push(go)); else g.busy++;
  try { return await fn(); } finally { const next = g.waiting.shift(); if (next) next(); else if (--g.busy === 0) pqGates.delete(id); }
}
// Why the outer connection did not come up, from what the OpenSSH client said as it stopped.
function pqFailure(log: string, inner: (Error & { level?: string }) | null, spawnErr: NodeJS.ErrnoException | null, via: string): PqFail {
  const said = log.split("\n").map((l) => l.trim()).filter((l) => l && !/^(debug1:|Authenticated to |Warning: Permanently added )/.test(l)), last = said[said.length - 1] ?? "";
  if (spawnErr) return pqFail("nossh", "this machine has no OpenSSH client with post-quantum key exchange");
  if (/Host key for .* has changed|Host key verification failed|No \S+ host key is known/.test(log)) return pqFail("hostkey", "");
  if (/no matching key exchange method found/.test(log)) return pqFail("nokex", "that server's SSH offers no post-quantum key exchange; OpenSSH 9.0 and newer do");
  if (/open failed: administratively prohibited/.test(log)) return pqFail("forward", "that server does not allow TCP forwarding for this login: AllowTcpForwarding, or an option on the key");
  if (/open failed: connect failed/.test(log)) return pqFail("noroute", `that server's SSH cannot be reached at ${via} from the server itself`);
  if (/Permission denied \(/.test(log)) return /bad permissions|are too open/.test(log) ? pqFail("other", "OpenSSH refuses the key file: its permissions are too open") : pqFail("auth", "the server refused the login made by the OpenSSH client");
  if (inner?.level === "client-authentication") return pqFail("auth", "the server refused the login");
  // the outer connection is fine, but what it was led to is not the pinned server: on that machine, another SSH server has this port
  if (inner && /verification failed|Host denied/i.test(inner.message)) return pqFail("innerkey", `what answers at ${via} on that server is another SSH server`);
  if (/^ssh: connect to host |Could not resolve hostname|timed out|Connection reset by peer|kex_exchange_identification|Connection closed by remote host/m.test(said.join("\n"))) return pqFail("down", last);
  return pqFail("other", (last || inner?.message || "the OpenSSH client stopped").slice(0, 300));
}
// The outer connection, as OpenSSH is told to make it: nothing from any ssh_config, this key only, the pinned host
// key only, post-quantum key exchange only.
type PqTarget = { host: string; port: number; username: string; keyPath: string; key: HostKey; kex: string[] };
const pqEnv = () => ({ PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin", HOME: homedir(), LC_ALL: "C" });
async function pqArgs(o: PqTarget, logLevel: string): Promise<string[]> {
  const algos = o.key.type === "ssh-ed25519" || /^ecdsa-sha2-nistp(256|384|521)$/.test(o.key.type) ? o.key.type : o.key.type === "ssh-rsa" ? "rsa-sha2-512,rsa-sha2-256" : "";
  if (!algos) throw pqFail("other", `its host key is of a kind (${o.key.type}) this connection does not handle`);
  const alias = `sshmcp-${createHash("sha256").update(pqKeyId(o.host, o.port, o.key.fp)).digest("hex").slice(0, 16)}`, kh = await knownHosts(alias, o.key);
  const lit = (path: string) => path.replace(/%/g, "%%"); // OpenSSH expands %-tokens in file names
  const file = /\s/.test(kh) ? `"${lit(kh)}"` : lit(kh);
  return ["-F", "none", "-i", lit(o.keyPath), "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
    "-o", "StrictHostKeyChecking=yes", "-o", `UserKnownHostsFile=${file}`, "-o", `GlobalKnownHostsFile=${file}`, "-o", `HostKeyAlias=${alias}`, "-o", `HostKeyAlgorithms=${algos}`,
    "-o", `KexAlgorithms=${o.kex.join(",")}`, "-o", "UpdateHostKeys=no", "-o", "CheckHostIP=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=15",
    "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", "-o", `LogLevel=${logLevel}`, "-p", String(o.port), "-l", o.username];
}
// Behind a port mapping (a container, a router) or with an SSH server bound to one address, the server's SSH is
// not at 127.0.0.1:<the port we connect to> as seen from the server. The server knows where it accepted us: asked
// over a post-quantum connection of its own, it answers "ip:port" - or null when it cannot be asked.
async function ownSshAddress(o: PqTarget): Promise<string | null> {
  try {
    const args = [...await pqArgs(o, "ERROR"), "-T", "--", o.host, 'echo "$SSH_CONNECTION"'];
    const out = await new Promise<string>((res) => { const ch = execFile("ssh", args, { timeout: 25_000, env: pqEnv() }, (_e, stdout) => res(String(stdout ?? ""))); ch.stdin?.end(); });
    const [, , ip, port] = out.trim().split(/\s+/);
    if (!ip || !/^[0-9A-Fa-f:.]{2,45}$/.test(ip) || !/^\d{1,5}$/.test(port ?? "") || Number(port) < 1 || Number(port) > 65535) return null;
    return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
  } catch { return null; }
}
// One connection with post-quantum key exchange on the wire: `ssh -W` as the carrier, the ssh2 client inside it.
// `via` is where the server's own SSH is, as seen from the server. Resolves when the inner client is ready;
// rejects with a PqFail.
function carried(o: PqTarget & { via: string; privateKey: Buffer }): Promise<Carried> {
  return pqArgs(o, "DEBUG1").then((args) => new Promise<Carried>((resolve, reject) => {
    let child: ReturnType<typeof spawn>;
    try { child = spawn("ssh", [...args, "-W", o.via, "--", o.host], { stdio: ["pipe", "pipe", "pipe"], env: pqEnv() }); }
    catch { return reject(pqFail("nossh", "this machine's OpenSSH client could not be started")); }
    const [stdin, stdout, stderr] = [child.stdin!, child.stdout!, child.stderr!];
    let log = "", settled = false, closed = false, spawnErr: NodeJS.ErrnoException | null = null;
    stderr.on("data", (d: Buffer) => { log = (log + d).slice(-65536); });
    child.on("error", (e: NodeJS.ErrnoException) => { spawnErr = e; closed = true; });
    child.on("close", () => { closed = true; });
    stdin.on("error", () => {});
    stdout.on("error", () => {});
    const sock = Duplex.from({ readable: stdout, writable: stdin });
    sock.on("error", () => {});
    const c = new Client();
    const fail = (inner: (Error & { level?: string }) | null) => {
      if (settled) return;
      settled = true;
      c.destroy();
      const done = () => { clearTimeout(wait); child.kill("SIGKILL"); reject(pqFailure(log, inner, spawnErr, o.via)); };
      const wait = setTimeout(done, 3000); // the reason is in what OpenSSH says as it stops: give it a moment to say it
      if (closed) done(); else { child.once("close", done); child.once("error", done); }
    };
    // The inner client is ready. Believe it only if OpenSSH itself reported a post-quantum key exchange for the outer one.
    const ready = (tries: number) => {
      const kex = /^debug1: kex: algorithm: (\S+)/m.exec(log)?.[1] ?? "";
      if (!kex && tries > 0) return void setTimeout(() => ready(tries - 1), 50); // its report can be a moment behind
      if (!PQ_KEX.includes(kex)) return fail(new Error(`the outer connection reported the key exchange "${kex || "?"}", which is not a post-quantum one`));
      if (settled) return;
      settled = true;
      c.on("close", () => child.kill());
      resolve({ client: c, kex });
    };
    c.on("ready", () => ready(10));
    c.on("error", (e: Error & { level?: string }) => fail(e));
    c.on("close", () => fail(null));
    c.connect({ sock, username: o.username, privateKey: o.privateKey, readyTimeout: 20_000, keepaliveInterval: 5_000, keepaliveCountMax: 2, hostVerifier: (key: Buffer) => fingerprintOf(key) === o.key.fp });
  }));
}
// ── v1.7: the post-quantum connection is kept and shared ─────────────────────────────────────────
// Making one costs two SSH handshakes, so it is not thrown away after a call. An unused one stays open for
// PQ_SSH_KEEP seconds (60; 0 = a new one for every call), and up to four calls run on one at the same time.
// What a caller gets is a lease: it opens its channels on the shared connection and, when the caller is done or
// gives up, closes those and nothing else.
const PQ_KEEP = (() => { const v = (process.env.PQ_SSH_KEEP ?? "").trim(), n = Number(v); return v !== "" && Number.isFinite(n) && n >= 0 ? n : 60; })() * 1000;
const PQ_SHARE = 4; // calls on one connection at a time; a call may hold two channels, and sshd takes 10 per connection unless told otherwise
// What the code that talks to a host needs from a connection: an ssh2 client of its own, or a lease on a shared one.
type Conn = {
  exec(command: string, cb: (err: Error | undefined, stream: ClientChannel) => void): unknown;
  sftp(cb: (err: Error | undefined, sftp: SFTPWrapper) => void): unknown;
  end(): unknown;
  destroy(): unknown;
};
type Shared = { ready: Promise<void>; client: Client | null; kex: string; leases: number; cap: number; dead: boolean; idle: NodeJS.Timeout | null; retire(): void };
const pqPool = new Map<string, Shared[]>(); // by server, login and pinned key
const pqCap = new Map<string, number>();    // learned about a server that takes fewer sessions per connection than usual

function pqShared(id: string, gate: string, o: PqTarget & { via: string; privateKey: Buffer }): Shared {
  const list = pqPool.get(id) ?? [];
  pqPool.set(id, list);
  const s: Shared = {
    ready: Promise.resolve(), client: null, kex: "", leases: 0, cap: PQ_KEEP ? Math.min(PQ_SHARE, pqCap.get(id) ?? PQ_SHARE) : 1, dead: false, idle: null,
    retire() {
      s.dead = true;
      if (s.idle) clearTimeout(s.idle);
      const at = list.indexOf(s);
      if (at >= 0) list.splice(at, 1);
      if (!list.length && pqPool.get(id) === list) pqPool.delete(id);
    },
  };
  list.push(s);
  // "end": the connection is going (its carrier's output has ended), and from then on ssh2 refuses to start anything on it
  s.ready = pqGate(gate, () => carried(o)).then(({ client, kex }) => { s.client = client; s.kex = kex; client.on("end", s.retire).on("close", s.retire); }, (e) => { s.retire(); throw e; });
  s.ready.catch(() => {}); // whoever waits for it gets the reason; nobody waiting is not an error
  return s;
}
function pqRelease(s: Shared): void {
  if (--s.leases > 0) return;
  if (s.dead) return void s.client?.end(); // taken out of use while calls were still on it: now it can go
  const close = () => { if (s.leases > 0 || s.dead) return; s.retire(); s.client?.end(); };
  if (!PQ_KEEP) return close();
  s.idle = setTimeout(close, PQ_KEEP);
  s.idle.unref();
}
// A lease on `first`. `another` gives a connection of its own, for the one case a call is moved: it could not
// even start on the shared one, because that had died unnoticed or the server takes fewer sessions than assumed.
// If no other connection can be made either, `explain` turns the reason for that into the error the caller gets.
function pqLeaseOn(first: Shared, id: string, another: () => Promise<Shared>, explain: (e: unknown) => Error): Conn {
  let cur = first, done = false, opened = 0;
  const mine = new Set<() => void>(); // how to close each channel this lease still has open
  const open = <T extends { once(event: "close", fn: () => void): unknown }>(start: (c: Client, cb: (err: Error | undefined, ch: T) => void) => void,
    shut: (ch: T) => void, cb: (err: Error | undefined, ch: T) => void, again = true): void => {
    if (done) return void cb(new Error("this connection was already given back"), undefined as never);
    const on = cur;
    const got = (err: Error | undefined, ch: T): void => {
      if (err) {
        if (!again || opened > 0 || done) return void cb(err, ch);
        if ((err as { reason?: unknown }).reason === undefined) on.retire(); // it stands, but starts nothing any more: no further call is put on it
        else if (on.leases > 1) { // the server refused one more session on this connection: remember how many it takes
          on.cap = Math.max(1, on.leases - 1);
          pqCap.set(id, Math.min(pqCap.get(id) ?? PQ_SHARE, on.cap));
        }
        return void another().then((s) => {
          if (done) return pqRelease(s);
          pqRelease(on);
          cur = s;
          open(start, shut, cb, false);
        }, (e) => cb(explain(e), ch));
      }
      opened++;
      const close = () => shut(ch);
      mine.add(close);
      ch.once("close", () => mine.delete(close));
      if (done) close(); // the caller gave up while the channel was being opened
      cb(undefined, ch);
    };
    // ssh2 throws instead of calling back when the connection has just gone ("Not connected"): the same as any failure to start
    try { start(on.client!, got); } catch (e) { got(e instanceof Error ? e : new Error(String(e)), undefined as never); }
  };
  const finish = () => {
    if (done) return;
    done = true;
    for (const close of [...mine]) { try { close(); } catch { /* already gone */ } }
    pqRelease(cur);
  };
  return {
    exec: (command, cb) => open<ClientChannel>((c, got) => c.exec(command, got), (ch) => ch.close(), cb),
    sftp: (cb) => open<SFTPWrapper>((c, got) => c.sftp(got), (sftp) => sftp.end(), cb),
    end: finish,
    destroy: finish,
  };
}
async function pqLease(cfg: HostCfg, label: string): Promise<Conn> {
  if (!cfg.hostFingerprint) throw new Error(`"${label}" has "pq": true but no hostFingerprint: a post-quantum connection needs the host key to be pinned.`);
  if (!cfg.privateKeyPath || cfg.passphraseEnv || cfg.passwordEnv) throw new Error(`"${label}" has "pq": true, which needs privateKeyPath to be a key file without a passphrase (no passphraseEnv, no passwordEnv).`);
  const kex = await pqHere();
  if (!kex.length) throw pqFail("nossh", "this machine has no OpenSSH client with post-quantum key exchange");
  const key = await pinnedKey(cfg), port = cfg.port ?? 22, via = cfg.pqVia ?? `127.0.0.1:${port}`, keyPath = cfg.privateKeyPath, username = cfg.username ?? "";
  const id = [cfg.host, port, via, username, keyPath, key.fp].join("|");
  const take = async (own: boolean): Promise<Shared> => {
    const s = (own ? undefined : pqPool.get(id)?.find((x) => !x.dead && x.leases < x.cap))
      ?? pqShared(id, `${cfg.host}:${port}`, { host: cfg.host!, port, via, username, keyPath, privateKey: readFileSync(keyPath), key, kex });
    s.leases++;
    if (s.idle) { clearTimeout(s.idle); s.idle = null; }
    try { await s.ready; } catch (e) { s.leases--; throw e; }
    if (s.dead) { s.leases--; return take(true); } // it closed while this call was waiting for it
    return s;
  };
  const first = await take(false);
  auditNote({ kex: first.kex });
  return pqLeaseOn(first, id, () => take(true), (e) => (isPqFail(e) ? pqError(label, cfg, e) : e instanceof Error ? e : new Error(String(e))));
}
function pqError(label: string, cfg: HostCfg, f: PqFail): Error {
  const at = `${cfg.host}:${cfg.port ?? 22}`;
  if (f.kind === "hostkey") return new Error(`The host key of ${at} is not the pinned one (${cfg.hostFingerprint}): host key verification failed. Nothing was run.`);
  if (f.kind === "innerkey") return new Error(`${at}: ${f.why}, not the pinned one (${cfg.hostFingerprint}): host key verification failed. Nothing was run.`);
  if (f.kind === "down") return new Error(`Cannot reach ${at} over SSH: ${f.why}`);
  if (f.kind === "auth") return new Error(`${at} did not accept the key for ${cfg.username}: ${f.why}. Nothing was run.`);
  return new Error(`"${label}" is a post-quantum host, and a post-quantum connection to it is not possible right now: ${f.why}. Nothing was run. ` +
    `It does not fall back by itself. If the change is lasting and a classical key exchange is acceptable for this host, set "pq": false for it in ${resolvePath(HOSTS_FILE)} or add it again with add_host (replace: true).`);
}

async function connect(cfg: HostCfg, name = ""): Promise<Conn> {
  const label = name || String(cfg.host);
  if (cfg.pq === true && PQ_MODE !== "off") {
    try { return await pqLease(cfg, label); }
    catch (e) { throw isPqFail(e) ? pqError(label, cfg, e) : e; }
  }
  if (PQ_MODE === "require" && !cfg.tunnel) throw new Error(`"${label}" is not a post-quantum host, and this connector only connects to hosts that are (PQ_SSH=require). Add it again with add_host (replace: true): that tries post-quantum key exchange first.`);
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
  return new Promise<Conn>((resolve, reject) => {
    const c = new Client();
    c.on("ready", () => resolve(c))
      .on("error", (e: Error) => reject(cfg.tunnel && /ECONNREFUSED/.test(e.message) ? tunnelClosed(label) : e))
      .connect(opts);
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
  const conn = await connect(cfg, name);
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
  const conn = await connect(getHost(name), name);
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
  // whole seconds slept, counted: bash's $SECONDS counts second boundaries crossed, and a shell that starts late in a
  // second can see 2 of them after one second
  if (action === "wait") return `${head}
n=0
while [ ! -f "$D/$id.exit" ] && [ "$n" -lt ${timeoutSec} ]; do
  alive "$(cat "$D/$id.pid" 2>/dev/null)" "$id" || break
  sleep 1
  n=$((n + 1))
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
  const conn = await connect(cfg, name);
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
    let stderr = "", aborted = false, settled = false, kill = () => {}, src: Readable | null = null;
    const abort = () => {
      if (settled || aborted) return;
      aborted = true;
      // The output was going to `stdout` and has stopped with it; whatever is still on its way now runs off to nowhere,
      // so the end of the script is seen as soon as it is gone, and its pipe or channel is closed.
      if (src) { src.unpipe(stdout); src.resume(); }
      kill();
      setTimeout(() => finish(null), 5000).unref();
    };
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
      src = child.stdout!;
      child.stdout!.pipe(stdout, { end: false });
      if (stdin) { child.stdin!.on("error", () => {}); stdin.pipe(child.stdin!); }
      child.on("close", finish);
      return;
    }
    connect(cfg, name).then((conn) => {
      kill = () => conn.destroy();
      if (aborted) { conn.destroy(); return finish(null); }
      conn.exec(`bash -c ${shq(script)}`, (err, stream) => {
        if (err) { conn.end(); return fail(err); }
        stream.stderr.on("data", onErr);
        src = stream;
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

// ── v1.4: audit log ───────────────────────────────────────────────────────────────────────────────────────────
// One JSON object per line in <state dir>/audit/audit.jsonl (the state dir is where jobs/, sessions/ and out/
// live), readable only by the user the server runs as:
//   {"t","id","via","ip","ua","tool","host","what",...}  written BEFORE the call runs, so a command that takes
//                                                         the server down with it is still on record
//   {"t","id","ok","exit","err","ms",...}                the result, written when the call returns
//   {"t","event":"start","version","pid"}                every start of the server
// File contents are never logged, only paths and sizes. Commands are logged after masking what looks like a
// credential: best effort, not a guarantee. The log lives on the machine it describes, so whoever holds the
// connector URL can also delete it; forward it somewhere else if it has to survive that.
type Who = { via: "mcp" | "bridge" | "tunnel"; ip: string; ua?: string; tok?: string };
type AuditInfo = { host?: string; what?: string; bytes?: number; cwd?: string; bg?: boolean; batch?: string };
type AuditEnd = { ok: boolean; err?: string; exit?: number | null; bytes?: number; kex?: string };
type Args = Record<string, any>; // tool arguments (already validated against the tool's schema) or a parsed log line

const envNum = (name: string, dflt: number) => { const v = process.env[name]; const n = v === undefined || v.trim() === "" ? NaN : Number(v); return Number.isFinite(n) ? n : dflt; };
const AUDIT_OFF = /^(off|0|false|no)$/i.test(process.env.AUDIT_LOG ?? "");
const AUDIT_MAX = Math.max(1024, Math.round(envNum("AUDIT_MAX_MB", 20) * 1024 * 1024)); // a file never grows past this: it is rotated first
const AUDIT_KEEP = Math.min(50, Math.max(0, Math.floor(envNum("AUDIT_KEEP", 5))));       // rotated files kept: audit.jsonl.1 (newest) ... .N
const AUDIT_CLIP = 2000;                                                                 // longest "what" kept per entry
const AUDIT_TAIL = 4 * 1024 * 1024;                                                      // how much of the end of a file the audit tool searches
let auditFile = "", auditSize = 0, auditIno = 0, auditErr = "", auditQueue: Promise<void> = Promise.resolve();

const REDACTIONS: [RegExp, string][] = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[private key]"],
  [/\b[0-9a-z]{6,12}\.[0-9a-f]{32}\b/g, "[bridge token]"],
  [/(\bBearer\s+)[A-Za-z0-9._~+\/=-]{8,}/gi, "$1***"],
  [/(--?(?:pass(?:word|phrase)?|token|secret|api[_-]?key|access[_-]?key)\s+)(?:"[^"]*"|'[^']*'|[^\s-]\S*)/gi, "$1***"],                                                        // --token VALUE
  [/((?:pass(?:word|wd|phrase)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization|credentials?)[\w-]{0,40}["']?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s&;|'"]+)/gi, "$1***"], // KEY=VALUE, "key": "value"
];
const redact = (s: string) => REDACTIONS.reduce((t, [re, to]) => t.replace(re, to), s.split(SECRET).join("[connector secret]"));
const clip = (s: string, max = AUDIT_CLIP) => (s.length > max ? `${s.slice(0, max)}…[+${s.length - max} chars]` : s);
// Text for the log: masked first and cut afterwards, so a credential that straddles the cut is not half-kept.
// Only the first 16 KB are looked at, which bounds the work whatever the size of the command.
const auditText = (s: string, max = AUDIT_CLIP) => {
  const head = redact(s.slice(0, 16_384));
  return head.length > max || s.length > 16_384 ? `${head.slice(0, max)}…[+${Math.max(1, s.length - max)} chars]` : head;
};

// Who is calling. Behind the reverse proxy the peer is always loopback, and the right-most X-Forwarded-For
// entry is the address the proxy itself saw (entries further left are whatever the client chose to send).
function whoOf(req: express.Request | IncomingMessage, via?: Who["via"]): Who {
  const peer = (req.socket.remoteAddress ?? "").replace(/^::ffff:/, "");
  const fwd = String(req.headers["x-forwarded-for"] ?? "").split(",").map((x) => x.trim()).filter(Boolean);
  const ip = (peer === "127.0.0.1" || peer === "::1") && fwd.length ? fwd[fwd.length - 1] : peer;
  const ua = String(req.headers["user-agent"] ?? "").replace(/[^\x20-\x7e]/g, "").slice(0, 120);
  const token = ((req as express.Request).params as Record<string, string> | undefined)?.token; // set on /b/:token/... routes
  return { via: via ?? (token ? "bridge" : "mcp"), ip: /^[0-9A-Fa-f:.]{2,45}$/.test(ip) ? ip : "?", ...(ua ? { ua } : {}), ...(token ? { tok: token.split(".")[0] } : {}) };
}

async function auditRotate(): Promise<void> {
  for (let i = AUDIT_KEEP; i >= 1; i--) await fs.rename(i === 1 ? auditFile : `${auditFile}.${i - 1}`, `${auditFile}.${i}`).catch(() => {});
  if (AUDIT_KEEP === 0) await fs.rm(auditFile, { force: true });
}
// Lines are written one at a time, in order. A write that fails is reported once on stderr and never fails the call.
// If the file was removed, replaced or cut since the last write, the log says so itself before it carries on.
function auditWrite(rec: Record<string, unknown>): Promise<void> {
  if (!auditFile) return Promise.resolve();
  let lines = `${JSON.stringify(rec)}\n`;
  return (auditQueue = auditQueue.then(async () => {
    try {
      let st = await fs.stat(auditFile).catch(() => null);
      const why = !st ? "the log file was missing" : auditIno && st.ino !== auditIno ? "the log file was replaced" : st.size < auditSize ? "the log file got shorter" : "";
      if (why) lines = `${JSON.stringify({ t: new Date().toISOString(), event: "reset", why })}\n${lines}`;
      if (!st) await mkdirp(dirname(auditFile)).then(() => fs.chmod(dirname(auditFile), 0o700)).catch(() => {});
      const bytes = Buffer.byteLength(lines);
      if (st && st.size > 0 && st.size + bytes > AUDIT_MAX) { await auditRotate(); st = null; }
      await fs.appendFile(auditFile, lines, { mode: 0o600 });
      if (!st || why) { const now = await fs.stat(auditFile); auditIno = now.ino; auditSize = now.size; } else auditSize = st.size + bytes;
      auditErr = "";
    } catch (e) {
      if (!auditErr) console.error(`audit log: cannot write ${auditFile}: ${(e as Error).message}`);
      auditErr = (e as Error).message;
    }
  }));
}
async function auditInit(): Promise<void> {
  if (AUDIT_OFF) return void console.log("audit log: off (AUDIT_LOG)");
  const dirs = process.env.AUDIT_DIR ? [process.env.AUDIT_DIR] : [join(dirname(JOBS_DIR), "audit"), join(homedir(), ".ssh-mcp", "audit")];
  for (const dir of dirs) {
    try {
      const file = join(dir, "audit.jsonl");
      await mkdirp(dir);
      await fs.chmod(dir, 0o700);
      await (await fs.open(file, "a", 0o600)).close();
      await fs.chmod(file, 0o600);
      const st = await fs.stat(file);
      auditFile = file; auditSize = st.size; auditIno = st.ino; auditErr = "";
      break;
    } catch (e) { auditErr = `${dir}: ${(e as Error).message}`; }
  }
  if (!auditFile) return void console.error(`audit log: NOT being written (${auditErr})`);
  console.log(`audit log: ${auditFile}`);
  await auditWrite({ t: new Date().toISOString(), event: "start", version: VERSION, pid: process.pid });
}

// The call being audited right now; code deeper down adds facts to its result record with auditNote (exit code, job id).
const auditScope = new AsyncLocalStorage<{ id: string; notes: Record<string, unknown> }>();
const auditNote = (fields: Record<string, unknown>) => { const s = auditScope.getStore(); if (s) Object.assign(s.notes, fields); };

// Run one call with an audit record around it: the "what" line first, the result line after.
async function audited<T>(who: Who, tool: string, info: AuditInfo, run: () => Promise<T>, result: (r: T) => AuditEnd): Promise<T> {
  if (!auditFile) return run();
  const id = randomBytes(4).toString("hex"), t0 = Date.now(), scope = { id, notes: {} as Record<string, unknown> };
  const { what, ...rest } = info;
  await auditWrite({ t: new Date(t0).toISOString(), id, ...who, tool, ...rest, ...(what ? { what: auditText(what) } : {}) });
  const end = (e: AuditEnd) => {
    const fin: Record<string, unknown> = { ...e, ...scope.notes };
    const codes = Array.isArray(fin.exits) ? fin.exits : fin.exit !== undefined ? [fin.exit] : [];
    if (codes.some((c) => c !== 0)) fin.ok = false; // a command that ran but did not exit 0 is not "ok"
    if (typeof fin.err === "string") fin.err = auditText(fin.err, 300);
    return auditWrite({ t: new Date().toISOString(), id, ...fin, ms: Date.now() - t0 });
  };
  try {
    const r = await auditScope.run(scope, run);
    await end(result(r));
    return r;
  } catch (e) {
    await end({ ok: false, err: (e as Error).message });
    throw e;
  }
}
const toolEnd = (out: ToolOut): AuditEnd => {
  if (!out.isError) return { ok: true };
  const first = out.content.find((c) => c.type === "text");
  return { ok: false, err: first?.type === "text" ? first.text.replace(/^Error: /, "") : "error" };
};

// What a call is about, for the log: the command, or the paths and sizes - never file content.
function auditInfo(tool: string, a: Args): AuditInfo {
  const host = typeof a.host === "string" ? a.host : undefined;
  switch (tool) {
    case "bash": return { host, what: a.command, ...(a.cwd ? { cwd: a.cwd } : {}), ...(a.run_in_background ? { bg: true } : {}) };
    case "ssh_exec": case "ssh_spawn": return { host, what: a.command };
    case "ssh_exec_many": return { host, what: ((a.commands ?? []) as Args[]).map((c) => `${c.id}: ${c.command}`).join("\n") };
    case "exec_code": return { host, what: `${a.language}: ${a.code}` };
    case "read": return { host, what: (a.files?.length ? (a.files as Args[]).map((f) => f.file_path) : [a.file_path]).join(", ") };
    case "write": {
      const files: Args[] = a.files?.length ? a.files : [{ file_path: a.file_path, content: a.content }];
      const sizes = files.map((f) => Buffer.byteLength(String(f.content ?? "")));
      return { host, what: files.map((f, i) => `${f.file_path ?? "?"} (${sizes[i]} B)`).join(", "), bytes: sizes.reduce((x, y) => x + y, 0) };
    }
    case "edit": {
      const perFile = new Map<string, number>();
      for (const e of (a.edits?.length ? a.edits : [a]) as Args[]) perFile.set(String(e.file_path ?? "?"), (perFile.get(String(e.file_path ?? "?")) ?? 0) + 1);
      return { host, what: [...perFile].map(([p, n]) => `${p} (${n} edit${n === 1 ? "" : "s"})`).join(", ") };
    }
    case "sftp_read": case "sftp_list": return { host, what: a.path };
    case "sftp_write": {
      const bytes = Buffer.from(String(a.content ?? ""), a.encoding === "base64" ? "base64" : "utf8").length;
      return { host, what: `${a.path} (${bytes} B)`, bytes };
    }
    case "ssh_job": return { host, what: `${a.action} ${a.jobId}` };
    case "batch": return { host, what: `${((a.ops ?? []) as unknown[]).length} ops` };
    case "bridge": return { what: `ttl_hours=${a.ttl_hours}` };
    case "add_host": return { what: `${a.name} = ${a.username}@${a.host}:${a.port}` };
    case "audit": return { what: [a.contains !== undefined ? `contains=${JSON.stringify(a.contains)}` : "", a.limit !== 50 ? `limit=${a.limit}` : "", a.since_minutes ? `since_minutes=${a.since_minutes}` : ""].filter(Boolean).join(" ") };
    default: return { host };
  }
}

async function auditTail(file: string): Promise<string> {
  const fh = await fs.open(file, "r").catch(() => null);
  if (!fh) return "";
  try {
    const { size } = await fh.stat(), from = Math.max(0, size - AUDIT_TAIL), buf = Buffer.alloc(size - from);
    await fh.read(buf, 0, buf.length, from);
    const s = buf.toString("utf8");
    return from > 0 ? s.slice(s.indexOf("\n") + 1) : s; // the first line was cut in half: drop it
  } finally { await fh.close(); }
}
// The log as text, one line per call (its two records joined): time, address, route, tool, host, result, duration, what.
async function auditShow(limit: number, contains: string | undefined, sinceMinutes: number | undefined, self: string | undefined): Promise<string> {
  await auditQueue; // everything written so far is on disk
  const starts = new Map<string, Args>(), entries: Args[] = [];
  for (const line of `${await auditTail(`${auditFile}.1`)}${await auditTail(auditFile)}`.split("\n")) {
    if (!line) continue;
    let r: Args;
    try { r = JSON.parse(line); } catch { continue; }
    if (r.event) entries.push(r);
    else if (r.tool) { if (r.id !== self) { starts.set(r.id, r); entries.push(r); } } // a query does not list itself
    else { const start = starts.get(r.id); if (start) start.end = r; }
  }
  const secs = (t: unknown) => `${String(t).slice(0, 19)}Z`;
  const flat = (t: string) => t.replace(/\s*\n\s*/g, " ⏎ ");
  const show = (r: Args): string => {
    if (r.event) return r.event === "start" ? `${secs(r.t)}  server started: v${r.version}, pid ${r.pid}` : `${secs(r.t)}  audit log ${r.event}: ${r.why ?? ""}`.trimEnd();
    const e: Args | undefined = r.end;
    const result = !e ? "no result (still running, or the server stopped)"
      : e.tripwire ? `REFUSED by the tripwire: ${clip(flat(String(e.tripwire)), 160)}`
      : (Array.isArray(e.exits) && !e.ok ? `exits ${e.exits.join(",")}`
        : typeof e.exit === "number" && e.exit !== 0 ? `exit ${e.exit}`
        : e.ok ? "ok" : `FAILED${e.err ? `: ${clip(flat(String(e.err)), 160)}` : ""}`)
        + (e.confirmed ? ` (confirmed: ${clip(flat(String(e.confirmed)), 160)})` : "") + (e.ok && typeof e.added === "boolean" ? (e.added ? " (added)" : " (not added yet)") : "");
    const what = [r.bg ? "[background]" : "", r.cwd ? `(in ${r.cwd})` : "", r.what ?? ""].filter(Boolean).join(" ");
    return [secs(r.t), r.ip ?? "-", r.via ?? "-", `${r.tool}${r.batch ? `#${String(r.batch).split("#")[1]}` : ""}`, r.host ? `${r.host}${e?.kex ? " (pq)" : ""}` : "-", result,
      e ? `${(Number(e.ms) / 1000).toFixed(2)}s` : "-", clip(flat(what), 300)].join("  ").trimEnd();
  };
  const after = sinceMinutes === undefined ? -Infinity : Date.now() - sinceMinutes * 60_000;
  const needle = contains?.toLowerCase();
  const lines = entries.filter((r) => Date.parse(r.t) >= after).map(show).filter((l) => needle === undefined || l.toLowerCase().includes(needle));
  const head = `audit log: ${auditFile} - `;
  return lines.length ? `${head}${Math.min(limit, lines.length)} of ${lines.length} matching entries, oldest first\n${lines.slice(-limit).join("\n")}` : `${head}no matching entries`;
}

// ── v1.5: tripwire ────────────────────────────────────────────────────────────────────────────────────────────
// A short list of commands that are almost never meant and hard to undo - delete / or a system directory,
// format or overwrite a disk, power the machine off, a fork bomb - is refused unless the call says confirm: true.
// It reads the text of the command and never runs anything to find out, so what a variable holds, what a script
// file does or what is piped into a shell is beyond it, and it is easy to get around on purpose. That is fine:
// it is there to catch accidents, not to stop anyone. TRIPWIRE=off turns it off.
const TRIPWIRE_OFF = /^(off|0|false|no)$/i.test(process.env.TRIPWIRE ?? "");
// A recursive delete, chmod or chown of one of these breaks the machine ...
const SYSTEM_DIRS = new Set(["/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/proc", "/run", "/sbin", "/sys", "/usr", "/var",
  "/usr/bin", "/usr/lib", "/usr/lib64", "/usr/sbin", "/var/lib"]);
// ... and a recursive delete of one of these loses just as much.
const VITAL_DIRS = new Set([...SYSTEM_DIRS, "~", "$HOME", "${HOME}", "/home", "/mnt", "/opt", "/root", "/srv", "/usr/local", "/usr/share"]);
const DISK = /^\/dev\/(?:(?:sd|hd|vd|xvd)[a-z]+\d*|nvme\d+n\d+(?:p\d+)?|mmcblk\d+(?:p\d+)?|md\d+|dm-\d+|(?:mapper|disk)\/\S+)$/;
const SHELL_WORDS = new Set(["then", "do", "else", "elif", "if", "while", "until", "!", "time", "command", "builtin", "exec", "nohup", "setsid"]);
const WRAPPER_ARG: Record<string, RegExp> = { sudo: /^-[ughpCDRT]$/, doas: /^-[uC]$/, nice: /^-n$/, ionice: /^-[cnp]$/, env: /^-[uCS]$/, stdbuf: /^$/ }; // options that take a value
const HERE_DOC = /^<<(-?)[ \t]*(?:'([^'\n]*)'|"([^"\n]*)"|\\?([^\s;|&<>()'"\\]+))/;
const baseName = (w: string) => w.slice(w.lastIndexOf("/") + 1);
const present = <T>(x: T | null | undefined): x is T => x != null;

// The here-document whose text starts after the newline at `nl`: [where the text ends, where its closing line ends], or null if it never closes.
function hereDoc(s: string, nl: number, end: string, dash: boolean): [number, number] | null {
  for (let j = nl; j >= 0; ) {
    const k = s.indexOf("\n", j + 1), line = s.slice(j + 1, k < 0 ? s.length : k);
    if ((dash ? line.replace(/^\t+/, "") : line) === end) return [j, k < 0 ? s.length : k];
    j = k;
  }
  return null;
}
// The simple commands of a shell command line: the words of each, and the here-documents it reads.
// It follows the shell's nesting - "..." may hold $(...), which holds commands with quotes of their own - because
// a splitter that loses its place there would later take the text of an `echo "..."` for commands. A command
// substitution leaves "$()" in the word it stood in, and its own commands are listed like any others.
type ShellCmd = { words: string[]; here: string[] };
function shellCommands(s: string): ShellCmd[] {
  const cmds: ShellCmd[] = [], waiting: { end: string; dash: boolean; of: ShellCmd }[] = [], DEEPEST = 40;
  let i = 0, arithmetic = true;
  // `((...))` or `$((...))` with s[at] its first "(": where it ends, or -1 if it is two nested subshells instead
  const arithmeticEnd = (at: number): number => {
    if (!arithmetic || s[at + 1] !== "(") return -1;
    for (let j = at + 2, depth = 2; j < s.length; j++) {
      if (s[j] === "(") depth++;
      else if (s[j] === ")" && --depth === 1) return s[j + 1] === ")" ? j + 1 : -1;
    }
    arithmetic = false; // it never closes: do not read the rest of the text again for every "(("
    return -1;
  };
  // `$(` or a backtick at i, with room to go deeper: reads the commands inside, leaves i on the closing character
  const substitution = (nest: number): string => {
    if (s[i] === "`") { i++; list("`", nest + 1); return "$()"; }
    const end = arithmeticEnd(i + 1);
    if (end >= 0) i = end; else { i += 2; list(")", nest + 1); }
    return "$()";
  };
  const starts = (nest: number) => nest < DEEPEST && ((s[i] === "$" && s[i + 1] === "(") || s[i] === "`");
  // "..." with i on the opening quote: its text, with i left on the closing quote
  const quoted = (nest: number): string => {
    let t = "";
    for (i++; i < s.length && s[i] !== '"'; i++) {
      if (s[i] === "\\" && i + 1 < s.length) t += s[++i];
      else if (starts(nest)) t += substitution(nest);
      else if (s[i] === "$" && s[i + 1] === "{" && nest < DEEPEST) t += param(nest + 1, true);
      else t += s[i];
    }
    return t;
  };
  // ${...} with i on the "$": its text as written, with i left on the closing brace. It may hold others: ${CC:+"${CC}"}
  const param = (nest: number, inQuotes: boolean): string => {
    const from = i;
    for (i += 2; i < s.length && s[i] !== "}"; i++) {
      if (s[i] === "\\") i++;
      else if (starts(nest)) substitution(nest);
      else if (s[i] === "$" && s[i + 1] === "{" && nest < DEEPEST) param(nest + 1, inQuotes);
      else if (s[i] === '"' && nest < DEEPEST) quoted(nest + 1);
      else if (s[i] === "'" && !inQuotes) { const k = s.indexOf("'", i + 1); i = k < 0 ? s.length : k; }
    }
    return s.slice(from, i + 1);
  };
  // A list of commands, up to the end of the text or to the character that closes it (left under i).
  const list = (close: "" | ")" | "`", nest: number): void => {
    let cur: ShellCmd = { words: [], here: [] }, w = "", open = false;
    let cases = 0, caseAt = -1, pattern = false, test = false; // inside case ... esac; where its word is; reading a label; inside [[ ]]
    let first = true;                                          // still in front of the command's own name (only `then`, `do`, ... so far)
    const word = () => {
      if (!open) return;
      const x = w, leads = first; w = ""; open = false;
      if (x === "esac" && !cur.words.length && cases > 0) { cases--; pattern = false; return; }
      cur.words.push(x);
      first = leads && SHELL_WORDS.has(x);
      if (x === "case" && leads) { cases++; caseAt = cur.words.length - 1; }
      else if (x === "in" && caseAt >= 0 && cur.words.length === caseAt + 3) { pattern = true; cur.words = []; caseAt = -1; first = true; }
      else if (x === "[[" && leads) test = true;
      else if (x === "]]") test = false;
    };
    const cmd = () => {
      word(); caseAt = -1; test = false; first = true;
      if (pattern) cur.words = [];                                              // a `case` label is not a command
      else if (cur.words.length) { cmds.push(cur); cur = { words: [], here: [] }; }
    };
    for (; i < s.length; i++) {
      const c = s[i];
      if (c === "'") { const k = s.indexOf("'", i + 1); w += s.slice(i + 1, k < 0 ? s.length : k); open = true; i = k < 0 ? s.length : k; }
      else if (c === '"') { w += quoted(nest + 1); open = true; }
      else if (c === "\\" && i + 1 < s.length) { i++; if (s[i] !== "\n") { w += s[i]; open = true; } }
      else if (c === "$" && s[i + 1] === "'") { for (i += 2; i < s.length && s[i] !== "'"; i++) w += s[i] === "\\" ? s[++i] ?? "" : s[i]; open = true; } // $'it\'s'
      else if (c === "$" && s[i + 1] === "{" && nest < DEEPEST) { w += param(nest + 1, false); open = true; }
      else if (c === "`" && close === "`") { cmd(); return; }
      else if (starts(nest)) { w += substitution(nest); open = true; }
      else if (c === "<" && s[i + 1] === "<" && s[i + 2] === "<") { word(); i += 2; }                                          // here-string
      else if (c === "<" && s[i + 1] === "<" && !test && HERE_DOC.test(s.slice(i, i + 200))) {
        const m = HERE_DOC.exec(s.slice(i, i + 200))!;
        word();
        waiting.push({ end: m[2] ?? m[3] ?? m[4], dash: m[1] === "-", of: cur });
        i += m[0].length - 1;
      }
      else if (c === "#" && !open) { while (i + 1 < s.length && s[i + 1] !== "\n") i++; }
      else if (c === " " || c === "\t" || c === "\r") word();
      else if (c === "\n") {
        cmd();
        for (const h of waiting.splice(0)) { // the text of a here-document is not commands - unless it is fed to a shell, see tripwire()
          const r = hereDoc(s, i, h.end, h.dash);
          h.of.here.push(s.slice(i + 1, r ? r[0] : s.length));
          i = r ? r[1] : s.length;
        }
      }
      else if (test && "()|&<>".includes(c)) { w += c; open = true; }                                                         // [[ $x =~ ^(a|b)$ ]]
      else if (c === ";") { cmd(); if (cases > 0 && (s[i + 1] === ";" || s[i + 1] === "&")) { pattern = true; i += s[i + 2] === "&" ? 2 : 1; } }
      else if (c === "&" || c === "|") cmd();
      else if (c === "(") {
        const end = arithmeticEnd(i);
        if (end >= 0) i = end;                                                                                                   // (( x++ )): no commands in it
        else if (pattern) continue;                                                                                              // (label)
        else if (open && /[=!@*?+]$/.test(w) && nest < DEEPEST) { const mark = cmds.length; i++; list(")", nest + 1); cmds.length = mark; w += "()"; } // arr=(a b), !(glob)
        else if (nest < DEEPEST) { cmd(); i++; list(")", nest + 1); }                                                            // ( subshell ), f()
        else cmd();
      }
      else if (c === ")") {
        word();                                                                                                                  // first: `esac)` ends the case, and then this closes the list
        if (pattern) { cur.words = []; pattern = false; }                                                                        // the end of a `case` label
        else if (close === ")") { cmd(); return; }
        else cur.words = [];
      }
      else if ((c === "{" && !open && /\s/.test(s[i + 1] ?? " ")) || (c === "}" && !open)) cmd();                              // a { group }, not a {brace,expansion}
      else { w += c; open = true; }
    }
    cmd();
  };
  list("", 0);
  return cmds;
}
// {a,b} alternatives of a word: /{etc,usr} -> /etc, /usr
function braces(word: string): string[] {
  let out = [word];
  for (let round = 0; round < 6 && word.length <= 200; round++) { // a path that matters is short, and a few levels are plenty
    const next: string[] = [];
    for (const x of out) {
      const m = next.length < 64 ? /^(.*?)\{([^{}]*,[^{}]*)\}(.*)$/s.exec(x) : null;
      if (m) for (const alt of m[2].split(",")) next.push(m[1] + alt + m[3]); else next.push(x);
    }
    if (next.length === out.length) break;
    out = next;
  }
  return out;
}
// Peel off what stands in front of the real command: VAR=value, shell keywords, sudo, timeout, env, nice ...
function realCommand(words: string[]): string[] {
  const w = words.slice();
  for (let n = 0; n < 12 && w.length; n++) {
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w[0])) { w.shift(); continue; }
    const name = baseName(w[0]);
    if (SHELL_WORDS.has(name)) { w.shift(); continue; }
    if (name === "timeout" || name in WRAPPER_ARG) {
      const takesValue = name === "timeout" ? /^-[ks]$/ : WRAPPER_ARG[name];
      w.shift();
      while (w.length && w[0].startsWith("-")) { if (takesValue.test(w.shift()!)) w.shift(); }
      if (name === "timeout") w.shift(); // the duration
      continue;
    }
    break;
  }
  return w;
}
// Why a command is on the short list, or null. Looks into `bash -c '...'`, `ssh host '...'`, `eval ...` and
// scripts fed to a shell as a here-document, a few levels deep.
function tripwire(command: string, depth = 0): string | null {
  if (command.length > 1_000_000) command = command.slice(0, 1_000_000); // far more than a shell accepts as one command
  if (/:\s{0,4}\(\s{0,4}\)\s{0,4}\{[^}]{0,40}:\s{0,4}\|\s{0,4}:[^}]{0,40}\}\s{0,4};\s{0,4}:/.test(command)) return "a fork bomb"; // bounded on purpose: this runs on every command
  const dirIn = (set: Set<string>) => (p: string) => { const t = p.replace(/\/{2,}/g, "/").replace(/\/\*$/, "").replace(/(.)\/+$/, "$1") || "/"; return set.has(t) ? t : null; };
  for (const { words, here } of shellCommands(command)) {
    for (let i = 0; i < words.length; i++) { // a redirect that lands on a disk, whatever the command is
      const m = /^\d*>>?(.*)$/.exec(words[i]), target = m ? m[1] || words[i + 1] || "" : "";
      if (DISK.test(target)) return `a redirect writes over the disk ${target}`;
    }
    const w = realCommand(words);
    const name = w.length ? baseName(w[0]) : /^(sudo|doas)$/.test(baseName(words[0])) ? "sh" : ""; // `sudo -i` is a shell
    if (!name) continue;
    const args = w.slice(1), flags: string[] = [], rest: string[] = [];
    let plain = false;
    for (const a of args) { if (!plain && a === "--") plain = true; else if (!plain && a.length > 1 && a.startsWith("-")) flags.push(a); else rest.push(a); }
    const recursive = (letters: string) => flags.some((f) => f === "--recursive" || (/^-[A-Za-z]+$/.test(f) && [...letters].some((l) => f.includes(l))));
    const targets = rest.flatMap((a) => braces(a)), disk = rest.find((a) => DISK.test(a));
    const vital = targets.map(dirIn(VITAL_DIRS)).find(present), system = targets.map(dirIn(SYSTEM_DIRS)).find(present);
    if (name === "rm" && vital && recursive("rR")) return `recursive delete of ${JSON.stringify(vital)}`;
    if (/^ch(mod|own|grp)$/.test(name) && system && recursive("R")) return `recursive ${name} of ${JSON.stringify(system)}`;
    if (name === "find") { // only when nothing narrows down what is deleted
      const a = args.slice();
      while (/^-[HLP]$/.test(a[0] ?? "")) a.shift();
      const at = a.findIndex((x) => /^[-(!]/.test(x)), expr = at < 0 ? [] : a.slice(at), root = a.slice(0, at < 0 ? a.length : at).flatMap((x) => braces(x)).map(dirIn(VITAL_DIRS)).find(present);
      const deletes = expr.includes("-delete") || expr.some((x, i) => /^-(exec|execdir|ok|okdir)$/.test(x) && baseName(expr[i + 1] ?? "") === "rm");
      const narrowed = expr.some((x) => /^-(i?name|i?path|i?wholename|i?regex|i?lname|user|group|uid|gid|[mca]time|[mca]min|newer\w*|size|inum|samefile|empty|perm|links|used)$/.test(x));
      if (root && deletes && !narrowed) return `find deletes everything under ${JSON.stringify(root)}`;
    }
    const device = rest.find((a) => a.startsWith("/dev/") || a.includes("$")); // a file image is fine; a device, or a variable that may be one, is not
    if (/^(mkfs(\..+)?|mke2fs|mkdosfs|mkntfs)$/.test(name) && device) return `${name} formats ${device}`;
    if ((name === "blkdiscard" || (name === "wipefs" && flags.some((f) => f === "--all" || /^-[A-Za-z]*a/.test(f)))) && device) return `${name} wipes ${device}`;
    if (name === "dd") { const of = args.map((a) => /^of=(.*)$/.exec(a)?.[1]).find((t) => t !== undefined && DISK.test(t)); if (of) return `dd writes over the disk ${of}`; }
    if (/^(shred|mkswap|tee)$/.test(name) && disk) return `${name} writes over the disk ${disk}`;
    if (/^(shutdown|poweroff|halt|reboot)$/.test(name) && !(name === "shutdown" && flags.includes("-c"))) return `${name} stops or restarts the machine`;
    if (/^(init|telinit)$/.test(name) && /^[06]$/.test(rest[0] ?? "")) return `${name} ${rest[0]} stops or restarts the machine`;
    if (name === "systemctl" && /^(poweroff|halt|reboot|kexec|soft-reboot|suspend|hibernate|hybrid-sleep)$/.test(rest[0] ?? "")) return `systemctl ${rest[0]} stops or restarts the machine`;
    if (depth < 3) { // a command handed to another shell: as a string, or as a script on its stdin
      const inner: string[] = [], shell = /^(ba|da|z|k)?sh$/.test(name);
      if (shell) { const i = args.findIndex((a) => /^-[A-Za-z]*c$/.test(a)); if (i >= 0) inner.push(args[i + 1] ?? ""); }
      else if (name === "su") { const i = args.findIndex((a) => a === "-c" || a === "--command"); if (i >= 0) inner.push(args[i + 1] ?? ""); }
      else if (name === "eval") inner.push(args.join(" "));
      else if (name === "ssh") { let i = 0; while (i < args.length && args[i].startsWith("-")) i += /^-[bcDEeFIiJLlmOopQRSWw]$/.test(args[i]) ? 2 : 1; inner.push(args.slice(i + 1).join(" ")); }
      if (shell || name === "su" || name === "ssh") inner.push(...here);
      for (const text of inner) { const why = text ? tripwire(text, depth + 1) : null; if (why) return why; }
    }
  }
  return null;
}
// Throws when a command is on the list and the call did not confirm it. Either way the audit log says so.
function tripCheck(commands: { label?: string; command: string }[], confirm: boolean | undefined, how = "confirm: true"): void {
  if (TRIPWIRE_OFF) return;
  const reason = commands.map((c) => ({ label: c.label, why: tripwire(c.command) })).filter((h) => h.why !== null).map((h) => `${h.label ? `[${h.label}] ` : ""}${h.why}`).join("; ");
  if (!reason) return;
  if (confirm) return void auditNote({ confirmed: reason });
  auditNote({ tripwire: reason });
  throw new Error(`Refused by the tripwire: ${reason}. Nothing was run. This is on the short list of commands that are rarely meant and hard to undo; if the user really wants it, send it again with ${how}.`);
}
const CONFIRM = "Set true to run a command that the server refused as catastrophic (it says so when it does). Only when the user really wants it";

// ── v1.5: add_host ────────────────────────────────────────────────────────────────────────────────────────────
// The connector has an SSH key of its own (created on first use, kept next to the other state). add_host logs
// in to a new server with it, pins the host key that server presented, and saves the entry in hosts.json.
// There is no password path on purpose: the one manual step is adding the public key on the new server.
let serialQueue: Promise<unknown> = Promise.resolve();
const serial = <T>(fn: () => Promise<T>): Promise<T> => { const p = serialQueue.then(fn, fn); serialQueue = p.catch(() => {}); return p; }; // one at a time
// The key as ssh2 reads it, if it can be read AND really signs; null otherwise.
function usableKey(privateKey: string | Buffer): ParsedKey | null {
  const parsed = sshUtils.parseKey(privateKey), k = Array.isArray(parsed) ? parsed[0] : parsed;
  if (!k || k instanceof Error) return null;
  const probe = Buffer.from("ssh-mcp key check"), signature = k.sign(probe);
  return !(signature instanceof Error) && k.verify(probe, signature) === true ? k : null;
}
// A new ed25519 key pair. ssh2 1.17's generator drops a leading zero byte of the public key, so about 1 key in
// 256 comes out as one that nothing can read, ssh2 itself included. Such a key must never be saved: it would make
// add_host fail for good, and the line shown to the user would be refused by every SSH server.
function newKeyPair(comment: string): { private: string; public: string } {
  for (let attempt = 0; attempt < 50; attempt++) {
    const pair = sshUtils.generateKeyPairSync("ed25519", { comment });
    const k = usableKey(pair.private), blob = Buffer.from(pair.public.split(" ")[1] ?? "", "base64");
    if (k && blob.length === 51 && blob.equals(k.getPublicSSH())) return pair; // 51 = "ssh-ed25519" + a whole 32-byte key
  }
  throw new Error("could not generate a usable SSH key");
}
async function connectorKey(): Promise<{ path: string; privateKey: Buffer; publicKey: string }> {
  let last: unknown;
  for (const dir of [join(dirname(JOBS_DIR), "keys"), join(homedir(), ".ssh-mcp", "keys")]) {
    try {
      const path = join(dir, "id_ed25519");
      await mkdirp(dir);
      await fs.chmod(dir, 0o700);
      const existing = await fs.readFile(path).catch(() => null);
      if (existing && !usableKey(existing)) { // a key nothing can read never logged in anywhere: keep it aside, make a new one
        const aside = `${path}.unusable-${Date.now()}`;
        await fs.rename(path, aside);
        await fs.rename(`${path}.pub`, `${aside}.pub`).catch(() => {});
      }
      if (!(await fs.stat(path).catch(() => null))) {
        const pair = newKeyPair(`ssh-mcp@${hostname()}`);
        const created = await fs.writeFile(path, pair.private, { mode: 0o600, flag: "wx" }).then(() => true, (e: NodeJS.ErrnoException) => { if (e.code !== "EEXIST") throw e; return false; });
        if (created) await fs.writeFile(`${path}.pub`, `${pair.public}\n`, { mode: 0o644 }); // otherwise another process made the key a moment ago: use that one
      }
      const privateKey = await fs.readFile(path), k = usableKey(privateKey);
      if (!k) throw new Error(`the key in ${path} cannot be read`);
      // The line to show is worked out from the private key; the .pub file only supplies the comment, and is put right if it says otherwise.
      const onDisk = (await fs.readFile(`${path}.pub`, "utf8").catch(() => "")).trim().split(/\s+/);
      const blob = k.getPublicSSH().toString("base64");
      const publicKey = `${k.type} ${blob} ${onDisk[1] === blob && onDisk[2] ? onDisk.slice(2).join(" ") : `ssh-mcp@${hostname()}`}`;
      if (onDisk[1] !== blob) await fs.writeFile(`${path}.pub`, `${publicKey}\n`, { mode: 0o644 });
      return { path, privateKey, publicKey };
    } catch (e) { last = e; }
  }
  throw new Error(`cannot create or read the connector's SSH key: ${(last as Error).message}`);
}
type Probe = { fp?: string; keyType?: string; ok: boolean; authFailed?: boolean; who?: string; err?: string };
// Connect once: note the host key the server presents, try to log in with the connector's key, and if that works run a test command.
// With `expect`, a server that presents any other host key is dropped before the login is even tried.
function probeHost(host: string, port: number, username: string, privateKey: Buffer, expect?: string): Promise<Probe> {
  return new Promise((done) => {
    const c = new Client();
    let fp: string | undefined, keyType: string | undefined, settled = false;
    const finish = (r: Probe) => { if (settled) return; settled = true; clearTimeout(timer); c.end(); done({ fp, keyType, ...r }); };
    const timer = setTimeout(() => finish({ ok: false, err: "timed out after 25 s" }), 25_000);
    c.on("ready", () => c.exec("whoami; uname -n", (err, stream) => {
      if (err) return finish({ ok: true, who: username });
      let out = "";
      stream.on("data", (d: Buffer) => (out += d));
      stream.stderr.on("data", () => {});
      stream.on("close", () => finish({ ok: true, who: out.trim().split(/\s+/).slice(0, 2).join(" on ") || username }));
    }));
    c.on("error", (e: Error & { level?: string }) => finish({ ok: false, authFailed: e.level === "client-authentication", err: e.message }));
    c.connect({
      host, port, username, privateKey, readyTimeout: 15_000,
      hostVerifier: (key: Buffer) => { // remember what was presented, so the caller can show it
        fp = fingerprintOf(key);
        keyType = keyTypeOf(key);
        return !expect || fp === expect;
      },
    });
  });
}
// The test add_host runs on a connection that is up: who it is logged in as, and where. Ends the connection.
const whoIs = (c: Client, fallback: string): Promise<string> => new Promise((res) => c.exec("whoami; uname -n", (err, stream) => {
  if (err) { c.end(); return res(fallback); }
  let out = "";
  stream.on("data", (d: Buffer) => (out += d));
  stream.stderr.on("data", () => {});
  stream.on("close", () => { c.end(); res(out.trim().split(/\s+/).slice(0, 2).join(" on ") || fallback); });
}));
const hostKeyFileOf = (type = "") => (type.startsWith("ecdsa") ? "ssh_host_ecdsa_key.pub" : /rsa/.test(type) ? "ssh_host_rsa_key.pub" : "ssh_host_ed25519_key.pub");

// hosts.json, rewritten as a whole - all or nothing - with the previous version kept as hosts.json.bak. Call it inside serial().
async function updateHosts(change: (all: Record<string, HostCfg>) => void): Promise<void> {
  const before = await fs.readFile(HOSTS_FILE, "utf8"), all = JSON.parse(before) as Record<string, HostCfg>;
  change(all);
  await fs.writeFile(`${HOSTS_FILE}.bak`, before, { mode: 0o600 });
  await fs.writeFile(`${HOSTS_FILE}.new`, `${JSON.stringify(all, null, 2)}\n`, { mode: 0o600 });
  await fs.chmod(`${HOSTS_FILE}.new`, 0o600);
  await fs.rename(`${HOSTS_FILE}.new`, HOSTS_FILE);
}

// ── v1.8: tunnels, for machines this connector cannot reach ──────────────────────────────────────────────────
// A machine behind NAT or a firewall is not connected to: it connects. add_host with tunnel: true hands out a link
// that works once; the script behind it (tunnel.sh), run as root on that machine, lets this connector's key log in
// there, makes a key for the tunnel and installs the service ssh-mcp-tunnel. That service keeps an SSH connection
// open to this connector, carried over HTTPS - the port that is reachable anyway, so nothing new has to be reachable
// on either side - and asks it for one remote forward: 127.0.0.1:<port> here leads to that machine's own SSH server.
// From then on the host is 127.0.0.1:<port> for every tool, its host key pinned like any other's.
// The SSH server at this end is started for each tunnel (sshd -i, fed the upgraded HTTPS connection), with a
// configuration that allows that and nothing else: post-quantum key exchange only, no shell, no command, no forwarding
// but the one remote forward, each key bound to its own port, logged in as an account of its own (TUNNEL_USER: when
// this runs as root, sshmcp-tunnel, created when first needed). TUNNEL=off turns all of it off.
const TUNNEL_OFF = /^(off|0|false|no)$/i.test(process.env.TUNNEL ?? "");
const RUN_AS = userInfo().username, AS_ROOT = process.getuid?.() === 0;
const TUNNEL_USER = process.env.TUNNEL_USER ?? (AS_ROOT ? "sshmcp-tunnel" : RUN_AS);
const STATE_DIR = dirname(JOBS_DIR);
// sshd reads it as TUNNEL_USER, so it is not in the private state: nothing in it is secret but the host key (mode 600)
const TUNNEL_DIR = resolvePath(process.env.TUNNEL_DIR ?? `${STATE_DIR}-tunnel`);
const LINKS_DIR = join(STATE_DIR, "tunnel"); // the links add_host hands out: private, like the rest of the state
const TUNNEL_PORTS = ((m) => (m ? [Number(m[1]), Number(m[2])] : [20200, 20999]))(/^(\d{4,5})-(\d{4,5})$/.exec(process.env.TUNNEL_PORTS ?? ""));
const LINK_MS = 30 * 60_000, TUNNELS_MAX = 64;
const isLinkId = (s: string) => /^[0-9a-f]{32}$/.test(s);
const sameId = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const keyFpOf = (line: string) => fingerprintOf(Buffer.from(line.split(" ")[1] ?? "", "base64"));
const runFile = (file: string, args: string[], timeout = 20_000) => new Promise<{ ok: boolean; out: string }>((res) =>
  execFile(file, args, { timeout }, (err, stdout, stderr) => res({ ok: !err, out: `${stdout}${stderr}`.trim() || (err ? err.message : "") })));
async function executable(files: Array<string | undefined>): Promise<string | null> {
  for (const f of files) if (f && (await fs.access(f, fsc.X_OK).then(() => true, () => false))) return f;
  return null;
}
const tunnelClosed = (label: string) => new Error(`"${label}" is reached through a tunnel that it opens itself, and that tunnel is not open: ` +
  `the machine is off or offline, or its service ssh-mcp-tunnel is not running (there: systemctl status ssh-mcp-tunnel)` +
  `${TUNNEL_OFF ? ". Besides, tunnels are turned off on this connector (TUNNEL=off)" : ""}.`);

// A link, from add_host until the machine is in; once the machine has called on it (POST /t/<link>), with what it sent.
type Link = { name: string; username: string; to: number; fingerprint?: string; replace?: boolean; exp: number;
  key?: string; hostKeys?: string[]; hostname?: string; client?: string; port?: number; id?: string };
const linkFile = (id: string) => join(LINKS_DIR, `${id}.json`);
async function linkOf(id: string): Promise<Link | null> {
  if (!isLinkId(id)) return null;
  const l = await fs.readFile(linkFile(id), "utf8").then((t) => JSON.parse(t) as Link, () => null);
  return l && l.exp > Date.now() ? l : null;
}
async function saveLink(id: string, l: Link): Promise<void> {
  await mkdirp(LINKS_DIR);
  await fs.chmod(LINKS_DIR, 0o700);
  await fs.writeFile(`${linkFile(id)}.new`, JSON.stringify(l), { mode: 0o600 });
  await fs.rename(`${linkFile(id)}.new`, linkFile(id));
}
async function allLinks(): Promise<Array<[string, Link]>> {
  const out: Array<[string, Link]> = [];
  for (const f of await fs.readdir(LINKS_DIR).catch(() => [] as string[])) {
    const id = f.slice(0, -5);
    if (!f.endsWith(".json") || !isLinkId(id)) continue;
    const l = await fs.readFile(join(LINKS_DIR, f), "utf8").then((t) => JSON.parse(t) as Link, () => null);
    if (l) out.push([id, l]);
  }
  return out;
}

// The SSH server end of the tunnels: its program, configuration and host key, made ready once (again after a failure).
type TunnelEnd = { sshd: string; config: string; hostKey: string; kex: string[] };
let tunnelEnd: Promise<TunnelEnd> | null = null;
const tunnelReady = (): Promise<TunnelEnd> => (tunnelEnd ??= setUpTunnelEnd().catch((e) => { tunnelEnd = null; throw e; }));
async function setUpTunnelEnd(): Promise<TunnelEnd> {
  if (TUNNEL_OFF) throw new Error("tunnels are turned off on this connector (TUNNEL=off)");
  const sshd = await executable([process.env.TUNNEL_SSHD, "/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"]);
  if (!sshd) throw new Error("this machine has no OpenSSH server program (sshd), which takes the tunnels at this end: install openssh-server (it does not have to run as a service)");
  const kex = await pqHere();
  if (!kex.length) throw new Error("this machine's OpenSSH has no post-quantum key exchange, and a tunnel is only made with one (OpenSSH 9.0 and newer have it)");
  // (by full path: the service's PATH has no sbin directories)
  if (TUNNEL_USER !== RUN_AS && !(await runFile((await executable(["/usr/bin/id", "/bin/id"])) ?? "id", ["-u", TUNNEL_USER])).ok) {
    if (!AS_ROOT) throw new Error(`the account ${TUNNEL_USER} (TUNNEL_USER), which tunnels log in as, does not exist, and only root can create it`);
    const shell = (await executable(["/usr/sbin/nologin", "/sbin/nologin"])) ?? "/bin/false";
    const useradd = await executable(["/usr/sbin/useradd", "/sbin/useradd", "/usr/bin/useradd"]);
    if (!useradd) throw new Error(`the account ${TUNNEL_USER} (TUNNEL_USER), which tunnels log in as, does not exist, and there is no useradd here to create it: create it yourself (no password, no shell)`);
    // password "*": none works, and unlike "!" it does not make OpenSSH take the account for a locked one
    const made = await runFile(useradd, ["--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", shell, "--password", "*", "--comment", "ssh-mcp tunnels", TUNNEL_USER]);
    if (!made.ok) throw new Error(`could not create the account ${TUNNEL_USER}, which tunnels log in as: ${made.out}`);
  }
  await mkdirp(TUNNEL_DIR);
  await fs.chmod(TUNNEL_DIR, 0o755);
  const keyPath = join(TUNNEL_DIR, "host_ed25519"), keys = join(TUNNEL_DIR, "authorized_keys"), config = join(TUNNEL_DIR, "sshd_config");
  const made = (e: NodeJS.ErrnoException) => { if (e.code !== "EEXIST") throw e; }; // another process was quicker: use what it made
  if (!(await fs.stat(keyPath).catch(() => null))) await fs.writeFile(keyPath, newKeyPair(`ssh-mcp-tunnel@${hostname()}`).private, { mode: 0o600, flag: "wx" }).catch(made);
  const k = usableKey(await fs.readFile(keyPath));
  if (!k) throw new Error(`the tunnels' host key ${keyPath} cannot be read`);
  await fs.writeFile(keys, "", { mode: 0o644, flag: "wx" }).catch(made);
  await fs.writeFile(`${config}.new`, [
    `# Written by Rackhand ${VERSION}: the SSH server end of the tunnels that machines open to this connector.`,
    "# It is not a daemon: the connector starts one for each tunnel (sshd -i), and it allows that tunnel and nothing else.",
    `HostKey ${keyPath}`,
    `AuthorizedKeysFile ${keys}`,
    `AllowUsers ${TUNNEL_USER}`,
    `PermitRootLogin ${TUNNEL_USER === "root" ? "prohibit-password" : "no"}`,
    "AuthenticationMethods publickey", "PubkeyAuthentication yes", "PasswordAuthentication no", "KbdInteractiveAuthentication no", "HostbasedAuthentication no", "UsePAM no",
    `KexAlgorithms ${kex.join(",")}`,
    "MaxSessions 0", "AllowTcpForwarding remote", "PermitOpen none", "GatewayPorts no", "AllowStreamLocalForwarding no", "AllowAgentForwarding no",
    "X11Forwarding no", "PermitTunnel no", "PermitTTY no", "PermitUserRC no", "PermitUserEnvironment no",
    "StrictModes yes", "UseDNS no", "LoginGraceTime 30", "MaxAuthTries 3", "ClientAliveInterval 15", "ClientAliveCountMax 3",
    "PidFile none", "LogLevel DEBUG1", "",
  ].join("\n"), { mode: 0o644 });
  await fs.rename(`${config}.new`, config);
  if (AS_ROOT) await mkdirp("/run/sshd"); // its privilege separation directory, which otherwise only a running system sshd keeps
  const check = await runFile(sshd, ["-t", "-f", config]);
  if (!check.ok) throw new Error(`the tunnels' SSH server refused its configuration (${config}): ${check.out}`);
  return { sshd, config, hostKey: `${k.type} ${k.getPublicSSH().toString("base64")}`, kex };
}

// The tunnels that are open now, by their address (one machine, whose reconnections can overlap for a moment).
type OpenTunnel = { name: string; blob: string; since: number; kex: string; in: boolean; up: boolean; end(why: string): void };
const tunnelsOpen = new Map<string, Set<OpenTunnel>>();
const openTunnel = (id: string) => [...(tunnelsOpen.get(id) ?? [])].find((t) => t.up);

// Brings the tunnels' authorized_keys in line with what is current - the tunnel hosts in hosts.json, and the links a
// machine has called on that have not run out - and ends every open tunnel whose key is no longer in it. Links that
// ran out are dropped. Call it inside serial().
async function tunnelTidy(): Promise<void> {
  // one line per key, allowing each port that key has now: a machine that runs a new link keeps its key, and needs its
  // old port until it is in on the new one
  const keys = new Map<string, { key: string; ports: Set<number>; names: Set<string> }>(); // by the key's base64
  const add = (name: string, port: number, key: string) => {
    const k = keys.get(key.split(" ")[1] ?? "") ?? { key, ports: new Set<number>(), names: new Set<string>() };
    k.ports.add(port);
    k.names.add(name);
    keys.set(key.split(" ")[1] ?? "", k);
  };
  for (const [id, l] of await allLinks()) {
    if (l.exp <= Date.now()) await fs.unlink(linkFile(id)).catch(() => {});
    else if (l.key && l.port) add(l.name, l.port, l.key);
  }
  for (const [name, h] of Object.entries(loadHosts())) if (h.tunnel && h.port) add(name, h.port, h.tunnel.key);
  const file = join(TUNNEL_DIR, "authorized_keys"), now = await fs.readFile(file, "utf8").catch(() => null);
  const text = [...keys.values()].map((k) =>
    `restrict,port-forwarding,${[...k.ports].sort((a, b) => a - b).map((p) => `permitlisten="127.0.0.1:${p}"`).join(",")} ${k.key} ssh-mcp:${[...k.names].join(",")}\n`).join("");
  if (now !== text && (now !== null || text)) {
    await mkdirp(TUNNEL_DIR);
    await fs.writeFile(`${file}.new`, text, { mode: 0o644 });
    await fs.chmod(`${file}.new`, 0o644);
    await fs.rename(`${file}.new`, file);
  }
  for (const set of tunnelsOpen.values()) for (const t of set) if (!keys.has(t.blob)) t.end("its key is no longer listed");
}

// A port for a new tunnel: in TUNNEL_PORTS, not used by any host or link, and free right now.
const portFree = (port: number) => new Promise<boolean>((res) => {
  const s = netServer();
  s.once("error", () => res(false));
  s.listen(port, "127.0.0.1", () => s.close(() => res(true)));
});
async function tunnelPort(): Promise<number> {
  const taken = new Set<number>();
  for (const h of Object.values(loadHosts())) if (h.port && h.host === "127.0.0.1") taken.add(h.port);
  for (const [, l] of await allLinks()) if (l.port && l.exp > Date.now()) taken.add(l.port);
  for (let p = TUNNEL_PORTS[0]; p <= TUNNEL_PORTS[1]; p++) if (!taken.has(p) && (await portFree(p))) return p;
  throw new Error(`no port is left for a tunnel in ${TUNNEL_PORTS.join("-")} (TUNNEL_PORTS)`);
}

// Where a tunnel address leads: a tunnel host, or a machine whose link is under way.
async function tunnelTarget(id: string): Promise<{ name: string; key: string; port: number } | null> {
  for (const [name, h] of Object.entries(loadHosts())) if (h.tunnel && h.port && sameId(h.tunnel.id, id)) return { name, key: h.tunnel.key, port: h.port };
  for (const [, l] of await allLinks()) if (l.id && l.key && l.port && l.exp > Date.now() && sameId(l.id, id)) return { name: l.name, key: l.key, port: l.port };
  return null;
}

// GET /t/<address> with "Upgrade: ssh-mcp-tunnel", through Caddy like everything else: after "101 Switching Protocols"
// the connection's bytes go to and from an sshd of its own. Anything else that asks for an upgrade is refused.
function tunnelUpgrade(req: IncomingMessage, socket: Socket, head: Buffer): void {
  socket.on("error", () => {});
  const no = (status: string) => { socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`); };
  const m = /^\/t\/([0-9a-f]{32})$/.exec((req.url ?? "").split("?")[0]);
  if (TUNNEL_OFF || !m || String(req.headers.upgrade ?? "").toLowerCase() !== "ssh-mcp-tunnel") return no("404 Not Found");
  void (async () => {
    const to = await tunnelTarget(m[1]);
    if (!to) return no("404 Not Found");
    const here = tunnelsOpen.get(m[1])?.size ?? 0, all = [...tunnelsOpen.values()].reduce((n, s) => n + s.size, 0);
    if (here >= 3 || all >= TUNNELS_MAX) {
      console.error(`tunnel ${to.name}: refused a connection - ${here >= 3 ? `${here} of its own are open` : `${all} tunnels are open (at most ${TUNNELS_MAX})`}`);
      return no("503 Service Unavailable");
    }
    const end = await tunnelReady().catch((e: Error) => { console.error(`tunnel: ${e.message}`); return null; });
    if (!end) return no("503 Service Unavailable");
    if (AS_ROOT) await mkdirp("/run/sshd");
    if (socket.destroyed) return;
    socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: ssh-mcp-tunnel\r\nConnection: Upgrade\r\n\r\n");
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 30_000);
    await audited(whoOf(req, "tunnel"), "tunnel", { host: to.name }, () => carryTunnel(m[1], to, end, socket, head), (e: AuditEnd) => e);
  })().catch((e) => { console.error(e); socket.destroy(); });
}

// One tunnel connection, until it ends. sshd tells on its stderr which key logged in, which key exchange it made and
// when the forward is listening: a login with the key of another tunnel ends it, and a machine that logs in anew
// ends what it left open before (a connection whose network went away silently would otherwise hold its port
// until sshd gives up on it, about 45 s).
function carryTunnel(id: string, to: { name: string; key: string; port: number }, end: TunnelEnd, socket: Socket, head: Buffer): Promise<AuditEnd> {
  return new Promise((done) => {
    const child = spawn(end.sshd, ["-i", "-e", "-f", end.config], { stdio: ["pipe", "pipe", "pipe"], detached: true }); // a group of its own, ended as one
    const set = tunnelsOpen.get(id) ?? new Set<OpenTunnel>();
    tunnelsOpen.set(id, set);
    const want = keyFpOf(to.key);
    let why = "", rest = "";
    const t: OpenTunnel = {
      name: to.name, blob: to.key.split(" ")[1] ?? "", since: Date.now(), kex: "", in: false, up: false,
      end(reason) {
        if (!why) why = reason;
        try { process.kill(-child.pid!, "SIGTERM"); } catch { /* already gone */ }
        socket.destroy();
        child.stdin.destroy();
        child.stdout.destroy();
      },
    };
    set.add(t);
    child.stderr.on("data", (d: Buffer) => {
      rest += d.toString("latin1");
      for (let nl = rest.indexOf("\n"); nl >= 0; nl = rest.indexOf("\n")) {
        const line = rest.slice(0, nl);
        rest = rest.slice(nl + 1);
        let m: RegExpExecArray | null;
        if (!t.kex && (m = /kex: algorithm: (\S+)/.exec(line))) t.kex = m[1];
        else if ((m = /Accepted publickey for \S+ from .* ssh2: \S+ (SHA256:[A-Za-z0-9+/]+)/.exec(line))) {
          if (m[1] !== want) t.end("it logged in with the key of another tunnel");
          else { t.in = true; for (const o of set) if (o !== t) o.end("the machine opened a new tunnel"); }
        } else if ((m = /listening on 127\.0\.0\.1 port (\d+)/.exec(line)) && Number(m[1]) === to.port) t.up = true;
        else if (!why && /(denied|refused|not allowed|Invalid user|no matching|Unable to negotiate|Connection closed by authenticating|fatal)/i.test(line))
          why = line.replace(/^debug\d: /, "").slice(0, 240);
      }
      if (rest.length > 8192) rest = rest.slice(-1024);
    });
    child.stdin.on("error", () => {});
    child.stdout.on("error", () => {});
    if (head.length) child.stdin.write(head);
    socket.pipe(child.stdin);
    child.stdout.pipe(socket);
    socket.on("close", () => t.end("the connection closed"));
    child.on("error", (e) => { if (!why) why = e.message; socket.destroy(); });
    child.on("close", () => {
      socket.destroy();
      set.delete(t);
      if (!set.size && tunnelsOpen.get(id) === set) tunnelsOpen.delete(id);
      const normal = t.in && /^(the connection closed|the machine opened a new tunnel)$/.test(why);
      done({ ok: t.in, ...(t.kex ? { kex: t.kex } : {}), ...(normal ? {} : { err: why || "it ended before it was in" }) });
    });
  });
}

function buildServer(base = "", viaBridge = false, who: Who = { via: "mcp", ip: "?" }): McpServer {
  const server = new McpServer({ name: "rackhand", version: VERSION }, { instructions: INSTRUCTIONS });
  // Tools are registered through `tool`, never directly: that is what puts every call in the audit log before it runs.
  const register = server.registerTool.bind(server) as unknown as (name: string, config: unknown, cb: (...xs: unknown[]) => Promise<ToolOut>) => unknown;
  const tool = ((name: string, config: unknown, cb: (...xs: unknown[]) => Promise<ToolOut>) =>
    register(name, config, (...xs: unknown[]) => audited(who, name, auditInfo(name, xs.length > 1 ? (xs[0] as Args) : {}), () => cb(...xs), toolEnd))) as unknown as McpServer["registerTool"];

  tool("list_hosts", {
    description: "List SSH hosts this connector can reach.",
    inputSchema: {},
  }, async () => {
    const h = loadHosts();
    // v1.6: a host whose key exchange was decided says so; one that never was (written by hand, or older) reads as before
    const kex = (v: HostCfg) => v.pq === true ? (PQ_MODE === "off" ? " (classical key exchange: PQ_SSH=off)" : " (post-quantum key exchange)")
      : v.pq === false ? ` (classical key exchange${v.pqWhy ? `: ${v.pqWhy}` : ""})` : "";
    // v1.8: a host that comes in through its own tunnel says whether that is open now, and with which key exchange
    const tun = (id: string) => {
      if (TUNNEL_OFF) return " (reverse tunnel: turned off on this connector, TUNNEL=off)";
      const t = openTunnel(id);
      return t ? ` (reverse tunnel: open, post-quantum key exchange ${t.kex || "?"})` : " (reverse tunnel: not open)";
    };
    return text(Object.entries(h).map(([k, v]) => v.local ? `${k}: (this VPS)` : `${k}: ${v.username}@${v.host}:${v.port ?? 22}${v.tunnel ? tun(v.tunnel.id) : kex(v)}`).join("\n"));
  });

  tool("ssh_exec", {
    description: "Run a shell command on a named host. Returns exit code, stdout, stderr.",
    inputSchema: {
      host: z.string().describe("Host name from list_hosts"),
      command: z.string().describe("Shell command to run"),
      timeout_sec: z.number().int().min(1).max(1800).default(120),
      confirm: z.boolean().optional().describe(CONFIRM),
    },
  }, async ({ host, command, timeout_sec, confirm }) => {
    try {
      tripCheck([{ command }], confirm);
      const r = await runCommand(host, command, timeout_sec);
      auditNote({ exit: r.code });
      return text(`exit: ${r.code}\n--- stdout ---\n${trunc(r.stdout)}\n--- stderr ---\n${trunc(r.stderr)}`);
    } catch (e) { return fail(e); }
  });

  tool("sftp_read", {
    description: "Read a file from a host (utf8 text, or base64 for binary).",
    inputSchema: {
      host: z.string(),
      path: z.string(),
      encoding: z.enum(["utf8", "base64"]).default("utf8"),
    },
  }, async ({ host, path, encoding }) => {
    try { return text(trunc((await readRemote(host, path)).toString(encoding))); } catch (e) { return fail(e); }
  });

  tool("sftp_write", {
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

  tool("sftp_list", {
    description: "List a directory on a host.",
    inputSchema: { host: z.string(), path: z.string().default(".") },
  }, async ({ host, path }) => {
    try { return text(await listRemote(host, path)); } catch (e) { return fail(e); }
  });

  // ── v1.1 tools ──────────────────────────────────────────────────────────────

  tool("ssh_exec_many", {
    description: "Run up to 10 shell commands concurrently on one host. Returns one block per id: exit code, stdout, stderr, duration.",
    inputSchema: {
      host: z.string().describe("Host name from list_hosts"),
      commands: z.array(z.object({
        id: z.string().min(1).max(64).regex(/^[^\r\n]+$/).describe("Your label for this command; echoed in its result block"),
        command: z.string().describe("Shell command to run"),
        timeout_sec: z.number().int().min(1).max(1800).default(120),
      })).min(1).max(10).describe("1-10 commands, run in parallel"),
      confirm: z.boolean().optional().describe(CONFIRM),
    },
  }, async ({ host, commands, confirm }) => {
    try {
      getHost(host);
      tripCheck(commands.map((c) => ({ label: c.id, command: c.command })), confirm);
      const dup = commands.find((c, i) => commands.findIndex((o) => o.id === c.id) !== i);
      if (dup) throw new Error(`Duplicate id "${dup.id}"`);
      const max = Math.floor(MAX_OUT / commands.length); // the MAX_OUT budget is shared across blocks
      const t0 = Date.now();
      const ms: number[] = [];
      const done = await Promise.allSettled(commands.map((c, i) =>
        runCommand(host, c.command, c.timeout_sec).finally(() => { ms[i] = Date.now() - t0; })));
      auditNote({ exits: done.map((d) => (d.status === "fulfilled" ? d.value.code : null)) });
      return text(done.map((d, i) => {
        const head = `=== [${commands[i].id}] `, dur = ` | ${(ms[i] / 1000).toFixed(2)}s ===`;
        return d.status === "fulfilled"
          ? `${head}exit: ${d.value.code}${dur}\n--- stdout ---\n${trunc(d.value.stdout, max)}\n--- stderr ---\n${trunc(d.value.stderr, max)}`
          : `${head}error: ${(d.reason as Error).message}${dur}`;
      }).join("\n\n"));
    } catch (e) { return fail(e); }
  });

  tool("ssh_spawn", {
    description: "Start a long-running shell command in the background on a host (bash under setsid/nohup) and return a jobId immediately. " +
      `Output goes to ${JOBS_DIR}/<jobId>.log and the exit code to <jobId>.exit. Follow up with ssh_job (status | tail | wait | kill) or ssh_jobs.`,
    inputSchema: {
      host: z.string().describe("Host name from list_hosts"),
      command: z.string().min(1).describe("Shell command (bash) to run in the background"),
      confirm: z.boolean().optional().describe(CONFIRM),
    },
  }, async ({ host, command, confirm }) => {
    try {
      checkPayload("command", command);
      tripCheck([{ command }], confirm);
      const id = newJobId();
      const r = await runScript(host, spawnScript(id, command), 60);
      if (r.code !== 0) throw new Error(`spawn failed (exit ${r.code}): ${(r.stderr || r.stdout).trim()}`);
      auditNote({ job: id });
      return text(`${r.stdout.trim()}\nnext: ssh_job { host: "${host}", jobId: "${id}", action: "tail" | "wait" | "status" | "kill" }`);
    } catch (e) { return fail(e); }
  });

  tool("ssh_job", {
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

  tool("ssh_jobs", {
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

  tool("exec_code", {
    description: "Write a code snippet to a temp file on a host and run it with python3, node or bash. Returns exit code, stdout, stderr.",
    inputSchema: {
      host: z.string().describe("Host name from list_hosts"),
      language: z.enum(["python", "node", "bash"]),
      code: z.string().min(1).describe("Source code to run"),
      timeout_sec: z.number().int().min(1).max(1800).default(120),
      confirm: z.boolean().optional().describe(CONFIRM),
    },
  }, async ({ host, language, code, timeout_sec, confirm }) => {
    try {
      checkPayload("code", code);
      if (language === "bash") tripCheck([{ command: code }], confirm); // the tripwire reads shell only
      const t0 = Date.now();
      const r = await runScript(host, codeScript(language, code, timeout_sec), timeout_sec + 15);
      auditNote({ exit: r.code });
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
    confirm: z.boolean().optional().describe(CONFIRM),
    description: z.string().optional().describe("What the command does (for the transcript; not used by the server)"),
  };
  // ok = the command ran and exited 0. budget = most bytes of output to return. inBatch: see bashScript's noteMove.
  const runBash = async ({ host, command, timeout, cwd, session, run_in_background, quiet, confirm }: z.infer<z.ZodObject<typeof bashShape>>, budget = OUT_HEAD + OUT_TAIL, inBatch = false): Promise<{ out: ToolOut; ok: boolean }> => {
    try {
      checkPayload("command", command);
      tripCheck([{ command }], confirm);
      if (run_in_background) {
        const id = newJobId();
        const cdExpr = cwd ? `printf %s ${shq(cwd)}` : session ? `cat "$(dirname "$D")/sessions/${session}.cwd" 2>/dev/null || printf %s ~` : "printf %s ~";
        const r = await runScript(host, spawnScript(id, command, cdExpr), 60);
        if (r.code !== 0) throw new Error(`spawn failed (exit ${r.code}): ${(r.stderr || r.stdout).trim()}`);
        auditNote({ job: id });
        return { out: text(`${r.stdout.trim()}\nnext: ssh_job { host: "${host}", jobId: "${id}", action: "tail" | "wait" | "status" | "kill" }`), ok: true };
      }
      const sec = Math.ceil(timeout / 1000);
      const r = await runScript(host, bashScript({ command, timeoutSec: sec, cwd, session, keep: outLimit(budget, quiet), noteMove: inBatch }), sec + 20);
      if (r.code !== 0) throw new Error((r.stderr || r.stdout).trim() || `exit ${r.code}`);
      const m = /^rc=(-?\d+)$/m.exec(r.stderr), rc = m ? Number(m[1]) : null; // the command's own exit code
      auditNote({ exit: rc });
      return { out: text(r.stdout === "" ? "(no output)" : r.stdout), ok: rc === 0 };
    } catch (e) { return { out: fail(e), ok: false }; }
  };
  tool("bash", {
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
  tool("read", {
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
  tool("write", {
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
  tool("edit", {
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
  tool("batch", {
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
      const t0 = Date.now(), batchId = auditScope.getStore()?.id;
      for (let i = 0; i < ops.length; i++) {
        const op = ops[i], kind = kinds[i];
        const label = kind === "bash" ? oneLine(op.bash!.description ?? op.bash!.command)
          : kind === "read" ? op.read!.file_path ?? `${op.read!.files?.length ?? 0} files`
          : kind === "write" ? op.write!.file_path ?? `${op.write!.files?.length ?? 0} files`
          : op.edit!.file_path ?? `${op.edit!.edits?.length ?? 0} edits`;
        const head = `=== [${i + 1}/${ops.length}] ${kind} ${label} | `;
        if (failN > 0 && stop_on_error) { skipN++; say(`${head}skipped ===\n`); continue; }
        const s0 = Date.now();
        const link = batchId ? { batch: `${batchId}#${i + 1}/${ops.length}` } : {}; // each step has its own audit record
        let out: ToolOut, ok: boolean;
        if (kind === "bash") {
          const a = { ...op.bash!, host, cwd: op.bash!.cwd ?? (firstBash ? cwd : undefined), session: op.bash!.session ?? sess };
          const r = await audited(who, "bash", { ...auditInfo("bash", a), ...link }, () => runBash(a, per - 300, true), (x) => toolEnd(x.out));
          firstBash = false; out = r.out; ok = r.ok;
        } else {
          const run = kind === "read" ? () => readTool({ ...op.read!, host }, per) : kind === "write" ? () => writeTool({ ...op.write!, host }) : () => editTool({ ...op.edit!, host });
          out = await audited(who, kind, { ...auditInfo(kind, { ...op[kind], host }), ...link }, run, toolEnd);
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
      auditNote({ ops: `${okN} ok, ${failN} failed, ${skipN} skipped`, err: failN ? `${failN} of ${ops.length} ops failed` : undefined });
      return { content, isError: failN > 0 };
    } catch (e) { return fail(e); }
  });

  tool("bridge", {
    description: "Open a direct path from your own sandbox shell to this server, so files and command output move at network speed without passing through the model. " +
      "Returns a time-limited URL and a one-line installer for the `box` command (exec, put, get, push, pull, call). Use it for bulk transfers, whole directories, binaries, and scripted sequences of commands.",
    inputSchema: { ttl_hours: z.number().min(1).max(168).default(12).describe("How long the URL stays valid") },
  }, async ({ ttl_hours }) => {
    // A bridge URL must expire when it says it does, so it cannot be used to mint its own successor.
    if (viaBridge) return fail(new Error("A bridge URL cannot create another one - call the bridge tool through the connector itself"));
    const { exp, token } = mintBridgeToken(Math.round(ttl_hours * 3600));
    auditNote({ tok: exp.toString(36) }); // requests made through this URL carry the same "tok" in the log
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

  // ── v1.4 ──
  tool("audit", {
    description: "Show this connector's audit log: one line per tool call and bridge request, oldest first - time (UTC), client address, route, tool, host, result, duration, " +
      "and the command or the paths. Calls from every chat and every client are in it; file contents never are.",
    inputSchema: {
      limit: z.number().int().min(1).max(500).default(50).describe("Show the newest N matching entries"),
      contains: z.string().min(1).max(200).optional().describe("Only entries whose line contains this text (case-insensitive): part of a command or path, a tool name, a host, an address"),
      since_minutes: z.number().int().min(1).max(525_600).optional().describe("Only entries from the last N minutes"),
    },
  }, async ({ limit, contains, since_minutes }) => {
    try {
      if (AUDIT_OFF) return text("The audit log is turned off on this server (AUDIT_LOG=off).");
      if (!auditFile) throw new Error(`the audit log is not being written: ${auditErr}`);
      const shown = await auditShow(limit, contains, since_minutes, auditScope.getStore()?.id);
      return text(trunc(auditErr ? `${shown}\nWARNING: the last write to the audit log failed: ${auditErr}` : shown));
    } catch (e) { return fail(e); }
  });

  // v1.8: add_host with tunnel: true - a link for the machine to call on, instead of a connection to it
  async function tunnelLink(o: { name: string; host?: string; username: string; port: number; fingerprint?: string; replace?: boolean }): Promise<string> {
    if (o.host) throw new Error("With tunnel: true, leave host out: that server connects to this connector, not the other way round.");
    const all = loadHosts();
    if (all[o.name]?.local) throw new Error(`"${o.name}" is this machine itself and cannot be replaced.`);
    if (o.name in all && !o.replace) throw new Error(`A host named "${o.name}" already exists. Pass replace: true to have the new machine take its name, or use another name.`);
    if (!/^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$/.test(base))
      throw new Error(`A tunnel comes in over HTTPS, and this connector was reached at ${base || "an unknown address"}: put it behind HTTPS first (the installer does that, with Caddy), or set PUBLIC_URL.`);
    await tunnelReady();
    await serial(connectorKey);
    const id = randomBytes(16).toString("hex"), exp = Date.now() + LINK_MS;
    await serial(async () => {
      await saveLink(id, { name: o.name, username: o.username, to: o.port, ...(o.fingerprint ? { fingerprint: o.fingerprint } : {}), ...(o.replace ? { replace: true } : {}), exp });
      await tunnelTidy();
    });
    auditNote({ added: false, tunnel: true });
    const url = `${base}/t/${id}`;
    return [
      `Not added yet: "${o.name}" is to connect to this connector through a tunnel of its own. On that machine, run as root:`,
      "",
      `  curl -fsSL ${url} | sudo bash`,
      "",
      `The link works once, until ${new Date(exp).toISOString().slice(11, 16)} UTC (30 minutes). To read the script first: curl -fsSL ${url}`,
      `It checks for an OpenSSH client with a post-quantum key exchange and an SSH server on port ${o.port}, lets this connector log in as ${o.username} there, ` +
        "and installs the service ssh-mcp-tunnel, which keeps an SSH connection open to this connector over HTTPS (port 443): nothing on that machine has to be reachable from outside. " +
        "It needs systemd; on a machine without, SSHMCP_TUNNEL_FOREGROUND=1 keeps the tunnel in the foreground instead.",
      `When it prints "connected", "${o.name}" can be used as host in every tool.`,
    ].join("\n");
  }

  // ── v1.5 ──
  tool("add_host", {
    description: "Connect another server to this connector, without editing hosts.json by hand. The connector has an SSH key of its own (created on first use). " +
      "If the server does not accept that key yet, the tool returns the public key line to add to the server's ~/.ssh/authorized_keys: have the user do that, then call it again. " +
      "When the login works it runs a test command, pins the server's host key and saves the host, which can be used as `host` at once. There is no password option. " +
      "The connection to that server uses post-quantum key exchange when the server's SSH has one; the result says which it is, and why not if not. " +
      "For a server this connector cannot reach (behind NAT or a firewall), pass tunnel: true and leave host out: the result is a one-line command to run on that server, which then connects to this connector itself.",
    inputSchema: {
      name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/).describe("Short name to use as `host` in the other tools, e.g. web-1"),
      host: z.string().regex(/^[A-Za-z0-9:][A-Za-z0-9.:-]{0,252}$/).optional().describe("IP address or DNS name of the server (leave it out with tunnel: true)"),
      username: z.string().regex(/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/).describe("User to log in as, e.g. root or ubuntu"),
      port: z.number().int().min(1).max(65535).default(22).describe("Its SSH port (with tunnel: true, the port its SSH server listens on there)"),
      fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]{43}=?$/).optional().describe("Expected host key fingerprint (SHA256:...); if given, the server must present exactly this key"),
      replace: z.boolean().optional().describe("Overwrite an existing host of the same name"),
      tunnel: z.boolean().optional().describe("The server cannot be reached from here (behind NAT or a firewall): it gets a command to run, and connects to this connector itself"),
    },
  }, async ({ name, host, username, port, fingerprint, replace, tunnel }) => {
    try {
      if (tunnel) return text(await tunnelLink({ name, host, username, port, fingerprint: fingerprint?.replace(/=+$/, ""), replace }));
      if (!host) throw new Error("host is required - or, for a server this connector cannot reach, tunnel: true");
      const target = `${username}@${host}:${port}`;
      const taken = (all: Record<string, HostCfg>) => {
        if (all[name]?.local) throw new Error(`"${name}" is this machine itself and cannot be replaced.`);
        if (name in all && !replace) throw new Error(`A host named "${name}" already exists (${all[name].username}@${all[name].host}:${all[name].port ?? 22}). Pass replace: true to overwrite it, or use another name.`);
      };
      taken(loadHosts());
      auditNote({ added: false });
      const key = await serial(connectorKey);
      const expect = fingerprint?.replace(/=+$/, "");
      const hk = await presentedKey(host, port, username); // no login yet: first see which server this is
      if ("err" in hk) throw new Error(`Cannot reach ${host}:${port} over SSH: ${hk.err}`);
      if (expect && expect !== hk.fp) throw new Error(`The host key of ${host}:${port} does not match: expected ${fingerprint}, but the server presented ${hk.fp} (${hk.type}). Nothing was added.`);
      // Post-quantum first: when it works, no login to this server ever crosses the network under a classical key exchange.
      let pq: { kex: string; who: string; via: string } | null = null, why = "", refused = false;
      if (PQ_MODE === "off") why = "PQ_SSH=off on this connector";
      else {
        const kex = await pqHere(), to = { host, port, username, keyPath: key.path, key: hk, kex }, home = `127.0.0.1:${port}`;
        if (!kex.length) why = "this machine has no OpenSSH client with post-quantum key exchange";
        // where the server's own SSH is, seen from the server: normally its loopback address and the same port; if not, the server is asked
        for (const guess of kex.length ? [home, null] : []) {
          try {
            const via = guess ?? await ownSshAddress(to);
            if (!via || (guess === null && via === home)) break; // it could not be asked, or it names what was just tried
            const got = await pqGate(`${host}:${port}`, () => carried({ ...to, via, privateKey: key.privateKey }));
            pq = { kex: got.kex, who: await whoIs(got.client, username), via };
            break;
          } catch (e) {
            if (!isPqFail(e)) throw e;
            if (e.kind === "hostkey") throw new Error(`The server at ${host}:${port} presented another host key a moment later (first ${hk.fp}). Nothing was added.`);
            if (guess === home || !why) why = e.kind === "down" ? `the OpenSSH client could not connect: ${e.why}` : e.why;
            refused = e.kind === "auth";
            if (e.kind !== "noroute" && e.kind !== "innerkey") break;
          }
        }
      }
      let who = pq?.who;
      if (!pq) {
        if (PQ_MODE === "require" && !refused) throw new Error(`${host}:${port} cannot be connected to with post-quantum key exchange: ${why}. This connector only adds hosts that can (PQ_SSH=require). Nothing was added.`);
        // The server said no to the key inside a post-quantum connection: that answer stands, and no second login is tried on a classical one.
        const p: Probe = refused ? { ok: false, authFailed: true } : await probeHost(host, port, username, key.privateKey, hk.fp);
        if (!p.ok && !p.authFailed) throw new Error(`${host}:${port} answered, but the login as ${username} did not complete: ${p.err}`);
        if (!p.ok) return text([
          `Not added yet: ${host}:${port} answered, but it does not accept this connector's key for the user ${username}.`,
          "",
          `1. On that server, as ${username}, add this line to ~/.ssh/authorized_keys:`,
          `     ${key.publicKey}`,
          "   For example by running this there:",
          `     mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${key.publicKey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`,
          `2. Make sure it is the right server: the host key it presented has the fingerprint ${hk.fp}`,
          `   (on that server: ssh-keygen -lf /etc/ssh/${hostKeyFileOf(hk.type)})`,
          `3. Call add_host again with the same arguments plus fingerprint: "${hk.fp}", so that exactly this server is added.`,
        ].join("\n"));
        who = p.who;
      }
      await serial(async () => {
        await updateHosts((all) => {
          taken(all);
          all[name] = { host, port, username, privateKeyPath: key.path, hostFingerprint: hk.fp,
            ...(pq ? { pq: true, ...(pq.via !== `127.0.0.1:${port}` ? { pqVia: pq.via } : {}) } : PQ_MODE === "off" ? {} : { pq: false, pqWhy: why }) };
        });
        await tunnelTidy(); // a tunnel host this replaced: its tunnel's key goes
      });
      if (pq) pqKeys.set(pqKeyId(host, port, hk.fp), hk);
      auditNote({ added: true, fp: hk.fp, ...(pq ? { kex: pq.kex } : {}) });
      return text([
        `Added host "${name}": ${target}`,
        `Host key pinned: ${hk.fp} (${hk.type})`,
        pq ? `Key exchange: ${pq.kex} (post-quantum) - the connection is made by this machine's OpenSSH client, everything else runs inside it`
          : `Key exchange: classical. Post-quantum was not possible: ${why}.`,
        `Test: logged in as ${who}`,
        `Use host: "${name}" in any tool. Saved in ${resolvePath(HOSTS_FILE)} (the previous version is kept as ${resolvePath(HOSTS_FILE)}.bak).`,
      ].join("\n"));
    } catch (e) { return fail(e); }
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
  const server = buildServer(publicBase(req), typeof (req.params as Record<string, string>).token === "string", whoOf(req));
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

// Every bridge request below is audited like a tool call (bridge.cli / get / put / pull / push / exec).
const same = (e: AuditEnd) => e;

bridge.get("/cli", guarded(async (req, res) => {
  await audited(whoOf(req), "bridge.cli", {}, async (): Promise<AuditEnd> => {
    const script = readFileSync(new URL("./box.sh", import.meta.url), "utf8");
    const token = (req.params as Record<string, string>).token; // from the parent route /b/:token (mergeParams)
    res.type("text/plain").send(script.replaceAll("__BOX_URL__", `${publicBase(req)}/b/${token}`).replaceAll("__BOX_VERSION__", VERSION));
    return { ok: true };
  }, same);
}));

// Run `fn` when a response is over, one way or the other; `fn` tells by res.writableFinished whether the client has
// left early. A response that is being sent hears that as its own "close". One that is still waiting its turn on
// the connection (a client may send several requests at once) hears nothing - only the connection itself does.
function whenClosed(res: express.Response, fn: () => void): void {
  const conn = res.req.socket;
  const once = () => { res.off("close", once); conn.off("close", once); fn(); };
  res.once("close", once);
  conn.once("close", once);
  if (conn.destroyed) queueMicrotask(once);
}

// What became of a response: "whole" when all of it was handed to the connection, "gone" when the client left
// first. A script that has exited says nothing about that: the end of its output can still be inside this server,
// waiting for a reader that is slower than the script was. Call it before the response can end - it listens for that.
function delivered(res: express.Response): Promise<"whole" | "gone"> {
  const conn = res.req.socket;
  return new Promise((resolve) => {
    res.once("finish", () => resolve(conn.destroyed ? "gone" : "whole")); // a last write cut off by a broken connection still "finishes"
    whenClosed(res, () => resolve("gone"));                               // after "finish" this changes nothing
  });
}

// A response whose length was announced is finished the moment that many bytes have gone out, not when the script
// that produced them has also exited: a client that closes as soon as it has everything (curl does) must not look
// like one that broke off. Bytes written to the returned stream go to `res`. When the script is done, end() the
// stream and wait for `fate`: "whole" or "gone" as from delivered(), or
//   "short"  the stream ended before the announced number of bytes had come - the response is broken off, never ended short
type Fate = "whole" | "short" | "gone";
function sized(res: express.Response, size: number): Transform & { fate: Promise<Fate> } {
  let left = size, complete = false, settle: (fate: Fate) => void = () => {};
  const fate = new Promise<Fate>((resolve) => { settle = resolve; }); // the first verdict stands
  const out = Object.assign(new Transform({
    transform(chunk: Buffer, _enc, cb) {
      if (complete) return cb();                                          // never more than was announced
      const part = chunk.length > left ? chunk.subarray(0, left) : chunk;
      left -= part.length;
      if (part.length) this.push(part);
      if (left === 0) { complete = true; this.push(null); }               // end of the body: the pipe ends `res` once all of it is written
      cb();
    },
    flush(cb) {                                                           // end(): everything that was written has been through here
      if (!complete) { settle("short"); out.unpipe(res); res.destroy(); }
      cb();
    },
  }), { fate });
  delivered(res).then(settle);                                            // only a complete body is ever ended
  out.on("error", () => {});
  whenClosed(res, () => { if (!res.writableFinished) out.destroy(); }); // the client left before it had everything: stop the script
  out.pipe(res);
  if (size === 0) { complete = true; out.push(null); }
  return out;
}

// GET /fs/<host>?p64=<path>  ->  the file's bytes
bridge.get("/fs/:host", guarded(async (req, res) => {
  const host = hostOf(req, res); if (!host) return;
  const p = absPath(req, res); if (!p) return;
  await audited(whoOf(req), "bridge.get", { host, what: p }, async (): Promise<AuditEnd> => {
    const st = await runScript(host, `f=${shq(p)}; [ -f "$f" ] && [ -r "$f" ] && wc -c < "$f"`, 30);
    if (st.code !== 0) { plain(res, 404, `No such readable file: ${host}:${p}`); return { ok: false, err: "no such readable file" }; }
    const size = Number(st.stdout.trim());
    res.status(200).set({ "Content-Type": "application/octet-stream", "Content-Length": String(size) });
    const out = sized(res, size);
    const r = await streamExec(host, `head -c ${size} -- ${shq(p)}`, null, out);
    // on failure the client sees a broken transfer, never a silently short file
    if (r.aborted || r.code !== 0) { res.destroy(); return { ok: false, err: r.aborted ? "the client disconnected" : `exit ${r.code}`, bytes: size }; }
    out.end();
    const fate = await out.fate;
    if (fate !== "whole") return { ok: false, err: fate === "short" ? "the file became shorter while it was being sent" : "the client disconnected", bytes: size };
    return { ok: true, bytes: size };
  }, same);
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
  await audited(whoOf(req), "bridge.put", { host, what: `${p} (${Number(want)} B)`, bytes: Number(want) }, async (): Promise<AuditEnd> => {
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
    if (r.aborted) { res.destroy(); return { ok: false, err: "the client disconnected" }; }
    if (r.code !== 0) { const msg = r.stderr.trim() || `write failed (exit ${r.code})`; plain(res, 500, msg); return { ok: false, err: msg }; }
    plain(res, 200, `wrote ${wrote.trim()} bytes to ${host}:${p}`);
    return { ok: true };
  }, same);
}));

// GET /tar/<host>?p64=<dir>[&x64=<exclude pattern>...]  ->  the directory tree as tar.gz
bridge.get("/tar/:host", guarded(async (req, res) => {
  const host = hostOf(req, res); if (!host) return;
  const dir = absPath(req, res); if (!dir) return;
  const ex = [...qlist(req.query.x), ...qlist(req.query.x64).map((x) => Buffer.from(x, "base64url").toString("utf8"))];
  await audited(whoOf(req), "bridge.pull", { host, what: `${dir}${ex.length ? ` (exclude: ${ex.join(", ")})` : ""}` }, async (): Promise<AuditEnd> => {
    const chk = await runScript(host, `[ -d ${shq(dir)} ] && [ -r ${shq(dir)} ]`, 30);
    if (chk.code !== 0) { plain(res, 404, `No such readable directory: ${host}:${dir}`); return { ok: false, err: "no such readable directory" }; }
    res.status(200).set({ "Content-Type": "application/gzip" });
    const out = new PassThrough(); // a stream of our own in between: closing it stops tar, also for a response that never got its turn
    out.on("error", () => {});
    whenClosed(res, () => { if (!res.writableFinished) out.destroy(); });
    const fate = delivered(res);
    out.pipe(res);
    const r = await streamExec(host, `tar -C ${shq(dir)} ${ex.map((x) => `--exclude=${shq(x)}`).join(" ")} -czf - .`, null, out);
    // tar exits 1 when a file changed while it was read (the archive is still good); anything worse breaks the transfer
    if (r.aborted || r.code === null || r.code > 1) {
      if (!r.aborted) console.error(`tar ${host}:${dir} failed (exit ${r.code}): ${r.stderr.trim()}`);
      res.destroy();
      return { ok: false, err: r.aborted ? "the client disconnected" : `tar failed (exit ${r.code}): ${r.stderr.trim()}` };
    }
    out.end(); // the pipe ends the response when the rest of the archive has gone out
    if ((await fate) !== "whole") return { ok: false, err: "the client disconnected" };
    return { ok: true };
  }, same);
}));

// PUT /tar/<host>?p64=<dir>  <-  a tar.gz stream, unpacked into the directory (created if missing)
bridge.put("/tar/:host", guarded(async (req, res) => {
  const host = hostOf(req, res); if (!host) return;
  const dir = absPath(req, res); if (!dir) return;
  await audited(whoOf(req), "bridge.push", { host, what: dir }, async (): Promise<AuditEnd> => {
    const r = await streamExec(host, `d=${shq(dir)}; mkdir -p -- "$d" && tar -C "$d" --no-same-owner -xzf -`, req, new PassThrough().resume());
    if (r.aborted) { res.destroy(); return { ok: false, err: "the client disconnected" }; }
    if (r.code !== 0) { const msg = r.stderr.trim() || `unpack failed (exit ${r.code})`; plain(res, 500, msg); return { ok: false, err: msg }; }
    plain(res, 200, `unpacked into ${host}:${dir}`);
    return { ok: true };
  }, same);
}));

// POST /exec/<host>[?timeout=<sec>&c64=<cwd>&confirm=1]  body = command  ->  merged output of any size, streamed;
// the command's exit code is in the X-Exit-Code header.
bridge.post("/exec/:host", express.text({ type: () => true, limit: "1mb" }), guarded(async (req, res) => {
  const host = hostOf(req, res); if (!host) return;
  const command = typeof req.body === "string" ? req.body : "";
  if (!command.trim()) return plain(res, 400, "the request body must be the command to run");
  if (Buffer.byteLength(command) > MAX_PAYLOAD) return plain(res, 413, `command too large (max ${MAX_PAYLOAD} bytes) - upload it as a script and run that`);
  const t = Math.min(1800, Math.max(1, Math.floor(Number(qstr(req.query.timeout) ?? 120)) || 120));
  const cwd = qval(req, "c64", "cwd");
  await audited(whoOf(req), "bridge.exec", { host, what: command, ...(cwd ? { cwd } : {}) }, async (): Promise<AuditEnd> => {
    try { tripCheck([{ command }], /^(1|true|yes)$/i.test(qstr(req.query.confirm) ?? ""), "?confirm=1 (box exec -y)"); }
    catch (e) { plain(res, 409, (e as Error).message); return { ok: false, err: (e as Error).message }; }
    // The script answers with one header line, "rc=<exit code> size=<bytes>", then the output itself.
    let head: Buffer | null = Buffer.alloc(0), started = false, rc: number | null = null, left = 0, complete = false, short = false;
    // when the announced body has gone in, the response ends (the pipe ends `res` once all of it is written),
    // whatever the script still does before it exits
    const pass = (t: Transform, bytes: Buffer) => { if (complete) return; left -= bytes.length; if (bytes.length) t.push(bytes); if (left <= 0) { complete = true; t.push(null); } };
    const body = new Transform({
      transform(chunk: Buffer, _enc, cb) {
        if (head === null) { pass(this, chunk); return cb(); }
        head = Buffer.concat([head, chunk]);
        const nl = head.indexOf(10);
        const m = nl < 0 ? null : /^rc=(-?\d+) size=(\d+)$/.exec(head.subarray(0, nl).toString("latin1"));
        if (!m) return cb(nl < 0 && head.length < 64 ? null : new Error("unexpected output from the exec script"));
        started = true; rc = Number(m[1]); left = Number(m[2]);
        res.status(200).set({ "Content-Type": "text/plain; charset=utf-8", "Content-Length": m[2], "X-Exit-Code": m[1] });
        const rest = head.subarray(nl + 1);
        head = null;
        pass(this, rest);
        cb();
      },
      flush(cb) { if (started && !complete) { short = true; body.unpipe(res); res.destroy(); } cb(); }, // less output than the script announced: broken off, never ended short
    });
    body.on("error", () => {});
    whenClosed(res, () => { if (!res.writableFinished) body.destroy(); }); // the client left before it had everything: stop the script
    const fate = delivered(res);
    body.pipe(res);
    const r = await streamExec(host, bashScript({ command, timeoutSec: t, cwd, raw: true }), null, body);
    if (!started) {
      const msg = r.stderr.trim() || `exec failed (exit ${r.code})`;
      body.unpipe(res);
      if (!res.destroyed) plain(res, 500, msg);
      return { ok: false, err: r.aborted ? "the client disconnected" : msg };
    }
    if (r.aborted || r.code !== 0) { res.destroy(); return { ok: false, exit: rc, err: r.aborted ? "the client disconnected" : `the exec script failed (exit ${r.code})` }; }
    body.end();
    const f = await fate;
    if (short || f !== "whole") return { ok: false, exit: rc, err: short ? "the output became shorter while it was being sent" : "the client disconnected" };
    return { ok: true, exit: rc };
  }, same);
}));

app.use("/b/:token", (req, res, next) => { if (bridgeTokenOk(String(req.params.token))) next(); else res.status(404).end(); }, bridge);

// ── v1.8: the tunnel links add_host hands out - the script for the machine, the machine calling in, the machine in ──
const linkGone = "This link has run out or was used up: call add_host again.";
const linkAnswer = (l: Link) => `port=${l.port}\nid=${l.id}\nuser=${TUNNEL_USER}\n`;
const httpsBase = (base: string) => /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$/.test(base);
// A public key line as "type base64", if it is one ssh2 can read; null otherwise.
function publicKeyLine(line: string): string | null {
  const [type, blob] = line.trim().split(/\s+/);
  if (!type || !blob || !/^[A-Za-z0-9@.-]+$/.test(type) || !/^[A-Za-z0-9+/]+={0,2}$/.test(blob)) return null;
  const parsed = sshUtils.parseKey(`${type} ${blob}`), k = Array.isArray(parsed) ? parsed[0] : parsed;
  return k && !(k instanceof Error) && k.type === type ? `${type} ${blob}` : null;
}

// GET /t/<link>: the script to run on the machine, with its blanks filled in (any number of times, until the link is used up)
app.get("/t/:id", guarded(async (req, res) => {
  const id = String(req.params.id), l = await linkOf(id);
  if (!l) return plain(res, 404, linkGone);
  await audited(whoOf(req, "tunnel"), "tunnel.link", { host: l.name }, async (): Promise<AuditEnd> => {
    const base = publicBase(req);
    if (!httpsBase(base)) { plain(res, 400, `A tunnel is made over HTTPS, and this link was fetched at ${base}.`); return { ok: false, err: "not over HTTPS" }; }
    const end = await tunnelReady(), key = await serial(connectorKey), [type, blob] = key.publicKey.split(" ");
    const fill: Record<string, string> = {
      __URL__: base, __ENROLL__: id, __NAME__: l.name, __USERNAME__: l.username, __SSHD_PORT__: String(l.to), __VERSION__: VERSION,
      __CONNECTOR_KEY__: `${type} ${blob} ssh-mcp@${hostname().replace(/[^A-Za-z0-9.-]/g, "") || "connector"}`,
      __TUNNEL_HOSTKEY__: end.hostKey, __KEX__: end.kex.join(","),
    };
    let script = readFileSync(new URL("./tunnel.sh", import.meta.url), "utf8");
    for (const [k, v] of Object.entries(fill)) {
      if (!/^[A-Za-z0-9@%+/=:,._ -]*$/.test(v)) throw new Error(`refusing to put ${JSON.stringify(v)} into a script`); // nothing that could break out of its quotes
      script = script.replaceAll(k, v);
    }
    res.type("text/plain").send(script);
    return { ok: true };
  }, same);
}));

// POST /t/<link>: the machine calls in - its key for the tunnel and its SSH host keys - and gets the port and the
// address of its tunnel. Once per link: the same machine asking again (a retry) gets the same answer, any other a no.
app.post("/t/:id", express.text({ type: () => true, limit: "64kb" }), guarded(async (req, res) => {
  const id = String(req.params.id), l0 = await linkOf(id);
  await audited(whoOf(req, "tunnel"), "tunnel.enroll", l0 ? { host: l0.name } : {}, async (): Promise<AuditEnd> => {
    const [status, answer] = await serial(async (): Promise<[number, string]> => { // ports, keys and records: one at a time
      const l = await linkOf(id);
      if (!l) return [404, linkGone];
      const lines = (typeof req.body === "string" ? req.body : "").split("\n");
      const field = (k: string) => lines.filter((x) => x.startsWith(`${k} `)).map((x) => x.slice(k.length + 1).trim());
      const printable = (v?: string) => v?.replace(/[^\x20-\x7e]/g, "").slice(0, 200);
      const key = publicKeyLine(field("key")[0] ?? "");
      if (!key?.startsWith("ssh-ed25519 ")) return [400, "The machine sent no ssh-ed25519 key for the tunnel."];
      const hostKeys = [...new Set(field("hostkey").map(publicKeyLine).filter((k): k is string => !!k))];
      if (!hostKeys.length) return [400, "The machine sent none of its SSH host keys."];
      if (l.fingerprint && !hostKeys.some((k) => keyFpOf(k) === samePin(l.fingerprint!)))
        return [409, `None of this machine's SSH host keys has the fingerprint add_host was given (${l.fingerprint}); it has ${hostKeys.map(keyFpOf).join(", ")}. Nothing was changed.`];
      if (l.key) return l.key === key ? [200, linkAnswer(l)] : [409, "This link was already used by another machine."];
      const all = loadHosts(), other = Object.entries(all).find(([n, h]) => n !== l.name && h.tunnel?.key === key);
      if (other) return [409, `This machine already comes in as "${other[0]}". To have it come in as "${l.name}" instead, remove "${other[0]}" from hosts.json first.`];
      if (l.name in all && !l.replace) return [409, `A host named "${l.name}" was added meanwhile: call add_host again, with replace: true or another name.`];
      Object.assign(l, { key, hostKeys, hostname: printable(field("hostname")[0]), client: printable(field("client")[0]), port: await tunnelPort(), id: randomBytes(16).toString("hex"), exp: Date.now() + LINK_MS });
      await saveLink(id, l);
      await tunnelTidy(); // its key, bound to its port
      return [200, linkAnswer(l)];
    });
    plain(res, status, answer);
    return status === 200 ? { ok: true } : { ok: false, err: answer };
  }, same);
}));

// POST /t/<link>/up: the machine has started its tunnel. Once the SSH server behind it presents one of the host keys
// the machine reported and lets the connector's key in, the host is saved - and the link is gone.
app.post("/t/:id/up", guarded(async (req, res) => {
  const id = String(req.params.id), l = await linkOf(id);
  await audited(whoOf(req, "tunnel"), "tunnel.up", l ? { host: l.name } : {}, async (): Promise<AuditEnd> => {
    const say = (status: number, msg: string): AuditEnd => { plain(res, status, msg); return status === 200 ? { ok: true } : { ok: false, err: msg }; };
    if (!l?.key || !l.port || !l.id) return say(404, linkGone);
    const hk = await presentedKey("127.0.0.1", l.port, l.username);
    if ("err" in hk) return say(503, `The tunnel is not open yet (${hk.err}).`);
    const reported = (l.hostKeys ?? []).map(keyFpOf);
    if (!reported.includes(hk.fp)) return say(409, `The SSH server behind the tunnel presented the host key ${hk.fp}, which is not one of those this machine reported (${reported.join(", ")}). Nothing was added.`);
    const key = await serial(connectorKey);
    const p = await probeHost("127.0.0.1", l.port, l.username, key.privateKey, hk.fp);
    if (!p.ok) return say(502, p.authFailed
      ? `The tunnel is open, but the SSH server on this machine does not let the connector's key in as ${l.username}: is the line the script added to that user's ~/.ssh/authorized_keys still there, and does that server read that file?`
      : `The tunnel is open, but the connector's login as ${l.username} did not complete: ${p.err}`);
    const refused = await serial(async () => {
      if (!(await linkOf(id))) return linkGone;
      const all = loadHosts();
      if (all[l.name]?.local || (l.name in all && !l.replace)) return `A host named "${l.name}" was added meanwhile. Nothing was added.`;
      await updateHosts((h) => { h[l.name] = { host: "127.0.0.1", port: l.port, username: l.username, privateKeyPath: key.path, hostFingerprint: hk.fp, tunnel: { id: l.id!, key: l.key!, to: l.to } }; });
      await fs.unlink(linkFile(id)).catch(() => {});
      await tunnelTidy(); // what the name had before, if it was replaced, goes now
      return "";
    });
    if (refused) return say(409, refused);
    const kex = openTunnel(l.id)?.kex ?? "";
    auditNote({ added: true, fp: hk.fp, ...(kex ? { kex } : {}) });
    return say(200, `connected: this machine is "${l.name}" at ${publicBase(req)}, and the connector logged in through the tunnel as ${p.who}. ` +
      `Its SSH host key ${hk.fp} is pinned; the tunnel's key exchange is ${kex ? `${kex} (post-quantum)` : "post-quantum"}.`);
  }, same);
}));

app.use((_req, res) => { res.status(404).end(); });

await auditInit();
const httpServer = app.listen(PORT, "127.0.0.1", () => console.log(`rackhand listening on 127.0.0.1:${PORT}`));
httpServer.on("upgrade", tunnelUpgrade); // v1.8: tunnels (everything else that asks for an upgrade is refused)
if (!TUNNEL_OFF) void serial(tunnelTidy).catch((e) => console.error(`tunnels: ${(e as Error).message}`)); // what ran out while this was not running
