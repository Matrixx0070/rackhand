// Black-box tests over the MCP HTTP endpoint (JSON-RPC), against a real server process.
// Hosts under test: "local" (child_process path) and "remote" (ssh2 path, via an in-process
// SSH server that runs commands with `sh -c`, i.e. a non-bash login shell).
// Run: node --test test/e2e.mjs      (SERVER_FILE=server.ts by default)
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { appendFileSync, mkdtempSync, writeFileSync, readFileSync, readdirSync, mkdirSync, rmSync, renameSync, existsSync, statSync, lstatSync, chmodSync,
  openSync, readSync, writeSync, fstatSync, fchmodSync, closeSync } from "node:fs";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { tmpdir, userInfo } from "node:os";
import net from "node:net";
import path from "node:path";
import http from "node:http";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { Server, utils } = require("ssh2");

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SERVER_FILE = process.env.SERVER_FILE ?? "server.ts";
const TMP = mkdtempSync(path.join(tmpdir(), "ssh-mcp-test-"));
const JOBS = path.join(TMP, "jobs");
const CODE_TMP = path.join(TMP, "codetmp");
const HOME2 = path.join(TMP, "home");
mkdirSync(CODE_TMP);
mkdirSync(HOME2);
const SECRET = randomBytes(32).toString("hex");
const PORT = 18787, PORT2 = 18788;
const BASE = `http://127.0.0.1:${PORT}/mcp/${SECRET}`;
const BASE2 = `http://127.0.0.1:${PORT2}/mcp/${SECRET}`;
const OLD = ["list_hosts", "ssh_exec", "sftp_read", "sftp_write", "sftp_list", "ssh_exec_many", "ssh_spawn", "ssh_job", "ssh_jobs", "exec_code"]; // v1.0 + v1.1, as deployed
const NEW = ["bash", "read", "write", "edit", "bridge"]; // v1.2
const V13 = ["batch"]; // v1.3
const V14 = ["audit"]; // v1.4
const V15 = ["add_host"]; // v1.5
const VERSION = "1.6.1";
const ALL_TOOLS = [...OLD, ...NEW, ...V13, ...V14, ...V15];
const HOSTS = ["local", "remote"];
const MAX_OUT = 100_000;
const SERVER_LOG = path.join(tmpdir(), `ssh-mcp-e2e-server-${process.getuid?.() ?? 0}.log`); // stdout+stderr of the servers under test (one per user)
writeFileSync(SERVER_LOG, "");

let sshd, sshd2, servers = [];

// authorizedFile: accept only the public keys listed in that file (read on every login); without it, any key.
// ssh2 1.17's generator drops a leading zero byte of an ed25519 public key, so about 1 key in 256 is one its own
// parser refuses ("Malformed OpenSSH private key"). The tests only start from keys that can be read ...
function keyPair() {
  for (;;) { const k = utils.generateKeyPairSync("ed25519"); if (!(utils.parseKey(k.private) instanceof Error)) return k; }
}
// ... except where a test wants exactly such a key.
function unreadableKeyPair() {
  for (let i = 0; i < 100_000; i++) { const k = utils.generateKeyPairSync("ed25519", { comment: "ssh-mcp@old" }); if (utils.parseKey(k.private) instanceof Error) return k; }
  throw new Error("the key generator made no unreadable key in 100000 tries");
}
function startSshd({ authorizedFile } = {}) {
  const host = keyPair(), client = keyPair();
  if (!authorizedFile) writeFileSync(path.join(TMP, "client"), client.private, { mode: 0o600 });
  const fp = "SHA256:" + createHash("sha256").update(utils.parseKey(host.private).getPublicSSH()).digest("base64").replace(/=+$/, "");
  const stats = { logins: 0 }; // public-key login attempts this server was offered
  const srv = new Server({ hostKeys: [host.private] }, (c) => {
    const kids = new Set();
    c.on("authentication", (ctx) => {
      if (ctx.method !== "publickey") return ctx.reject(["publickey"]);
      stats.logins++;
      if (!authorizedFile) return ctx.accept();
      const allowed = (existsSync(authorizedFile) ? readFileSync(authorizedFile, "utf8") : "").split("\n").filter(Boolean).map((l) => utils.parseKey(l)).filter((k) => !(k instanceof Error));
      const key = allowed.find((k) => k.type === ctx.key.algo && k.getPublicSSH().equals(ctx.key.data));
      if (!key || (ctx.signature && key.verify(ctx.blob, ctx.signature, ctx.hashAlgo) !== true)) return ctx.reject(["publickey"]);
      ctx.accept();
    });
    c.on("ready", () => c.on("session", (accept) => {
      const session = accept();
      session.on("exec", (acc, _rej, info) => {
        const stream = acc();
        // Like sshd: run through the login shell (dash here), finish when the process is gone AND its pipes are closed.
        const child = spawn("sh", ["-c", info.command], { env: { ...process.env, TMPDIR: CODE_TMP }, stdio: ["pipe", "pipe", "pipe"] });
        kids.add(child);
        stream.pipe(child.stdin);                      // stdin: EOF only when the client ends the channel
        child.stdin.on("error", () => {});
        child.stdout.on("data", (d) => { if (stream.write(d) === false) { child.stdout.pause(); stream.once("drain", () => child.stdout.resume()); } });
        child.stderr.on("data", (d) => stream.stderr.write(d));
        child.on("close", (code) => { kids.delete(child); stream.exit(code ?? 255); stream.end(); });
      });
      session.on("sftp", (acc) => serveSftp(acc()));
    }));
    c.on("close", () => { for (const k of kids) { k.stdin.destroy(); k.stdout.destroy(); k.stderr.destroy(); k.kill("SIGKILL"); } }); // like sshd: the session's pipes close
    c.on("error", () => {});
  });
  return new Promise((res) => srv.listen(0, "127.0.0.1", () => res({ srv, port: srv.address().port, fp, stats })));
}

// Minimal SFTP subsystem backed by the local filesystem, enough for ssh2's readFile/writeFile/readdir.
function serveSftp(sftp) {
  const { STATUS_CODE, flagsToString } = utils.sftp;
  const handles = new Map(); let next = 0;
  const put = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(next); handles.set(next++, v); return b; };
  const get = (h) => handles.get(h.readUInt32BE(0));
  const fail = (id, e) => sftp.status(id, e?.code === "ENOENT" ? STATUS_CODE.NO_SUCH_FILE : e?.code === "EACCES" ? STATUS_CODE.PERMISSION_DENIED : STATUS_CODE.FAILURE, e?.message);
  const attrs = (st) => ({ mode: st.mode, uid: st.uid, gid: st.gid, size: st.size, atime: Math.floor(st.atimeMs / 1000), mtime: Math.floor(st.mtimeMs / 1000) });
  const guard = (fn) => (id, ...a) => { try { fn(id, ...a); } catch (e) { fail(id, e); } };
  sftp.on("OPEN", guard((id, file, flags, a) => sftp.handle(id, put({ fd: openSync(file, flagsToString(flags) ?? "r", a?.mode ?? 0o666) }))));
  sftp.on("READ", guard((id, h, off, len) => { const buf = Buffer.alloc(len); const n = readSync(get(h).fd, buf, 0, len, off); n ? sftp.data(id, buf.subarray(0, n)) : sftp.status(id, STATUS_CODE.EOF); }));
  sftp.on("WRITE", guard((id, h, off, data) => { writeSync(get(h).fd, data, 0, data.length, off); sftp.status(id, STATUS_CODE.OK); }));
  sftp.on("FSTAT", guard((id, h) => sftp.attrs(id, attrs(fstatSync(get(h).fd)))));
  sftp.on("FSETSTAT", guard((id, h, a) => { if (a.mode !== undefined) fchmodSync(get(h).fd, a.mode & 0o7777); sftp.status(id, STATUS_CODE.OK); }));
  sftp.on("SETSTAT", guard((id, p, a) => { if (a.mode !== undefined) chmodSync(p, a.mode & 0o7777); sftp.status(id, STATUS_CODE.OK); }));
  sftp.on("STAT", guard((id, p) => sftp.attrs(id, attrs(statSync(p)))));
  sftp.on("LSTAT", guard((id, p) => sftp.attrs(id, attrs(lstatSync(p)))));
  sftp.on("OPENDIR", guard((id, p) => sftp.handle(id, put({ dir: p, list: readdirSync(p), done: false }))));
  sftp.on("READDIR", guard((id, h) => {
    const d = get(h);
    if (d.done || d.list.length === 0) return sftp.status(id, STATUS_CODE.EOF);
    d.done = true;
    sftp.name(id, d.list.map((f) => { const st = lstatSync(path.join(d.dir, f)); return { filename: f, longname: `${st.isDirectory() ? "d" : "-"}rwxr-xr-x 1 ${st.uid} ${st.gid} ${st.size} Jan  1 00:00 ${f}`, attrs: attrs(st) }; }));
  }));
  sftp.on("CLOSE", guard((id, h) => { const v = get(h); if (v?.fd !== undefined) closeSync(v.fd); handles.delete(h.readUInt32BE(0)); sftp.status(id, STATUS_CODE.OK); }));
  sftp.on("MKDIR", guard((id, p, a) => { mkdirSync(p, a?.mode ?? 0o777); sftp.status(id, STATUS_CODE.OK); }));
  sftp.on("REALPATH", guard((id, p) => sftp.name(id, [{ filename: path.resolve(p), longname: path.resolve(p), attrs: {} }])));
}

function startServer(port, env = {}) {
  const p = spawn(process.execPath, ["--import", "tsx", path.join(ROOT, SERVER_FILE)], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port), MCP_SECRET: SECRET, HOSTS_FILE: path.join(TMP, "hosts.json"), JOBS_DIR: JOBS, TMPDIR: CODE_TMP, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  servers.push(p);
  return new Promise((res, rej) => {
    let out = "";
    const t = setTimeout(() => rej(new Error("server did not start:\n" + out)), 30_000);
    const on = (d) => { out += d; appendFileSync(SERVER_LOG, d); if (out.includes("listening")) { clearTimeout(t); res(p); } };
    p.stdout.on("data", on);
    p.stderr.on("data", on);
    p.on("exit", (c) => { clearTimeout(t); rej(new Error(`server exited ${c}:\n${out}`)); });
  });
}

let nextId = 1;
async function rpc(base, method, params) {
  const res = await fetch(base, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }),
  });
  const body = await res.text();
  if (res.status !== 200) return { status: res.status, json: null };
  const json = (res.headers.get("content-type") ?? "").includes("text/event-stream")
    ? JSON.parse(body.split("\n").filter((l) => l.startsWith("data: ")).pop().slice(6))
    : JSON.parse(body);
  return { status: res.status, json };
}
async function call(name, args, base = BASE) {
  const { json } = await rpc(base, "tools/call", { name, arguments: args });
  if (json.error) return { isError: true, text: json.error.message };
  return { isError: !!json.result.isError, text: json.result.content.filter((c) => c.type === "text").map((c) => c.text).join("") };
}
const field = (text, key) => (text.match(new RegExp(`^${key}: (.*)$`, "m")) ?? [])[1];
const logPart = (text) => text.slice(text.indexOf(" ---\n", text.indexOf("--- log (last ")) + 5);
const pgrep = (pat) => { try { return execFileSync("pgrep", ["-f", pat]).toString().trim(); } catch { return ""; } }; // no shell: pattern must not match our own helper
const pkill9 = (pat) => { try { execFileSync("pkill", ["-9", "-f", pat]); } catch {} };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function spawnJob(host, command, base = BASE) {
  const s = await call("ssh_spawn", { host, command }, base);
  assert.equal(s.isError, false, s.text);
  const jobId = field(s.text, "jobId");
  assert.match(jobId, /^\d{8}-\d{6}-[0-9a-f]{6}$/, s.text);
  return { jobId, text: s.text };
}
const job = (host, jobId, action, extra = {}, base = BASE) => call("ssh_job", { host, jobId, action, ...extra }, base);

before(async () => {
  sshd = await startSshd();
  sshd2 = await startSshd({ authorizedFile: path.join(TMP, "authorized_keys") }); // for add_host: a host that does not know the connector's key yet
  writeFileSync(path.join(TMP, "hosts.json"), JSON.stringify({
    local: { local: true },
    remote: { host: "127.0.0.1", port: sshd.port, username: "t", privateKeyPath: path.join(TMP, "client"), hostFingerprint: sshd.fp },
  }));
  await startServer(PORT);
  await startServer(PORT2, { JOBS_DIR: "/proc/nope/jobs", HOME: HOME2 });
});
after(() => {
  for (const p of servers) p.kill("SIGKILL");
  sshd.srv.close();
  sshd2.srv.close();
  for (const s of realSshds) s.proc?.kill("SIGKILL");
  for (const n of ["31337", "31338", "41337", "41338", "51337", "51338", "61337", "61338", "71337", "71338"]) pkill9(`sleep ${n}`);
  rmSync(TMP, { recursive: true, force: true });
});

// ───────────────────────── Regression: the 10 deployed tools ─────────────────────────

test("R1 existing 10 tools: name/description/inputSchema as in the deployed baseline (the command tools only gained the optional `confirm`)", async () => {
  const baseline = JSON.parse(readFileSync(path.join(ROOT, "test/baseline-tools.json"), "utf8"));
  assert.deepEqual(baseline.map((t) => t.name).sort(), [...OLD].sort());
  const { json } = await rpc(BASE, "tools/list");
  // the baseline was captured on production, where JOBS_DIR is the default; the test server uses a temp dir
  const live = JSON.parse(JSON.stringify(json.result.tools).replaceAll(JOBS, "/var/lib/ssh-mcp/jobs"));
  for (const b of baseline) {
    const t = live.find((x) => x.name === b.name);
    if (["ssh_exec", "ssh_exec_many", "ssh_spawn", "exec_code"].includes(b.name)) {
      assert.equal(t.inputSchema.properties.confirm.type, "boolean", `${b.name} has no confirm`);
      assert.ok(!(t.inputSchema.required ?? []).includes("confirm"));
      delete t.inputSchema.properties.confirm;
    } else assert.equal(t.inputSchema.properties?.confirm, undefined, `${b.name} must not have confirm`);
    assert.deepEqual(t, b, `tool ${b.name} changed`);
  }
});

test("R2 ssh_exec local: exit/stdout/stderr text format unchanged", async () => {
  const r = await call("ssh_exec", { host: "local", command: "echo out; echo err >&2; exit 3" });
  assert.equal(r.isError, false);
  assert.equal(r.text, "exit: 3\n--- stdout ---\nout\n\n--- stderr ---\nerr\n");
});

test("R3 sftp_write / sftp_read / sftp_list local round-trip", async () => {
  const f = path.join(TMP, "f.txt");
  const w = await call("sftp_write", { host: "local", path: f, content: "héllo\n", mode: "0640" });
  assert.equal(w.text, `Wrote 7 bytes to local:${f}`);
  assert.equal((await call("sftp_read", { host: "local", path: f })).text, "héllo\n");
  assert.equal((await call("sftp_read", { host: "local", path: f, encoding: "base64" })).text, Buffer.from("héllo\n").toString("base64"));
  assert.match((await call("sftp_list", { host: "local", path: TMP })).text, /-rw-r----- .* f\.txt/);
});

test("R4 secret path: wrong secret 404, GET 405", async () => {
  assert.equal((await rpc(`http://127.0.0.1:${PORT}/mcp/wrong`, "tools/list")).status, 404);
  assert.equal((await fetch(BASE)).status, 405);
});

test("R5 ssh_exec remote (ssh2 path)", async () => {
  const r = await call("ssh_exec", { host: "remote", command: "echo remote-ok; echo e >&2; exit 4" });
  assert.equal(r.text, "exit: 4\n--- stdout ---\nremote-ok\n\n--- stderr ---\ne\n");
});

test("R6 unknown host is an error; list_hosts lists both", async () => {
  const r = await call("ssh_exec", { host: "nope", command: "true" });
  assert.equal(r.isError, true);
  assert.match(r.text, /Unknown host "nope"/);
  assert.equal((await call("list_hosts", {})).text, `local: (this VPS)\nremote: t@127.0.0.1:${sshd.port}`);
});

test("R7 ssh_exec keeps MAX_OUT truncation", async () => {
  const r = await call("ssh_exec", { host: "local", command: "head -c 150000 /dev/zero | tr '\\0' x" });
  assert.match(r.text, /x\n…\[truncated 50000 chars\]\n--- stderr ---/);
});

// ───────────────────────── New tools ─────────────────────────

test("N1 tools/list exposes exactly the 18 tools", async () => {
  const { json } = await rpc(BASE, "tools/list");
  assert.deepEqual(json.result.tools.map((t) => t.name).sort(), [...ALL_TOOLS].sort());
});

const splitBlocks = (text) => text.split(/\n\n(?==== \[)/).map((b) => {
  const m = b.match(/^=== \[(.+?)\] (?:exit: (-?\d+|null)|error: (.*?)) \| (\d+\.\d\d)s ===/);
  assert.ok(m, `bad block header: ${b.slice(0, 120)}`);
  const out = b.match(/\n--- stdout ---\n([\s\S]*)\n--- stderr ---\n([\s\S]*)$/);
  return { id: m[1], exit: m[2] === undefined ? undefined : m[2], error: m[3], sec: Number(m[4]), stdout: out?.[1], stderr: out?.[2] };
});

for (const host of HOSTS) {
  test(`N2 ssh_exec_many ${host}: concurrent, one block per id with exit/stdout/stderr/duration`, async () => {
    const t0 = performance.now();
    const r = await call("ssh_exec_many", { host, commands: [
      { id: "a", command: "sleep 1; echo A" },
      { id: "b", command: "sleep 1; echo B >&2; exit 2" },
      { id: "c", command: "sleep 1; echo C", timeout_sec: 30 },
    ] });
    const ms = performance.now() - t0;
    assert.equal(r.isError, false, r.text);
    assert.ok(ms < 2700, `took ${ms.toFixed(0)}ms for 3×1s — not concurrent`);
    const b = splitBlocks(r.text);
    assert.deepEqual(b.map((x) => x.id), ["a", "b", "c"]);
    assert.deepEqual(b.map((x) => x.exit), ["0", "2", "0"]);
    assert.deepEqual(b.map((x) => x.stdout), ["A\n", "", "C\n"]);
    assert.deepEqual(b.map((x) => x.stderr), ["", "B\n", ""]);
    for (const x of b) assert.ok(x.sec >= 0.95 && x.sec < 2.7, `duration ${x.sec}`);
  });

  test(`N3 ssh_exec_many ${host}: a timeout in one command does not affect the others`, async () => {
    const t0 = performance.now();
    const r = await call("ssh_exec_many", { host, commands: [
      { id: "slow", command: "sleep 20", timeout_sec: 1 },
      { id: "fast", command: "echo ok" },
    ] });
    assert.ok(performance.now() - t0 < 6000);
    const [slow, fast] = splitBlocks(r.text);
    assert.equal(fast.exit, "0");
    assert.equal(fast.stdout, "ok\n");
    assert.ok(slow.error ? /Timed out after 1s/.test(slow.error) : slow.exit !== "0", r.text);
    assert.ok(slow.sec >= 0.95 && slow.sec < 4);
  });

  test(`N4 ssh_exec_many ${host}: total output stays bounded (MAX_OUT shared across blocks)`, async () => {
    const big = "head -c 300000 /dev/zero | tr '\\0' x";
    const r = await call("ssh_exec_many", { host, commands: [{ id: "one", command: big }, { id: "two", command: big }] });
    const b = splitBlocks(r.text);
    for (const x of b) assert.match(x.stdout, /^x{50000}\n…\[truncated 250000 chars\]$/);
    assert.ok(r.text.length < 2 * MAX_OUT + 1000, `len ${r.text.length}`);
  });
}

test("N5 ssh_exec_many validation: duplicate ids, >10 commands, empty list, unknown host", async () => {
  const dup = await call("ssh_exec_many", { host: "local", commands: [{ id: "x", command: "true" }, { id: "x", command: "true" }] });
  assert.equal(dup.isError, true);
  assert.match(dup.text, /Duplicate id "x"/);
  const many = await call("ssh_exec_many", { host: "local", commands: Array.from({ length: 11 }, (_, i) => ({ id: `c${i}`, command: "true" })) });
  assert.equal(many.isError, true);
  assert.equal((await call("ssh_exec_many", { host: "local", commands: [] })).isError, true);
  const ten = await call("ssh_exec_many", { host: "local", commands: Array.from({ length: 10 }, (_, i) => ({ id: `c${i}`, command: `echo ${i}` })) });
  assert.equal(ten.isError, false);
  assert.deepEqual(splitBlocks(ten.text).map((x) => x.stdout), Array.from({ length: 10 }, (_, i) => `${i}\n`));
  const bad = await call("ssh_exec_many", { host: "nope", commands: [{ id: "x", command: "true" }] });
  assert.equal(bad.isError, true);
  assert.match(bad.text, /Unknown host "nope"/);
});

for (const [i, host] of HOSTS.entries()) {
  test(`N6 ssh_spawn ${host}: returns immediately; status → running; wait → exit code + log; files on disk`, async () => {
    const t0 = performance.now();
    const { jobId, text } = await spawnJob(host, "echo start; sleep 2; echo done; echo oops >&2; exit 7");
    const ms = performance.now() - t0;
    assert.ok(ms < 1800, `spawn took ${ms.toFixed(0)}ms — it must not wait for the 2s job`);
    assert.equal(field(text, "log"), `${JOBS}/${jobId}.log`);
    const st = await job(host, jobId, "status");
    assert.equal(st.isError, false, st.text);
    assert.equal(field(st.text, "job"), jobId);
    assert.equal(field(st.text, "state"), "running");
    assert.match(field(st.text, "pid"), /^\d+$/);
    assert.match(field(st.text, "started"), /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    assert.match(field(st.text, "command"), /^echo start; sleep 2/);
    const w = await job(host, jobId, "wait", { timeout_sec: 20 });
    assert.equal(field(w.text, "state"), "exited", w.text);
    assert.equal(field(w.text, "exit"), "7");
    assert.equal(logPart(w.text), "start\ndone\noops\n");
    assert.equal(readFileSync(`${JOBS}/${jobId}.exit`, "utf8"), "7\n");
    assert.equal(readFileSync(`${JOBS}/${jobId}.log`, "utf8"), "start\ndone\noops\n");
    const again = await job(host, jobId, "status");
    assert.equal(field(again.text, "state"), "exited");
    assert.match(field(again.text, "ended"), /^\d{4}-/);
  });

  test(`N7 ssh_job kill ${host}: SIGTERM ends the whole process group, exit 143`, async () => {
    const n = 31337 + i;
    const { jobId } = await spawnJob(host, `sleep ${n}`);
    assert.notEqual(pgrep(`sleep ${n}`), "");
    const k = await job(host, jobId, "kill");
    assert.match(k.text, /kill: terminated with SIGTERM/);
    assert.equal(field(k.text, "state"), "exited");
    assert.equal(field(k.text, "exit"), "143");
    assert.equal(pgrep(`sleep ${n}`), "");
    assert.match((await job(host, jobId, "kill")).text, /kill: nothing to do \(state: exited\)/);
  });

  test(`N8 ssh_job kill ${host}: job ignoring SIGTERM gets SIGKILL after 5s, exit 137`, async () => {
    const n = 41337 + i;
    const { jobId } = await spawnJob(host, `trap "" TERM; sleep ${n}`);
    const t0 = performance.now();
    const k = await job(host, jobId, "kill");
    assert.ok(performance.now() - t0 >= 4500);
    assert.match(k.text, /SIGKILL/);
    assert.equal(field(k.text, "state"), "exited");
    assert.equal(field(k.text, "exit"), "137");
    assert.equal(pgrep(`sleep ${n}`), "");
  });

  test(`N9 ssh_job tail ${host}: last N bytes, default 8 KB`, async () => {
    const { jobId } = await spawnJob(host, "head -c 20000 /dev/zero | tr '\\0' x; echo; echo END-MARK");
    await job(host, jobId, "wait", { timeout_sec: 20 });
    const t = await job(host, jobId, "tail");
    assert.match(t.text, /--- log \(last 8192 bytes\) ---/);
    assert.equal(field(t.text, "state"), "exited");
    assert.equal(logPart(t.text).length, 8192);
    assert.ok(logPart(t.text).endsWith("x\nEND-MARK\n"));
    assert.equal(logPart((await job(host, jobId, "tail", { bytes: 10 })).text), "\nEND-MARK\n");
    assert.match(field(t.text, "log"), /\(20010 bytes\)$/);
  });

  test(`N10 ssh_job wait ${host}: returns state running when timeout_sec passes first`, async () => {
    const n = 51337 + i;
    const { jobId } = await spawnJob(host, `echo waiting; sleep ${n}`);
    const t0 = performance.now();
    const w = await job(host, jobId, "wait", { timeout_sec: 2 });
    const ms = performance.now() - t0;
    assert.ok(ms >= 1800 && ms < 6000, `wait took ${ms.toFixed(0)}ms`);
    assert.equal(field(w.text, "state"), "running");
    assert.match(w.text, /still running after 2s/);
    assert.equal(logPart(w.text), "waiting\n");
    await job(host, jobId, "kill");
    assert.equal(pgrep(`sleep ${n}`), "");
  });

  test(`N11 ssh_spawn ${host}: command with quotes, $, newlines, heredoc, unicode runs verbatim`, async () => {
    const cmd = `printf '%s\\n' "it's \\"q\\" $((6*7))"\necho 'ünïcödé ✓'\ncat <<'EOF'\nheredoc $HOME 'single' "double" \\back\nEOF\n`;
    const { jobId } = await spawnJob(host, cmd);
    const w = await job(host, jobId, "wait", { timeout_sec: 20 });
    assert.equal(field(w.text, "exit"), "0", w.text);
    assert.equal(logPart(w.text), `it's "q" 42\nünïcödé ✓\nheredoc $HOME 'single' "double" \\back\n`);
    assert.equal(readFileSync(`${JOBS}/${jobId}.cmd`, "utf8"), cmd);
  });

  test(`N12 ssh_job ${host}: state lost when the job vanished without an exit record`, async () => {
    const n = 61337 + i;
    const { jobId } = await spawnJob(host, `sleep ${n}`);
    const pid = Number(field((await job(host, jobId, "status")).text, "pid"));
    process.kill(pid, "SIGKILL");
    pkill9(`sleep ${n}`);
    await sleep(300);
    const st = await job(host, jobId, "status");
    assert.equal(field(st.text, "state"), "lost", st.text);
    assert.match((await job(host, jobId, "wait", { timeout_sec: 30 })).text, /state: lost/);
    assert.match((await job(host, jobId, "kill")).text, /kill: nothing to do \(state: lost\)/);
  });

  test(`N13 ssh_spawn ${host}: 5 concurrent spawns get distinct jobs, all finish 0`, async () => {
    const jobs = await Promise.all(Array.from({ length: 5 }, (_, k) => spawnJob(host, `echo job-${k}`)));
    assert.equal(new Set(jobs.map((j) => j.jobId)).size, 5);
    for (const [k, j] of jobs.entries()) {
      const w = await job(host, j.jobId, "wait", { timeout_sec: 20 });
      assert.equal(field(w.text, "exit"), "0");
      assert.equal(logPart(w.text), `job-${k}\n`);
    }
  });

  test(`N14 ssh_jobs ${host}: lists jobs newest first with state and exit code; limit works`, async () => {
    const a = await spawnJob(host, "exit 3");
    await job(host, a.jobId, "wait", { timeout_sec: 20 });
    await sleep(1100); // ids are second-resolution; make ordering deterministic
    const b = await spawnJob(host, "sleep 30");
    const l = await call("ssh_jobs", { host });
    assert.equal(l.isError, false, l.text);
    const rows = l.text.split("\n").filter((x) => /^\d{8}-\d{6}-/.test(x)).map((x) => x.split("\t"));
    assert.match(l.text.split("\n")[0], /^JOB\tSTATE\tEXIT\tELAPSED\tSTARTED\tCOMMAND$/);
    assert.equal(rows[0][0], b.jobId);
    assert.deepEqual(rows[0].slice(1, 3), ["running", "-"]);
    const ra = rows.find((r) => r[0] === a.jobId);
    assert.deepEqual(ra.slice(1, 3), ["exited", "3"]);
    assert.equal(ra[5], "exit 3");
    assert.deepEqual(rows.map((r) => r[0]), rows.map((r) => r[0]).sort().reverse());
    assert.match(l.text, new RegExp(`total: ${readdirSync(JOBS).filter((f) => f.endsWith(".cmd")).length} job\\(s\\) in ${JOBS}`));
    const one = await call("ssh_jobs", { host, limit: 1 });
    assert.equal(one.text.split("\n").filter((x) => /^\d{8}-\d{6}-/.test(x)).length, 1);
    await job(host, b.jobId, "kill");
  });

  test(`N15 ssh_job ${host}: unknown and malformed jobId are errors`, async () => {
    const u = await job(host, "20000101-000000-abcdef", "status");
    assert.equal(u.isError, true);
    assert.match(u.text, /No such job: 20000101-000000-abcdef/);
    for (const bad of ["../../etc/passwd", "a b", "x;id", ""]) assert.equal((await job(host, bad, "status")).isError, true, bad);
    assert.equal((await job(host, "20000101-000000-abcdef", "explode")).isError, true);
  });

  test(`N16 exec_code ${host}: python — stdout, stderr, exit code`, async () => {
    const r = await call("exec_code", { host, language: "python", code: 'import sys\nprint("py", sys.version_info[0])\nprint("e", file=sys.stderr)\nsys.exit(5)\n' });
    assert.equal(r.isError, false, r.text);
    assert.equal(r.text, "exit: 5\n--- stdout ---\npy 3\n\n--- stderr ---\ne\n");
  });

  test(`N17 exec_code ${host}: node`, async () => {
    const r = await call("exec_code", { host, language: "node", code: 'const os = require("os");\nconsole.log(os.platform(), [1, 2, 3].map((x) => x * 2).join(","));\n' });
    assert.equal(r.text, "exit: 0\n--- stdout ---\nlinux 2,4,6\n\n--- stderr ---\n");
  });

  test(`N18 exec_code ${host}: bash`, async () => {
    const r = await call("exec_code", { host, language: "bash", code: 'set -e\narr=(a b c)\necho "${#arr[@]} $((1+2))"\nfalse\necho unreachable\n' });
    assert.equal(r.text, "exit: 1\n--- stdout ---\n3 3\n\n--- stderr ---\n");
  });

  test(`N19 exec_code ${host}: timeout kills the script, keeps partial output, reports it`, async () => {
    const t0 = performance.now();
    const r = await call("exec_code", { host, language: "python", timeout_sec: 2, code: 'import time\nprint("begin", flush=True)\nwhile True:\n    time.sleep(0.2)\n' });
    const ms = performance.now() - t0;
    assert.ok(ms >= 1900 && ms < 9000, `took ${ms.toFixed(0)}ms`);
    assert.equal(r.text, "exit: 124 (timed out after 2s)\n--- stdout ---\nbegin\n\n--- stderr ---\n");
    await sleep(200);
    assert.equal(pgrep("ssh-mcp-code\\."), "");
  });

  test(`N20 exec_code ${host}: code with quotes, backslashes, $, backticks, unicode is written verbatim; stdin is empty`, async () => {
    const code = `import sys\ns = 'it\\'s "x" \\\\ $HOME \`bt\` ✓'\nprint(s)\nprint('''triple ' " ''')\nprint(repr(sys.stdin.read()))\n`;
    const r = await call("exec_code", { host, language: "python", code, timeout_sec: 20 });
    assert.equal(r.text, `exit: 0\n--- stdout ---\nit's "x" \\ $HOME \`bt\` ✓\ntriple ' " \n''\n\n--- stderr ---\n`);
  });
}

test("N21 exec_code validation: oversize code, unknown language, unknown host", async () => {
  const big = await call("exec_code", { host: "local", language: "bash", code: "#".repeat(70_000) });
  assert.equal(big.isError, true);
  assert.match(big.text, /too large/);
  assert.equal((await call("exec_code", { host: "local", language: "ruby", code: "puts 1" })).isError, true);
  const bad = await call("exec_code", { host: "nope", language: "bash", code: "true" });
  assert.equal(bad.isError, true);
  assert.match(bad.text, /Unknown host "nope"/);
  const okBig = await call("exec_code", { host: "local", language: "bash", code: "echo fits\n" + "#".repeat(60_000) });
  assert.equal(okBig.text, "exit: 0\n--- stdout ---\nfits\n\n--- stderr ---\n");
});

test("N22 exec_code leaves no temp files behind", () => {
  assert.deepEqual(readdirSync(CODE_TMP).filter((f) => f.startsWith("ssh-mcp-code")), []);
});

test("N23 jobs dir falls back to $HOME/.ssh-mcp/jobs when the configured dir is not writable", async () => {
  const { jobId, text } = await spawnJob("local", "echo fallback", BASE2);
  assert.equal(field(text, "log"), `${HOME2}/.ssh-mcp/jobs/${jobId}.log`);
  const w = await job("local", jobId, "wait", { timeout_sec: 20 }, BASE2);
  assert.equal(field(w.text, "exit"), "0");
  assert.equal(logPart(w.text), "fallback\n");
  assert.ok(existsSync(`${HOME2}/.ssh-mcp/jobs/${jobId}.exit`));
  assert.match((await call("ssh_jobs", { host: "local" }, BASE2)).text, new RegExp(`${jobId}\texited\t0\t`));
});

test("N24 ssh_spawn validation: oversize command, unknown host", async () => {
  const big = await call("ssh_spawn", { host: "local", command: ":".repeat(70_000) });
  assert.equal(big.isError, true);
  assert.match(big.text, /too large/);
  const bad = await call("ssh_spawn", { host: "nope", command: "true" });
  assert.equal(bad.isError, true);
  assert.match(bad.text, /Unknown host "nope"/);
});

// ═════════════════════════ v1.2: the same four tools a sandbox has, on the host ═════════════════════════

const P = (...a) => path.join(TMP, ...a);
const tool = async (name, args, base = BASE) => (await rpc(base, "tools/call", { name, arguments: args })).json.result;
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

test("R8 sftp_write / sftp_read / sftp_list remote round-trip (real SFTP path)", async () => {
  const f = P("rf.txt");
  const w = await call("sftp_write", { host: "remote", path: f, content: "remote héllo\n", mode: "0640" });
  assert.equal(w.text, `Wrote 14 bytes to remote:${f}`);
  assert.equal(readFileSync(f, "utf8"), "remote héllo\n");
  assert.equal((await call("sftp_read", { host: "remote", path: f })).text, "remote héllo\n");
  assert.match((await call("sftp_list", { host: "remote", path: TMP })).text, /rf\.txt/);
});

for (const [i, host] of HOSTS.entries()) {
  test(`P1 bash ${host}: merged output in order, exit code line only on failure`, async () => {
    const ok = await call("bash", { host, command: "echo out; echo err >&2; echo out2" });
    assert.equal(ok.isError, false, ok.text);
    assert.equal(ok.text, "out\nerr\nout2\n");
    const bad = await call("bash", { host, command: "echo out; echo err >&2; exit 3", description: "ignored label" });
    assert.equal(bad.text, "out\nerr\n[exit code: 3]");
    assert.equal((await call("bash", { host, command: "true" })).text, "(no output)");
    assert.equal((await call("bash", { host, command: "printf 'no newline'; exit 1" })).text, "no newline\n[exit code: 1]");
  });

  test(`P2 bash ${host}: cwd param; default is the home directory; cd does not leak without a session`, async () => {
    assert.equal((await call("bash", { host, command: "pwd", cwd: TMP })).text, TMP + "\n");
    assert.equal((await call("bash", { host, command: "pwd" })).text, process.env.HOME + "\n");
    await call("bash", { host, command: "cd /tmp" });
    assert.equal((await call("bash", { host, command: "pwd" })).text, process.env.HOME + "\n");
    const miss = await call("bash", { host, command: "pwd", cwd: "/nonexistent-dir-xyz" });
    assert.equal(miss.isError, true);
    assert.match(miss.text, /No such directory: \/nonexistent-dir-xyz/);
  });

  test(`P3 bash ${host}: session keeps the working directory between calls, sessions are isolated`, async () => {
    const s = `sess-${host}`;
    mkdirSync(P("proj", "sub"), { recursive: true });
    assert.equal((await call("bash", { host, session: s, command: `cd ${P("proj")}` })).text, `[cwd: ${P("proj")}]`);
    assert.equal((await call("bash", { host, session: s, command: "pwd" })).text, P("proj") + "\n");
    assert.equal((await call("bash", { host, session: s, command: "cd sub && pwd; false" })).text, `${P("proj", "sub")}\n[exit code: 1]\n[cwd: ${P("proj", "sub")}]`);
    assert.equal((await call("bash", { host, session: s, command: "pwd" })).text, P("proj", "sub") + "\n");
    assert.equal((await call("bash", { host, session: `other-${host}`, command: "pwd" })).text, process.env.HOME + "\n");
    assert.equal((await call("bash", { host, session: s, cwd: TMP, command: "pwd" })).text, `${TMP}\n[cwd: ${TMP}]`); // explicit cwd wins and is remembered
    assert.equal((await call("bash", { host, session: s, command: "pwd" })).text, TMP + "\n");
    assert.equal((await call("bash", { host, session: "bad name!", command: "pwd" })).isError, true);
  });

  test(`P4 bash ${host}: timeout (ms) kills the command, keeps partial output`, async () => {
    const t0 = performance.now();
    const r = await call("bash", { host, timeout: 1500, command: "echo begin; sleep 20; echo never" });
    assert.ok(performance.now() - t0 < 9000);
    assert.equal(r.text, "begin\n[timed out after 2s - exit code: 124]");
  });

  test(`P5 bash ${host}: oversized output is cut in the middle and kept in full on the host`, async () => {
    const r = await call("bash", { host, command: "head -c 300000 /dev/zero | tr '\\0' x; echo; echo END" });
    assert.ok(r.text.length < MAX_OUT + 600, `len ${r.text.length}`);
    assert.ok(r.text.startsWith("xxxx") && r.text.endsWith("x\nEND\n"), r.text.slice(-40));
    const m = r.text.match(/\[(\d+) bytes omitted - full output saved on the host: (\S+)\]/);
    assert.ok(m, r.text.slice(59_900, 60_300));
    assert.equal(Number(m[1]), 300_005 - 98_000);
    assert.equal(statSync(m[2]).size, 300_005);
    const tail = await call("bash", { host, command: `tail -c 5 ${m[2]}` });
    assert.equal(tail.text, "\nEND\n");
  });

  test(`P6 bash ${host}: a child left running in the background does not block the call`, async () => {
    const n = 71337 + i;
    const t0 = performance.now();
    const r = await call("bash", { host, command: `sleep ${n} & echo started` });
    assert.ok(performance.now() - t0 < 4000, "call waited for the background child");
    assert.equal(r.text, "started\n");
    assert.notEqual(pgrep(`sleep ${n}`), "");
    pkill9(`sleep ${n}`);
  });

  test(`P7 bash ${host}: run_in_background returns a job id; cwd applies`, async () => {
    const r = await call("bash", { host, cwd: TMP, run_in_background: true, command: "pwd; sleep 1; echo bg-done" });
    assert.equal(r.isError, false, r.text);
    const jobId = field(r.text, "jobId");
    assert.match(jobId, /^\d{8}-\d{6}-[0-9a-f]{6}$/, r.text);
    const w = await job(host, jobId, "wait", { timeout_sec: 20 });
    assert.equal(field(w.text, "exit"), "0", w.text);
    assert.equal(logPart(w.text), `${TMP}\nbg-done\n`);
  });

  test(`P8 bash ${host}: quotes, $, heredoc, unicode run verbatim; stdin is empty`, async () => {
    const cmd = `printf '%s\\n' "it's \\"q\\" $((6*7))"\ncat <<'EOF'\nheredoc $HOME \\back ✓\nEOF\ncat; echo "stdin-done"`;
    assert.equal((await call("bash", { host, command: cmd })).text, `it's "q" 42\nheredoc $HOME \\back ✓\nstdin-done\n`);
  });

  test(`P10 read ${host}: numbered lines like cat -n, offset/limit, footers`, async () => {
    const f = P(`read-${host}.txt`);
    writeFileSync(f, "l1\nl2\n\tl3 tabbed\nl4\nl5"); // no trailing newline
    assert.equal((await call("read", { host, file_path: f })).text, "     1\tl1\n     2\tl2\n     3\t\tl3 tabbed\n     4\tl4\n     5\tl5\n");
    assert.equal((await call("read", { host, file_path: f, offset: 2, limit: 2 })).text, "     2\tl2\n     3\t\tl3 tabbed\n[lines 2-3 shown; more follow - continue with offset=4]\n");
    assert.equal((await call("read", { host, file_path: f, offset: 4, limit: 2 })).text, "     4\tl4\n     5\tl5\n");
    assert.equal((await call("read", { host, file_path: f, offset: 10 })).text, "[offset 10 is past the end of the file (5 lines)]\n");
    writeFileSync(f, "");
    assert.equal((await call("read", { host, file_path: f })).text, "(empty file)\n");
    writeFileSync(f, "x".repeat(2500) + "\nshort\n");
    assert.equal((await call("read", { host, file_path: f })).text, `     1\t${"x".repeat(2000)}... [line truncated]\n     2\tshort\n`);
  });

  test(`P11 read ${host}: missing file, directory, binary and bad input are errors`, async () => {
    writeFileSync(P(`bin-${host}`), Buffer.from([1, 2, 0, 3, 4, 5]));
    for (const [fp, re] of [[P("nope.txt"), /File does not exist/], [TMP, /is a directory/], [P(`bin-${host}`), /Binary file \(6 bytes\)/]]) {
      const r = await call("read", { host, file_path: fp });
      assert.equal(r.isError, true, r.text);
      assert.match(r.text, re);
    }
    assert.equal((await call("read", { host })).isError, true); // neither file_path nor files
    assert.equal((await call("read", { host, file_path: "relative.txt" })).isError, true);
  });

  test(`P12 read ${host}: several files in one call, per-file errors inline, shared output budget`, async () => {
    const a = P(`ra-${host}.txt`), b = P(`rb-${host}.txt`);
    writeFileSync(a, "A1\nA2\nA3\n");
    writeFileSync(b, "B1\n");
    const r = await call("read", { host, files: [{ file_path: a, offset: 2 }, { file_path: P("nope.txt") }, { file_path: b }] });
    assert.equal(r.isError, false, r.text);
    assert.equal(r.text, `=== ${a} ===\n     2\tA2\n     3\tA3\n\n=== ${P("nope.txt")} ===\nERROR: File does not exist: ${P("nope.txt")}\n\n=== ${b} ===\n     1\tB1\n`);
    const big = [1, 2, 3, 4].map((k) => P(`big${k}-${host}.txt`));
    for (const f of big) writeFileSync(f, Array.from({ length: 5000 }, (_, k) => `line ${k} ${"y".repeat(40)}`).join("\n") + "\n");
    const many = await call("read", { host, files: big.map((file_path) => ({ file_path })) });
    assert.ok(many.text.length <= MAX_OUT + 2000, `len ${many.text.length}`);
    assert.equal((many.text.match(/output budget reached/g) ?? []).length, 4);
    for (const f of big) assert.ok(many.text.includes(`=== ${f} ===\n     1\tline 0 `));
    assert.equal((await call("read", { host, files: [{ file_path: P("nope1") }, { file_path: P("nope2") }] })).isError, true);
  });

  test(`P13 read ${host}: an image comes back as an image block`, async () => {
    const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==", "base64");
    const f = P(`dot-${host}.png`);
    writeFileSync(f, png);
    const res = await tool("read", { host, file_path: f });
    const img = res.content.find((c) => c.type === "image");
    assert.ok(img, JSON.stringify(res).slice(0, 300));
    assert.equal(img.mimeType, "image/png");
    assert.ok(Buffer.from(img.data, "base64").equals(png));
    const mix = await tool("read", { host, files: [{ file_path: f }, { file_path: P(`ra-${host}.txt`) }] });
    assert.deepEqual(mix.content.map((c) => c.type), ["text", "image", "text"]);
  });

  test(`P14 write ${host}: creates parent directories, overwrite keeps the file mode`, async () => {
    const f = P(`w-${host}`, "deep", "er", "file.txt");
    const w = await call("write", { host, file_path: f, content: "héllo ✓\nline2\n" });
    assert.equal(w.isError, false, w.text);
    assert.equal(w.text, `Wrote 17 bytes to ${host}:${f}`);
    assert.equal(readFileSync(f, "utf8"), "héllo ✓\nline2\n");
    chmodSync(f, 0o600);
    await call("write", { host, file_path: f, content: "v2\n" });
    assert.equal(readFileSync(f, "utf8"), "v2\n");
    assert.equal(statSync(f).mode & 0o777, 0o600);
  });

  test(`P15 write ${host}: 30 files in one call, per-file errors do not stop the rest`, async () => {
    const files = Array.from({ length: 30 }, (_, k) => ({ file_path: P(`bulk-${host}`, `d${k % 5}`, `f${k}.txt`), content: `content ${k}\n`.repeat(k + 1) }));
    files[0].mode = "0750";
    const w = await call("write", { host, files });
    assert.equal(w.isError, false, w.text);
    assert.match(w.text, /30 files written, \d+ bytes$/);
    for (const f of files) assert.equal(readFileSync(f.file_path, "utf8"), f.content);
    assert.equal(statSync(files[0].file_path).mode & 0o777, 0o750);
    const bad = await call("write", { host, files: [{ file_path: P(`bulk-${host}`, "ok.txt"), content: "ok" }, { file_path: "/proc/nope/x.txt", content: "x" }] });
    assert.equal(bad.isError, true);
    assert.match(bad.text, /ERROR \/proc\/nope\/x\.txt/);
    assert.equal(readFileSync(P(`bulk-${host}`, "ok.txt"), "utf8"), "ok");
  });

  test(`P16 edit ${host}: exact unique replacement, numbered snippet, mode preserved`, async () => {
    const f = P(`e-${host}.js`);
    writeFileSync(f, "const a = 1;\nconst b = 2;\nfunction f() {\n  return a + b;\n}\n");
    chmodSync(f, 0o755);
    const r = await call("edit", { host, file_path: f, old_string: "  return a + b;", new_string: "  return a * b; // $& $1 literal" });
    assert.equal(r.isError, false, r.text);
    assert.match(r.text, new RegExp(`^Edited ${host}:${reEsc(f)}: 1 replacement\\n`));
    assert.ok(r.text.includes("     4\t  return a * b; // $& $1 literal\n"), r.text);
    assert.equal(readFileSync(f, "utf8"), "const a = 1;\nconst b = 2;\nfunction f() {\n  return a * b; // $& $1 literal\n}\n");
    assert.equal(statSync(f).mode & 0o777, 0o755);
  });

  test(`P17 edit ${host}: not found / ambiguous / replace_all / invalid input leave the file alone`, async () => {
    const f = P(`e2-${host}.txt`);
    const orig = "x = 1\nx = 1\nx = 1\ny = 2\n";
    writeFileSync(f, orig);
    const nf = await call("edit", { host, file_path: f, old_string: "z = 9", new_string: "z = 0" });
    assert.equal(nf.isError, true);
    assert.match(nf.text, /old_string not found/);
    const amb = await call("edit", { host, file_path: f, old_string: "x = 1", new_string: "x = 5" });
    assert.equal(amb.isError, true);
    assert.match(amb.text, /matches 3 places/);
    assert.equal(readFileSync(f, "utf8"), orig);
    const all = await call("edit", { host, file_path: f, old_string: "x = 1", new_string: "x = 5", replace_all: true });
    assert.match(all.text, /: 3 replacements\n/);
    assert.equal(readFileSync(f, "utf8"), "x = 5\nx = 5\nx = 5\ny = 2\n");
    assert.equal((await call("edit", { host, file_path: f, old_string: "y = 2", new_string: "y = 2" })).isError, true);
    assert.equal((await call("edit", { host, file_path: P("missing.txt"), old_string: "a", new_string: "b" })).isError, true);
    const bin = P(`e3-${host}.bin`);
    writeFileSync(bin, Buffer.from([0x61, 0xff, 0xfe, 0x62]));
    const nb = await call("edit", { host, file_path: bin, old_string: "a", new_string: "c" });
    assert.equal(nb.isError, true);
    assert.match(nb.text, /not valid UTF-8/);
    assert.ok(readFileSync(bin).equals(Buffer.from([0x61, 0xff, 0xfe, 0x62])));
  });

  test(`P18 edit ${host}: many edits in one call, applied in order, all-or-nothing per file`, async () => {
    const a = P(`m-a-${host}.txt`), b = P(`m-b-${host}.txt`), c = P(`m-c-${host}.txt`);
    writeFileSync(a, "one\ntwo\nthree\n");
    writeFileSync(b, "alpha\nbeta\n");
    writeFileSync(c, "keep\n");
    const r = await call("edit", { host, edits: [
      { file_path: a, old_string: "one", new_string: "ONE" },
      { file_path: b, old_string: "alpha", new_string: "ALPHA" },
      { file_path: a, old_string: "ONE\ntwo", new_string: "1\n2" }, // sees the result of the first edit
      { file_path: b, old_string: "gamma", new_string: "GAMMA" },   // fails -> b stays untouched
      { file_path: c, old_string: "keep", new_string: "kept" },
    ] });
    assert.equal(r.isError, true, r.text);
    assert.equal(readFileSync(a, "utf8"), "1\n2\nthree\n");
    assert.equal(readFileSync(b, "utf8"), "alpha\nbeta\n");
    assert.equal(readFileSync(c, "utf8"), "kept\n");
    assert.match(r.text, new RegExp(`OK ${host}:${reEsc(a)}: 2 edits`));
    assert.match(r.text, new RegExp(`FAILED ${host}:${reEsc(b)} \\(not modified\\): edit #4: old_string not found`));
    const ok = await call("edit", { host, edits: [{ file_path: b, old_string: "beta", new_string: "BETA" }, { file_path: c, old_string: "kept", new_string: "done" }] });
    assert.equal(ok.isError, false, ok.text);
    assert.equal(readFileSync(b, "utf8"), "alpha\nBETA\n");
    assert.equal(readFileSync(c, "utf8"), "done\n");
  });
}

// ═════════════════════════ v1.2: bridge (direct sandbox <-> host path, no model in between) ═════════════════════════

const signTok = (exp) => `${exp.toString(36)}.${createHmac("sha256", SECRET).update("bridge:" + exp).digest("hex").slice(0, 32)}`;
const now = () => Math.floor(Date.now() / 1000);
const p64 = (s) => Buffer.from(s).toString("base64url");
let BR; // base URL carrying a token minted by the bridge tool

test("G1 bridge tool mints a time-limited URL for sandbox shells", async () => {
  const r = await call("bridge", { ttl_hours: 2 });
  assert.equal(r.isError, false, r.text);
  const m = r.text.match(/(http:\/\/127\.0\.0\.1:\d+\/b\/([0-9a-z]+\.[0-9a-f]{32}))\/cli/);
  assert.ok(m, r.text);
  BR = m[1];
  const exp = parseInt(m[2].split(".")[0], 36);
  assert.ok(Math.abs(exp - (now() + 7200)) < 60, `exp ${exp}`);
  assert.equal(m[2], signTok(exp));
  assert.match(r.text, /box (exec|put|get|push|pull)/);
});

test("G2 bridge auth: only a valid, unexpired token opens /b/<token>/...", async () => {
  const good = `http://127.0.0.1:${PORT}/b/${signTok(now() + 600)}`;
  assert.equal((await rpc(`${good}/mcp`, "tools/list")).json.result.tools.length, ALL_TOOLS.length);
  assert.equal((await call("ssh_exec", { host: "local", command: "echo via-bridge" }, `${good}/mcp`)).text, "exit: 0\n--- stdout ---\nvia-bridge\n\n--- stderr ---\n");
  const expired = `http://127.0.0.1:${PORT}/b/${signTok(now() - 5)}`;
  const forged = `http://127.0.0.1:${PORT}/b/${(now() + 600).toString(36)}.${"0".repeat(32)}`;
  for (const bad of [expired, forged, `http://127.0.0.1:${PORT}/b/garbage`]) {
    assert.equal((await rpc(`${bad}/mcp`, "tools/list")).status, 404);
    assert.equal((await fetch(`${bad}/cli`)).status, 404);
    assert.equal((await fetch(`${bad}/fs/local?p64=${p64("/etc/hostname")}`)).status, 404);
  }
});

for (const host of HOSTS) {
  test(`G3 bridge fs ${host}: binary upload/download round-trip, parents, mode, errors`, async () => {
    const data = randomBytes(3 * 1024 * 1024 + 123);
    const remote = P(`br-${host}`, "a b", "ünï", "blob.bin");
    const put = await fetch(`${BR}/fs/${host}?p64=${p64(remote)}&mode=0640`, { method: "PUT", headers: { "Content-Type": "application/octet-stream" }, body: data });
    assert.equal(put.status, 200, await put.text());
    assert.ok(readFileSync(remote).equals(data));
    assert.equal(statSync(remote).mode & 0o777, 0o640);
    const get = await fetch(`${BR}/fs/${host}?p64=${p64(remote)}`);
    assert.equal(get.status, 200);
    assert.equal(get.headers.get("content-length"), String(data.length));
    assert.ok(Buffer.from(await get.arrayBuffer()).equals(data));
    assert.equal((await fetch(`${BR}/fs/${host}?path=${encodeURIComponent(remote)}`)).status, 200); // plain ?path= works too
    assert.equal((await fetch(`${BR}/fs/${host}?p64=${p64(P("nope.bin"))}`)).status, 404);
    assert.equal((await fetch(`${BR}/fs/${host}?p64=${p64("relative.bin")}`)).status, 400);
    assert.equal((await fetch(`${BR}/fs/nohost?p64=${p64(remote)}`)).status, 404);
  });

  test(`G4 bridge tar ${host}: a directory tree goes up and comes back identical`, async () => {
    const src = P(`tree-${host}`), dst = P(`tree-dst-${host}`), back = P(`tree-back-${host}`);
    for (let k = 0; k < 40; k++) {
      mkdirSync(path.join(src, `d${k % 4}`, "x"), { recursive: true });
      writeFileSync(path.join(src, `d${k % 4}`, "x", `f${k}.bin`), randomBytes(1000 + k));
    }
    mkdirSync(path.join(src, "node_modules"));
    writeFileSync(path.join(src, "node_modules", "skip.js"), "skip");
    const tgz = execFileSync("tar", ["-C", src, "-czf", "-", "."], { maxBuffer: 64 << 20 });
    const up = await fetch(`${BR}/tar/${host}?p64=${p64(dst)}`, { method: "PUT", headers: { "Content-Type": "application/gzip" }, body: tgz });
    assert.equal(up.status, 200, await up.text());
    execFileSync("diff", ["-r", src, dst]);
    const down = await fetch(`${BR}/tar/${host}?p64=${p64(dst)}&x=node_modules`);
    assert.equal(down.status, 200);
    mkdirSync(back);
    execFileSync("tar", ["-C", back, "-xzf", "-"], { input: Buffer.from(await down.arrayBuffer()) });
    assert.equal(existsSync(path.join(back, "node_modules")), false);
    execFileSync("diff", ["-r", "-x", "node_modules", src, back]);
    assert.equal((await fetch(`${BR}/tar/${host}?p64=${p64(P("no-such-dir"))}`)).status, 404);
  });

  test(`G5 bridge exec ${host}: raw merged output, exit code in a header, cwd, timeout, no truncation`, async () => {
    const KEPT_OUT = new Set(existsSync(path.join(TMP, "out")) ? readdirSync(path.join(TMP, "out")) : []); // oversized outputs kept by earlier bash-tool tests
    const r = await fetch(`${BR}/exec/${host}?c64=${p64(TMP)}`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "pwd; echo err >&2; exit 7" });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("x-exit-code"), "7");
    assert.equal(await r.text(), `${TMP}\nerr\n`);
    const t = await fetch(`${BR}/exec/${host}?timeout=1`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "echo a; sleep 20" });
    assert.equal(t.headers.get("x-exit-code"), "124");
    assert.equal(await t.text(), "a\n");
    const big = await fetch(`${BR}/exec/${host}`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "head -c 400000 /dev/zero | tr '\\0' z" });
    assert.equal((await big.text()).length, 400000);
    // far beyond any in-memory buffer: streamed, with an exact length and the exit code up front
    const huge = await fetch(`${BR}/exec/${host}`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "head -c 12000000 /dev/zero | tr '\\0' q; exit 5" });
    assert.equal(huge.status, 200);
    assert.equal(huge.headers.get("content-length"), "12000000");
    assert.equal(huge.headers.get("x-exit-code"), "5");
    const buf = Buffer.from(await huge.arrayBuffer());
    assert.equal(buf.length, 12000000);
    assert.ok(buf[0] === 0x71 && buf[6_000_000] === 0x71 && buf[11_999_999] === 0x71);
    const none = await fetch(`${BR}/exec/${host}`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "true" });
    assert.deepEqual([none.status, none.headers.get("x-exit-code"), none.headers.get("content-length"), await none.text()], [200, "0", "0", ""]);
    const badCwd = await fetch(`${BR}/exec/${host}?c64=${p64(P("no-such-dir"))}`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "pwd" });
    assert.equal(badCwd.status, 500);
    assert.match(await badCwd.text(), /No such directory/);
    assert.equal((await fetch(`${BR}/exec/${host}`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "  " })).status, 400);
    assert.equal((await fetch(`${BR}/exec/${host}`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "#".repeat(70_000) })).status, 413);
    assert.deepEqual(readdirSync(path.join(TMP, "out")).filter((f) => !KEPT_OUT.has(f)), [], "raw exec leaves no output files behind");
  });
}

test("G6 box CLI served by the connector: tools, exec, put/get, push/pull, call - local and remote", async () => {
  const cli = P("box");
  writeFileSync(cli, await (await fetch(`${BR}/cli`)).text(), { mode: 0o755 });
  // async on purpose: the "remote" SSH server lives in this process, a sync child would freeze it
  const run = promisify(execFile);
  const box = async (args, opts = {}, input = "") => {
    const pr = run("bash", [cli, ...args], { encoding: "utf8", maxBuffer: 64 << 20, ...opts });
    pr.child.stdin.end(input);
    return (await pr).stdout;
  };
  assert.deepEqual((await box(["tools"])).trim().split(/\s+/).sort(), [...ALL_TOOLS].sort());
  assert.equal(await box(["exec", "--", "echo hi; echo e >&2"]), "hi\ne\n");
  assert.equal(await box(["exec", "-C", TMP, "remote", "--", "pwd"]), TMP + "\n");
  assert.equal(await box(["exec", "--", "-"], {}, "cd /tmp\npwd\nexit 4\n").catch((e) => `${e.code}:${e.stdout}`), "4:/tmp\n"); // script from stdin
  assert.equal(await box(["exec", "--", "-"]).catch((e) => e.code), 2);                 // ...and an empty one is refused by the client
  const failed = await box(["exec", "--", "echo out; exit 3"]).catch((e) => e);
  assert.equal(failed.code, 3);
  assert.equal(failed.stdout, "out\n");
  for (const host of HOSTS) {
    const data = randomBytes(500_000), src = P(`cli-src-${host}.bin`), rem = P(`cli-${host}`, "up load.bin"), back = P(`cli-back-${host}.bin`);
    writeFileSync(src, data);
    await box(["put", src, `${host}:${rem}`, "0600"]);
    assert.ok(readFileSync(rem).equals(data));
    assert.equal(statSync(rem).mode & 0o777, 0o600);
    await box(["get", `${host}:${rem}`, back]);
    assert.ok(readFileSync(back).equals(data));
    assert.ok((await run("bash", [cli, "get", `${host}:${rem}`, "-"], { encoding: "buffer", maxBuffer: 64 << 20 })).stdout.equals(data));
    const tree = P(`tree-${host}`), up = P(`cli-tree-${host}`), down = P(`cli-tree-back-${host}`);
    await box(["push", tree, `${host}:${up}`, "-x", "node_modules"]);
    execFileSync("diff", ["-r", "-x", "node_modules", tree, up]);
    assert.equal(existsSync(path.join(up, "node_modules")), false);
    await box(["pull", `${host}:${up}`, down]);
    execFileSync("diff", ["-r", up, down]);
  }
  assert.ok((await box(["put", P("cli-src-local.bin"), P("cli-default-host.bin")])).includes("500000")); // host defaults to local
  assert.match(await box(["call", "ssh_exec", JSON.stringify({ host: "local", command: "echo from-call" })]), /from-call/);
  assert.match(await box(["--version"]), /^box \d/);
});

test("G7 bridge: 16 parallel downloads on one token", async () => {
  const f = P("par.bin");
  const data = randomBytes(200_000);
  writeFileSync(f, data);
  const all = await Promise.all(Array.from({ length: 16 }, () => fetch(`${BR}/fs/local?p64=${p64(f)}`).then((r) => r.arrayBuffer())));
  for (const b of all) assert.ok(Buffer.from(b).equals(data));
});

test("G8 a bridge URL cannot mint another bridge URL (it must expire when it says it does)", async () => {
  const r = await call("bridge", { ttl_hours: 100 }, `${BR}/mcp`);
  assert.equal(r.isError, true, r.text);
  assert.match(r.text, /cannot create another/);
  assert.doesNotMatch(r.text, /\/b\//);
});

// Send only the first part of an upload, then drop the connection.
const brokenPut = (url, total, send) => new Promise((resolve) => {
  const u = new URL(url);
  const req = http.request({ host: u.hostname, port: u.port, path: u.pathname + u.search, method: "PUT", headers: { "Content-Type": "application/octet-stream", "Content-Length": total } });
  req.on("error", () => {});
  req.write(randomBytes(send), () => setTimeout(() => { req.destroy(); resolve(); }, 300));
});

for (const host of HOSTS) {
  test(`G9 bridge upload ${host}: all-or-nothing, keeps mode, writes through symlinks, needs a length`, async () => {
    const dir = P(`atomic-${host}`), f = path.join(dir, "app.bin"), link = path.join(dir, "link.bin");
    mkdirSync(dir);
    writeFileSync(f, "old content\n", { mode: 0o600 });
    chmodSync(f, 0o600);
    await brokenPut(`${BR}/fs/${host}?p64=${p64(f)}`, 5_000_000, 100_000);
    for (let i = 0; i < 60 && (readdirSync(dir).length !== 1 || pgrep(f)); i++) await sleep(100);
    assert.deepEqual(readdirSync(dir), ["app.bin"], "no partial file is left behind");
    assert.equal(readFileSync(f, "utf8"), "old content\n", "the existing file is untouched");
    assert.equal(pgrep(f), "", "nothing is left waiting for the rest of the upload");
    // a complete upload replaces the content and keeps the existing mode
    const put = await fetch(`${BR}/fs/${host}?p64=${p64(f)}`, { method: "PUT", headers: { "Content-Type": "application/octet-stream" }, body: "new content\n" });
    assert.equal(put.status, 200, await put.text());
    assert.equal(readFileSync(f, "utf8"), "new content\n");
    assert.equal(statSync(f).mode & 0o777, 0o600);
    // JSON is just bytes here (no body parser may eat it)
    const js = await fetch(`${BR}/fs/${host}?p64=${p64(path.join(dir, "data.json"))}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: '{"a": 1}' });
    assert.equal(js.status, 200, await js.text());
    assert.equal(readFileSync(path.join(dir, "data.json"), "utf8"), '{"a": 1}');
    // a symlink stays a symlink; its target gets the bytes
    execFileSync("ln", ["-s", f, link]);
    const viaLink = await fetch(`${BR}/fs/${host}?p64=${p64(link)}`, { method: "PUT", headers: { "Content-Type": "application/octet-stream" }, body: "through the link\n" });
    assert.equal(viaLink.status, 200, await viaLink.text());
    assert.ok(lstatSync(link).isSymbolicLink());
    assert.equal(readFileSync(f, "utf8"), "through the link\n");
    // a directory is refused, and so is a body of unknown length
    assert.equal((await fetch(`${BR}/fs/${host}?p64=${p64(dir)}`, { method: "PUT", headers: { "Content-Type": "application/octet-stream" }, body: "x" })).status, 500);
    const status = await new Promise((resolve, reject) => {
      const u = new URL(`${BR}/fs/${host}?p64=${p64(path.join(dir, "chunked.bin"))}`);
      const req = http.request({ host: u.hostname, port: u.port, path: u.pathname + u.search, method: "PUT", headers: { "Transfer-Encoding": "chunked" } }, (res) => { res.resume(); resolve(res.statusCode); });
      req.on("error", reject);
      req.end("abc");
    });
    assert.equal(status, 411);
    assert.equal(existsSync(path.join(dir, "chunked.bin")), false);
  });
}

test("G10 a client that disconnects mid-download does not leave the transfer running on the host", async () => {
  const dir = P("slow-tree");
  mkdirSync(dir);
  execFileSync("truncate", ["-s", "3G", path.join(dir, "sparse.bin")]); // ~10 s of gzip work
  const ac = new AbortController();
  const r = await fetch(`${BR}/tar/local?p64=${p64(dir)}`, { signal: ac.signal });
  await r.body.getReader().read();
  assert.notEqual(pgrep(`tar -C ${dir}`), "", "tar is running");
  ac.abort();
  for (let i = 0; i < 60 && pgrep(`tar -C ${dir}`); i++) await sleep(100);
  assert.equal(pgrep(`tar -C ${dir}`), "", "tar was stopped");
  assert.equal((await rpc(BASE, "tools/list")).status, 200); // and the server is fine
});

// One HTTP request over a bare socket that is closed the moment the announced body is complete. That is what curl
// does; fetch keeps its connections open, so it never shows what a server does when the client leaves at once.
function rawRequest(url, { method = "GET", body = "" } = {}) {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const sock = net.connect(Number(u.port), u.hostname, () =>
      sock.write(`${method} ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${u.host}\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`));
    let buf = Buffer.alloc(0);
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      const at = buf.indexOf("\r\n\r\n");
      if (at < 0) return;
      const head = buf.subarray(0, at).toString("latin1"), len = Number((/^content-length: (\d+)$/im.exec(head) ?? [])[1]);
      if (Number.isNaN(len) || buf.length - (at + 4) < len) return;
      sock.destroy();
      resolve({ status: Number(head.split(" ")[1]), body: buf.subarray(at + 4, at + 4 + len) });
    });
    sock.on("error", reject);
    sock.on("close", () => reject(new Error("the connection closed before the whole response had arrived")));
  });
}

test("G11 a client that closes the connection as soon as it has the whole response - as curl does - is not recorded as a broken transfer", async () => {
  const br = BR ?? (await call("bridge", { ttl_hours: 1 })).text.match(/(http:\/\/127\.0\.0\.1:\d+\/b\/[0-9a-z]+\.[0-9a-f]{32})\/cli/)[1];
  for (const host of HOSTS) {
    const f = P(`g11-${host}.bin`), data = randomBytes(70_000);
    writeFileSync(f, data);
    for (let i = 0; i < 6; i++) {
      const r = await rawRequest(`${br}/exec/${host}`, { method: "POST", body: `echo g11-${host}-${i}` });
      assert.deepEqual([r.status, r.body.toString()], [200, `g11-${host}-${i}\n`]);
      const g = await rawRequest(`${br}/fs/${host}?p64=${p64(f)}`);
      assert.deepEqual([g.status, g.body.equals(data)], [200, true]);
    }
    const none = await rawRequest(`${br}/exec/${host}`, { method: "POST", body: ": g11-no-output" });
    assert.deepEqual([none.status, none.body.length], [200, 0]);
    // and with bodies large enough that the server has to wait for the client now and then
    const big = P(`g11-${host}-big.bin`), bytes = randomBytes(6 * 1024 * 1024), sum = (b) => createHash("sha256").update(b).digest("hex");
    writeFileSync(big, bytes);
    const down = await rawRequest(`${br}/fs/${host}?p64=${p64(big)}`);
    assert.deepEqual([down.status, down.body.length, sum(down.body)], [200, bytes.length, sum(bytes)]);
    const out = await rawRequest(`${br}/exec/${host}`, { method: "POST", body: `echo g11-big >/dev/null; cat ${big}` });
    assert.deepEqual([out.status, out.body.length, sum(out.body)], [200, bytes.length, sum(bytes)]);
  }
  const pick = (es) => es.filter((e) => (e.tool === "bridge.exec" && /^(echo|:) g11-/.test(e.what ?? "")) || (e.tool === "bridge.get" && /g11-/.test(e.what ?? "")));
  const mine = await auditWhen(pick, (got) => got.length >= 30 && got.every((e) => e.done));
  assert.equal(mine.length, 30);
  assert.deepEqual(mine.filter((e) => !e.ok).map((e) => `${e.tool} ${e.what}: ${e.err}`), [], "each of them got its whole answer");
});

// ═════════════════════════ v1.3: fewer round trips - batch, quiet output, server instructions ═════════════════════════

test("V1 the five v1.2 tools are unchanged (bash only gained the optional `quiet` and `confirm`)", async () => {
  const baseline = JSON.parse(readFileSync(path.join(ROOT, "test/baseline-tools-v1.2.json"), "utf8"));
  assert.deepEqual(baseline.map((t) => t.name).sort(), [...NEW].sort());
  const { json } = await rpc(BASE, "tools/list");
  const live = JSON.parse(JSON.stringify(json.result.tools).replaceAll(JOBS, "/var/lib/ssh-mcp/jobs"));
  for (const b of baseline) {
    const t = live.find((x) => x.name === b.name);
    if (b.name === "bash") {
      assert.equal(t.inputSchema.properties.quiet.type, "boolean");
      assert.equal(t.inputSchema.properties.confirm.type, "boolean");
      for (const k of ["quiet", "confirm"]) { assert.ok(!(t.inputSchema.required ?? []).includes(k)); delete t.inputSchema.properties[k]; }
    }
    assert.deepEqual(t, b, `tool ${b.name} changed`);
  }
});

test("I1 initialize: current version and short instructions that point every model at batch / bulk calls", async () => {
  const { json } = await rpc(BASE, "initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "e2e", version: "1" } });
  assert.equal(json.result.serverInfo.version, VERSION);
  const ins = json.result.instructions;
  assert.equal(typeof ins, "string");
  for (const word of ["batch", "files", "ssh_exec_many", "quiet", "run_in_background", "audit", "add_host"]) assert.ok(ins.includes(word), `instructions do not mention ${word}`);
  assert.ok(ins.length < 1500, `instructions are ${ins.length} chars`);
});

// One block per op: "=== [i/n] <kind> <label> | ok|FAILED|skipped [| 0.12s] ===", then the op's output; last line is the summary.
function parseBatch(text) {
  const heads = [...text.matchAll(/^=== \[(\d+)\/(\d+)\] (bash|read|write|edit) (.*?) \| (ok|FAILED|skipped)(?: \| (\d+\.\d\d)s)? ===\n/gm)];
  const sum = text.match(/^=== batch: (.*?) \| (\d+\.\d\d)s ===$/m);
  assert.ok(sum, `no summary line: ${text.slice(-300)}`);
  const ops = heads.map((m, k) => ({ i: Number(m[1]), n: Number(m[2]), kind: m[3], label: m[4], status: m[5],
    body: text.slice(m.index + m[0].length, k + 1 < heads.length ? heads[k + 1].index : sum.index) }));
  return { ops, summary: sum[1] };
}
const SEQ_BYTES = 108_894; // bytes printed by `seq 1 20000`

for (const [i, host] of HOSTS.entries()) {
  test(`Q1 bash quiet ${host}: only the end of the output comes back, the rest stays on the host`, async () => {
    assert.equal((await call("bash", { host, quiet: true, command: "echo hi" })).text, "hi\n");            // small output: unchanged
    assert.equal((await call("bash", { host, quiet: true, command: "true" })).text, "(no output)");
    const ok = await call("bash", { host, quiet: true, command: "seq 1 20000" });
    assert.equal(ok.isError, false, ok.text.slice(0, 300));
    const m = ok.text.match(/^\.\.\.\[(\d+) bytes omitted - full output saved on the host: (\S+)\]\.\.\.\n/);
    assert.ok(m, ok.text.slice(0, 200));
    assert.equal(Number(m[1]), SEQ_BYTES - 2000);
    assert.equal(statSync(m[2]).size, SEQ_BYTES);
    assert.equal(ok.text.length, m[0].length + 2000);
    assert.ok(ok.text.endsWith("19999\n20000\n"));
    const bad = await call("bash", { host, quiet: true, command: "seq 1 20000; exit 7" });                 // a failure shows more of the end
    const mb = bad.text.match(/^\.\.\.\[(\d+) bytes omitted - full output saved on the host: (\S+)\]\.\.\.\n/);
    assert.equal(Number(mb[1]), SEQ_BYTES - 8000);
    assert.ok(bad.text.endsWith("20000\n[exit code: 7]"), bad.text.slice(-60));
    const loud = await call("bash", { host, command: "seq 1 20000" });                                     // without quiet: as before
    assert.ok(loud.text.length > 97_000 && loud.text.startsWith("1\n2\n3\n"));
  });

  test(`B1 batch ${host}: write, edit, bash and read in ONE call, in order, one block each`, async () => {
    const d = P(`batch-${host}`);
    const r = await call("batch", { host, ops: [
      { write: { files: [{ file_path: `${d}/a.txt`, content: "alpha\nbeta\n" }, { file_path: `${d}/sub/b.txt`, content: "one\n" }] } },
      { edit: { file_path: `${d}/a.txt`, old_string: "beta", new_string: "BETA" } },
      { bash: { command: "cat a.txt; echo err >&2", cwd: d } },
      { read: { file_path: `${d}/sub/b.txt` } },
    ] });
    assert.equal(r.isError, false, r.text);
    const b = parseBatch(r.text);
    assert.deepEqual(b.ops.map((o) => [o.i, o.n, o.kind, o.status]), [[1, 4, "write", "ok"], [2, 4, "edit", "ok"], [3, 4, "bash", "ok"], [4, 4, "read", "ok"]]);
    assert.deepEqual(b.ops.map((o) => o.label), ["2 files", `${d}/a.txt`, "cat a.txt; echo err >&2", `${d}/sub/b.txt`]);
    assert.match(b.ops[0].body, /^Wrote 11 bytes to .*\n.*\n2 files written, 15 bytes\n$/);
    assert.match(b.ops[1].body, /: 1 replacement\n--- lines 1-\d after the edit ---\n     1\talpha\n     2\tBETA\n/);
    assert.equal(b.ops[2].body, "alpha\nBETA\nerr\n");
    assert.equal(b.ops[3].body, "     1\tone\n");
    assert.equal(b.summary, "4 ok, 0 failed, 0 skipped");
    assert.equal(readFileSync(`${d}/a.txt`, "utf8"), "alpha\nBETA\n");
    const one = await call("batch", { host, ops: [{ bash: { command: "true", description: "do nothing" } }] });
    assert.deepEqual(parseBatch(one.text).ops.map((o) => [o.label, o.body]), [["do nothing", "(no output)\n"]]);
  });

  test(`B2 batch ${host}: stops at the first failure - later ops are skipped and change nothing`, async () => {
    const d = P(`batch-stop-${host}`);
    mkdirSync(d);
    writeFileSync(`${d}/keep.txt`, "keep\n");
    const r = await call("batch", { host, ops: [
      { bash: { command: "echo one" } },
      { bash: { command: "echo two; exit 3" } },
      { write: { file_path: `${d}/never.txt`, content: "x" } },
      { bash: { command: `touch ${d}/never2.txt` } },
    ] });
    assert.equal(r.isError, true, r.text);
    const b = parseBatch(r.text);
    assert.deepEqual(b.ops.map((o) => o.status), ["ok", "FAILED", "skipped", "skipped"]);
    assert.equal(b.ops[1].body, "two\n[exit code: 3]\n");
    assert.equal(b.ops[2].body + b.ops[3].body, "");
    assert.equal(b.summary, "1 ok, 1 failed, 2 skipped");
    assert.deepEqual(readdirSync(d), ["keep.txt"]);
    // every kind of op can be the one that stops it
    for (const [op, why] of [
      [{ edit: { file_path: `${d}/keep.txt`, old_string: "absent", new_string: "x" } }, /old_string not found/],
      [{ read: { file_path: `${d}/missing.txt` } }, /File does not exist/],
      [{ write: { file_path: "relative.txt", content: "x" } }, /file_path must be absolute/],
      [{ bash: { command: "pwd", cwd: `${d}/no-such-dir` } }, /No such directory/],
    ]) {
      const s = parseBatch((await call("batch", { host, ops: [op, { bash: { command: `touch ${d}/never3.txt` } }] })).text);
      assert.deepEqual(s.ops.map((o) => o.status), ["FAILED", "skipped"], JSON.stringify(op));
      assert.match(s.ops[0].body, why);
    }
    assert.deepEqual(readdirSync(d), ["keep.txt"]);
    assert.equal(readFileSync(`${d}/keep.txt`, "utf8"), "keep\n");
  });

  test(`B3 batch ${host}: stop_on_error false runs everything and reports each failure; a timeout is a failure`, async () => {
    const r = await call("batch", { host, stop_on_error: false, ops: [
      { bash: { command: "echo a" } },
      { bash: { command: "echo b; sleep 20", timeout: 1000 } },
      { read: { file_path: P("definitely-missing.txt") } },
      { bash: { command: "echo d" } },
    ] });
    assert.equal(r.isError, true);
    const b = parseBatch(r.text);
    assert.deepEqual(b.ops.map((o) => o.status), ["ok", "FAILED", "FAILED", "ok"]);
    assert.equal(b.ops[1].body, "b\n[timed out after 1s - exit code: 124]\n");
    assert.equal(b.ops[3].body, "d\n");
    assert.equal(b.summary, "2 ok, 2 failed, 0 skipped");
  });

  test(`B4 batch ${host}: bash ops of one batch share a working directory; cwd and session work as in bash`, async () => {
    const d = P(`batch-cwd-${host}`);
    mkdirSync(`${d}/sub`, { recursive: true });
    const b = parseBatch((await call("batch", { host, cwd: d, ops: [
      { bash: { command: "pwd" } },
      { bash: { command: "cd sub" } },
      { read: { file_path: P("hosts.json"), limit: 1 } },
      { bash: { command: "pwd" } },
    ] })).text);
    assert.deepEqual(b.ops.map((o) => o.status), ["ok", "ok", "ok", "ok"]);
    assert.equal(b.ops[0].body, `${d}\n`);                       // starts in the batch cwd, no note because nothing moved
    assert.equal(b.ops[1].body, `[cwd: ${d}/sub]\n`);           // cd is noted ...
    assert.equal(b.ops[3].body, `${d}/sub\n`);                  // ... and carries to the next bash op
    // nothing leaks out of the batch
    assert.equal((await call("bash", { host, command: "pwd" })).text, process.env.HOME + "\n");
    assert.equal(parseBatch((await call("batch", { host, ops: [{ bash: { command: "pwd" } }] })).text).ops[0].body, process.env.HOME + "\n");
    // a named session is the same one the bash tool uses
    const s = `batch-sess-${host}`;
    await call("batch", { host, session: s, ops: [{ bash: { command: `cd ${d}` } }] });
    assert.equal((await call("bash", { host, session: s, command: "pwd" })).text, `${d}\n`);
    assert.equal(parseBatch((await call("batch", { host, session: s, ops: [{ bash: { command: "pwd" } }] })).text).ops[0].body, `${d}\n`);
    // an op's own cwd wins for that op
    assert.equal(parseBatch((await call("batch", { host, cwd: d, ops: [{ bash: { command: "pwd", cwd: TMP } }] })).text).ops[0].body, `${TMP}\n`);
  });

  test(`B6 batch ${host}: all ops share one output budget; what is cut stays in full on the host`, async () => {
    const r = await call("batch", { host, ops: [
      { bash: { command: "echo small" } },
      ...Array.from({ length: 4 }, () => ({ bash: { command: "head -c 60000 /dev/zero | tr '\\0' x" } })),
    ] });
    assert.equal(r.isError, false, r.text.slice(0, 300));
    assert.ok(r.text.length < MAX_OUT + 1500, `len ${r.text.length}`);
    const b = parseBatch(r.text);
    assert.equal(b.ops[0].body, "small\n");
    for (const o of b.ops.slice(1)) {
      assert.ok(o.body.length > 15_000 && o.body.length < 21_000, `body ${o.body.length}`);
      const m = o.body.match(/\[(\d+) bytes omitted - full output saved on the host: (\S+)\]/);
      assert.ok(m, o.body.slice(0, 100));
      assert.equal(statSync(m[2]).size, 60_000);
    }
  });

  test(`B7 batch ${host}: an image read, a background job and a quiet command inside one batch`, async () => {
    const png = P(`batch-dot-${host}.png`);
    writeFileSync(png, Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==", "base64"));
    const res = await tool("batch", { host, ops: [
      { read: { file_path: png } },
      { bash: { command: `sleep ${61337 + i}`, run_in_background: true } },
      { bash: { command: "seq 1 20000", quiet: true } },
    ] });
    assert.equal(!!res.isError, false);
    assert.deepEqual(res.content.map((c) => c.type), ["text", "image", "text"]);
    assert.equal(res.content[1].mimeType, "image/png");
    const b = parseBatch(res.content.filter((c) => c.type === "text").map((c) => c.text).join(""));
    assert.deepEqual(b.ops.map((o) => o.status), ["ok", "ok", "ok"]);
    const jobId = field(b.ops[1].body, "jobId");
    assert.match(jobId, /^\d{8}-\d{6}-[0-9a-f]{6}$/, b.ops[1].body);
    assert.equal(field((await job(host, jobId, "kill")).text, "state"), "exited");
    assert.ok(b.ops[2].body.length < 2300 && b.ops[2].body.endsWith("19999\n20000\n"), `quiet body ${b.ops[2].body.length}`);
  });
}

test("B5 batch validation: each op is exactly one of bash/read/write/edit; nothing runs when the request is malformed", async () => {
  const f = P("batch-validation.txt");
  const w = { write: { file_path: f, content: "x" } };
  const none = await call("batch", { host: "local", ops: [w, {}] });
  assert.equal(none.isError, true);
  assert.match(none.text, /op #2: .*exactly one of bash, read, write, edit/);
  const two = await call("batch", { host: "local", ops: [w, { bash: { command: "true" }, read: { file_path: f } }] });
  assert.match(two.text, /op #2: .*exactly one of bash, read, write, edit/);
  assert.equal((await call("batch", { host: "nope", ops: [w] })).isError, true);
  assert.match((await call("batch", { host: "nope", ops: [w] })).text, /Unknown host "nope"/);
  assert.equal((await call("batch", { host: "local", ops: [] })).isError, true);
  assert.equal((await call("batch", { host: "local", ops: Array.from({ length: 31 }, () => w) })).isError, true);
  assert.equal((await call("batch", { host: "local", ops: [w, { bash: { command: "" } }] })).isError, true);
  assert.equal(existsSync(f), false, "a malformed batch must not run its first ops");
});

// ═════════════════════════ v1.4: audit log - every call on record, before it runs ═════════════════════════

const AUDIT_FILE = P("audit", "audit.jsonl");
const auditLines = (file = AUDIT_FILE) => (existsSync(file) ? readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
// One merged entry per call: its start record plus (when it finished) its result record. Server events are passed through.
function auditEntries(file = AUDIT_FILE) {
  const byId = new Map(), out = [];
  for (const r of auditLines(file)) {
    if (r.event) { out.push(r); continue; }
    if (r.tool) { const e = { ...r, done: false }; byId.set(r.id, e); out.push(e); continue; }
    const e = byId.get(r.id);
    assert.ok(e, `a result record without a start record: ${JSON.stringify(r)}`);
    Object.assign(e, { ...r, t: e.t, done: true });
  }
  return out;
}
// Streaming bridge routes write their result record after the response has ended, so wait for it.
async function auditWhen(pick, ready, file = AUDIT_FILE) {
  let got = [];
  for (let i = 0; i < 60; i++) { got = pick(auditEntries(file)); if (ready(got)) return got; await sleep(50); }
  return got;
}
const hex = () => randomBytes(4).toString("hex");

for (const host of HOSTS) {
  test(`A1 audit ${host}: every command is on record - who, what, exit code, duration`, async () => {
    const mark = `a1-${host}-${hex()}`, t0 = Date.now();
    await call("bash", { host, command: `echo ${mark}` });
    await call("bash", { host, command: `echo ${mark}; exit 3`, cwd: TMP });
    await call("bash", { host, command: `echo ${mark}; sleep 20`, timeout: 1000 });
    await call("ssh_exec", { host, command: `echo ${mark}; exit 5` });
    const es = auditEntries().filter((e) => e.what?.includes(mark));
    assert.deepEqual(es.map((e) => [e.tool, e.host, e.ok, e.exit, e.done]),
      [["bash", host, true, 0, true], ["bash", host, false, 3, true], ["bash", host, false, 124, true], ["ssh_exec", host, false, 5, true]]);
    const e = es[0];
    assert.equal(e.what, `echo ${mark}`);
    assert.equal(e.via, "mcp");
    assert.equal(e.ip, "127.0.0.1");
    assert.match(e.id, /^[0-9a-f]{8}$/);
    assert.ok(Date.parse(e.t) >= t0 - 1000 && Date.parse(e.t) <= Date.now(), e.t);
    assert.ok(Number.isInteger(e.ms) && e.ms >= 0 && e.ms < 20_000, String(e.ms));
    assert.equal(es[1].cwd, TMP);
    assert.ok(es[2].ms >= 900, "the duration of the timed-out command is recorded");
  });

  test(`A2 audit ${host}: file tools record paths and sizes - never the content`, async () => {
    const d = P(`audit-files-${host}`), secret = `TOP-SECRET-CONTENT-${host}`;
    await call("write", { host, files: [{ file_path: `${d}/a.txt`, content: `${secret}\nline2\n` }, { file_path: `${d}/b.txt`, content: "x" }] });
    await call("edit", { host, file_path: `${d}/a.txt`, old_string: "line2", new_string: `${secret}-NEW` });
    await call("read", { host, files: [{ file_path: `${d}/a.txt` }, { file_path: `${d}/b.txt` }] });
    await call("sftp_write", { host, path: `${d}/c.bin`, content: Buffer.from(secret).toString("base64"), encoding: "base64" });
    await call("sftp_read", { host, path: `${d}/c.bin` });
    await call("read", { host, file_path: `${d}/missing.txt` });
    const es = auditEntries().filter((e) => e.what?.includes(d));
    assert.deepEqual(es.map((e) => [e.tool, e.ok, e.done]), [["write", true, true], ["edit", true, true], ["read", true, true], ["sftp_write", true, true], ["sftp_read", true, true], ["read", false, true]]);
    assert.equal(es[0].what, `${d}/a.txt (${secret.length + 7} B), ${d}/b.txt (1 B)`);
    assert.equal(es[0].bytes, secret.length + 8);
    assert.equal(es[1].what, `${d}/a.txt (1 edit)`);
    assert.equal(es[2].what, `${d}/a.txt, ${d}/b.txt`);
    assert.equal(es[3].what, `${d}/c.bin (${secret.length} B)`);
    assert.equal(es[4].what, `${d}/c.bin`);
    assert.match(es[5].err, /File does not exist/);
    assert.ok(!readFileSync(AUDIT_FILE, "utf8").includes("TOP-SECRET-CONTENT"), "file content must never reach the audit log");
  });

  test(`A4 audit ${host}: each step of a batch has its own record, linked to the batch; skipped steps have none`, async () => {
    const d = P(`audit-batch-${host}`);
    await call("batch", { host, ops: [
      { write: { file_path: `${d}/a.txt`, content: "one\n" } },
      { bash: { command: `cat ${d}/a.txt; exit 2` } },
      { bash: { command: `echo never-ran-${host}` } },
    ] });
    const es = auditEntries();
    const b = es.filter((e) => e.tool === "batch" && e.host === host).at(-1);
    assert.deepEqual([b.what, b.ok, b.ops, b.done, b.err], ["3 ops", false, "1 ok, 1 failed, 1 skipped", true, "1 of 3 ops failed"]);
    const ops = es.filter((e) => e.batch?.startsWith(`${b.id}#`));
    assert.deepEqual(ops.map((e) => [e.batch, e.tool, e.host, e.ok, e.exit ?? null, e.done]),
      [[`${b.id}#1/3`, "write", host, true, null, true], [`${b.id}#2/3`, "bash", host, false, 2, true]]);
    assert.equal(ops[0].what, `${d}/a.txt (4 B)`);
    assert.equal(ops[1].what, `cat ${d}/a.txt; exit 2`);
    assert.ok(!es.some((e) => e.what?.includes(`never-ran-${host}`)), "a skipped step never ran, so it is not in the log");
  });
}

test("A3 audit: passwords, tokens, keys and the connector's own secret are masked before anything is written", async () => {
  const commands = [
    `: mysql --password=hunter2secret -u root`,
    `: export API_TOKEN="tokvalue12345"`,
    `: curl -H 'Authorization: Bearer abcdefghijklmnop123456' https://example.com`,
    `: tool --api-key keyvalue98765 --verbose`,
    `: echo '{"client_secret": "jsonsecretvalue1"}'`,
    `: curl http://127.0.0.1:${PORT}/mcp/${SECRET}`,
    `: cat <<'K'\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaGtleXZhbHVl\n-----END OPENSSH PRIVATE KEY-----\nK`,
  ];
  for (const command of commands) assert.equal((await call("bash", { host: "local", command })).text, "(no output)", command);
  await call("exec_code", { host: "local", language: "bash", code: `: PASSWORD=codepassvalue1` });
  const raw = readFileSync(AUDIT_FILE, "utf8");
  for (const leaked of ["hunter2secret", "tokvalue12345", "abcdefghijklmnop123456", "keyvalue98765", "jsonsecretvalue1", SECRET, "b3BlbnNzaGtleXZhbHVl", "codepassvalue1"])
    assert.ok(!raw.includes(leaked), `${leaked.slice(0, 12)}... leaked into the audit log`);
  const whats = auditEntries().map((e) => e.what ?? "");
  assert.ok(whats.includes(": mysql --password=*** -u root"), "the rest of the command stays readable");
  assert.ok(whats.includes(": tool --api-key *** --verbose"));
  assert.ok(whats.some((w) => w.includes("Authorization: ") && w.endsWith(" https://example.com")));
  assert.ok(whats.includes(`: curl http://127.0.0.1:${PORT}/mcp/[connector secret]`));
  assert.ok(whats.includes("bash: : PASSWORD=***"));
});

test("A5 audit: bridge requests are on record too, tied to the bridge URL they came through - never the token itself", async () => {
  const mint = await call("bridge", { ttl_hours: 1 });
  const [, url, exp, sig] = mint.text.match(/(http:\/\/\S+\/b\/([0-9a-z]+)\.([0-9a-f]{32}))/);
  const d = P("audit-bridge"), octet = { "Content-Type": "application/octet-stream" };
  mkdirSync(d);
  await (await fetch(`${url}/exec/local?c64=${p64(TMP)}`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "echo audit-bridge-exec; exit 6" })).text();
  await (await fetch(`${url}/fs/local?p64=${p64(`${d}/up.bin`)}`, { method: "PUT", headers: octet, body: "12345" })).text();
  await (await fetch(`${url}/fs/local?p64=${p64(`${d}/up.bin`)}`)).arrayBuffer();
  const tgz = Buffer.from(await (await fetch(`${url}/tar/local?p64=${p64(d)}&x=skip-me`)).arrayBuffer());
  await (await fetch(`${url}/tar/local?p64=${p64(`${d}/copy`)}`, { method: "PUT", headers: octet, body: tgz })).text();
  await call("bash", { host: "local", command: "echo audit-bridge-mcp" }, `${url}/mcp`);
  await (await fetch(`${url}/cli`)).text();
  await (await fetch(`${url}/fs/local?p64=${p64(`${d}/missing.bin`)}`)).text();
  const es = await auditWhen((all) => all.filter((e) => e.tok === exp), (list) => list.length === 9 && list.every((e) => e.done));
  assert.deepEqual(es.map((e) => [e.tool, e.via, e.ok, e.done]), [
    ["bridge", "mcp", true, true], ["bridge.exec", "bridge", false, true], ["bridge.put", "bridge", true, true], ["bridge.get", "bridge", true, true],
    ["bridge.pull", "bridge", true, true], ["bridge.push", "bridge", true, true], ["bash", "bridge", true, true], ["bridge.cli", "bridge", true, true], ["bridge.get", "bridge", false, true]]);
  assert.deepEqual([es[1].what, es[1].exit, es[1].cwd, es[1].host], ["echo audit-bridge-exec; exit 6", 6, TMP, "local"]);
  assert.deepEqual([es[2].what, es[2].bytes], [`${d}/up.bin (5 B)`, 5]);
  assert.deepEqual([es[3].what, es[3].bytes], [`${d}/up.bin`, 5]);
  assert.equal(es[4].what, `${d} (exclude: skip-me)`);
  assert.equal(es[5].what, `${d}/copy`);
  assert.equal(es[6].what, "echo audit-bridge-mcp");
  assert.match(es[8].err, /no such readable file/i);
  assert.ok(!readFileSync(AUDIT_FILE, "utf8").includes(sig), "the signature half of a bridge token must never be logged");
});

test("A6 audit: the client address is the one the reverse proxy saw (right-most X-Forwarded-For), with the user agent", async () => {
  const send = (command, headers) => fetch(BASE, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method: "tools/call", params: { name: "bash", arguments: { host: "local", command } } }),
  }).then((r) => r.text());
  await send("echo a6-proxied", { "X-Forwarded-For": "6.6.6.6, 198.51.100.7", "User-Agent": "Claude-User-Test/1.0" });
  await send("echo a6-direct", { "User-Agent": "x".repeat(500) });
  await send("echo a6-garbage", { "X-Forwarded-For": "not an address <script>" });
  const pick = (what) => auditEntries().filter((e) => e.what === what).at(-1);
  assert.deepEqual([pick("echo a6-proxied").ip, pick("echo a6-proxied").ua], ["198.51.100.7", "Claude-User-Test/1.0"]);
  assert.equal(pick("echo a6-direct").ip, "127.0.0.1");
  assert.equal(pick("echo a6-direct").ua.length, 120);
  assert.equal(pick("echo a6-garbage").ip, "?");
});

test("A7 audit: a command is recorded BEFORE it runs, so one that kills the connector is still in the log; every start is recorded", async () => {
  const jobs = P("a7", "jobs"), file = P("a7", "audit", "audit.jsonl"), port = 18790, base = `http://127.0.0.1:${port}/mcp/${SECRET}`;
  const p = await startServer(port, { JOBS_DIR: jobs });
  assert.deepEqual(auditLines(file).map((r) => [r.event, r.pid, r.version]), [["start", p.pid, VERSION]]);
  const gone = new Promise((res) => p.once("exit", res));
  await assert.rejects(call("bash", { host: "local", command: `kill -9 ${p.pid} # a7-killer` }, base));
  await gone;
  const e = auditEntries(file).find((x) => x.what?.includes("a7-killer"));
  assert.ok(e, "the command that killed the server is in the log");
  assert.equal(e.done, false);
  // a new server on the same state directory carries on in the same file and shows the call that never returned
  await startServer(port, { JOBS_DIR: jobs });
  const shown = (await call("audit", { contains: "a7-killer" }, base)).text;
  assert.match(shown, new RegExp(`  bash  local  no result \\(still running, or the server stopped\\)  -  kill -9 ${p.pid} # a7-killer$`, "m"));
  assert.equal(auditLines(file).filter((r) => r.event === "start").length, 2);
  assert.match((await call("audit", { contains: "server started" }, base)).text, new RegExp(`^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ  server started: v${VERSION.replaceAll(".", "\\.")}, pid \\d+$`, "m"));
});

test("A8 audit: the log rotates at its size limit and keeps a fixed number of old files", async () => {
  const dir = P("a8", "audit"), port = 18791, base = `http://127.0.0.1:${port}/mcp/${SECRET}`, limit = Math.round(0.004 * 1024 * 1024);
  await startServer(port, { JOBS_DIR: P("a8", "jobs"), AUDIT_MAX_MB: "0.004", AUDIT_KEEP: "2" });
  for (let i = 0; i < 60; i++) await call("ssh_exec", { host: "local", command: `: ${"x".repeat(300)} a8-n${i}` }, base);
  const files = readdirSync(dir).sort();
  assert.deepEqual(files, ["audit.jsonl", "audit.jsonl.1", "audit.jsonl.2"]);
  for (const f of files) assert.ok(statSync(path.join(dir, f)).size <= limit, `${f} is ${statSync(path.join(dir, f)).size} bytes`);
  // oldest file first: every line is whole JSON and the calls are in order, ending with the last one made
  const seq = ["audit.jsonl.2", "audit.jsonl.1", "audit.jsonl"].flatMap((f) => auditLines(path.join(dir, f))).filter((r) => r.what).map((r) => Number(r.what.match(/a8-n(\d+)$/)[1]));
  assert.ok(seq.length >= 10 && seq.length < 60, `kept ${seq.length} calls`);
  assert.deepEqual(seq, Array.from({ length: seq.length }, (_, k) => 60 - seq.length + k));
});

test("A9 audit tool: the newest entries, filtered by text and by age; its own calls are on record too", async () => {
  const mark = `a9-${hex()}`, line = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ  127\.0\.0\.1  mcp  /;
  for (const n of [1, 2, 3]) await call("bash", { host: "local", command: `echo ${mark}-${n}; exit ${n - 1}` });
  const all = (await call("audit", { contains: mark })).text.split("\n");
  assert.match(all[0], /^audit log: .*\/audit\.jsonl - 3 of 3 matching entries, oldest first$/);
  assert.equal(all.length, 4);
  for (const l of all.slice(1)) assert.match(l, line);
  assert.match(all[1], new RegExp(`  bash  local  ok  \\d+\\.\\d\\ds  echo ${mark}-1; exit 0$`));
  assert.match(all[2], new RegExp(`  bash  local  exit 1  \\d+\\.\\d\\ds  echo ${mark}-2; exit 1$`));
  assert.match(all[3], new RegExp(`  bash  local  exit 2  \\d+\\.\\d\\ds  echo ${mark}-3; exit 2$`));
  // the query above is itself an entry now, and a query never lists itself while it runs
  const two = (await call("audit", { contains: mark, limit: 2 })).text.split("\n");
  assert.match(two[0], / - 2 of 4 matching entries, oldest first$/);
  assert.match(two[1], new RegExp(`echo ${mark}-3; exit 2$`));
  assert.match(two[2], new RegExp(`  audit  -  ok  \\d+\\.\\d\\ds  contains="${mark}"$`));
  // age filter: an old entry is found without it and left out with it
  appendFileSync(AUDIT_FILE, `{"t":"2020-01-01T00:00:00.000Z","id":"0ld0ld00","via":"mcp","ip":"10.9.9.9","tool":"bash","host":"local","what":"echo ${mark}-old"}\n{"t":"2020-01-01T00:00:01.000Z","id":"0ld0ld00","ok":true,"exit":0,"ms":1000}\n`);
  assert.match((await call("audit", { contains: `${mark}-old` })).text, new RegExp(`^2020-01-01T00:00:00Z  10\\.9\\.9\\.9  mcp  bash  local  ok  1\\.00s  echo ${mark}-old$`, "m"));
  assert.doesNotMatch((await call("audit", { contains: `${mark}-old`, since_minutes: 60 })).text, /2020-01-01/);
  assert.match((await call("audit", { contains: "NO-SUCH-TEXT-ANYWHERE-zz" })).text, / - no matching entries$/);
  assert.equal((await call("audit", { limit: 0 })).isError, true);
  // multi-line commands stay on one line
  await call("bash", { host: "local", command: `: ${mark}-multi\n: second line` });
  assert.match((await call("audit", { contains: `${mark}-multi` })).text, new RegExp(`  : ${mark}-multi ⏎ : second line$`, "m"));
});

test("A10 audit: the log is private to the service user (0700 / 0600) and follows the state directory when the default is not writable", async () => {
  assert.equal(statSync(P("audit")).mode & 0o777, 0o700);
  assert.equal(statSync(AUDIT_FILE).mode & 0o777, 0o600);
  await call("list_hosts", {}, BASE2);            // this server has JOBS_DIR=/proc/nope/jobs and HOME=HOME2
  const fallback = path.join(HOME2, ".ssh-mcp", "audit", "audit.jsonl");
  assert.ok(auditEntries(fallback).some((e) => e.tool === "list_hosts" && e.done && e.ok), "calls are logged under ~/.ssh-mcp/audit");
  assert.equal(statSync(fallback).mode & 0o777, 0o600);
});

test("A11 AUDIT_LOG=off: nothing is written, the tools work, and the audit tool says so", async () => {
  const port = 18792, base = `http://127.0.0.1:${port}/mcp/${SECRET}`;
  await startServer(port, { JOBS_DIR: P("a11", "jobs"), AUDIT_LOG: "off" });
  assert.equal((await call("bash", { host: "local", command: "echo a11" }, base)).text, "a11\n");
  const b = await call("batch", { host: "local", ops: [{ bash: { command: "echo a11-batch" } }] }, base);
  assert.match(b.text, /a11-batch\n=== batch: 1 ok, 0 failed, 0 skipped/);
  assert.equal(existsSync(P("a11", "audit")), false);
  assert.match((await call("audit", {}, base)).text, /turned off/);
});

test("A12 audit: tools can only be registered through the audited wrapper", () => {
  const src = readFileSync(path.join(ROOT, SERVER_FILE), "utf8");
  assert.equal((src.match(/server\.registerTool\b/g) ?? []).length, 1, "server.registerTool must appear once: inside the wrapper that writes the audit record");
});

test("A13 audit: every one of the tools leaves a record", async () => {
  const f = P("a13.txt"), from = auditEntries().length;
  await call("list_hosts", {});
  await call("ssh_exec", { host: "local", command: "true" });
  await call("sftp_write", { host: "local", path: f, content: "one\n" });
  await call("sftp_read", { host: "local", path: f });
  await call("sftp_list", { host: "local", path: TMP });
  await call("ssh_exec_many", { host: "local", commands: [{ id: "a", command: "true" }, { id: "b", command: "exit 2" }] });
  const { jobId } = await spawnJob("local", "echo a13-job");
  await job("local", jobId, "wait", { timeout_sec: 20 });
  await call("ssh_jobs", { host: "local", limit: 1 });
  await call("exec_code", { host: "local", language: "bash", code: "exit 4" });
  await call("bash", { host: "local", command: "sleep 0.1", run_in_background: true });
  await call("read", { host: "local", file_path: f });
  await call("write", { host: "local", file_path: f, content: "two\n" });
  await call("edit", { host: "local", file_path: f, old_string: "two", new_string: "three" });
  await call("batch", { host: "local", ops: [{ read: { file_path: f } }] });
  await call("bridge", {});
  await call("add_host", { name: "a13-nowhere", host: "127.0.0.1", port: 1, username: "nobody" });
  await call("audit", { limit: 1 });
  const es = auditEntries().slice(from), names = (await rpc(BASE, "tools/list")).json.result.tools.map((t) => t.name);
  assert.equal(names.length, ALL_TOOLS.length);
  for (const n of names) assert.ok(es.some((e) => e.tool === n && e.done), `no audit record for ${n}`);
  const of = (toolName) => es.find((e) => e.tool === toolName && !e.batch);
  assert.deepEqual([of("ssh_exec_many").what, of("ssh_exec_many").exits, of("ssh_exec_many").ok], ["a: true\nb: exit 2", [0, 2], false]);
  assert.deepEqual([of("exec_code").what, of("exec_code").exit, of("exec_code").ok], ["bash: exit 4", 4, false]);
  assert.deepEqual([of("ssh_spawn").what, of("ssh_spawn").job], ["echo a13-job", jobId]);
  assert.equal(of("ssh_job").what, `wait ${jobId}`);
  assert.deepEqual([of("bash").what, of("bash").bg, typeof of("bash").job], ["sleep 0.1", true, "string"]);
  assert.equal(of("edit").what, `${f} (1 edit)`);
  assert.equal(of("sftp_list").what, TMP);
  assert.equal(of("bridge").what, "ttl_hours=12");
});

test("A14 audit: if the log is removed, cut or replaced, the log itself says so and carries on", async () => {
  const dir = P("a14", "audit"), file = path.join(dir, "audit.jsonl"), port = 18793, base = `http://127.0.0.1:${port}/mcp/${SECRET}`;
  await startServer(port, { JOBS_DIR: P("a14", "jobs") });
  const run = (n) => call("ssh_exec", { host: "local", command: `: a14-${n}` }, base);
  const shape = () => auditLines(file).map((r) => r.event ? `${r.event}: ${r.why ?? ""}` : r.what ?? "result");
  await run(1);
  assert.deepEqual(shape(), ["start: ", ": a14-1", "result"]);
  rmSync(file);                                                    // removed
  await run(2);
  assert.deepEqual(shape(), ["reset: the log file was missing", ": a14-2", "result"]);
  writeFileSync(file, "");                                         // emptied in place
  await run(3);
  assert.deepEqual(shape(), ["reset: the log file got shorter", ": a14-3", "result"]);
  writeFileSync(`${file}.edited`, readFileSync(file));              // swapped for an edited copy of the same size
  renameSync(`${file}.edited`, file);
  await run(4);
  assert.deepEqual(shape().slice(3), ["reset: the log file was replaced", ": a14-4", "result"]);
  await run(5);                                                    // untouched since: nothing to report
  assert.deepEqual(shape().slice(6), [": a14-5", "result"]);
  rmSync(dir, { recursive: true });                                // the whole directory removed
  await run(6);
  assert.deepEqual(shape(), ["reset: the log file was missing", ": a14-6", "result"]);
  assert.deepEqual([statSync(dir).mode & 0o777, statSync(file).mode & 0o777], [0o700, 0o600]);
  assert.match((await call("audit", {}, base)).text, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ  audit log reset: the log file was missing$/m);
});

test("A15 audit: a long command is masked first and cut to 2000 characters afterwards", async () => {
  const long = `: ${"a".repeat(1975)} password=straddle-secret-value ${"b".repeat(3000)}`;   // the password sits right on the cut
  assert.equal((await call("bash", { host: "local", command: long })).text, "(no output)");
  const e = auditEntries().filter((x) => x.what?.startsWith(": aaaaaaaa")).at(-1);
  assert.equal(e.what.slice(0, 2000), `: ${"a".repeat(1975)} password=***${" ".repeat(1)}${"b".repeat(2000)}`.slice(0, 2000));
  assert.match(e.what.slice(2000), /^…\[\+\d+ chars\]$/);
  assert.ok(!readFileSync(AUDIT_FILE, "utf8").includes("straddle"), "no part of a credential on the cut may be kept");
  const t0 = Date.now();                                           // a hostile 60 KB command must not stall the server
  assert.equal((await call("bash", { host: "local", command: `: ${"pass".repeat(15000)}` })).isError, false);
  assert.ok(Date.now() - t0 < 3000, `took ${Date.now() - t0} ms`);
});

// ═════════════════════════ v1.5: tripwire - a few catastrophic commands need `confirm: true` ═════════════════════════
// SAFETY OF THESE TESTS: every catastrophic command below is written so that it cannot do anything even if the
// tripwire is broken and lets it through: it sits behind `false &&` or inside `if false`, or it is the `--help`
// of a command (which only prints its help), or it targets /proc (where nothing can be deleted).

const TRIPPED = /^Error: Refused by the tripwire: /;
const TRIP_CASES = [
  ["false && rm -rf /", /recursive delete of "\/"/],
  ["false && rm -rf / home/user/old", /recursive delete of "\/"/],                    // the classic stray space
  ["false && rm -fr /*", /recursive delete of "\/"/],
  ["false && sudo rm -rf --no-preserve-root /", /recursive delete of "\/"/],
  ["false && rm -rf ~", /recursive delete of "~"/],
  ['false && rm -rf "$HOME"/', /recursive delete of "\$HOME"/],
  ["false && rm -rf ${HOME}/*", /recursive delete of "\$\{HOME\}"/],
  ["false && rm -r /etc", /recursive delete of "\/etc"/],
  ["false && rm -Rf /usr/", /recursive delete of "\/usr"/],
  ["false && rm --recursive --force /var/lib/*", /recursive delete of "\/var\/lib"/],
  ["false && /bin/rm -rf /boot", /recursive delete of "\/boot"/],
  ["false && rm -rf /{etc,usr}", /recursive delete of "\/etc"/],
  ["if false; then rm -rf /; fi", /recursive delete of "\/"/],
  ["false && bash -c 'rm -rf /'", /recursive delete of "\/"/],
  ['false && sudo sh -lc "rm -rf /opt/*"', /recursive delete of "\/opt"/],
  ["false && ssh -p 2222 -i /root/.ssh/id root@10.0.0.9 'rm -rf /'", /recursive delete of "\/"/],
  ['false && eval "rm -rf /"', /recursive delete of "\/"/],
  ["false && timeout 5 rm -rf /", /recursive delete of "\/"/],
  ["false && nohup rm -rf / &", /recursive delete of "\/"/],
  ["false && FOO=1 BAR=2 rm -rf /", /recursive delete of "\/"/],
  ["false && sudo -u root rm -rf /", /recursive delete of "\/"/],
  ["false && true; false && rm -rf /", /recursive delete of "\/"/],
  ["false && chmod -R 777 /", /recursive chmod of "\/"/],
  ["false && chown -R nobody:nogroup /etc", /recursive chown of "\/etc"/],
  ["false && find / -delete", /find deletes everything under "\/"/],
  ["false && find /etc -type f -exec rm {} +", /find deletes everything under "\/etc"/],
  ["false && mkfs.ext4 /dev/sdb1", /mkfs\.ext4 formats \/dev\/sdb1/],
  ["false && mkfs -t xfs /dev/nvme1n1", /mkfs formats \/dev\/nvme1n1/],
  ["false && mkfs.ext4 -F \"$DEV\"", /mkfs\.ext4 formats \$DEV/],
  ["false && wipefs -a /dev/sda", /wipefs wipes \/dev\/sda/],
  ["false && bash <<'EOF'\nrm -rf /\nEOF", /recursive delete of "\/"/],             // a script fed to a shell
  ["false && sudo -i <<EOF\nreboot\nEOF", /reboot stops or restarts the machine/],
  ["false && ssh web-1 <<'EOF'\nset -e\nmkfs.ext4 /dev/sdb\nEOF", /mkfs\.ext4 formats \/dev\/sdb/],
  ["false && dd if=/dev/zero of=/dev/sda bs=1M", /dd writes over the disk \/dev\/sda/],
  ["false && cat image.iso > /dev/nvme0n1", /a redirect writes over the disk \/dev\/nvme0n1/],
  ["false && echo x >/dev/sdb", /a redirect writes over the disk \/dev\/sdb/],
  ["false && echo x | tee /dev/vda", /tee writes over the disk \/dev\/vda/],
  ["false && shred -n 1 /dev/xvdf", /shred writes over the disk \/dev\/xvdf/],
  ["false && shutdown -h now", /shutdown stops or restarts the machine/],
  ["false && reboot", /reboot stops or restarts the machine/],
  ["false && poweroff", /poweroff stops or restarts the machine/],
  ["false && halt -p", /halt stops or restarts the machine/],
  ["false && init 0", /init 0 stops or restarts the machine/],
  ["false && systemctl poweroff", /systemctl poweroff stops or restarts the machine/],
  ["false && sudo systemctl reboot", /systemctl reboot stops or restarts the machine/],
  ["false && /sbin/reboot", /reboot stops or restarts the machine/],
  ["false && :(){ :|:& };:", /a fork bomb/],
  // the splitter keeps its place through here-documents, nested shells, arithmetic, brace lists and ${...}
  ["false && cat <<EOF\nx\nEOF\nfalse && rm -rf /", /recursive delete of "\/"/],
  ["false && cat <<EOF\nx\n  EOF\nrm -rf /tmp/in-the-text\nEOF\nfalse && reboot", /reboot stops or restarts the machine/],   // an indented EOF does not close <<EOF
  ["false && cat <<-EOF\n\tx\n\tEOF\nfalse && reboot", /reboot stops or restarts the machine/],
  ["false && bash -c \"bash -c 'bash -c \\\"reboot\\\"'\"", /reboot stops or restarts the machine/],
  ["false && echo $((1 << 3)); false && rm -rf /", /recursive delete of "\/"/],
  ["false && rm -rf /{usr/{bin,lib},tmp/x}", /recursive delete of "\/usr\/bin"/],
  ["false && A=1 B=2 env C=3 nice -n 5 timeout -k 3 10 sudo -u root reboot", /reboot stops or restarts the machine/],
  ['false && rm -rf ${CC:+"${CC}"} /', /recursive delete of "\/"/],
  // ... and through the shell's nesting: quotes inside "$(...)", commands inside substitutions, `case` inside them
  ["false && V=\"$(grep '\"version\"' package.json | cut -d '\"' -f4)\"\nfalse && reboot", /reboot stops or restarts the machine/],
  ['false && echo "$(rm -rf /)"', /recursive delete of "\/"/],
  ['false && echo ${X:-$(poweroff)}', /poweroff stops or restarts the machine/],
  ["false && x=$(case $1 in a) echo 1;; esac); false && reboot", /reboot stops or restarts the machine/],
  ['if false; then case "$1" in\n go) reboot;;\nesac; fi', /reboot stops or restarts the machine/],
  ["false && diff <(ls) <(reboot)", /reboot stops or restarts the machine/],
  // first in the command, and harmless by nature
  ["shutdown --help", /shutdown stops or restarts the machine/],
  ["reboot --help", /reboot stops or restarts the machine/],
  ["poweroff --help", /poweroff stops or restarts the machine/],
  ["halt --help", /halt stops or restarts the machine/],
  ["mkfs.ext4 /dev/tw-no-such-device", /mkfs\.ext4 formats \/dev\/tw-no-such-device/],
  ["rm -rf /proc", /recursive delete of "\/proc"/],
];

test("T1 tripwire: catastrophic commands are refused before anything runs, with the reason and the way to go ahead", async () => {
  for (const [command, why] of TRIP_CASES) {
    const r = await call("bash", { host: "local", command });
    assert.equal(r.isError, true, command);
    assert.match(r.text, TRIPPED, command);
    assert.match(r.text, why, command);
    assert.match(r.text, /Nothing was run\. .*confirm: true/, command);
  }
  assert.match((await call("bash", { host: "remote", command: "false && rm -rf /" })).text, TRIPPED); // other hosts too
});

test("T2 tripwire: ordinary commands are not touched - including ones that only mention or resemble the dangerous ones", async () => {
  const d = P("tw");
  mkdirSync(`${d}/sub/deep`, { recursive: true });
  writeFileSync(`${d}/sub/f.txt`, "x");
  const fine = [                                   // every one of these really runs: absolute temp paths and read-only commands only
    `echo "rm -rf /"`,
    `echo 'shutdown -h now' > ${d}/note.txt`,
    `printf '%s\n' reboot poweroff`,
    `rm -rf ${d}/sub/deep`,
    `rm -rf ${d}/sub/*`,
    `rm -f ${d}/nothing-here`,
    `rm -rf /tmp/tw-does-not-exist-${hex()}`,
    `rm -rf /var/lib/tw-does-not-exist-${hex()}/cache`,
    `grep -r shutdown ${d} || true`,
    `dd if=/dev/zero of=${d}/zero.bin bs=1 count=1 2>/dev/null`,
    `echo x > /dev/null`,
    `ls /etc > ${d}/ls.txt`,
    `chmod -R 755 ${d}`,
    `find ${d} -name '*.nope' -delete`,
    `cat > ${d}/script.sh <<'EOF'\nrm -rf /\nshutdown -h now\nmkfs.ext4 /dev/sda1\nEOF`,
    `# rm -rf /\necho comment-ok`,
    `systemctl status reboot.target >/dev/null 2>&1 || true`,
    `man shutdown >/dev/null 2>&1 || true`,
    `test -d /etc && echo etc-exists`,
    `echo "$(echo nested) and \`echo backticks\`"`,
    `case reboot in\n  reboot|halt) echo case-ok;;\n  shutdown) echo no;;\nesac`,
    `echo $((1 << 3))\necho after-shift`,
    `mkdir -p ${d}/{keep,old} && rm -rf ${d}/{old,gone}`,
  ];
  for (const command of fine) {
    const r = await call("bash", { host: "local", command });
    assert.equal(r.isError, false, `${command}\n${r.text}`);
    assert.doesNotMatch(r.text, /tripwire/, command);
  }
  assert.equal(readFileSync(`${d}/script.sh`, "utf8"), "rm -rf /\nshutdown -h now\nmkfs.ext4 /dev/sda1\n");
  assert.deepEqual(readdirSync(`${d}/sub`), []);
  assert.deepEqual([existsSync(`${d}/keep`), existsSync(`${d}/old`)], [true, false]);

  // Routine admin work that only looks alarming. None of these runs: each sits inside `if false`.
  const routine = [
    "rm -rf node_modules dist .cache", "rm -rf /opt/app/releases/2024-01-01", "rm -rf /home/deploy/app/tmp/*", "rm -rf /var/log/myapp/*.gz", "rm -rf /var/lib/apt/lists/*",
    "rm -rf /usr/local/go && tar -C /usr/local -xzf go.tar.gz", "rm -rf /usr/local/{go,node}", "rm -rf /var/{cache,tmp}/myapp", "rm -r /etc/nginx/sites-enabled/old.conf",
    "rm -f /etc/nginx/conf.d/default.conf", 'rm -rf "$BUILD_DIR"/*', "rm -rf ./build", "rm -rf ~/projects/old-app", "rm -rf $HOME/.cache/pip", "rm -rf /tmp/*",
    "chown -R www-data:www-data /var/www/html", 'chown -R "$USER":"$USER" ~', "chown -R deploy:deploy /opt /srv", "chmod -R u+rwX /home/deploy/app",
    "find /var/log -name '*.gz' -mtime +30 -delete", "find / -name '*.pyc' -delete", "find /home -name .DS_Store -delete", "find / -name '*.conf' 2>/dev/null | head",
    "dd if=/dev/sda of=/root/backup.img bs=1M", "dd if=/dev/zero of=/swapfile bs=1M count=1024 && mkswap /swapfile && swapon /swapfile", "mkfs.ext4 -F disk.img", "wipefs /dev/sda",
    "lsblk -f /dev/sda; fdisk -l /dev/nvme0n1; smartctl -a /dev/sda", "mount /dev/sdb1 /mnt/data && umount /mnt/data",
    "systemctl restart nginx && systemctl status nginx", "shutdown -c", "command -v reboot", "which shutdown poweroff", "docker exec web rm -rf /app/cache", "kubectl delete pod web-1",
    "git clean -fdx", "apt-get -y autoremove && apt-get clean", "tar -czf /root/etc-backup.tgz /etc", "rsync -a --delete /srv/app/ /srv/backup/app/",
    "journalctl -u nginx --since '-1h' | grep -i 'shutdown\\|reboot'", "awk '/halt/ {print}' /var/log/syslog", "sed -i 's/poweroff/reboot/' notes.txt",
    'for s in reboot halt; do echo "$s"; done', 'case "$1" in\n  start) echo start;;\n  reboot|halt) echo power;;\n  shutdown) echo down;;\nesac', "x=$(( (2 + 3) * 4 )); echo $x",
    "python3 - <<'PY'\nimport os\nprint(\"rm -rf /\")\nPY", "cat <<EOF | tee notes.txt\nrm -rf /\nreboot\nEOF",
    'git commit -m "$(cat <<\'EOF\'\nFix "reboot" handling\n\nreboot now waits; rm -rf / is "refused"\nEOF\n)"',
    "curl -fsSL https://example.com/install.sh | bash",
    "V=\"$(grep '\"version\"' package.json | cut -d '\"' -f4)\"\necho \"done; reboot to apply\"",   // quotes inside "$(...)" must not turn the next string into commands
    'rm -rf "$(pwd)"/*', "rm -rf $(mktemp -d)/", 'if [[ "$cmd" =~ ^(reboot|shutdown)$ ]]; then echo blocked; fi', 'cmds=(reboot halt "shutdown -h now"); echo ${#cmds[@]}',
    'x="$(case "$1" in reboot) echo "a)b";; *) echo c;; esac)"\necho "y; halt"', "N=${N:-$(wc -l ${F} | awk '{print $1}')}\necho \"a; halt b\"", "echo $'it\\'s; reboot'",
    "x=\"$(cat <<EOF\nit's \"x\"; reboot\nEOF\n)\"\necho \"q; halt\"",
    `echo 'abc' "it's" # rm -rf /`, 'echo "${CC:+"${CC}"}"; echo "$(echo "a b")"', "f() { echo hi; }; f", "rm -rf /tmp/build/{a,b} /srv/app/{cache,tmp}/old",
  ];
  for (const command of routine) {
    const r = await call("bash", { host: "local", command: `if false; then\n${command}\nfi` });
    assert.equal(r.isError, false, `${command}\n${r.text}`);
    assert.doesNotMatch(r.text, /tripwire/, command);
  }
});

test("T3 tripwire: confirm: true runs the command; both the refusal and the confirmation are in the audit log", async () => {
  const command = "false && reboot; echo ran-anyway";
  const no = await call("bash", { host: "local", command });
  assert.match(no.text, TRIPPED);
  const yes = await call("bash", { host: "local", command, confirm: true });
  assert.deepEqual([yes.isError, yes.text], [false, "ran-anyway\n"]);
  const [refused, confirmed] = auditEntries().filter((e) => e.what === command).slice(-2);
  assert.deepEqual([refused.ok, refused.tripwire, refused.exit ?? null], [false, "reboot stops or restarts the machine", null]);
  assert.match(refused.err, /^Refused by the tripwire/);
  assert.deepEqual([confirmed.ok, confirmed.confirmed, confirmed.exit], [true, "reboot stops or restarts the machine", 0]);
  assert.equal((await call("bash", { host: "local", command: "echo plain", confirm: true })).text, "plain\n"); // confirm on an ordinary command changes nothing
  const shown = (await call("audit", { contains: "ran-anyway", limit: 2 })).text.split("\n").slice(1); // and the audit tool says it in plain words
  assert.match(shown[0], /  bash  local  REFUSED by the tripwire: reboot stops or restarts the machine  0\.\d\ds  false && reboot; echo ran-anyway$/);
  assert.match(shown[1], /  bash  local  ok \(confirmed: reboot stops or restarts the machine\)  \d+\.\d\ds  false && reboot; echo ran-anyway$/);
});

test("T4 tripwire: every way of running a command is covered - ssh_exec, ssh_exec_many, ssh_spawn, exec_code, batch, the bridge and the box CLI", async () => {
  const d = P("tw-all"), marker = `${d}/must-not-exist`;
  mkdirSync(d);
  const bad = "false && shutdown -h now";
  assert.match((await call("ssh_exec", { host: "local", command: bad })).text, TRIPPED);
  assert.equal((await call("ssh_exec", { host: "local", command: `${bad}; echo exec-confirmed`, confirm: true })).text, "exit: 0\n--- stdout ---\nexec-confirmed\n\n--- stderr ---\n");

  const many = await call("ssh_exec_many", { host: "local", commands: [{ id: "one", command: `touch ${marker}` }, { id: "two", command: bad }] });
  assert.match(many.text, /^Error: Refused by the tripwire: \[two\] shutdown stops or restarts the machine\./);
  assert.equal(existsSync(marker), false, "none of the commands may run when one is refused");
  assert.match((await call("ssh_exec_many", { host: "local", confirm: true, commands: [{ id: "one", command: "echo many-confirmed" }, { id: "two", command: bad }] })).text, /=== \[one\] exit: 0 .*\n--- stdout ---\nmany-confirmed/);

  assert.match((await call("ssh_spawn", { host: "local", command: bad })).text, TRIPPED);
  const spawned = await call("ssh_spawn", { host: "local", command: `${bad}; echo spawn-confirmed`, confirm: true });
  assert.match((await job("local", field(spawned.text, "jobId"), "wait", { timeout_sec: 20 })).text, /spawn-confirmed/);

  assert.match((await call("exec_code", { host: "local", language: "bash", code: "if false; then\n  mkfs.ext4 /dev/sdz9\nfi\n" })).text, /^Error: Refused by the tripwire: mkfs\.ext4 formats \/dev\/sdz9\./);
  assert.match((await call("exec_code", { host: "local", language: "bash", code: "if false; then\n  mkfs.ext4 /dev/sdz9\nfi\necho code-confirmed\n", confirm: true })).text, /code-confirmed/);
  assert.match((await call("exec_code", { host: "local", language: "python", code: 'print("rm -rf / is only text here")' })).text, /rm -rf \/ is only text here/); // shell only

  const b = parseBatch((await call("batch", { host: "local", ops: [{ write: { file_path: `${d}/a.txt`, content: "x" } }, { bash: { command: "false && poweroff" } }, { bash: { command: `touch ${marker}` } }] })).text);
  assert.deepEqual(b.ops.map((o) => o.status), ["ok", "FAILED", "skipped"]);
  assert.match(b.ops[1].body, TRIPPED);
  assert.equal(existsSync(marker), false);
  const b2 = parseBatch((await call("batch", { host: "local", ops: [{ bash: { command: "false && poweroff; echo batch-confirmed", confirm: true } }] })).text);
  assert.deepEqual(b2.ops.map((o) => [o.status, o.body]), [["ok", "batch-confirmed\n"]]);

  const url = (await call("bridge", { ttl_hours: 1 })).text.match(/(http:\/\/\S+\/b\/[0-9a-z]+\.[0-9a-f]{32})/)[1];
  const post = (q, body) => fetch(`${url}/exec/local${q}`, { method: "POST", headers: { "Content-Type": "text/plain" }, body });
  const refused = await post("", "false && reboot");
  assert.equal(refused.status, 409);
  assert.match(await refused.text(), /^Refused by the tripwire: reboot stops or restarts the machine\. Nothing was run\..*confirm=1/);
  const went = await post("?confirm=1", "false && reboot; echo bridge-confirmed");
  assert.deepEqual([went.status, went.headers.get("x-exit-code"), await went.text()], [200, "0", "bridge-confirmed\n"]);

  const cli = P("box-tw");
  writeFileSync(cli, await (await fetch(`${url}/cli`)).text(), { mode: 0o755 });
  const run = promisify(execFile);
  const no = await run("bash", [cli, "exec", "--", "false && reboot"], { encoding: "utf8" }).catch((e) => e);
  assert.equal(no.code, 255);
  assert.match(no.stderr, /Refused by the tripwire.*box exec -y/s);
  assert.equal((await run("bash", [cli, "exec", "-y", "--", "false && reboot; echo cli-confirmed"], { encoding: "utf8" })).stdout, "cli-confirmed\n");
});

test("T5 TRIPWIRE=off: the server does not look at commands at all", async () => {
  const port = 18794, base = `http://127.0.0.1:${port}/mcp/${SECRET}`;
  await startServer(port, { JOBS_DIR: P("t5", "jobs"), TRIPWIRE: "off" });
  assert.equal((await call("bash", { host: "local", command: "false && reboot; echo tripwire-off" }, base)).text, "tripwire-off\n");
});

// ═════════════════════════ v1.5: add_host - connect another server without editing hosts.json by hand ═════════════════════════

test("H1 add_host: the first call creates the connector's key and says how to authorize it - nothing is added yet", async () => {
  const args = { name: "web-1", host: "127.0.0.1", port: sshd2.port, username: "deploy" };
  const r = await call("add_host", args);
  assert.equal(r.isError, false, r.text);
  assert.match(r.text, /^Not added yet: /);
  const pub = readFileSync(P("keys", "id_ed25519.pub"), "utf8").trim();
  assert.match(pub, /^ssh-ed25519 AAAA\S+ ssh-mcp@\S+$/);
  assert.ok(r.text.includes(pub), "the public key to authorize is shown");
  assert.match(r.text, /authorized_keys/);
  assert.ok(r.text.includes(sshd2.fp), "the fingerprint of the host key is shown, so it can be checked");
  assert.match(r.text, /ssh_host_ed25519_key\.pub/);
  assert.ok(r.text.includes(`fingerprint: "${sshd2.fp}"`), "the next call is told to pass the fingerprint it was shown");
  assert.equal("web-1" in JSON.parse(readFileSync(P("hosts.json"), "utf8")), false);
  assert.deepEqual([statSync(P("keys")).mode & 0o777, statSync(P("keys", "id_ed25519")).mode & 0o777], [0o700, 0o600]);
  assert.ok((await call("add_host", args)).text.includes(pub), "the same key every time");
});

test("H2 add_host: once the key is authorized the host is tested, its host key pinned, and it works at once", async () => {
  const before = readFileSync(P("hosts.json"), "utf8"), key = P("keys", "id_ed25519");
  appendFileSync(P("authorized_keys"), readFileSync(`${key}.pub`, "utf8"));
  const r = await call("add_host", { name: "web-1", host: "127.0.0.1", port: sshd2.port, username: "deploy" });
  assert.equal(r.isError, false, r.text);
  assert.match(r.text, new RegExp(`^Added host "web-1": deploy@127\\.0\\.0\\.1:${sshd2.port}\\n`));
  assert.ok(r.text.includes(sshd2.fp));
  assert.match(r.text, /logged in as \S+ on \S+/);
  const hosts = JSON.parse(readFileSync(P("hosts.json"), "utf8"));
  const { pq, pqWhy, ...entry } = hosts["web-1"];
  assert.deepEqual(entry, { host: "127.0.0.1", port: sshd2.port, username: "deploy", privateKeyPath: key, hostFingerprint: sshd2.fp });
  assert.equal(pq, false, "this test server has no post-quantum key exchange, and the entry says so"); // v1.6
  assert.match(pqWhy, /post-quantum/);
  assert.match(r.text, /^Key exchange: classical\. Post-quantum was not possible: /m);
  assert.deepEqual([hosts.local, hosts.remote], [JSON.parse(before).local, JSON.parse(before).remote], "the other hosts are untouched");
  assert.equal(statSync(P("hosts.json")).mode & 0o777, 0o600);
  assert.equal(readFileSync(P("hosts.json.bak"), "utf8"), before, "the previous file is kept as hosts.json.bak");
  assert.equal((await call("ssh_exec", { host: "web-1", command: "echo via-new-host" })).text, "exit: 0\n--- stdout ---\nvia-new-host\n\n--- stderr ---\n");
  assert.match((await call("list_hosts", {})).text, new RegExp(`^web-1: deploy@127\\.0\\.0\\.1:${sshd2.port} \\(classical key exchange: [^()]*post-quantum[^()]*(\\([^()]*\\))?[^()]*\\)$`, "m"));
});

test("H3 add_host: refuses what it should - an existing name, a host key that is not the expected one, a host it cannot reach", async () => {
  const at = { host: "127.0.0.1", port: sshd2.port, username: "deploy" };
  const names = () => Object.keys(JSON.parse(readFileSync(P("hosts.json"), "utf8")));
  const taken = await call("add_host", { name: "web-1", ...at });
  assert.deepEqual([taken.isError, /already exists.*replace: true/.test(taken.text)], [true, true], taken.text);
  assert.equal((await call("add_host", { name: "local", ...at })).isError, true);
  const replaced = await call("add_host", { name: "web-1", ...at, username: "other", replace: true });
  assert.match(replaced.text, /^Added host "web-1": other@/);
  assert.equal(JSON.parse(readFileSync(P("hosts.json"), "utf8"))["web-1"].username, "other");

  const offered = sshd2.stats.logins;
  const wrong = await call("add_host", { name: "web-2", ...at, fingerprint: `SHA256:${"A".repeat(43)}` });
  assert.equal(wrong.isError, true);
  assert.match(wrong.text, /does not match/);
  assert.equal(sshd2.stats.logins, offered, "no login is even tried against a server that presents another host key");
  assert.ok(wrong.text.includes(sshd2.fp), "it says which key the server presented");
  assert.ok(!names().includes("web-2"));
  assert.match((await call("add_host", { name: "web-2", ...at, fingerprint: sshd2.fp })).text, /^Added host "web-2"/);

  const dead = await call("add_host", { name: "web-3", host: "127.0.0.1", port: 1, username: "deploy" });
  assert.equal(dead.isError, true);
  assert.match(dead.text, /Cannot reach 127\.0\.0\.1:1/);
  assert.ok(!names().includes("web-3"));
  for (const bad of [{ name: "bad name!" }, { name: "ok", host: "bad host;rm" }, { name: "ok", username: "bad user" }, { name: "ok", port: 70000 }])
    assert.equal((await call("add_host", { name: "x", ...at, ...bad })).isError, true, JSON.stringify(bad));
  assert.deepEqual(names(), ["local", "remote", "web-1", "web-2"]);
});

test("H4 add_host: its calls are in the audit log, and the private key never leaves the key file", async () => {
  const es = auditEntries().filter((e) => e.tool === "add_host" && e.what?.startsWith("web-"));
  assert.ok(es.length >= 6);
  assert.equal(es[0].what, `web-1 = deploy@127.0.0.1:${sshd2.port}`);
  assert.deepEqual([es[0].ok, es[0].added], [true, false]);
  assert.ok(es.some((e) => e.added === true && e.what.startsWith("web-1 = deploy@")));
  assert.ok(es.some((e) => e.ok === false && e.what.startsWith("web-3 = ")));
  const shown = (await call("audit", { contains: "add_host", limit: 100 })).text;
  assert.match(shown, /  add_host  -  ok \(not added yet\)  \d+\.\d\ds  web-1 = deploy@/);
  assert.match(shown, /  add_host  -  ok \(added\)  \d+\.\d\ds  web-1 = deploy@/);
  const body = readFileSync(P("keys", "id_ed25519"), "utf8").split("\n").filter((l) => l && !l.startsWith("-----"));
  const everything = readFileSync(AUDIT_FILE, "utf8") + (await call("add_host", { name: "web-9", host: "127.0.0.1", port: sshd2.port, username: "deploy", fingerprint: "SHA256:nope" })).text + (await call("audit", { contains: "add_host", limit: 100 })).text;
  for (const l of body) assert.ok(!everything.includes(l), "a line of the private key leaked");
});

test("H5 add_host: the pinned host key is enforced - if another server answers at that address, nothing is run on it", async () => {
  const file = P("hosts.json"), before = readFileSync(file, "utf8"), hosts = JSON.parse(before);
  hosts["web-moved"] = { ...hosts["web-2"], port: sshd.port }; // same pin, but behind the address there is now a server with another host key
  writeFileSync(file, JSON.stringify(hosts, null, 2));
  try {
    const marker = P("h5-must-not-exist");
    for (const [name, args] of [["ssh_exec", { command: `touch ${marker}` }], ["bash", { command: `touch ${marker}` }], ["sftp_list", { path: "/" }]]) {
      const r = await call(name, { host: "web-moved", ...args });
      assert.equal(r.isError, true, `${name}: ${r.text}`);
      assert.match(r.text, /verification failed/i, name);
    }
    assert.equal(existsSync(marker), false);
    assert.match((await call("ssh_exec", { host: "web-2", command: "echo pinned-ok" })).text, /pinned-ok/); // the right server still works
  } finally { writeFileSync(file, before); }
});

test("H6 add_host: a connector key that cannot be read is set aside and a new one made - the generator's bad keys never reach a server", async () => {
  const port = 18795, base = `http://127.0.0.1:${port}/mcp/${SECRET}`, dir = P("h6", "keys");
  const bad = unreadableKeyPair(); // what about 1 install in 256 would have got from the key generator
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, "id_ed25519"), bad.private, { mode: 0o600 });
  writeFileSync(path.join(dir, "id_ed25519.pub"), bad.public + "\n");
  writeFileSync(P("h6", "hosts.json"), JSON.stringify({ local: { local: true } }));
  await startServer(port, { JOBS_DIR: P("h6", "jobs"), HOSTS_FILE: P("h6", "hosts.json") });
  const at = { name: "h6", host: "127.0.0.1", port: sshd2.port, username: "deploy" };

  const first = await call("add_host", at, base);
  assert.equal(first.isError, false, first.text);
  assert.match(first.text, /^Not added yet: /);
  const key = utils.parseKey(readFileSync(path.join(dir, "id_ed25519")));
  assert.ok(!(key instanceof Error), "the key in use can be read");
  const line = readFileSync(path.join(dir, "id_ed25519.pub"), "utf8").trim();
  assert.equal(Buffer.from(line.split(" ")[1], "base64").length, 51, "its public key is a whole ed25519 key (32 bytes)");
  assert.ok(Buffer.from(line.split(" ")[1], "base64").equals(key.getPublicSSH()), "the .pub line belongs to the private key");
  assert.ok(first.text.includes(line) && !first.text.includes(bad.public.split(" ")[1]), "the line shown to the user is the new key, not the unreadable one");
  const aside = readdirSync(dir).filter((f) => f.startsWith("id_ed25519.unusable-")).sort();
  assert.equal(aside.length, 2, `the old pair is kept aside, not deleted: ${readdirSync(dir)}`);
  assert.equal(readFileSync(path.join(dir, aside[0]), "utf8"), bad.private);

  appendFileSync(P("authorized_keys"), line + "\n");
  assert.match((await call("add_host", { ...at, fingerprint: sshd2.fp }, base)).text, /^Added host "h6": deploy@/);
  assert.match((await call("ssh_exec", { host: "h6", command: "echo with-the-new-key" }, base)).text, /with-the-new-key/);
  assert.deepEqual(readdirSync(dir).filter((f) => f.startsWith("id_ed25519.unusable-")).sort(), aside, "a good key is left alone on later calls");
});

// ═════════════════════════ v1.6: post-quantum key exchange for remote hosts ═════════════════════════
// The SSH library the connector uses has no post-quantum key exchange; the system's OpenSSH has. For a host
// marked "pq": true the connection that crosses the network is made by OpenSSH (post-quantum key exchange only,
// host key pinned) and does nothing but carry bytes to that server's own SSH port; the library's connection
// runs inside it. These tests use a real sshd, because its log is the evidence for what was on the wire: hosts
// are added by the address 127.0.0.2, the inner connection arrives on 127.0.0.1.
const SSHD_BIN = ["/usr/sbin/sshd", "/usr/local/sbin/sshd", "/usr/bin/sshd", "/opt/homebrew/sbin/sshd"].find((f) => existsSync(f));
const PQ_NAMES = ["mlkem768x25519-sha256", "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com"];
const PQ_HERE = (() => { try { return execFileSync("ssh", ["-Q", "kex"], { stdio: ["ignore", "pipe", "ignore"] }).toString().split("\n").filter((k) => PQ_NAMES.includes(k)); } catch { return []; } })();
const NO_REAL = !SSHD_BIN ? "no sshd on this machine" : !PQ_HERE.length ? "the OpenSSH client on this machine has no post-quantum key exchange" : false;
const ME = userInfo().username;
const freePort = () => new Promise((res) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const port = s.address().port; s.close(() => res(port)); }); });
const realSshds = [];
let realA, realB;
async function realSshd(options = {}) {
  const dir = mkdtempSync(path.join(TMP, "sshd-")), port = await freePort(), keys = { a: keyPair(), b: keyPair() };
  for (const [n, k] of Object.entries(keys)) writeFileSync(path.join(dir, `host-${n}`), k.private, { mode: 0o600 });
  const fpOf = (k) => "SHA256:" + createHash("sha256").update(utils.parseKey(k.private).getPublicSSH()).digest("base64").replace(/=+$/, "");
  const s = { dir, port, fp: fpOf(keys.a), authorized: path.join(dir, "authorized_keys"), log: path.join(dir, "sshd.log"), proc: null };
  writeFileSync(s.authorized, "");
  writeFileSync(s.log, "");
  if (process.getuid?.() === 0) mkdirSync("/run/sshd", { recursive: true }); // sshd wants this directory when it runs as root
  s.stop = async () => { const p = s.proc; if (!p) return; s.proc = null; const gone = new Promise((r) => p.once("exit", r)); p.kill("SIGTERM"); await gone; };
  // (re)start it, on the same port: kex = the only key exchange it offers, forwarding = AllowTcpForwarding, hostKey = which of its
  // two host keys, listen = the addresses it listens on
  s.start = async ({ kex, forwarding = true, hostKey = "a", listen = ["127.0.0.1", "127.0.0.2"] } = {}) => {
    await s.stop();
    writeFileSync(path.join(dir, "sshd_config"), [`Port ${port}`, ...listen.map((a) => `ListenAddress ${a}`), `HostKey ${path.join(dir, `host-${hostKey}`)}`, "PidFile none",
      `AuthorizedKeysFile ${s.authorized}`, "StrictModes no", "UsePAM no", "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PermitRootLogin yes", "LogLevel DEBUG1",
      "Subsystem sftp internal-sftp", `AllowTcpForwarding ${forwarding ? "yes" : "no"}`, ...(kex ? [`KexAlgorithms ${kex}`] : []), ""].join("\n"));
    const from = s.mark(), fd = openSync(s.log, "a");
    s.proc = spawn(SSHD_BIN, ["-D", "-e", "-f", path.join(dir, "sshd_config")], { stdio: ["ignore", fd, fd] });
    closeSync(fd);
    for (let i = 0; i < 100; i++) { if ((s.since(from).match(/Server listening on/g) ?? []).length >= listen.length) return s; await sleep(50); }
    throw new Error(`sshd did not start:\n${s.since(from)}`);
  };
  s.mark = () => statSync(s.log).size;                            // a place in its log ...
  s.since = (mark) => readFileSync(s.log).subarray(mark).toString(); // ... and what it logged after that
  realSshds.push(s);
  return s.start(options);
}
// What the server saw, one entry per connection in the order they came: the address it arrived on, the key
// exchange it negotiated, whether a login was accepted on it, and whether it is one the server opened to itself
// for a forwarding request (inner). (Only for calls made one after the other.)
function wire(log) {
  const seen = [];
  let forwarding = false;
  for (const line of log.split("\n")) {
    if (/server_request_direct_tcpip/.test(line)) { forwarding = true; continue; }
    const c = /^Connection from \S+ port \d+ on (\S+) port \d+/.exec(line);
    if (c) { seen.push({ on: c[1], kex: null, login: false, tried: false, inner: forwarding }); forwarding = false; continue; }
    const cur = seen[seen.length - 1];
    if (!cur) continue;
    const k = /kex: algorithm: (\S+)/.exec(line);
    if (k && !cur.kex) cur.kex = k[1];
    if (/^(Accepted|Failed|Postponed) publickey| userauth-request for user /.test(line)) cur.tried = true; // a login was at least attempted
    if (/^Accepted publickey/.test(line)) cur.login = true;
  }
  return seen;
}
const isPq = (kex) => PQ_NAMES.includes(kex);
const count = (text, re) => (text.match(re) ?? []).length;

test("K1 add_host to a real OpenSSH server: the login, and everything after it, travels inside a post-quantum connection", { skip: NO_REAL }, async () => {
  realA = await realSshd();
  const at = { name: "pq-1", host: "127.0.0.2", port: realA.port, username: ME };
  const first = await call("add_host", at);
  assert.match(first.text, /^Not added yet: /, first.text);
  assert.ok(first.text.includes(realA.fp), "the host key it must check is shown");
  // already now: the one login that was tried (and refused, the key is not known there yet) went over a post-quantum key exchange
  const tries = wire(realA.since(0)).filter((c) => c.tried);
  assert.ok(tries.length >= 1 && tries.every((c) => isPq(c.kex) && !c.login), JSON.stringify(wire(realA.since(0))));
  appendFileSync(realA.authorized, readFileSync(P("keys", "id_ed25519.pub"), "utf8"));

  const mark = realA.mark();
  const r = await call("add_host", { ...at, fingerprint: realA.fp });
  assert.equal(r.isError, false, r.text);
  assert.match(r.text, /^Added host "pq-1": /);
  const kex = (/^Key exchange: (\S+) \(post-quantum\)/m.exec(r.text) ?? [])[1];
  assert.ok(PQ_HERE.includes(kex), `the result names the key exchange that was negotiated: ${r.text}`);
  assert.match(r.text, new RegExp(`logged in as ${ME} on \\S+`));
  assert.deepEqual(JSON.parse(readFileSync(P("hosts.json"), "utf8"))["pq-1"],
    { host: "127.0.0.2", port: realA.port, username: ME, privateKeyPath: P("keys", "id_ed25519"), hostFingerprint: realA.fp, pq: true });
  assert.match((await call("list_hosts", {})).text, new RegExp(`^pq-1: ${ME}@127\\.0\\.0\\.2:${realA.port} \\(post-quantum key exchange\\)$`, "m"));
  assert.equal((await call("bash", { host: "pq-1", command: "echo through-pq; id -un" })).text, `through-pq\n${ME}\n`);

  // the server's own account of it
  const seen = wire(realA.since(mark)), outside = seen.filter((c) => c.on === "127.0.0.2"), inside = seen.filter((c) => c.on === "127.0.0.1");
  assert.ok(outside.filter((c) => c.login).length >= 2, `logins from outside: ${JSON.stringify(seen)}`);
  assert.deepEqual(outside.filter((c) => c.login && !isPq(c.kex)), [], "no login from outside over a classical key exchange - not even add_host's own test");
  assert.ok(outside.filter((c) => c.login).every((c) => c.kex === kex), "the key exchange add_host reported is the one the server used");
  assert.ok(inside.length >= 2 && inside.every((c) => c.inner && c.login && !isPq(c.kex)), "the library's own connection is one the server opened to its own loopback address, inside the outer one");
});

test("K2 every kind of call works through it - commands, files, parallel commands, jobs, batches, the bridge - and all of it is post-quantum on the wire", { skip: NO_REAL }, async () => {
  const host = "pq-1", d = P("k2"), f = path.join(d, "f.txt"), mark = realA.mark();
  mkdirSync(d);
  assert.match((await call("bash", { host, command: `cd ${d} && echo in-session`, session: "k2" })).text, /in-session/);
  assert.match((await call("bash", { host, command: "pwd", session: "k2" })).text, new RegExp(`^${d}$`, "m"));
  // (this sshd logs at debug level to its stderr, and a few of those lines end up in a session's stderr - a real one logs to syslog)
  assert.match((await call("ssh_exec", { host, command: "echo out; echo err >&2; exit 3" })).text, /^exit: 3\n--- stdout ---\nout\n\n--- stderr ---\n(debug1: [^\n]*\n)*err\n$/);

  assert.equal((await call("write", { host, file_path: f, content: "alpha\nbeta\n" })).isError, false);
  assert.match((await call("read", { host, file_path: f })).text, /alpha[\s\S]*beta/);
  assert.equal((await call("edit", { host, file_path: f, old_string: "beta", new_string: "gamma" })).isError, false);
  assert.equal(readFileSync(f, "utf8"), "alpha\ngamma\n");
  const g = path.join(d, "g.txt");
  assert.equal((await call("sftp_write", { host, path: g, content: "héllo\n", mode: "0640" })).text, `Wrote 7 bytes to ${host}:${g}`);
  assert.equal((await call("sftp_read", { host, path: g })).text, "héllo\n");
  assert.match((await call("sftp_list", { host, path: d })).text, /g\.txt/);

  const many = await call("ssh_exec_many", { host, commands: [1, 2, 3, 4, 5, 6, 7, 8].map((n) => ({ id: `c${n}`, command: `echo par-${n}` })) });
  for (let n = 1; n <= 8; n++) assert.match(many.text, new RegExp(`par-${n}\\b`), many.text);
  const { jobId } = await spawnJob(host, "sleep 0.3; echo job-done");
  const waited = await job(host, jobId, "wait", { timeout_sec: 20 });
  assert.match(waited.text, /^state: exited$/m, waited.text);
  assert.match(waited.text, /job-done/);
  const b = await call("batch", { host, ops: [{ write: { file_path: path.join(d, "b.txt"), content: "from-batch\n" } }, { bash: { command: `cat ${path.join(d, "b.txt")}` } }] });
  assert.match(b.text, /from-batch[\s\S]*batch: 2 ok, 0 failed, 0 skipped/, b.text);

  // the bridge: 3 MB of random bytes there and back, and a command with a lot of output
  const br = BR ?? (await call("bridge", { ttl_hours: 1 })).text.match(/(http:\/\/127\.0\.0\.1:\d+\/b\/[0-9a-z]+\.[0-9a-f]{32})\/cli/)[1];
  const data = randomBytes(3 * 1024 * 1024), remote = path.join(d, "blob.bin");
  const put = await fetch(`${br}/fs/${host}?p64=${p64(remote)}`, { method: "PUT", headers: { "Content-Type": "application/octet-stream" }, body: data });
  assert.equal(put.status, 200, await put.text());
  const got = Buffer.from(await (await fetch(`${br}/fs/${host}?p64=${p64(remote)}`)).arrayBuffer());
  assert.equal(createHash("sha256").update(got).digest("hex"), createHash("sha256").update(data).digest("hex"), "3 MB came back unchanged");
  const big = await fetch(`${br}/exec/${host}`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "head -c 2000000 /dev/zero | tr '\\0' k; exit 5" });
  assert.deepEqual([big.status, big.headers.get("x-exit-code"), (await big.text()).length], [200, "5", 2000000]);
  const slow = await call("bash", { host, command: "echo started; sleep 30", timeout: 2000 });
  assert.match(slow.text, /started/);
  assert.match(slow.text, /timed out|timeout/i, slow.text);

  await sleep(300); // the last connections are logged as they close
  const log = realA.since(mark), outside = count(log, /^Connection from \S+ port \d+ on 127\.0\.0\.2 port/gm), inside = count(log, /^Connection from \S+ port \d+ on 127\.0\.0\.1 port/gm);
  const pq = count(log, new RegExp(`kex: algorithm: (${PQ_NAMES.map((n) => n.replace(/[.]/g, "\\.")).join("|")}) `, "g")), all = count(log, /kex: algorithm: \S+ /g);
  assert.ok(outside >= 15, `connections from outside: ${outside}`);
  assert.equal(pq, outside, "every connection that came in from outside negotiated a post-quantum key exchange");
  assert.equal(all - pq, inside, "the only classical key exchanges are the inner connections, on the server's own loopback address");
});

test("K3 the host key is pinned on the outer connection too: another server at that address gets no login and runs nothing", { skip: NO_REAL }, async () => {
  await realA.start({ hostKey: "b" });
  const mark = realA.mark(), marker = P("k3-must-not-exist");
  try {
    for (const [name, args] of [["bash", { command: `touch ${marker}` }], ["ssh_exec", { command: `touch ${marker}` }], ["sftp_list", { path: "/" }]]) {
      const r = await call(name, { host: "pq-1", ...args });
      assert.equal(r.isError, true, `${name}: ${r.text}`);
      assert.match(r.text, /host key/i, name);
    }
    assert.equal(existsSync(marker), false);
    assert.deepEqual(wire(realA.since(mark)).filter((c) => c.login), [], "no login was accepted");
  } finally { await realA.start(); }
  assert.equal((await call("bash", { host: "pq-1", command: "echo back" })).text, "back\n");
});

test("K4 no silent downgrade: when post-quantum key exchange stops being possible, calls fail and say so - until the owner changes the host on purpose", { skip: NO_REAL }, async () => {
  const file = P("hosts.json"), before = readFileSync(file, "utf8"), marker = P("k4-must-not-exist");
  try {
    await realA.start({ kex: "curve25519-sha256" }); // e.g. the server was reinstalled with an older or stripped-down SSH
    let mark = realA.mark();
    const r = await call("bash", { host: "pq-1", command: `touch ${marker}` });
    assert.equal(r.isError, true, r.text);
    assert.match(r.text, /post-quantum/i);
    assert.match(r.text, /Nothing was run/);
    assert.match(r.text, /"pq": false/, "it says how to make the host a classical one on purpose");
    assert.deepEqual(wire(realA.since(mark)).filter((c) => c.login), [], "no login, classical or otherwise");

    await realA.start({ forwarding: false });
    const f = await call("ssh_exec", { host: "pq-1", command: `touch ${marker}` });
    assert.equal(f.isError, true, f.text);
    assert.match(f.text, /forwarding/i);
    assert.match(f.text, /Nothing was run/);
    assert.equal(existsSync(marker), false);

    const hosts = JSON.parse(before);
    hosts["pq-1"].pq = false;
    writeFileSync(file, JSON.stringify(hosts, null, 2));
    mark = realA.mark();
    assert.equal((await call("bash", { host: "pq-1", command: "echo classical-now" })).text, "classical-now\n");
    assert.ok(wire(realA.since(mark)).some((c) => c.on === "127.0.0.2" && c.login && !isPq(c.kex)), "now the login is over a classical key exchange, as asked");
    assert.match((await call("list_hosts", {})).text, new RegExp(`^pq-1: ${ME}@127\\.0\\.0\\.2:${realA.port} \\(classical key exchange\\)$`, "m"));
  } finally { writeFileSync(file, before); await realA.start(); }
  assert.equal((await call("bash", { host: "pq-1", command: "echo pq-again" })).text, "pq-again\n");
});

test("K5 add_host says plainly when post-quantum is not possible, and why; the host is then added as a classical one", { skip: NO_REAL }, async () => {
  realB = await realSshd({ kex: "curve25519-sha256" });
  appendFileSync(realB.authorized, readFileSync(P("keys", "id_ed25519.pub"), "utf8"));
  const at = { host: "127.0.0.2", port: realB.port, username: ME, fingerprint: realB.fp };
  const saved = (name) => JSON.parse(readFileSync(P("hosts.json"), "utf8"))[name];

  const old = await call("add_host", { name: "old-ssh", ...at });
  assert.match(old.text, /^Added host "old-ssh": /, old.text);
  assert.match(old.text, /^Key exchange: classical\. Post-quantum was not possible: .*no post-quantum key exchange/m);
  assert.equal(saved("old-ssh").pq, false);
  assert.match(saved("old-ssh").pqWhy, /no post-quantum key exchange/);
  assert.equal((await call("bash", { host: "old-ssh", command: "echo ok-classical" })).text, "ok-classical\n");
  assert.match((await call("list_hosts", {})).text, /^old-ssh: \S+ \(classical key exchange: .*no post-quantum key exchange.*\)$/m);

  await realB.start({ forwarding: false });
  const nofwd = await call("add_host", { name: "no-fwd", ...at });
  assert.match(nofwd.text, /^Key exchange: classical\. Post-quantum was not possible: .*forwarding/m, nofwd.text);
  assert.equal(saved("no-fwd").pq, false);

  await realB.start(); // once the server allows it, adding the host again makes it post-quantum
  const again = await call("add_host", { name: "no-fwd", ...at, replace: true });
  assert.match(again.text, /^Key exchange: \S+ \(post-quantum\)/m, again.text);
  assert.deepEqual([saved("no-fwd").pq, "pqWhy" in saved("no-fwd")], [true, false]);
  assert.equal((await call("bash", { host: "no-fwd", command: "echo now-pq" })).text, "now-pq\n");
});

test("K6 PQ_SSH=require refuses every remote host that is not post-quantum; PQ_SSH=off turns the feature off", { skip: NO_REAL }, async () => {
  const hosts = JSON.parse(readFileSync(P("hosts.json"), "utf8")), file = P("k6-hosts.json");
  writeFileSync(file, JSON.stringify({ local: hosts.local, remote: hosts.remote, "pq-1": hosts["pq-1"], "old-ssh": hosts["old-ssh"] }));
  const strict = `http://127.0.0.1:18796/mcp/${SECRET}`, off = `http://127.0.0.1:18797/mcp/${SECRET}`;
  await startServer(18796, { HOSTS_FILE: file, PQ_SSH: "require" });
  await startServer(18797, { HOSTS_FILE: file, PQ_SSH: "off" });

  assert.equal((await call("bash", { host: "pq-1", command: "echo strict-ok" }, strict)).text, "strict-ok\n"); // a new process: it finds the pinned host key by itself
  assert.match((await call("bash", { host: "local", command: "echo local-ok" }, strict)).text, /local-ok/);
  await realB.start({ kex: "curve25519-sha256" });
  for (const h of ["remote", "old-ssh"]) {
    const r = await call("ssh_exec", { host: h, command: "true" }, strict);
    assert.equal(r.isError, true, `${h}: ${r.text}`);
    assert.match(r.text, /PQ_SSH=require/, h);
  }
  const no = await call("add_host", { name: "strict-no", host: "127.0.0.2", port: realB.port, username: ME, fingerprint: realB.fp }, strict);
  assert.equal(no.isError, true, no.text);
  assert.match(no.text, /PQ_SSH=require/);
  assert.match(no.text, /Nothing was added/);
  assert.equal("strict-no" in JSON.parse(readFileSync(file, "utf8")), false);

  const mark = realA.mark();
  assert.equal((await call("bash", { host: "pq-1", command: "echo off-ok" }, off)).text, "off-ok\n");
  assert.ok(wire(realA.since(mark)).some((c) => c.on === "127.0.0.2" && c.login && !isPq(c.kex)), "with PQ_SSH=off the connection is the plain one");
  assert.match((await call("list_hosts", {}, off)).text, /^pq-1: \S+ \(classical key exchange: PQ_SSH=off\)$/m);
  await realB.start();
  const added = await call("add_host", { name: "off-add", host: "127.0.0.2", port: realB.port, username: ME, fingerprint: realB.fp }, off);
  assert.match(added.text, /^Key exchange: classical\. .*PQ_SSH=off/m, added.text);
  assert.equal("pq" in JSON.parse(readFileSync(file, "utf8"))["off-add"], false, "nothing is decided about the host while the feature is off");
});

test("K7 a host written into hosts.json by hand becomes post-quantum with \"pq\": true - given a pinned host key and a key file without a passphrase", { skip: NO_REAL }, async () => {
  const file = P("hosts.json"), before = readFileSync(file, "utf8"), hosts = JSON.parse(before);
  const base = { host: "127.0.0.2", port: realA.port, username: ME, privateKeyPath: P("keys", "id_ed25519"), pq: true };
  hosts["by-hand"] = { ...base, hostFingerprint: realA.fp };
  hosts["no-pin"] = base;
  hosts["with-pass"] = { ...base, hostFingerprint: realA.fp, passphraseEnv: "SOME_PASSPHRASE" };
  writeFileSync(file, JSON.stringify(hosts, null, 2));
  try {
    const mark = realA.mark();
    assert.equal((await call("bash", { host: "by-hand", command: "echo by-hand-ok" })).text, "by-hand-ok\n");
    const seen = wire(realA.since(mark)).filter((c) => c.on === "127.0.0.2" && c.login);
    assert.ok(seen.length === 1 && isPq(seen[0].kex), JSON.stringify(seen));
    const pin = await call("bash", { host: "no-pin", command: "true" });
    assert.deepEqual([pin.isError, /hostFingerprint/.test(pin.text)], [true, true], pin.text);
    const pass = await call("bash", { host: "with-pass", command: "true" });
    assert.deepEqual([pass.isError, /passphrase/.test(pass.text)], [true, true], pass.text);
  } finally { writeFileSync(file, before); }
});

test("K8 where the server's own SSH is not at its loopback address and that port - a port mapping, an SSH server bound to one address - add_host asks the server", { skip: NO_REAL }, async () => {
  const saved = (name) => JSON.parse(readFileSync(P("hosts.json"), "utf8"))[name];
  // a "router": port q on 127.0.0.2 leads to the SSH server, which itself listens on another port
  await realB.start();
  const router = net.createServer((a) => { const b = net.connect(realB.port, "127.0.0.1"); a.pipe(b); b.pipe(a); a.on("error", () => b.destroy()); b.on("error", () => a.destroy()); });
  await new Promise((res) => router.listen(0, "127.0.0.2", res));
  const q = router.address().port;
  try {
    const r = await call("add_host", { name: "mapped", host: "127.0.0.2", port: q, username: ME, fingerprint: realB.fp });
    assert.match(r.text, /^Key exchange: \S+ \(post-quantum\)/m, r.text);
    assert.deepEqual([saved("mapped").pq, saved("mapped").port, saved("mapped").pqVia], [true, q, `127.0.0.1:${realB.port}`]);
    assert.equal((await call("bash", { host: "mapped", command: "echo through-the-mapping" })).text, "through-the-mapping\n");
  } finally { router.close(); }

  // an SSH server that does not listen on the loopback address at all
  await realB.start({ listen: ["127.0.0.2"] });
  const mark = realB.mark();
  const one = await call("add_host", { name: "one-address", host: "127.0.0.2", port: realB.port, username: ME, fingerprint: realB.fp });
  assert.match(one.text, /^Key exchange: \S+ \(post-quantum\)/m, one.text);
  assert.deepEqual([saved("one-address").pq, saved("one-address").pqVia], [true, `127.0.0.2:${realB.port}`]);
  assert.equal((await call("bash", { host: "one-address", command: "echo one-address-ok" })).text, "one-address-ok\n");
  const seen = wire(realB.since(mark));
  assert.ok(seen.filter((c) => c.login && isPq(c.kex) && !c.inner).length >= 2, JSON.stringify(seen));
  assert.deepEqual(seen.filter((c) => c.login && !isPq(c.kex) && !c.inner), [], "still no login from outside over a classical key exchange");
  await realB.start();
});

test("K9 the audit log records the key exchange of each call, and no helper process is left behind", { skip: NO_REAL }, async () => {
  const es = auditEntries().filter((e) => e.host === "pq-1" && e.done);
  const through = es.find((e) => e.what === "echo through-pq; id -un");
  assert.ok(through && PQ_HERE.includes(through.kex), JSON.stringify(through));
  assert.equal(es.find((e) => e.what === "echo classical-now").kex, undefined, "a classical call has no such mark");
  assert.ok(es.filter((e) => e.ok && e.kex).length >= 10);
  const shown = (await call("audit", { contains: "through-pq", limit: 5 })).text;
  assert.match(shown, /  bash  pq-1 \(pq\)  ok  /, shown);
  let left = "";
  for (let i = 0; i < 50; i++) { left = pgrep("HostKeyAlias=sshmcp-"); if (!left) break; await sleep(100); }
  assert.equal(left, "", "OpenSSH helper processes still running");
});
