// Print the tools/list result of an MCP endpoint as stable JSON (sorted by tool name).
// Usage: node test/snapshot.mjs http://127.0.0.1:8787/mcp/<secret> [name,name,...]
const [url, only] = process.argv.slice(2);
const res = await fetch(url, {
  method: "POST",
  headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
});
const body = await res.text();
const json = (res.headers.get("content-type") ?? "").includes("text/event-stream")
  ? JSON.parse(body.split("\n").filter((l) => l.startsWith("data: ")).pop().slice(6))
  : JSON.parse(body);
let tools = json.result.tools.sort((a, b) => a.name.localeCompare(b.name));
if (only) tools = tools.filter((t) => only.split(",").includes(t.name));
console.log(JSON.stringify(tools, null, 2));
