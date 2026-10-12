import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const envText = fs.readFileSync(path.join(repoRoot, ".env"), "utf8");
const config = new Map(
  envText.split(/\r?\n/).filter((line) => line && !line.trimStart().startsWith("#"))
    .map((line) => {
      const separator = line.indexOf("=");
      return separator > 0 ? [line.slice(0, separator).trim(), line.slice(separator + 1)] : ["", ""];
    })
    .filter(([key]) => key),
);

const origin = new URL(config.get("ORIGIN_URL") ?? "");
const listen = config.get("LISTEN_ADDR") ?? "127.0.0.1:8080";
if (origin.hostname !== "127.0.0.1" || origin.port !== "3001" || listen !== "127.0.0.1:8080") {
  throw new Error("Local verification refused: expected ORIGIN_URL=http://127.0.0.1:3001 and LISTEN_ADDR=127.0.0.1:8080.");
}

function request(base, requestPath, method = "GET") {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: base.hostname,
      port: base.port,
      path: requestPath,
      method,
      timeout: 8_000,
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks),
      }));
    });
    req.on("timeout", () => req.destroy(new Error("request timed out")));
    req.on("error", reject);
    req.end();
  });
}

const gallery = [
  { name: "homepage", path: "/", status: 200, contains: "Cat Break" },
  { name: "stylesheet", path: "/style.css", status: 200, type: "text/css" },
  { name: "gallery image", path: "/assets/cat-bowl.png", status: 200, type: "image/png" },
  { name: "HEAD image response", path: "/assets/cat-bowl.png", method: "HEAD", status: 200, empty: true },
  { name: "server source is private", path: "/server.js", status: 404 },
  { name: "project README is private", path: "/README.md", status: 404 },
  { name: "traversal is rejected", path: "/%2e%2e/README.md", status: 404 },
  { name: "unsupported method is rejected", path: "/", method: "POST", status: 405, allow: "GET, HEAD" },
];

const attacks = [
  { name: "encoded traversal filtered", path: "/%2e%2e/README.md", status: 403 },
  { name: "SQL injection filtered", path: "/?id=1%20UNION%20SELECT%20NULL--", status: 403 },
  { name: "script injection filtered", path: "/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", status: 403 },
];

let failures = 0;
async function check(base, test, gateway = false) {
  try {
    const result = await request(base, test.path, test.method);
    let passed = result.status === test.status;
    if (passed && test.contains) passed = result.body.toString("utf8").includes(test.contains);
    if (passed && test.type) passed = String(result.headers["content-type"] ?? "").startsWith(test.type);
    if (passed && test.empty) passed = result.body.length === 0 && Number(result.headers["content-length"]) > 0;
    if (passed && test.allow) passed = String(result.headers.allow ?? "").includes(test.allow);
    if (passed && gateway && test.path === "/") {
      passed = String(result.headers["x-content-type-options"] ?? "").split(",").some((value) => value.trim() === "nosniff") &&
        result.headers["x-frame-options"] === "DENY" &&
        String(result.headers["content-security-policy"] ?? "").includes("script-src 'none'");
    }
    if (!passed) failures++;
    process.stdout.write(`${passed ? "PASS" : "FAIL"} ${gateway ? "gateway" : "origin"}: ${test.name} (HTTP ${result.status})\n`);
  } catch (error) {
    failures++;
    process.stdout.write(`FAIL ${gateway ? "gateway" : "origin"}: ${test.name} (${error.message})\n`);
  }
}

for (const test of gallery) await check(origin, test);
await check(origin, { name: "origin does not reflect SQL input", path: "/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", status: 200, contains: "Cat Break" });
const gateway = new URL("http://127.0.0.1:8080");
await check(gateway, { name: "protected homepage and security headers", path: "/", status: 200, contains: "Cat Break" }, true);
await check(gateway, { name: "protected image", path: "/assets/cat-bowl.png", status: 200, type: "image/png" }, true);
for (const test of attacks) await check(gateway, test, true);

if (failures) {
  process.stderr.write(`${failures} protected-site check(s) failed.\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("All local protected-site checks passed.\n");
}
