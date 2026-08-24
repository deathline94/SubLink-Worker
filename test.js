import test from "node:test";
import assert from "node:assert/strict";

import { __SUBLINK_WORKER_TESTS__ } from "./Worker.js";

const {
  handleRequest,
  validateSubscriptionContent,
  createPasswordRecord,
  verifyPasswordEntry,
  loadPasswordEntry,
  constantTimeEqual,
  escapeHtml,
  sha256Hex,
  normalizePath,
  SESSION_COOKIE,
} = __SUBLINK_WORKER_TESTS__;

const ORIGIN = "https://worker.test";
const PASSWORD = "correct-horse-battery";
const IP = "203.0.113.10";

class MemoryKV {
  constructor() {
    this.map = new Map();
    this.putCounts = new Map();
  }
  async get(key) {
    const value = this.map.get(key);
    return value === undefined ? null : value;
  }
  async put(key, value) {
    this.map.set(key, value);
    this.putCounts.set(key, (this.putCounts.get(key) || 0) + 1);
  }
  async delete(key) {
    this.map.delete(key);
  }
  async list({ prefix = "" } = {}) {
    const keys = [...this.map.keys()]
      .filter((name) => name.startsWith(prefix))
      .sort()
      .map((name) => ({ name }));
    return { keys, list_complete: true };
  }
}

function makeEnv(kv, overrides = {}) {
  return { sub: kv, AUTH_SECRET: "unit-test-pepper-value", ...overrides };
}

function postForm(path, fields, { headers = {}, cookie } = {}) {
  const allHeaders = { "CF-Connecting-IP": IP, ...headers };
  if (cookie) allHeaders.cookie = cookie;
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    body: new URLSearchParams(fields),
    headers: allHeaders,
  });
}

function postJson(path, payload, { headers = {}, cookie } = {}) {
  const allHeaders = {
    "CF-Connecting-IP": IP,
    "content-type": "application/json",
    ...headers,
  };
  if (cookie) allHeaders.cookie = cookie;
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    body: JSON.stringify(payload),
    headers: allHeaders,
  });
}

function getRequest(path, { headers = {}, cookie } = {}) {
  const allHeaders = { "CF-Connecting-IP": IP, ...headers };
  if (cookie) allHeaders.cookie = cookie;
  return new Request(`${ORIGIN}${path}`, { headers: allHeaders });
}

async function setupAdmin(kv, password = PASSWORD, overrides = {}) {
  const res = await handleRequest(
    postForm("/admin/setup", { password }),
    makeEnv(kv, overrides)
  );
  assert.equal(res.status, 303, "setup should redirect");
  const setCookie = res.headers.get("set-cookie") || "";
  const match = new RegExp(`${SESSION_COOKIE}=([^;]+)`).exec(setCookie);
  assert.ok(match, "setup should issue session cookie");
  return `${SESSION_COOKIE}=${match[1]}`;
}

async function openDashboard(kv, cookie, overrides = {}) {
  const res = await handleRequest(getRequest("/admin", { cookie }), makeEnv(kv, overrides));
  assert.equal(res.status, 200);
  const html = await res.text();
  const match = /name="csrf-token" content="([^"]+)"/.exec(html);
  assert.ok(match, "dashboard should expose csrf token");
  return { html, csrf: match[1] };
}

async function saveLinks(kv, cookie, csrf, links, { json = false, extra = {} } = {}, overrides = {}) {
  const request = json
    ? postJson("/update-links", { links, ...extra }, { cookie, headers: { "x-csrf-token": csrf } })
    : postForm("/update-links", { links, csrf_token: csrf, ...extra }, { cookie });
  const res = await handleRequest(request, makeEnv(kv, overrides));
  return res;
}

function base64UrlEncode(bytes) {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

test("normalizePath collapses repeated trailing slashes", () => {
  assert.equal(normalizePath("/admin///"), "/admin");
  assert.equal(normalizePath("/"), "/");
});

test("validateSubscriptionContent counts protocols case-insensitively", () => {
  const result = validateSubscriptionContent("VLESS://a\nTrojan://b\nss://c\n");
  assert.equal(result.configCount, 3);
  assert.equal(result.protocolCounts.vless, 1);
  assert.equal(result.protocolCounts.trojan, 1);
  assert.equal(result.errors.length, 0);
});

test("validateSubscriptionContent reports unknown formats with correct line numbers", () => {
  const content = "vless://ok\nnonsense-line\nss://also-ok";
  const result = validateSubscriptionContent(content);
  assert.equal(result.configCount, 2);
  assert.ok(result.warnings.some((w) => w.includes("line 2")), JSON.stringify(result.warnings));
});

test("validateSubscriptionContent detects duplicates", () => {
  const result = validateSubscriptionContent("vless://dup\nvless://dup\n");
  assert.equal(result.configCount, 2);
  assert.ok(result.warnings.some((w) => w.startsWith("Duplicate entry detected")));
});

test("validateSubscriptionContent expands JSON arrays like the server contract", () => {
  const arr = JSON.stringify([
    { name: "a", type: "vmess" },
    { name: "b", type: "trojan" },
    { name: "c", type: "ss" },
  ]);
  const result = validateSubscriptionContent(arr);
  assert.equal(result.configCount, 3);
  assert.equal(result.protocolCounts.json, 3);
});

test("validateSubscriptionContent counts two objects sharing one line separately", () => {
  const result = validateSubscriptionContent('{"a":1}{"b":2}');
  assert.equal(result.configCount, 2);
});

test("validateSubscriptionContent flags invalid and unclosed JSON blocks", () => {
  const invalid = validateSubscriptionContent("{not json}");
  assert.ok(invalid.warnings.some((w) => w.includes("Invalid JSON block")));

  const unclosed = validateSubscriptionContent("{\"open\": \"unclosed\nvless://after");
  assert.ok(unclosed.warnings.some((w) => w.includes("Unclosed JSON block near line 1")));
  assert.equal(unclosed.configCount, 1);
});

test("validateSubscriptionContent warns on empty JSON arrays", () => {
  const result = validateSubscriptionContent("[]");
  assert.equal(result.configCount, 0);
  assert.ok(result.warnings.some((w) => w.includes("is empty")));
});

test("validateSubscriptionContent handles CRLF content", () => {
  const content = "vless://a\r\n{\"x\":1}\r\ngarbage\r\n";
  const result = validateSubscriptionContent(content);
  assert.equal(result.configCount, 2);
  assert.ok(result.warnings.some((w) => w.includes("line 3")));
});

test("validateSubscriptionContent enforces the size limit", () => {
  const content = "vless://aaaaaaaaaaaaaaaaaaaa\n".repeat(2_600_000);
  const result = validateSubscriptionContent(content);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /exceeds the 24 MiB limit/);
});

test("constantTimeEqual behaves like equality without shortcuts", () => {
  assert.equal(constantTimeEqual("abc", "abc"), true);
  assert.equal(constantTimeEqual("abc", "abd"), false);
  assert.equal(constantTimeEqual("", ""), true);
  assert.equal(constantTimeEqual("a", "ab"), false);
});

test("escapeHtml escapes all dangerous characters", () => {
  assert.equal(escapeHtml(`<a href="x">&'</a>`), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;");
});

test("PBKDF2 records round-trip and reject wrong passwords", async () => {
  const env = makeEnv(new MemoryKV());
  const record = await createPasswordRecord(PASSWORD, env);
  assert.equal(record.version, 3);
  assert.equal(typeof record.pepperId, "string");

  const ok = await verifyPasswordEntry(PASSWORD, { kind: "hashed", record }, env);
  assert.equal(ok.ok, true);
  assert.equal(ok.migrated, true);

  const bad = await verifyPasswordEntry("wrong-password", { kind: "hashed", record }, env);
  assert.equal(bad.ok, false);
  assert.equal(bad.pepperMismatch, undefined);
});

test("rotating AUTH_SECRET is detected instead of failing as a bad password", async () => {
  const record = await createPasswordRecord(PASSWORD, makeEnv(new MemoryKV()));

  const samePepper = await verifyPasswordEntry(
    PASSWORD,
    { kind: "hashed", record },
    makeEnv(new MemoryKV())
  );
  assert.equal(samePepper.ok, true);

  const rotated = await verifyPasswordEntry(PASSWORD, { kind: "hashed", record }, makeEnv(new MemoryKV(), { AUTH_SECRET: "different-secret-value" }));
  assert.equal(rotated.ok, false);
  assert.equal(rotated.pepperMismatch, true);

  const removed = await verifyPasswordEntry(PASSWORD, { kind: "hashed", record }, makeEnv(new MemoryKV(), { AUTH_SECRET: "" }));
  assert.equal(removed.pepperMismatch, true);
});

test("legacy plaintext passwords verify and are flagged for migration", async () => {
  const kv = new MemoryKV();
  await kv.put("admin_password", "legacy-pass-1");
  const entry = await loadPasswordEntry(kv);
  assert.equal(entry.kind, "legacy");

  const result = await verifyPasswordEntry("legacy-pass-1", entry, makeEnv(kv));
  assert.equal(result.ok, true);
  assert.equal(result.migrated, false);
});

test("v2 salted SHA-256 records still verify", async () => {
  const salt = "abcd1234";
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${salt}:${PASSWORD}`)
  );
  const record = {
    version: 2,
    algorithm: "sha-256",
    salt,
    hash: base64UrlEncode(new Uint8Array(digest)),
  };

  const result = await verifyPasswordEntry(PASSWORD, { kind: "hashed", record }, makeEnv(new MemoryKV()));
  assert.equal(result.ok, true);
  assert.equal(result.migrated, false);
});

test("v2 HMAC records verify with the pepper and report mismatch without it", async () => {
  const salt = "abcd1234";
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode("unit-test-pepper-value"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${salt}:${PASSWORD}`)
  );
  const record = {
    version: 2,
    algorithm: "hmac-sha256",
    salt,
    hash: base64UrlEncode(new Uint8Array(signature)),
  };

  const withSecret = await verifyPasswordEntry(
    PASSWORD,
    { kind: "hashed", record },
    makeEnv(new MemoryKV())
  );
  assert.equal(withSecret.ok, true);

  const withoutSecret = await verifyPasswordEntry(
    PASSWORD,
    { kind: "hashed", record },
    makeEnv(new MemoryKV(), { AUTH_SECRET: "" })
  );
  assert.equal(withoutSecret.ok, false);
  assert.equal(withoutSecret.pepperMismatch, true);
});

test("setup issues a host-prefixed session cookie and refuses duplicates", async () => {
  const kv = new MemoryKV();
  const cookie = await setupAdmin(kv);

  assert.ok(cookie.startsWith("__Host-sublink_session="));

  const second = await handleRequest(postForm("/admin/setup", { password: "another-pass-1" }), makeEnv(kv));
  assert.equal(second.status, 409);
});

test("dashboard requires a session and exposes CSRF when signed in", async () => {
  const kv = new MemoryKV();
  await setupAdmin(kv);

  const anonymous = await handleRequest(getRequest("/admin"), makeEnv(kv));
  assert.equal(anonymous.status, 200);
  assert.ok((await anonymous.text()).includes("Sign in to SubLink"));

  const fresh = new MemoryKV();
  const cookie = await setupAdmin(fresh);
  const { html, csrf } = await openDashboard(fresh, cookie);
  assert.ok(html.includes("Subscription nodes"));
  assert.ok(csrf.length > 20);
});

test("dashboard shows login page for expired sessions", async () => {
  const kv = new MemoryKV();
  const setCookieRes = await handleRequest(postForm("/admin/setup", { password: PASSWORD }), makeEnv(kv));
  const token = new RegExp(`${SESSION_COOKIE}=([^;]+)`).exec(setCookieRes.headers.get("set-cookie"))[1];
  const key = `session:${await sha256Hex(token)}`;
  await kv.put(key, JSON.stringify({ csrfToken: "x", expiresAt: new Date(Date.now() - 1000).toISOString() }));

  const res = await handleRequest(getRequest("/admin", { cookie: `${SESSION_COOKIE}=${token}` }), makeEnv(kv));
  const html = await res.text();
  assert.ok(html.includes("Sign in to SubLink"));
  assert.equal(kv.map.has(key), false, "expired session should be deleted");
});

test("update-links authenticates before parsing the body", async () => {
  const kv = new MemoryKV();

  const unauthenticated = new Request(`${ORIGIN}/update-links`, {
    method: "POST",
    headers: { "content-type": "application/json", "CF-Connecting-IP": IP },
    body: "{definitely-not-json",
  });
  const res = await handleRequest(unauthenticated, makeEnv(kv));
  assert.equal(res.status, 401, "auth must be checked before body parsing");
});

test("full save flow stores links, backup, and matching metadata", async () => {
  const kv = new MemoryKV();
  const cookie = await setupAdmin(kv);
  const { csrf } = await openDashboard(kv, cookie);
  const links = "vless://node-a\nvless://node-b\n";

  const denied = await saveLinks(kv, cookie, "wrong-csrf-token", links);
  assert.equal(denied.status, 403);

  const res = await saveLinks(kv, cookie, csrf, links);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);

  assert.equal(await kv.get("vpn_links"), links);
  assert.equal(await kv.get("vpn_links_backup"), "");
  const meta = JSON.parse(await kv.get("vpn_meta"));
  assert.equal(meta.fingerprint, await sha256Hex(links));
  assert.equal(meta.configCount, 2);
});

test("identical re-save short-circuits without rewriting keys", async () => {
  const kv = new MemoryKV();
  const cookie = await setupAdmin(kv);
  const { csrf } = await openDashboard(kv, cookie);
  const links = "vless://same-node\n";

  await saveLinks(kv, cookie, csrf, links);
  const putsAfterFirst = kv.putCounts.get("vpn_links");

  const res = await saveLinks(kv, cookie, csrf, links);
  const body = await res.json();
  assert.equal(body.unchanged, true);
  assert.equal(kv.putCounts.get("vpn_links"), putsAfterFirst, "links must not be rewritten");
});

test("empty saves require confirmation and accept boolean confirm_empty over JSON", async () => {
  const kv = new MemoryKV();
  const cookie = await setupAdmin(kv);
  const { csrf } = await openDashboard(kv, cookie);

  const refused = await saveLinks(kv, cookie, csrf, "", { json: true });
  assert.equal(refused.status, 400);

  const confirmed = await saveLinks(kv, cookie, csrf, "", {
    json: true,
    extra: { confirm_empty: true },
  });
  assert.equal(confirmed.status, 200);
  const body = await confirmed.json();
  assert.equal(body.ok, true);
  assert.equal(body.unchanged, true, 'empty initial state equals stored "" and must not rewrite');
  assert.equal(body.meta.fingerprint, await sha256Hex(""));
  const feed = await handleRequest(getRequest("/"), makeEnv(kv));
  assert.equal(await feed.text(), "");
});

test("restore-backup swaps current links into the backup slot", async () => {
  const kv = new MemoryKV();
  const cookie = await setupAdmin(kv);
  const { csrf } = await openDashboard(kv, cookie);

  await saveLinks(kv, cookie, csrf, "vless://first\n");
  await saveLinks(kv, cookie, csrf, "vless://second\n");

  const res = await handleRequest(
    postForm("/restore-backup", { csrf_token: csrf }, { cookie }),
    makeEnv(kv)
  );
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.links, "vless://first\n");
  assert.equal(await kv.get("vpn_links"), "vless://first\n");
  assert.equal(await kv.get("vpn_links_backup"), "vless://second\n");

  const meta = JSON.parse(await kv.get("vpn_meta"));
  assert.equal(meta.fingerprint, await sha256Hex("vless://first\n"));
});

test("failed logins are throttled per IP regardless of User-Agent", async () => {
  const kv = new MemoryKV();
  await setupAdmin(kv);

  for (let i = 0; i < 8; i += 1) {
    const res = await handleRequest(
      postForm("/admin/login", { password: "guess-" + i }, {
        headers: { "User-Agent": `attacker-ua-${i}` },
      }),
      makeEnv(kv)
    );
    assert.equal(res.status, 401, `attempt ${i} should fail with 401`);
  }

  const rotatedUa = await handleRequest(
    postForm("/admin/login", { password: PASSWORD }, {
      headers: { "User-Agent": "fresh-user-agent" },
    }),
    makeEnv(kv)
  );
  assert.equal(rotatedUa.status, 429, "UA rotation must not reset the counter");
  assert.equal(rotatedUa.headers.get("retry-after"), String(15 * 60));

  const otherIp = await handleRequest(
    postForm("/admin/login", { password: PASSWORD }, {
      headers: { "CF-Connecting-IP": "198.51.100.77", "User-Agent": "anything" },
    }),
    makeEnv(kv)
  );
  assert.equal(otherIp.status, 303, "a different IP must not share the bucket");
});

test("password change throttles wrong current-password guesses", async () => {
  const kv = new MemoryKV();
  const cookie = await setupAdmin(kv);
  const { csrf } = await openDashboard(kv, cookie);

  for (let i = 0; i < 8; i += 1) {
    const res = await handleRequest(
      postForm("/admin/password", {
        csrf_token: csrf,
        current_password: "wrong-guess-" + i,
        new_password: "new-valid-pass-1",
      }, { cookie }),
      makeEnv(kv)
    );
    assert.equal(res.status, 401, `wrong guess ${i} should be rejected`);
  }

  const blocked = await handleRequest(
    postForm("/admin/password", {
      csrf_token: csrf,
      current_password: PASSWORD,
      new_password: "new-valid-pass-1",
    }, { cookie }),
    makeEnv(kv)
  );
  assert.equal(blocked.status, 429);
});

test("password change signs out every existing session", async () => {
  const kv = new MemoryKV();
  const cookie = await setupAdmin(kv);
  const { csrf } = await openDashboard(kv, cookie);

  const res = await handleRequest(
    postForm("/admin/password", {
      csrf_token: csrf,
      current_password: PASSWORD,
      new_password: "rotated-pass-99",
    }, { cookie }),
    makeEnv(kv)
  );
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.signedOut, true);

  assert.equal([...kv.map.keys()].some((k) => k.startsWith("session:")), false, "all sessions revoked");

  const stalePage = await handleRequest(getRequest("/admin", { cookie }), makeEnv(kv));
  assert.ok((await stalePage.text()).includes("Sign in to SubLink"), "old cookie must be dead");

  const oldLogin = await handleRequest(postForm("/admin/login", { password: PASSWORD }), makeEnv(kv));
  assert.equal(oldLogin.status, 401);

  const newLogin = await handleRequest(postForm("/admin/login", { password: "rotated-pass-99" }), makeEnv(kv));
  assert.equal(newLogin.status, 303);
});

test("legacy plaintext passwords migrate transparently on login", async () => {
  const kv = new MemoryKV();
  await kv.put("admin_password", "legacy-pass-1");

  const first = await handleRequest(postForm("/admin/login", { password: "legacy-pass-1" }), makeEnv(kv));
  assert.equal(first.status, 303);

  const stored = JSON.parse(await kv.get("admin_password"));
  assert.equal(stored.version, 3, "record should be rehashed to PBKDF2");

  const second = await handleRequest(postForm("/admin/login", { password: "legacy-pass-1" }), makeEnv(kv));
  assert.equal(second.status, 303);
});

test("AUTH_SECRET rotation produces explicit guidance on the login page", async () => {
  const kv = new MemoryKV();
  await setupAdmin(kv, PASSWORD);

  const res = await handleRequest(
    postForm("/admin/login", { password: PASSWORD }),
    makeEnv(kv, { AUTH_SECRET: "rotated-away-secret" })
  );
  assert.equal(res.status, 401);
  assert.match(await res.text(), /AUTH_SECRET changed/);
});

test("subscription endpoint negotiates formats and sets hygiene headers", async () => {
  const kv = new MemoryKV();
  const cookie = await setupAdmin(kv);
  const { csrf } = await openDashboard(kv, cookie);
  await saveLinks(kv, cookie, csrf, "vless://feed-node\n");

  const raw = await handleRequest(getRequest("/", {
    headers: { "User-Agent": "curl/8.0" },
  }), makeEnv(kv));
  assert.equal(raw.status, 200);
  assert.equal(await raw.text(), "vless://feed-node\n");
  assert.equal(raw.headers.get("vary"), "User-Agent");
  assert.equal(raw.headers.get("subscription-userinfo"), null);

  const b64 = await handleRequest(getRequest("/?b64=1", {
    headers: { "User-Agent": "curl/8.0" },
  }), makeEnv(kv));
  const encoded = await b64.text();
  assert.equal(Buffer.from(encoded, "base64").toString("utf8"), "vless://feed-node\n");

  const agentNegotiated = await handleRequest(getRequest("/", {
    headers: { "User-Agent": "Shadowrocket/1995 CFNetwork/1" },
  }), makeEnv(kv));
  assert.notEqual(await agentNegotiated.text(), "vless://feed-node\n");

  const clash = await handleRequest(getRequest("/", {
    headers: { "User-Agent": "clash-verge/1.0" },
  }), makeEnv(kv));
  assert.equal(await clash.text(), "vless://feed-node\n", "clash must receive raw text, not base64");

  const head = await handleRequest(new Request(`${ORIGIN}/`, { method: "HEAD" }), makeEnv(kv));
  assert.equal(head.status, 200);

  const postRoot = await handleRequest(new Request(`${ORIGIN}/`, { method: "POST" }), makeEnv(kv));
  assert.equal(postRoot.status, 405);
});

test("SUB_TOKEN moves the feed behind a private path", async () => {
  const kv = new MemoryKV();
  const token = "tok-super-private-01";
  const cookie = await setupAdmin(kv);
  const { csrf, html } = await openDashboard(kv, cookie, { SUB_TOKEN: token });
  await saveLinks(kv, cookie, csrf, "vless://secret-node\n", {}, { SUB_TOKEN: token });

  assert.ok(html.includes(`/sub/${token}`), "dashboard should advertise the tokenized URL");

  const root = await handleRequest(getRequest("/", {}, { SUB_TOKEN: token }), makeEnv(kv, { SUB_TOKEN: token }));
  assert.equal(root.status, 404);

  const good = await handleRequest(
    getRequest(`/sub/${encodeURIComponent(token)}`, {}, { SUB_TOKEN: token }),
    makeEnv(kv, { SUB_TOKEN: token })
  );
  assert.equal(good.status, 200);
  assert.equal(await good.text(), "vless://secret-node\n");

  const bad = await handleRequest(
    getRequest("/sub/wrong-token-value", {}, { SUB_TOKEN: token }),
    makeEnv(kv, { SUB_TOKEN: token })
  );
  assert.equal(bad.status, 404);
});

test("weak SUB_TOKEN values fall back to public behavior", async () => {
  const kv = new MemoryKV();
  await setupAdmin(kv, PASSWORD, { SUB_TOKEN: "short" });

  const res = await handleRequest(getRequest("/", {}, { SUB_TOKEN: "short" }), makeEnv(kv, { SUB_TOKEN: "short" }));
  assert.equal(res.status, 200);
});

test("misc routes behave: favicon, trailing slashes, 404", async () => {
  const kv = new MemoryKV();

  const favicon = await handleRequest(getRequest("/favicon.ico"), makeEnv(kv));
  assert.equal(favicon.status, 204);

  const slashed = await handleRequest(getRequest("/admin///"), makeEnv(kv));
  assert.equal(slashed.status, 200);

  const missing = await handleRequest(getRequest("/nope"), makeEnv(kv));
  assert.equal(missing.status, 404);

  const postFavicon = await handleRequest(new Request(`${ORIGIN}/favicon.ico`, { method: "POST" }), makeEnv(kv));
  assert.equal(postFavicon.status, 405);
});
