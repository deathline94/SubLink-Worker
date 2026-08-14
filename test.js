import assert from "node:assert/strict";
import test from "node:test";
import worker, { __SUBLINK_WORKER_TESTS__ } from "./Worker.js";

// Mock Cloudflare KV in-memory store
function createMockKV() {
  const store = new Map();
  return {
    store,
    async get(key) {
      const val = store.get(key);
      return val === undefined ? null : val;
    },
    async put(key, value, options = {}) {
      store.set(key, String(value));
    },
    async delete(key) {
      store.delete(key);
    },
  };
}

test("constantTimeEqual", () => {
  const { constantTimeEqual } = __SUBLINK_WORKER_TESTS__;
  assert.equal(constantTimeEqual("secret123", "secret123"), true);
  assert.equal(constantTimeEqual("secret123", "secret124"), false);
  assert.equal(constantTimeEqual("secret123", "secret12"), false);
  assert.equal(constantTimeEqual("", ""), true);
  assert.equal(constantTimeEqual("a", ""), false);
});

test("Password hashing with PBKDF2 and legacy upgrade verification", async () => {
  const { createPasswordRecord, verifyPasswordEntry, loadPasswordEntry } =
    __SUBLINK_WORKER_TESTS__;
  const kv = createMockKV();
  const env = { sub: kv, AUTH_SECRET: "test-secret" };

  // Create v3 PBKDF2 record
  const record = await createPasswordRecord("myStrongPassword123!", env);
  assert.equal(record.version, 3);
  assert.equal(record.algorithm, "pbkdf2-sha256");
  assert.ok(record.salt);
  assert.ok(record.hash);

  // Store in KV and verify
  await kv.put("admin_password", JSON.stringify(record));
  const entry = await loadPasswordEntry(kv);
  assert.equal(entry.kind, "hashed");

  const checkValid = await verifyPasswordEntry("myStrongPassword123!", entry, env);
  assert.equal(checkValid.ok, true);

  const checkInvalid = await verifyPasswordEntry("wrongPassword", entry, env);
  assert.equal(checkInvalid.ok, false);

  // Legacy plaintext verification
  await kv.put("admin_password", "legacyPassword");
  const legacyEntry = await loadPasswordEntry(kv);
  assert.equal(legacyEntry.kind, "legacy");
  const checkLegacy = await verifyPasswordEntry("legacyPassword", legacyEntry, env);
  assert.equal(checkLegacy.ok, true);
  assert.equal(checkLegacy.migrated, false);
});

test("Subscription validation and protocol counters", () => {
  const { validateSubscriptionContent } = __SUBLINK_WORKER_TESTS__;

  const content = [
    "vless://uuid@example.com:443?security=tls#Node1",
    "vmess://eyJ2IjoiMiIsInBzIjoiTm9kZTIifQ==",
    "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388#Node3",
    "trojan://password@example.com:443#Node4",
    "hysteria2://pass@example.com:443#Node5",
    "wireguard://privatekey@1.2.3.4:51820#Node6",
    "socks5://user:pass@1.2.3.4:1080#Node7",
    "vless://uuid@example.com:443?security=tls#Node1", // duplicate
  ].join("\n");

  const result = validateSubscriptionContent(content);
  assert.equal(result.configCount, 8);
  assert.equal(result.protocolCounts.vless, 2);
  assert.equal(result.protocolCounts.vmess, 1);
  assert.equal(result.protocolCounts.ss, 1);
  assert.equal(result.protocolCounts.trojan, 1);
  assert.equal(result.protocolCounts.hysteria2, 1);
  assert.equal(result.protocolCounts.wireguard, 1);
  assert.equal(result.protocolCounts.socks5, 1);
  assert.ok(result.warnings.some((w) => w.includes("Duplicate entry")));
});

test("Public subscription: Raw, Base64 query parameter, and User-Agent auto-negotiation", async () => {
  const kv = createMockKV();
  const env = { sub: kv };
  const links = "vless://uuid@example.com:443#Node1\ntrojan://pwd@example.com:443#Node2";
  await kv.put("vpn_links", links);

  // 1. Raw output (default)
  const reqRaw = new Request("https://sub.example.com/");
  const resRaw = await worker.fetch(reqRaw, env);
  assert.equal(resRaw.status, 200);
  assert.equal(await resRaw.text(), links);
  assert.equal(resRaw.headers.get("subscription-userinfo"), "upload=0; download=0; total=0; expire=0");
  assert.equal(resRaw.headers.get("profile-update-interval"), "24");

  // 2. Base64 via query parameter ?b64=1
  const reqB64 = new Request("https://sub.example.com/?b64=1");
  const resB64 = await worker.fetch(reqB64, env);
  assert.equal(resB64.status, 200);
  const b64Text = await resB64.text();
  assert.equal(Buffer.from(b64Text, "base64").toString("utf-8"), links);

  // 3. Auto Base64 for Shadowrocket User-Agent
  const reqUA = new Request("https://sub.example.com/sub", {
    headers: { "User-Agent": "Shadowrocket/2.2.0" },
  });
  const resUA = await worker.fetch(reqUA, env);
  assert.equal(resUA.status, 200);
  const uaB64Text = await resUA.text();
  assert.equal(Buffer.from(uaB64Text, "base64").toString("utf-8"), links);
});

test("End-to-end admin auth flow and CSRF protection", async () => {
  const kv = createMockKV();
  const env = { sub: kv, AUTH_SECRET: "test-auth-secret" };

  // Setup password
  const setupForm = new FormData();
  setupForm.set("password", "TestPassword123!");
  const setupReq = new Request("https://sub.example.com/admin/setup", {
    method: "POST",
    body: setupForm,
  });
  const setupRes = await worker.fetch(setupReq, env);
  assert.equal(setupRes.status, 303);
  const sessionCookie = setupRes.headers.get("set-cookie");
  assert.ok(sessionCookie);

  // Read admin page with session
  const adminReq = new Request("https://sub.example.com/admin", {
    headers: { Cookie: sessionCookie },
  });
  const adminRes = await worker.fetch(adminReq, env);
  assert.equal(adminRes.status, 200);
  const html = await adminRes.text();
  assert.ok(html.includes("Subscription nodes"));

  // Extract CSRF token from HTML
  const csrfMatch = /name="csrf-token" content="([^"]+)"/.exec(html) ||
    /name="csrf_token" value="([^"]+)"/.exec(html);
  assert.ok(csrfMatch);
  const csrfToken = csrfMatch[1];

  // Update links via JSON API
  const updateReq = new Request("https://sub.example.com/update-links", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-csrf-token": csrfToken,
      Cookie: sessionCookie,
    },
    body: JSON.stringify({
      links: "vless://uuid@node.com:443#PrimaryNode",
      confirm_empty: "false",
    }),
  });
  const updateRes = await worker.fetch(updateReq, env);
  assert.equal(updateRes.status, 200);
  const updateBody = await updateRes.json();
  assert.equal(updateBody.ok, true);
  assert.equal(updateBody.meta.configCount, 1);

  // Verify KV updated
  const stored = await kv.get("vpn_links");
  assert.equal(stored, "vless://uuid@node.com:443#PrimaryNode");
});
