const GLOBAL_KV = typeof sub !== "undefined" ? sub : null;
const GLOBAL_AUTH_SECRET =
  typeof AUTH_SECRET !== "undefined" ? String(AUTH_SECRET || "") : "";

const APP_NAME = "SubLink Worker";
const SESSION_COOKIE = "__Host-sublink_session";
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const LOGIN_WINDOW_SECONDS = 15 * 60;
const LOGIN_MAX_FAILURES = 8;
const MAX_LINKS_BYTES = 24 * 1024 * 1024;
const SUPPORTED_PROTOCOLS = [
  "vless",
  "vmess",
  "ss",
  "trojan",
  "hysteria2",
  "hy2",
  "hysteria",
  "tuic",
  "wireguard",
];

if (typeof addEventListener === "function") {
  addEventListener("fetch", (event) => {
    event.respondWith(handleRequest(event.request));
  });
}

async function handleRequest(request, env = getDefaultEnv()) {
  const url = new URL(request.url);
  const path = normalizePath(url.pathname);

  try {
    if (path === "/favicon.ico") {
      return request.method === "GET"
        ? new Response(null, { status: 204 })
        : methodNotAllowed(["GET"]);
    }

    if (path === "/" || path === "/sub") {
      return request.method === "GET"
        ? generateSubscription(env)
        : methodNotAllowed(["GET"]);
    }

    if (path === "/admin") {
      return request.method === "GET"
        ? handleAdminPage(request, env)
        : methodNotAllowed(["GET"]);
    }

    if (path === "/admin/setup") {
      return request.method === "POST"
        ? handleSetup(request, env)
        : methodNotAllowed(["POST"]);
    }

    if (path === "/admin/login") {
      return request.method === "POST"
        ? handleLogin(request, env)
        : methodNotAllowed(["POST"]);
    }

    if (path === "/admin/logout") {
      return request.method === "POST"
        ? handleLogout(request, env)
        : methodNotAllowed(["POST"]);
    }

    if (path === "/admin/password") {
      return request.method === "POST"
        ? handlePasswordChange(request, env)
        : methodNotAllowed(["POST"]);
    }

    if (path === "/update-links") {
      return request.method === "POST"
        ? handleUpdateLinks(request, env)
        : methodNotAllowed(["POST"]);
    }

    if (path === "/restore-backup") {
      return request.method === "POST"
        ? handleRestoreBackup(request, env)
        : methodNotAllowed(["POST"]);
    }

    return textResponse("Not found", {
      status: 404,
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    console.error(error);
    return textResponse("Internal server error", {
      status: 500,
      headers: { "cache-control": "no-store" },
    });
  }
}

function getDefaultEnv() {
  return {
    sub: GLOBAL_KV,
    AUTH_SECRET: GLOBAL_AUTH_SECRET,
  };
}

function normalizePath(pathname) {
  if (pathname.length > 1 && pathname.endsWith("/")) {
    return pathname.slice(0, -1);
  }
  return pathname || "/";
}

function getKV(env) {
  return env && env.sub && typeof env.sub.get === "function" ? env.sub : null;
}

async function handleAdminPage(request, env) {
  const nonce = randomBase64Url(18);
  const kv = getKV(env);

  if (!kv) {
    return htmlResponse(generateAdminErrorPage({
      nonce,
      title: "KV binding missing",
      details: [
        'Create a Cloudflare KV namespace and bind it to this Worker as "sub".',
        "The public subscription cannot be stored until that binding exists.",
      ],
    }), { nonce, status: 503 });
  }

  const passwordEntry = await loadPasswordEntry(kv);
  if (passwordEntry.kind === "missing") {
    return htmlResponse(generateAuthPage({
      mode: "setup",
      nonce,
      warning: authSecretWarning(env),
    }), { nonce });
  }

  const session = await getSession(request, kv);
  if (!session) {
    return htmlResponse(generateAuthPage({
      mode: "login",
      nonce,
      warning: authSecretWarning(env),
    }), { nonce });
  }

  const links = await kvGet(kv, "vpn_links", "");
  const backup = await kvGet(kv, "vpn_links_backup", null);
  const storedMeta = await kvGetJson(kv, "vpn_meta", null);
  const validation = validateSubscriptionContent(links);
  const meta =
    storedMeta || (await buildMetadata(links, validation));

  return htmlResponse(generateDashboardPage({
    nonce,
    csrfToken: session.data.csrfToken,
    links,
    hasBackup: backup !== null,
    meta,
    validation,
    subscriptionUrl: `${new URL(request.url).origin}/`,
    hasAuthSecret: hasAuthSecret(env),
  }), { nonce });
}

async function handleSetup(request, env) {
  const kv = getKV(env);
  if (!kv) return jsonResponse({ ok: false, error: "KV binding missing." }, { status: 503 });

  const existing = await loadPasswordEntry(kv);
  if (existing.kind !== "missing") {
    return jsonResponse({ ok: false, error: "Admin password is already set." }, { status: 409 });
  }

  const form = await safeFormData(request);
  const password = getFormString(form, "password");
  const validationError = validatePassword(password);
  if (validationError) {
    const nonce = randomBase64Url(18);
    return htmlResponse(generateAuthPage({
      mode: "setup",
      nonce,
      error: validationError,
      warning: authSecretWarning(env),
    }), { nonce, status: 400 });
  }

  await kv.put("admin_password", JSON.stringify(await createPasswordRecord(password, env)));
  const session = await createSession(kv);
  return redirectToAdmin(session.cookie);
}

async function handleLogin(request, env) {
  const kv = getKV(env);
  const nonce = randomBase64Url(18);
  if (!kv) {
    return htmlResponse(generateAdminErrorPage({
      nonce,
      title: "KV binding missing",
      details: ['Bind a KV namespace named "sub" before signing in.'],
    }), { nonce, status: 503 });
  }

  const clientKey = await loginThrottleKey(request);
  const throttle = await readLoginThrottle(kv, clientKey);
  if (throttle.blocked) {
    return htmlResponse(generateAuthPage({
      mode: "login",
      nonce,
      error: "Too many sign-in attempts. Try again in a few minutes.",
      warning: authSecretWarning(env),
    }), { nonce, status: 429 });
  }

  const form = await safeFormData(request);
  const password = getFormString(form, "password");
  const entry = await loadPasswordEntry(kv);

  if (entry.kind === "missing") {
    return redirectToAdmin();
  }

  const verification = await verifyPasswordEntry(password, entry, env);
  if (!verification.ok) {
    await recordLoginFailure(kv, clientKey, throttle.count);
    return htmlResponse(generateAuthPage({
      mode: "login",
      nonce,
      error: "Unable to sign in with those credentials.",
      warning: authSecretWarning(env),
    }), { nonce, status: 401 });
  }

  if (entry.kind === "legacy") {
    await kv.put("admin_password", JSON.stringify(await createPasswordRecord(password, env)));
  }

  await clearLoginThrottle(kv, clientKey);
  const session = await createSession(kv);
  return redirectToAdmin(session.cookie);
}

async function handleLogout(request, env) {
  const kv = getKV(env);
  if (!kv) return jsonResponse({ ok: false, error: "KV binding missing." }, { status: 503 });

  const form = await safeFormData(request);
  const session = await requireSessionAndCsrf(request, kv, form);
  if (!session.ok) return session.response;

  await kv.delete(session.session.key);
  return jsonResponse({ ok: true }, {
    headers: { "set-cookie": expireSessionCookie() },
  });
}

async function handlePasswordChange(request, env) {
  const kv = getKV(env);
  if (!kv) return jsonResponse({ ok: false, error: "KV binding missing." }, { status: 503 });

  const form = await safeFormData(request);
  const session = await requireSessionAndCsrf(request, kv, form);
  if (!session.ok) return session.response;

  const currentPassword = getFormString(form, "current_password");
  const newPassword = getFormString(form, "new_password");
  const validationError = validatePassword(newPassword);
  if (validationError) {
    return jsonResponse({ ok: false, error: validationError }, { status: 400 });
  }

  const entry = await loadPasswordEntry(kv);
  const verification = await verifyPasswordEntry(currentPassword, entry, env);
  if (!verification.ok) {
    return jsonResponse({ ok: false, error: "Current password did not match." }, { status: 401 });
  }

  await kv.put("admin_password", JSON.stringify(await createPasswordRecord(newPassword, env)));
  return jsonResponse({ ok: true, message: "Password updated." });
}

async function handleUpdateLinks(request, env) {
  const kv = getKV(env);
  if (!kv) return jsonResponse({ ok: false, error: "KV binding missing." }, { status: 503 });

  const input = await safeRequestInput(request);
  const session = await requireSessionAndCsrf(request, kv, input);
  if (!session.ok) return session.response;

  if (!hasInputField(input, "links")) {
    return jsonResponse({ ok: false, error: "Malformed request: missing links field." }, { status: 400 });
  }

  const links = getFormString(input, "links");
  const confirmEmpty = getFormString(input, "confirm_empty") === "true";
  const validation = validateSubscriptionContent(links);

  if (validation.errors.length) {
    return jsonResponse({ ok: false, error: validation.errors[0], validation }, { status: 413 });
  }

  if (validation.isEmpty && !confirmEmpty) {
    return jsonResponse({
      ok: false,
      error: "Empty subscription requires confirmation.",
      validation,
    }, { status: 400 });
  }

  const previousLinks = await kvGet(kv, "vpn_links", "");
  await kv.put("vpn_links_backup", previousLinks);
  await kv.put("vpn_links", links);

  const meta = await buildMetadata(links, validation);
  await kv.put("vpn_meta", JSON.stringify(meta));

  return jsonResponse({ ok: true, meta, validation });
}

async function handleRestoreBackup(request, env) {
  const kv = getKV(env);
  if (!kv) return jsonResponse({ ok: false, error: "KV binding missing." }, { status: 503 });

  const form = await safeFormData(request);
  const session = await requireSessionAndCsrf(request, kv, form);
  if (!session.ok) return session.response;

  const backup = await kvGet(kv, "vpn_links_backup", null);
  if (backup === null) {
    return jsonResponse({ ok: false, error: "No backup is available." }, { status: 404 });
  }

  const current = await kvGet(kv, "vpn_links", "");
  await kv.put("vpn_links_backup", current);
  await kv.put("vpn_links", backup);

  const validation = validateSubscriptionContent(backup);
  const meta = await buildMetadata(backup, validation);
  await kv.put("vpn_meta", JSON.stringify(meta));

  return jsonResponse({ ok: true, links: backup, meta, validation });
}

async function generateSubscription(env) {
  const kv = getKV(env);
  if (!kv) {
    return textResponse("KV binding missing. Bind a namespace named sub.", {
      status: 503,
      headers: { "cache-control": "no-store" },
    });
  }

  const rawContent = await kvGet(kv, "vpn_links", "");
  return textResponse(rawContent, {
    headers: {
      "cache-control": "no-store",
      "profile-update-interval": "24",
      "subscription-userinfo": "upload=0; download=0; total=0; expire=0",
    },
  });
}

async function safeFormData(request) {
  try {
    return await request.formData();
  } catch (_error) {
    return null;
  }
}

async function safeRequestInput(request) {
  const contentType = request.headers.get("content-type") || "";
  if (contentType.toLowerCase().includes("application/json")) {
    try {
      const parsed = JSON.parse(await request.text());
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch (_error) {
      return null;
    }
  }

  return safeFormData(request);
}

function hasInputField(input, key) {
  if (!input) return false;
  if (typeof input.has === "function") return input.has(key);
  return Object.prototype.hasOwnProperty.call(input, key);
}

function getFormString(form, key) {
  if (!form) return "";
  let value;
  if (typeof form.get === "function") {
    if (!form.has(key)) return "";
    value = form.get(key);
  } else {
    if (!Object.prototype.hasOwnProperty.call(form, key)) return "";
    value = form[key];
  }
  return typeof value === "string" ? value : "";
}

function validatePassword(password) {
  if (!password) return "Password is required.";
  return "";
}

function hasAuthSecret(env) {
  return !!(env && typeof env.AUTH_SECRET === "string" && env.AUTH_SECRET.trim());
}

function authSecretWarning(env) {
  return hasAuthSecret(env)
    ? ""
    : "Optional AUTH_SECRET is not configured. Passwords are still salted, but adding AUTH_SECRET improves protection if KV data is exposed.";
}

async function loadPasswordEntry(kv) {
  const raw = await kvGet(kv, "admin_password", null);
  if (raw === null || raw === "") return { kind: "missing" };

  try {
    const parsed = JSON.parse(raw);
    if (parsed && parsed.version === 2 && parsed.salt && parsed.hash && parsed.algorithm) {
      return { kind: "hashed", record: parsed };
    }
  } catch (_error) {
    // Legacy versions stored the password directly as plain text.
  }

  return { kind: "legacy", password: raw };
}

async function createPasswordRecord(password, env) {
  const salt = randomBase64Url(16);
  const algorithm = hasAuthSecret(env) ? "hmac-sha256" : "salted-sha256";
  const hash = await hashPassword(password, salt, env, algorithm);

  return {
    version: 2,
    algorithm,
    salt,
    hash,
    createdAt: new Date().toISOString(),
  };
}

async function verifyPasswordEntry(password, entry, env) {
  if (!entry || entry.kind === "missing") return { ok: false };

  if (entry.kind === "legacy") {
    return { ok: constantTimeEqual(password, entry.password), migrated: false };
  }

  const record = entry.record;
  const hash = await hashPassword(password, record.salt, env, record.algorithm);
  return { ok: constantTimeEqual(hash, record.hash), migrated: true };
}

async function hashPassword(password, salt, env, algorithm) {
  const material = `${salt}:${password}`;

  if (algorithm === "hmac-sha256") {
    if (!hasAuthSecret(env)) return "";
    const key = await crypto.subtle.importKey(
      "raw",
      encodeText(env.AUTH_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", key, encodeText(material));
    return base64UrlEncodeBytes(new Uint8Array(signature));
  }

  const digest = await crypto.subtle.digest("SHA-256", encodeText(material));
  return base64UrlEncodeBytes(new Uint8Array(digest));
}

async function createSession(kv) {
  const token = randomBase64Url(32);
  const csrfToken = randomBase64Url(32);
  const tokenHash = await sha256Hex(token);
  const key = `session:${tokenHash}`;
  const now = Date.now();
  const data = {
    csrfToken,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + SESSION_TTL_SECONDS * 1000).toISOString(),
  };

  await kv.put(key, JSON.stringify(data), { expirationTtl: SESSION_TTL_SECONDS });

  return {
    key,
    token,
    data,
    cookie: `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${SESSION_TTL_SECONDS}; Secure; HttpOnly; SameSite=Strict`,
  };
}

async function getSession(request, kv) {
  const token = parseCookies(request.headers.get("Cookie") || "").get(SESSION_COOKIE);
  if (!token) return null;

  const key = `session:${await sha256Hex(token)}`;
  const data = await kvGetJson(kv, key, null);
  if (!data || !data.csrfToken || !data.expiresAt) return null;

  if (Date.parse(data.expiresAt) <= Date.now()) {
    await kv.delete(key);
    return null;
  }

  return { key, token, data };
}

async function requireSessionAndCsrf(request, kv, form = null) {
  const session = await getSession(request, kv);
  if (!session) {
    return {
      ok: false,
      response: jsonResponse({ ok: false, error: "Authentication required." }, { status: 401 }),
    };
  }

  const headerToken = request.headers.get("x-csrf-token") || "";
  const formToken = form ? getFormString(form, "csrf_token") : "";
  const provided = headerToken || formToken;

  if (!provided || !constantTimeEqual(provided, session.data.csrfToken)) {
    return {
      ok: false,
      response: jsonResponse({ ok: false, error: "CSRF token missing or invalid." }, { status: 403 }),
    };
  }

  return { ok: true, session };
}

function expireSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`;
}

async function loginThrottleKey(request) {
  const ip =
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For") ||
    "unknown";
  const userAgent = request.headers.get("User-Agent") || "unknown";
  return `login_fail:${await sha256Hex(`${ip}|${userAgent}`)}`;
}

async function readLoginThrottle(kv, key) {
  const data = await kvGetJson(kv, key, { count: 0 });
  const count = Number(data.count || 0);
  return { count, blocked: count >= LOGIN_MAX_FAILURES };
}

async function recordLoginFailure(kv, key, currentCount) {
  await kv.put(key, JSON.stringify({
    count: currentCount + 1,
    updatedAt: new Date().toISOString(),
  }), { expirationTtl: LOGIN_WINDOW_SECONDS });
}

async function clearLoginThrottle(kv, key) {
  await kv.delete(key);
}

function parseCookies(header) {
  const cookies = new Map();
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const index = trimmed.indexOf("=");
    if (index === -1) continue;
    cookies.set(trimmed.slice(0, index), trimmed.slice(index + 1));
  }
  return cookies;
}

async function kvGet(kv, key, fallback) {
  const value = await kv.get(key);
  return value === null || typeof value === "undefined" ? fallback : value;
}

async function kvGetJson(kv, key, fallback) {
  const value = await kvGet(kv, key, null);
  if (value === null) return fallback;

  try {
    return JSON.parse(value);
  } catch (_error) {
    return fallback;
  }
}

async function buildMetadata(content, validation = validateSubscriptionContent(content)) {
  return {
    updatedAt: new Date().toISOString(),
    byteSize: validation.byteSize,
    fingerprint: await sha256Hex(content),
    configCount: validation.configCount,
    protocolCounts: validation.protocolCounts,
    warningCount: validation.warnings.length,
  };
}

function validateSubscriptionContent(content) {
  const text = typeof content === "string" ? content : "";
  const byteSize = byteLength(text);
  const result = {
    byteSize,
    maxBytes: MAX_LINKS_BYTES,
    isEmpty: text.trim().length === 0,
    configCount: 0,
    protocolCounts: {},
    warnings: [],
    errors: [],
  };

  if (byteSize > MAX_LINKS_BYTES) {
    result.errors.push(`Content is ${formatBytes(byteSize)}, exceeding the 24 MiB save limit.`);
  }

  if (result.isEmpty) {
    result.warnings.push("Subscription is empty.");
    return result;
  }

  const seen = new Set();
  let index = 0;

  while (index < text.length) {
    index = skipWhitespace(text, index);
    if (index >= text.length) break;

    const char = text[index];
    if (char === "{" || char === "[") {
      const block = readJsonBlock(text, index);
      if (block.complete) {
        const rawBlock = text.slice(index, block.end);
        recordDuplicate(rawBlock.trim(), seen, result);
        recordJsonBlock(rawBlock, lineNumberAt(text, index), result);
        index = block.end;
        continue;
      }

      pushWarning(result, `Unclosed JSON block near line ${lineNumberAt(text, index)}.`);
      index = nextLineIndex(text, index);
      continue;
    }

    const lineEnd = nextLineIndex(text, index);
    const line = text.slice(index, lineEnd).trim();
    recordLine(line, lineNumberAt(text, index), seen, result);
    index = lineEnd + 1;
  }

  return result;
}

function recordLine(line, lineNumber, seen, result) {
  if (!line) return;

  const protocol = protocolFromLine(line);
  if (protocol && SUPPORTED_PROTOCOLS.includes(protocol)) {
    result.configCount += 1;
    result.protocolCounts[protocol] = (result.protocolCounts[protocol] || 0) + 1;
    recordDuplicate(line, seen, result);
    return;
  }

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(line)) {
    pushWarning(result, `Unsupported protocol on line ${lineNumber}: ${line.slice(0, 48)}`);
    return;
  }

  pushWarning(result, `Unknown content on line ${lineNumber}: ${line.slice(0, 48)}`);
}

function recordJsonBlock(rawBlock, lineNumber, result) {
  try {
    const parsed = JSON.parse(rawBlock);
    const count = Array.isArray(parsed) ? parsed.length : 1;
    if (Array.isArray(parsed) && count === 0) {
      pushWarning(result, `JSON array on line ${lineNumber} is empty.`);
    }
    result.configCount += Math.max(count, 0);
    result.protocolCounts.json = (result.protocolCounts.json || 0) + Math.max(count, 0);
  } catch (_error) {
    pushWarning(result, `Invalid JSON block near line ${lineNumber}.`);
  }
}

function recordDuplicate(value, seen, result) {
  if (!value) return;
  if (seen.has(value)) {
    pushWarning(result, `Duplicate entry detected: ${value.slice(0, 48)}`);
    return;
  }
  seen.add(value);
}

function protocolFromLine(line) {
  const match = /^([a-z][a-z0-9+.-]*):\/\//i.exec(line);
  return match ? match[1].toLowerCase() : "";
}

function readJsonBlock(text, start) {
  const opener = text[start];
  const stack = [opener];
  let inString = false;
  let escaped = false;

  for (let i = start + 1; i < text.length; i += 1) {
    const char = text[i];

    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === '"') {
        inString = false;
      }
      continue;
    }

    if (char === '"') {
      inString = true;
      continue;
    }

    if (char === "{" || char === "[") {
      stack.push(char);
      continue;
    }

    if (char === "}" || char === "]") {
      const expected = stack.pop();
      if ((char === "}" && expected !== "{") || (char === "]" && expected !== "[")) {
        return { complete: false, end: i + 1 };
      }
      if (!stack.length) return { complete: true, end: i + 1 };
    }
  }

  return { complete: false, end: text.length };
}

function skipWhitespace(text, index) {
  while (index < text.length && /\s/.test(text[index])) index += 1;
  return index;
}

function nextLineIndex(text, index) {
  const lineFeed = text.indexOf("\n", index);
  return lineFeed === -1 ? text.length : lineFeed;
}

function lineNumberAt(text, index) {
  let count = 1;
  for (let i = 0; i < index; i += 1) {
    if (text[i] === "\n") count += 1;
  }
  return count;
}

function pushWarning(result, message) {
  if (result.warnings.length < 50) result.warnings.push(message);
}

function generateAuthPage({ mode, nonce, error = "", warning = "" }) {
  const isSetup = mode === "setup";
  const title = isSetup ? "Set Admin Password" : "Admin Sign In";
  const action = isSetup ? "/admin/setup" : "/admin/login";
  const button = isSetup ? "Create Password" : "Sign In";
  const hint = isSetup
    ? "Create the first admin password for this Worker."
    : "Sign in to manage the public subscription output.";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${APP_NAME} - ${title}</title>
  <style nonce="${nonce}">${baseStyles()}</style>
</head>
<body class="auth-screen">
  <main class="auth-panel" aria-labelledby="auth-title">
    <div class="brand-mark" aria-hidden="true">SL</div>
    <h1 id="auth-title">${title}</h1>
    <p>${hint}</p>
    ${error ? `<div class="notice error">${escapeHtml(error)}</div>` : ""}
    ${warning ? `<div class="notice warning">${escapeHtml(warning)}</div>` : ""}
    <form method="POST" action="${action}" class="stack">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="${isSetup ? "new-password" : "current-password"}" required>
      <button class="primary-button" type="submit">${button}</button>
    </form>
  </main>
</body>
</html>`;
}

function generateAdminErrorPage({ nonce, title, details }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${APP_NAME} - Setup Required</title>
  <style nonce="${nonce}">${baseStyles()}</style>
</head>
<body class="auth-screen">
  <main class="auth-panel" aria-labelledby="error-title">
    <div class="brand-mark" aria-hidden="true">SL</div>
    <h1 id="error-title">${escapeHtml(title)}</h1>
    ${details.map((item) => `<p>${escapeHtml(item)}</p>`).join("")}
  </main>
</body>
</html>`;
}

function generateDashboardPage({
  nonce,
  csrfToken,
  links,
  hasBackup,
  meta,
  validation,
  subscriptionUrl,
  hasAuthSecret,
}) {
  const initialState = {
    csrfToken,
    hasBackup,
    meta,
    validation,
    subscriptionUrl,
    hasAuthSecret,
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="csrf-token" content="${escapeHtml(csrfToken)}">
  <title>${APP_NAME} - Admin</title>
  <style nonce="${nonce}">${baseStyles()}${dashboardStyles()}</style>
</head>
<body class="dashboard-screen">
  <header class="topbar">
    <div>
      <div class="eyebrow">Cloudflare Worker</div>
      <h1>${APP_NAME}</h1>
    </div>
    <div class="topbar-actions">
      <span id="save-state" class="state-pill clean">Saved</span>
      <button id="logout-button" class="ghost-button" type="button">Logout</button>
    </div>
  </header>

  <main class="workspace">
    <section class="editor-panel" aria-labelledby="editor-title">
      <div class="panel-header">
        <div>
          <h2 id="editor-title">Subscription Content</h2>
          <p>Public raw output is served from <code>/</code> and <code>/sub</code>.</p>
        </div>
        <div class="toolbar">
          <button id="import-button" class="ghost-button" type="button">Import</button>
          <button id="export-button" class="ghost-button" type="button">Export</button>
          <button id="validate-button" class="ghost-button" type="button">Validate</button>
          <button id="restore-button" class="ghost-button" type="button"${hasBackup ? "" : " disabled"}>Restore</button>
        </div>
      </div>

      <form id="links-form">
        <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
        <textarea id="links-box" name="links" spellcheck="false" placeholder="Paste vless://, vmess://, ss://, trojan://, hysteria2://, wireguard://, or JSON configs here.">${escapeHtml(links)}</textarea>
        <div class="editor-actions">
          <button id="clear-button" class="danger-button" type="button">Clear</button>
          <button id="save-button" class="primary-button" type="submit">Save Changes</button>
        </div>
      </form>
    </section>

    <aside class="status-rail" aria-label="Subscription status">
      <section class="stat-block">
        <h2>Status</h2>
        <div class="metric-grid">
          <div><span>Configs</span><strong id="config-count">${validation.configCount}</strong></div>
          <div><span>Size</span><strong id="byte-size">${escapeHtml(formatBytes(validation.byteSize))}</strong></div>
          <div><span>Warnings</span><strong id="warning-count">${validation.warnings.length}</strong></div>
          <div><span>Updated</span><strong id="updated-at">${escapeHtml(formatDate(meta.updatedAt))}</strong></div>
        </div>
      </section>

      <section class="stat-block">
        <h2>Public URL</h2>
        <div class="copy-row">
          <input id="subscription-url" value="${escapeHtml(subscriptionUrl)}" readonly>
          <button id="copy-button" class="ghost-button" type="button">Copy</button>
        </div>
        <p class="fine-print">Root output remains public by project choice. Cloudflare KV changes can take 60 seconds or more to appear globally.</p>
      </section>

      <section class="stat-block">
        <h2>Protocol Mix</h2>
        <div id="protocol-list" class="protocol-list"></div>
      </section>

      <section class="stat-block">
        <h2>Validation</h2>
        <div id="validation-list" class="validation-list"></div>
      </section>

      <section class="stat-block">
        <h2>Security</h2>
        <p id="auth-secret-state" class="fine-print"></p>
        <form id="password-form" class="stack compact">
          <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
          <label for="current-password">Current password</label>
          <input id="current-password" name="current_password" type="password" autocomplete="current-password">
          <label for="new-password">New password</label>
          <input id="new-password" name="new_password" type="password" autocomplete="new-password">
          <button class="ghost-button" type="submit">Change Password</button>
        </form>
      </section>
    </aside>
  </main>

  <div id="notifications" aria-live="polite" aria-atomic="true"></div>
  <input id="file-input" type="file" accept=".txt,.json" hidden>
  <script id="sublink-state" type="application/json" nonce="${nonce}">${safeJsonForScript(initialState)}</script>
  <script nonce="${nonce}">${dashboardScript()}</script>
</body>
</html>`;
}

function baseStyles() {
  return `
:root {
  color-scheme: dark;
  --bg: #090b0f;
  --surface: #111620;
  --surface-2: #171e2a;
  --border: #263244;
  --text: #f5f7fb;
  --muted: #9aa7b8;
  --accent: #20d0a8;
  --accent-2: #5aa7ff;
  --danger: #ff5c7a;
  --warning: #f0b84d;
  --ok: #39d98a;
  --shadow: 0 20px 50px rgba(0, 0, 0, 0.28);
}
* { box-sizing: border-box; }
html, body { min-height: 100%; }
body {
  margin: 0;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: var(--bg);
  color: var(--text);
}
button, input, textarea {
  font: inherit;
}
button {
  border: 0;
}
code {
  color: var(--accent);
}
.auth-screen {
  display: grid;
  place-items: center;
  min-height: 100vh;
  padding: 24px;
  background:
    linear-gradient(180deg, rgba(32, 208, 168, 0.08), transparent 40%),
    var(--bg);
}
.auth-panel {
  width: min(440px, 100%);
  padding: 32px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  box-shadow: var(--shadow);
}
.brand-mark {
  display: grid;
  place-items: center;
  width: 48px;
  height: 48px;
  margin-bottom: 20px;
  border-radius: 8px;
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  color: #07100d;
  font-weight: 800;
}
h1, h2, p {
  margin-top: 0;
}
h1 {
  margin-bottom: 8px;
  font-size: clamp(26px, 5vw, 36px);
  letter-spacing: 0;
}
h2 {
  margin-bottom: 8px;
  font-size: 16px;
  letter-spacing: 0;
}
p {
  color: var(--muted);
  line-height: 1.6;
}
label {
  color: var(--muted);
  font-size: 13px;
  font-weight: 600;
}
input, textarea {
  width: 100%;
  color: var(--text);
  background: #090d14;
  border: 1px solid var(--border);
  border-radius: 6px;
  outline: none;
}
input {
  min-height: 42px;
  padding: 10px 12px;
}
textarea {
  min-height: 58vh;
  padding: 16px;
  resize: vertical;
  font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
  font-size: 13px;
  line-height: 1.55;
  white-space: pre;
}
input:focus, textarea:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(32, 208, 168, 0.12);
}
.primary-button, .ghost-button, .danger-button {
  min-height: 38px;
  padding: 9px 14px;
  border-radius: 6px;
  color: var(--text);
  cursor: pointer;
  transition: background 160ms ease, border-color 160ms ease, transform 160ms ease;
}
.primary-button {
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  color: #06100d;
  font-weight: 800;
}
.ghost-button {
  background: var(--surface-2);
  border: 1px solid var(--border);
}
.danger-button {
  background: rgba(255, 92, 122, 0.12);
  border: 1px solid rgba(255, 92, 122, 0.5);
  color: #ffd4dd;
}
button:hover:not(:disabled) {
  transform: translateY(-1px);
}
button:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}
.stack {
  display: grid;
  gap: 12px;
}
.compact {
  gap: 8px;
}
.notice {
  margin: 16px 0;
  padding: 12px;
  border-radius: 6px;
  font-size: 13px;
  line-height: 1.5;
}
.notice.error {
  background: rgba(255, 92, 122, 0.12);
  border: 1px solid rgba(255, 92, 122, 0.45);
}
.notice.warning {
  background: rgba(240, 184, 77, 0.12);
  border: 1px solid rgba(240, 184, 77, 0.45);
}`;
}

function dashboardStyles() {
  return `
.dashboard-screen {
  min-height: 100vh;
}
.topbar {
  position: sticky;
  top: 0;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 16px 24px;
  background: rgba(9, 11, 15, 0.92);
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(16px);
}
.topbar h1 {
  margin: 0;
  font-size: 22px;
}
.eyebrow {
  margin-bottom: 3px;
  color: var(--accent);
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0;
  text-transform: uppercase;
}
.topbar-actions, .toolbar, .editor-actions, .copy-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.state-pill {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 12px;
  border: 1px solid var(--border);
  color: var(--muted);
}
.state-pill.dirty {
  color: #171103;
  background: var(--warning);
  border-color: var(--warning);
}
.state-pill.clean {
  color: #04140d;
  background: var(--ok);
  border-color: var(--ok);
}
.state-pill.error {
  color: #fff;
  background: var(--danger);
  border-color: var(--danger);
}
.workspace {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 360px;
  gap: 18px;
  width: min(1500px, 100%);
  margin: 0 auto;
  padding: 18px;
}
.editor-panel, .stat-block {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  box-shadow: var(--shadow);
}
.editor-panel {
  min-width: 0;
  overflow: hidden;
}
.panel-header {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  padding: 18px;
  border-bottom: 1px solid var(--border);
}
.panel-header p {
  margin-bottom: 0;
  font-size: 13px;
}
#links-form {
  padding: 18px;
}
.editor-actions {
  justify-content: flex-end;
  margin-top: 12px;
}
.status-rail {
  display: grid;
  align-content: start;
  gap: 14px;
}
.stat-block {
  padding: 16px;
}
.metric-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
}
.metric-grid div {
  padding: 12px;
  background: #0c1119;
  border: 1px solid var(--border);
  border-radius: 6px;
}
.metric-grid span {
  display: block;
  margin-bottom: 6px;
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
}
.metric-grid strong {
  font-size: 18px;
}
.copy-row input {
  min-width: 0;
  font-size: 12px;
}
.fine-print {
  margin: 10px 0 0;
  font-size: 12px;
}
.protocol-list, .validation-list {
  display: grid;
  gap: 8px;
}
.protocol-row, .validation-item {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 9px 10px;
  background: #0c1119;
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--muted);
  font-size: 13px;
}
.validation-item {
  display: block;
  line-height: 1.45;
}
.validation-item.warning {
  border-color: rgba(240, 184, 77, 0.45);
  color: #ffe2a8;
}
.validation-item.error {
  border-color: rgba(255, 92, 122, 0.55);
  color: #ffd4dd;
}
#notifications {
  position: fixed;
  top: 78px;
  right: 18px;
  z-index: 20;
  display: grid;
  gap: 10px;
  width: min(360px, calc(100vw - 36px));
}
.toast {
  padding: 12px 14px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  border-radius: 6px;
  box-shadow: var(--shadow);
  color: var(--text);
  font-size: 13px;
}
.toast.error {
  border-left-color: var(--danger);
}
@media (max-width: 980px) {
  .workspace {
    grid-template-columns: 1fr;
  }
  textarea {
    min-height: 46vh;
  }
}
@media (max-width: 680px) {
  .topbar, .panel-header, .toolbar, .editor-actions {
    align-items: stretch;
    flex-direction: column;
  }
  .topbar-actions {
    width: 100%;
    justify-content: space-between;
  }
  .workspace {
    padding: 10px;
  }
  .metric-grid {
    grid-template-columns: 1fr;
  }
}`;
}

function dashboardScript() {
  return `
(function () {
  "use strict";

  const state = JSON.parse(document.getElementById("sublink-state").textContent);
  const csrfToken = state.csrfToken;
  const linksBox = document.getElementById("links-box");
  const linksForm = document.getElementById("links-form");
  const saveState = document.getElementById("save-state");
  const saveButton = document.getElementById("save-button");
  const fileInput = document.getElementById("file-input");
  let lastSavedValue = linksBox.value;
  let latestValidation = state.validation;

  function byteLength(value) {
    return new TextEncoder().encode(value).length;
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KiB";
    return (bytes / 1024 / 1024).toFixed(2) + " MiB";
  }

  function protocolFromLine(line) {
    const match = /^([a-z][a-z0-9+.-]*):\\/\\//i.exec(line);
    return match ? match[1].toLowerCase() : "";
  }

  function analyzeContent(content) {
    const supported = ${JSON.stringify(SUPPORTED_PROTOCOLS)};
    const lines = content.split(/\\r?\\n/);
    const protocolCounts = {};
    const warnings = [];
    const errors = [];
    const seen = new Set();
    let configCount = 0;
    const trimmed = content.trim();
    const bytes = byteLength(content);

    if (bytes > ${MAX_LINKS_BYTES}) {
      errors.push("Content exceeds the 24 MiB save limit.");
    }
    if (!trimmed) {
      warnings.push("Subscription is empty.");
      return { byteSize: bytes, isEmpty: true, configCount, protocolCounts, warnings, errors };
    }

    if ((trimmed.startsWith("{") || trimmed.startsWith("["))) {
      try {
        const parsed = JSON.parse(trimmed);
        const count = Array.isArray(parsed) ? parsed.length : 1;
        configCount += count;
        protocolCounts.json = count;
        return { byteSize: bytes, isEmpty: false, configCount, protocolCounts, warnings, errors };
      } catch (_error) {
        warnings.push("Top-level JSON could not be parsed; line checks will continue.");
      }
    }

    lines.forEach(function (line, index) {
      const value = line.trim();
      if (!value) return;
      if (seen.has(value)) warnings.push("Duplicate entry detected on line " + (index + 1) + ".");
      seen.add(value);
      const protocol = protocolFromLine(value);
      if (protocol && supported.includes(protocol)) {
        configCount += 1;
        protocolCounts[protocol] = (protocolCounts[protocol] || 0) + 1;
      } else if (protocol) {
        warnings.push("Unsupported protocol on line " + (index + 1) + ": " + protocol);
      } else if (value.startsWith("{") || value.startsWith("[")) {
        warnings.push("JSON block detected on line " + (index + 1) + "; server will validate the full block on save.");
        configCount += 1;
        protocolCounts.json = (protocolCounts.json || 0) + 1;
      } else {
        warnings.push("Unknown content on line " + (index + 1) + ".");
      }
    });

    return { byteSize: bytes, isEmpty: false, configCount, protocolCounts, warnings: warnings.slice(0, 50), errors };
  }

  function setSaveState(mode, label) {
    saveState.className = "state-pill " + mode;
    saveState.textContent = label;
  }

  function renderStats(validation, meta) {
    latestValidation = validation;
    document.getElementById("config-count").textContent = validation.configCount;
    document.getElementById("byte-size").textContent = formatBytes(validation.byteSize);
    document.getElementById("warning-count").textContent = validation.warnings.length + validation.errors.length;
    if (meta && meta.updatedAt) {
      document.getElementById("updated-at").textContent = new Date(meta.updatedAt).toLocaleString();
    }

    const protocolList = document.getElementById("protocol-list");
    const protocols = Object.entries(validation.protocolCounts || {});
    protocolList.textContent = "";
    if (!protocols.length) {
      const item = document.createElement("div");
      item.className = "protocol-row";
      item.textContent = "No protocols detected";
      protocolList.appendChild(item);
    } else {
      protocols.sort().forEach(function (entry) {
        const row = document.createElement("div");
        row.className = "protocol-row";
        const name = document.createElement("span");
        const count = document.createElement("strong");
        name.textContent = entry[0];
        count.textContent = entry[1];
        row.append(name, count);
        protocolList.appendChild(row);
      });
    }

    const validationList = document.getElementById("validation-list");
    validationList.textContent = "";
    const messages = []
      .concat((validation.errors || []).map(function (message) { return { type: "error", message }; }))
      .concat((validation.warnings || []).map(function (message) { return { type: "warning", message }; }));
    if (!messages.length) {
      const item = document.createElement("div");
      item.className = "validation-item";
      item.textContent = "No validation issues detected.";
      validationList.appendChild(item);
    } else {
      messages.forEach(function (entry) {
        const item = document.createElement("div");
        item.className = "validation-item " + entry.type;
        item.textContent = entry.message;
        validationList.appendChild(item);
      });
    }
  }

  function toast(message, type) {
    const node = document.createElement("div");
    node.className = "toast " + (type || "");
    node.textContent = message;
    document.getElementById("notifications").appendChild(node);
    setTimeout(function () { node.remove(); }, 5000);
  }

  async function postForm(url, form) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "x-csrf-token": csrfToken },
      body: form,
    });
    const body = await response.json().catch(function () {
      return { ok: false, error: "Unexpected response." };
    });
    if (!response.ok || !body.ok) {
      throw new Error(body.error || "Request failed.");
    }
    return body;
  }

  async function postJson(url, data) {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-csrf-token": csrfToken,
      },
      body: JSON.stringify(data),
    });
    const body = await response.json().catch(function () {
      return { ok: false, error: "Unexpected response." };
    });
    if (!response.ok || !body.ok) {
      throw new Error(body.error || "Request failed.");
    }
    return body;
  }

  linksBox.addEventListener("input", function () {
    const validation = analyzeContent(linksBox.value);
    renderStats(validation, null);
    if (linksBox.value === lastSavedValue) {
      setSaveState("clean", "Saved");
    } else {
      setSaveState("dirty", "Unsaved");
    }
  });

  linksForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    const validation = analyzeContent(linksBox.value);
    if (validation.isEmpty && !confirm("Save an empty public subscription?")) {
      return;
    }

    const payload = {
      csrf_token: csrfToken,
      links: linksBox.value,
      confirm_empty: validation.isEmpty ? "true" : "false",
    };
    saveButton.disabled = true;
    setSaveState("dirty", "Saving");

    try {
      const body = await postJson("/update-links", payload);
      lastSavedValue = linksBox.value;
      renderStats(body.validation, body.meta);
      setSaveState("clean", "Saved");
      document.getElementById("restore-button").disabled = false;
      toast("Subscription saved. Edge caches may take a little time to converge.");
    } catch (error) {
      setSaveState("error", "Error");
      toast(error.message, "error");
    } finally {
      saveButton.disabled = false;
    }
  });

  document.getElementById("validate-button").addEventListener("click", function () {
    renderStats(analyzeContent(linksBox.value), null);
    toast("Validation refreshed.");
  });

  document.getElementById("clear-button").addEventListener("click", function () {
    if (confirm("Clear the editor? Save is still required afterward.")) {
      linksBox.value = "";
      linksBox.dispatchEvent(new Event("input"));
    }
  });

  document.getElementById("import-button").addEventListener("click", function () {
    fileInput.click();
  });

  fileInput.addEventListener("change", function () {
    const file = fileInput.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function () {
      linksBox.value = String(reader.result || "");
      linksBox.dispatchEvent(new Event("input"));
      toast("Imported " + file.name + ".");
      fileInput.value = "";
    };
    reader.readAsText(file);
  });

  document.getElementById("export-button").addEventListener("click", function () {
    const blob = new Blob([linksBox.value], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "sublink-config.txt";
    anchor.click();
    URL.revokeObjectURL(url);
    toast("Export started.");
  });

  document.getElementById("restore-button").addEventListener("click", async function () {
    if (!confirm("Restore the previous saved subscription? Current content becomes the new backup.")) return;
    const form = new FormData();
    form.set("csrf_token", csrfToken);
    try {
      const body = await postForm("/restore-backup", form);
      linksBox.value = body.links;
      lastSavedValue = body.links;
      renderStats(body.validation, body.meta);
      setSaveState("clean", "Saved");
      toast("Backup restored.");
    } catch (error) {
      toast(error.message, "error");
    }
  });

  document.getElementById("copy-button").addEventListener("click", async function () {
    const input = document.getElementById("subscription-url");
    try {
      await navigator.clipboard.writeText(input.value);
    } catch (_error) {
      input.select();
      document.execCommand("copy");
    }
    toast("Public subscription URL copied.");
  });

  document.getElementById("logout-button").addEventListener("click", async function () {
    const form = new FormData();
    form.set("csrf_token", csrfToken);
    try {
      await postForm("/admin/logout", form);
      window.location.href = "/admin";
    } catch (error) {
      toast(error.message, "error");
    }
  });

  document.getElementById("password-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await postForm("/admin/password", form);
      event.currentTarget.reset();
      toast("Password changed.");
    } catch (error) {
      toast(error.message, "error");
    }
  });

  document.getElementById("auth-secret-state").textContent = state.hasAuthSecret
    ? "AUTH_SECRET is configured for HMAC password protection."
    : "AUTH_SECRET is not configured; salted SHA-256 fallback is active.";

  renderStats(latestValidation, state.meta);
})();
`;
}

function htmlResponse(html, { nonce, status = 200, headers = {} } = {}) {
  const responseHeaders = secureHtmlHeaders(nonce);
  for (const [key, value] of Object.entries(headers)) {
    responseHeaders.set(key, value);
  }
  return new Response(html, { status, headers: responseHeaders });
}

function jsonResponse(body, { status = 200, headers = {} } = {}) {
  const responseHeaders = new Headers({
    "content-type": "application/json; charset=UTF-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  });
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === "set-cookie") {
      responseHeaders.append(key, value);
    } else {
      responseHeaders.set(key, value);
    }
  }
  return new Response(JSON.stringify(body), { status, headers: responseHeaders });
}

function textResponse(text, { status = 200, headers = {} } = {}) {
  return new Response(text, {
    status,
    headers: {
      "content-type": "text/plain; charset=UTF-8",
      "x-content-type-options": "nosniff",
      ...headers,
    },
  });
}

function secureHtmlHeaders(nonce) {
  return new Headers({
    "content-type": "text/html; charset=UTF-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "content-security-policy": [
      "default-src 'none'",
      `script-src 'nonce-${nonce}'`,
      `style-src 'nonce-${nonce}'`,
      "connect-src 'self'",
      "form-action 'self'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
    ].join("; "),
  });
}

function methodNotAllowed(allowed) {
  return textResponse("Method not allowed", {
    status: 405,
    headers: {
      allow: allowed.join(", "),
      "cache-control": "no-store",
    },
  });
}

function redirectToAdmin(cookie = "") {
  const headers = new Headers({
    location: "/admin",
    "cache-control": "no-store",
  });
  if (cookie) headers.append("set-cookie", cookie);
  return new Response(null, { status: 303, headers });
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeJsonForScript(value) {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function byteLength(value) {
  return encodeText(value).length;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MiB`;
}

function formatDate(value) {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Never";
  return date.toLocaleString("en-US", { hour12: false });
}

function encodeText(value) {
  return new TextEncoder().encode(String(value));
}

function randomBase64Url(size) {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return base64UrlEncodeBytes(bytes);
}

function base64UrlEncodeBytes(bytes) {
  let base64;
  if (typeof Buffer !== "undefined") {
    base64 = Buffer.from(bytes).toString("base64");
  } else {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    base64 = btoa(binary);
  }
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", encodeText(value));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function constantTimeEqual(left, right) {
  const a = String(left);
  const b = String(right);
  let mismatch = a.length ^ b.length;
  const length = Math.max(a.length, b.length);

  for (let i = 0; i < length; i += 1) {
    const ca = i < a.length ? a.charCodeAt(i) : 0;
    const cb = i < b.length ? b.charCodeAt(i) : 0;
    mismatch |= ca ^ cb;
  }

  return mismatch === 0;
}

if (typeof addEventListener !== "function") {
  globalThis.__SUBLINK_WORKER_TESTS__ = {
    handleRequest,
    validateSubscriptionContent,
    createPasswordRecord,
    verifyPasswordEntry,
    loadPasswordEntry,
    escapeHtml,
    SESSION_COOKIE,
  };
}
