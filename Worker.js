const APP_NAME = "SubLink Worker";
const APP_VERSION = "2.0.0";
const SESSION_COOKIE = "__Host-sublink_session";
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const LOGIN_WINDOW_SECONDS = 15 * 60;
const LOGIN_MAX_FAILURES = 8;
const MAX_LINKS_BYTES = 24 * 1024 * 1024;
const PBKDF2_ITERATIONS = 100000;

const SUPPORTED_PROTOCOLS = [
  "vless",
  "vmess",
  "ss",
  "ssr",
  "trojan",
  "hysteria2",
  "hy2",
  "hysteria",
  "tuic",
  "wireguard",
  "wg",
  "socks5",
  "socks",
  "http",
  "https",
];

// Clients whose subscriptions are conventionally base64-encoded link lists.
// Clash/Stash are deliberately excluded: they require YAML, which this worker
// does not generate, so serving them base64 would only produce garbage.
const KNOWN_B64_CLIENT_AGENTS = [
  "v2rayn",
  "v2rayng",
  "shadowrocket",
  "quantumult",
  "streisand",
  "loon",
  "surfboard",
  "kitsunebi",
  "sagernet",
  "nekobox",
  "sing-box",
  "hiddify",
];

// Dual runtime support. The Service Worker listener below only fires on legacy
// SW-format deployments; ES Module workers exclusively use the default export,
// where this listener is inert. Keeping both lets the same file deploy either way.
if (typeof addEventListener === "function") {
  addEventListener("fetch", (event) => {
    event.respondWith(handleRequest(event.request, getDefaultEnv()));
  });
}

export default {
  async fetch(request, env = {}, ctx) {
    return handleRequest(request, env);
  },
};

async function handleRequest(request, env = getDefaultEnv()) {
  const url = new URL(request.url);
  const path = normalizePath(url.pathname);

  try {
    const isReadMethod = request.method === "GET" || request.method === "HEAD";
    const notFound = () =>
      textResponse("Not found", {
        status: 404,
        headers: { "cache-control": "no-store" },
      });

    if (path === "/favicon.ico") {
      return isReadMethod
        ? new Response(null, { status: 204 })
        : methodNotAllowed(["GET", "HEAD"]);
    }

    if (path === "/" || path === "/sub") {
      if (!isReadMethod) return methodNotAllowed(["GET", "HEAD"]);
      // With SUB_TOKEN configured the public root stops serving the feed;
      // the subscription moves to /sub/<token> only.
      if (hasSubToken(env)) return notFound();
      return generateSubscription(request, env);
    }

    if (path.startsWith("/sub/")) {
      if (!isReadMethod) return methodNotAllowed(["GET", "HEAD"]);
      if (!hasSubToken(env)) return notFound();
      const token = decodeURIComponentSafe(path.slice("/sub/".length));
      if (!token || !constantTimeEqual(token, env.SUB_TOKEN.trim())) return notFound();
      return generateSubscription(request, env);
    }

    if (path === "/admin") {
      return isReadMethod
        ? handleAdminPage(request, env)
        : methodNotAllowed(["GET", "HEAD"]);
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

    return notFound();
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
    sub: typeof sub !== "undefined" ? sub : null,
    AUTH_SECRET: typeof AUTH_SECRET !== "undefined" ? String(AUTH_SECRET || "") : "",
    SUB_TOKEN: typeof SUB_TOKEN !== "undefined" && SUB_TOKEN ? String(SUB_TOKEN) : "",
  };
}

function normalizePath(pathname) {
  let path = pathname || "/";
  while (path.length > 1 && path.endsWith("/")) {
    path = path.slice(0, -1);
  }
  return path;
}

function getKV(env) {
  if (env && env.sub && typeof env.sub.get === "function") return env.sub;
  if (typeof sub !== "undefined" && sub && typeof sub.get === "function") return sub;
  return null;
}

function hasAuthSecret(env) {
  return !!(env && typeof env.AUTH_SECRET === "string" && env.AUTH_SECRET.trim());
}

function hasSubToken(env) {
  // Opt-in private feed. A token shorter than 16 chars is ignored so weak
  // values cannot silently weaken the default public behavior.
  return !!(env && typeof env.SUB_TOKEN === "string" && env.SUB_TOKEN.trim().length >= 16);
}

function authSecretWarning(env) {
  return hasAuthSecret(env)
    ? ""
    : "Optional AUTH_SECRET is not configured. PBKDF2 hashing is active, but AUTH_SECRET provides extra defense-in-depth.";
}

// ---------------------------------------------------------------------------
// Route Handlers
// ---------------------------------------------------------------------------

async function handleAdminPage(request, env) {
  const nonce = randomBase64Url(18);
  const kv = getKV(env);

  if (!kv) {
    return htmlResponse(
      generateAdminErrorPage({
        nonce,
        title: "KV binding missing",
        details: [
          'Create a Cloudflare KV namespace and bind it to this Worker with the variable name "sub".',
          "The public subscription and settings cannot be saved until this binding exists.",
        ],
      }),
      { nonce, status: 503 }
    );
  }

  const passwordEntry = await loadPasswordEntry(kv);
  if (passwordEntry.kind === "missing") {
    return htmlResponse(
      generateAuthPage({
        mode: "setup",
        nonce,
        warning: authSecretWarning(env),
      }),
      { nonce }
    );
  }

  const session = await getSession(request, kv);
  if (!session) {
    return htmlResponse(
      generateAuthPage({
        mode: "login",
        nonce,
        warning: authSecretWarning(env),
      }),
      { nonce }
    );
  }

  const links = await kvGet(kv, "vpn_links", "");
  const backup = await kvGet(kv, "vpn_links_backup", null);
  const storedMeta = await kvGetJson(kv, "vpn_meta", null);

  // Prefer fingerprint-verified cached metadata over a full re-parse so large
  // subscriptions do not burn CPU limits on every dashboard load.
  const fingerprint = await sha256Hex(links);
  let validation;
  if (
    storedMeta &&
    storedMeta.fingerprint === fingerprint &&
    Array.isArray(storedMeta.warnings) &&
    Array.isArray(storedMeta.errors)
  ) {
    validation = {
      byteSize: typeof storedMeta.byteSize === "number" ? storedMeta.byteSize : byteLength(links),
      maxBytes: MAX_LINKS_BYTES,
      isEmpty: links.trim().length === 0,
      configCount: Number(storedMeta.configCount || 0),
      protocolCounts: storedMeta.protocolCounts || {},
      warnings: storedMeta.warnings,
      errors: storedMeta.errors,
    };
  } else {
    validation = validateSubscriptionContent(links);
  }

  const meta = storedMeta || (await buildMetadata(links, validation));
  const url = new URL(request.url);
  const subBase = hasSubToken(env)
    ? `${url.origin}/sub/${encodeURIComponent(env.SUB_TOKEN.trim())}`
    : `${url.origin}/`;

  return htmlResponse(
    generateDashboardPage({
      nonce,
      csrfToken: session.data.csrfToken,
      links,
      hasBackup: backup !== null,
      meta,
      validation,
      subscriptionUrl: subBase,
      base64Url: `${subBase}?b64=1`,
      hasAuthSecret: hasAuthSecret(env),
    }),
    { nonce }
  );
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
    return htmlResponse(
      generateAuthPage({
        mode: "setup",
        nonce,
        error: validationError,
        warning: authSecretWarning(env),
      }),
      { nonce, status: 400 }
    );
  }

  // Narrow the first-setup race: KV has no compare-and-swap, so re-check
  // immediately before committing. Concurrent setups remain theoretically
  // possible but the window shrinks to a single round-trip.
  const recheck = await loadPasswordEntry(kv);
  if (recheck.kind !== "missing") {
    return jsonResponse({ ok: false, error: "Admin password is already set." }, { status: 409 });
  }

  const record = await createPasswordRecord(password, env);
  await kv.put("admin_password", JSON.stringify(record));
  const session = await createSession(kv);
  return redirectToAdmin(session.cookie);
}

async function handleLogin(request, env) {
  const kv = getKV(env);
  const nonce = randomBase64Url(18);
  if (!kv) {
    return htmlResponse(
      generateAdminErrorPage({
        nonce,
        title: "KV binding missing",
        details: ['Bind a KV namespace named "sub" before signing in.'],
      }),
      { nonce, status: 503 }
    );
  }

  const clientKey = await loginThrottleKey(request);
  const throttle = await readLoginThrottle(kv, clientKey);
  if (throttle.blocked) {
    return htmlResponse(
      generateAuthPage({
        mode: "login",
        nonce,
        error: "Too many sign-in attempts. Try again in 15 minutes.",
        warning: authSecretWarning(env),
      }),
      { nonce, status: 429, headers: { "retry-after": String(LOGIN_WINDOW_SECONDS) } }
    );
  }

  const form = await safeFormData(request);
  const password = getFormString(form, "password");
  const entry = await loadPasswordEntry(kv);

  if (entry.kind === "missing") {
    return redirectToAdmin();
  }

  const verification = await verifyPasswordEntry(password, entry, env);
  if (verification.pepperMismatch) {
    // The stored hash is bound to a different AUTH_SECRET. Say so plainly
    // instead of looping on "Invalid credentials" forever.
    return htmlResponse(
      generateAuthPage({
        mode: "login",
        nonce,
        error:
          'AUTH_SECRET changed since this password was saved. Sign-in stays disabled until the stored credential is reset (delete the "admin_password" key in KV, then reload this page).',
        warning: authSecretWarning(env),
      }),
      { nonce, status: 401 }
    );
  }
  if (!verification.ok) {
    await recordLoginFailure(kv, clientKey, throttle.count);
    return htmlResponse(
      generateAuthPage({
        mode: "login",
        nonce,
        error: "Invalid credentials.",
        warning: authSecretWarning(env),
      }),
      { nonce, status: 401 }
    );
  }

  // Transparently rehash legacy or v2 passwords to modern PBKDF2
  if (!verification.migrated) {
    const modernRecord = await createPasswordRecord(password, env);
    await kv.put("admin_password", JSON.stringify(modernRecord));
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

  // Throttle guesses of the current password (shares the per-IP login budget).
  const throttleKey = await loginThrottleKey(request);
  const throttle = await readLoginThrottle(kv, throttleKey);
  if (throttle.blocked) {
    return jsonResponse(
      { ok: false, error: "Too many attempts. Try again in 15 minutes." },
      { status: 429, headers: { "retry-after": String(LOGIN_WINDOW_SECONDS) } }
    );
  }

  const currentPassword = getFormString(form, "current_password");
  const newPassword = getFormString(form, "new_password");
  const validationError = validatePassword(newPassword);
  if (validationError) {
    return jsonResponse({ ok: false, error: validationError }, { status: 400 });
  }

  const entry = await loadPasswordEntry(kv);
  const verification = await verifyPasswordEntry(currentPassword, entry, env);
  if (!verification.ok) {
    if (!verification.pepperMismatch) {
      await recordLoginFailure(kv, throttleKey, throttle.count);
    }
    return jsonResponse(
      {
        ok: false,
        error: verification.pepperMismatch
          ? "Stored credentials are tied to a different AUTH_SECRET."
          : "Current password did not match.",
      },
      { status: 401 }
    );
  }

  const record = await createPasswordRecord(newPassword, env);
  await kv.put("admin_password", JSON.stringify(record));
  await clearLoginThrottle(kv, throttleKey);

  // Rotating the password invalidates every session, including the current
  // one — a stolen cookie cannot survive a credential change.
  await revokeAllSessions(kv);

  return jsonResponse({
    ok: true,
    message: "Password updated. All devices were signed out.",
    signedOut: true,
  });
}

async function handleUpdateLinks(request, env) {
  const kv = getKV(env);
  if (!kv) return jsonResponse({ ok: false, error: "KV binding missing." }, { status: 503 });

  // Authenticate BEFORE parsing the (potentially large) request body so
  // unauthenticated callers cannot force multipart/JSON parse work.
  const session = await getSession(request, kv);
  if (!session) {
    return jsonResponse({ ok: false, error: "Authentication required." }, { status: 401 });
  }

  const input = await safeRequestInput(request);
  if (!input) {
    return jsonResponse({ ok: false, error: "Malformed request body." }, { status: 400 });
  }
  if (!hasInputField(input, "links")) {
    return jsonResponse({ ok: false, error: "Malformed request: missing links field." }, { status: 400 });
  }

  const headerToken = request.headers.get("x-csrf-token") || "";
  const provided = headerToken || getFormString(input, "csrf_token");
  if (!provided || !constantTimeEqual(provided, session.data.csrfToken)) {
    return jsonResponse({ ok: false, error: "CSRF token missing or invalid." }, { status: 403 });
  }

  const links = getFormString(input, "links");
  const confirmEmpty = getFormBoolean(input, "confirm_empty");
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
  if (previousLinks === links) {
    // Byte-identical save: refresh metadata only if missing, skip the rewrites.
    let meta = await kvGetJson(kv, "vpn_meta", null);
    if (!meta) {
      meta = await buildMetadata(links, validation);
      await kv.put("vpn_meta", JSON.stringify(meta));
    }
    return jsonResponse({ ok: true, meta, validation, unchanged: true });
  }

  await kv.put("vpn_links_backup", previousLinks);

  const meta = await buildMetadata(links, validation);
  // Commit order matters: metadata first, links last. If any write fails
  // midway, vpn_links still pairs with a vpn_meta of the matching fingerprint.
  await kv.put("vpn_meta", JSON.stringify(meta));
  await kv.put("vpn_links", links);

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

  const validation = validateSubscriptionContent(backup);
  const meta = await buildMetadata(backup, validation);
  // Same commit order as update-links: metadata first, links last.
  await kv.put("vpn_meta", JSON.stringify(meta));
  await kv.put("vpn_links", backup);

  return jsonResponse({ ok: true, links: backup, meta, validation });
}

async function generateSubscription(request, env) {
  const kv = getKV(env);
  if (!kv) {
    return textResponse("KV binding missing. Bind a namespace named sub.", {
      status: 503,
      headers: { "cache-control": "no-store" },
    });
  }

  const rawContent = await kvGet(kv, "vpn_links", "");
  const url = new URL(request.url);
  const userAgent = (request.headers.get("User-Agent") || "").toLowerCase();

  const wantsBase64 =
    url.searchParams.get("b64") === "1" ||
    url.searchParams.get("format") === "base64" ||
    KNOWN_B64_CLIENT_AGENTS.some((agent) => userAgent.includes(agent));

  let body = rawContent;
  let filename = "subscription.txt";

  if (wantsBase64 && rawContent.trim()) {
    body = base64EncodeUtf8(rawContent);
    filename = "subscription.b64";
  }

  return textResponse(body, {
    headers: {
      "cache-control": "no-store",
      // Body depends on User-Agent negotiation, so caches must key on it.
      vary: "User-Agent",
      "profile-update-interval": "24",
      // No subscription-userinfo header: fabricated zero quotas render as an
      // "expired"/empty account badge in several clients.
      "content-disposition": `inline; filename="${filename}"`,
      "profile-title": "SubLink Subscription",
    },
  });
}

// ---------------------------------------------------------------------------
// Helpers & Data Access
// ---------------------------------------------------------------------------

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

function getFormBoolean(form, key) {
  if (!form) return false;
  let value;
  if (typeof form.get === "function") {
    if (!form.has(key)) return false;
    value = form.get(key);
  } else {
    if (!Object.prototype.hasOwnProperty.call(form, key)) return false;
    value = form[key];
  }
  if (value === true) return true;
  if (typeof value === "string") {
    return ["true", "1", "yes", "on"].includes(value.trim().toLowerCase());
  }
  return false;
}

function validatePassword(password) {
  if (!password) return "Password is required.";
  if (password.length < 8) return "Password must be at least 8 characters long.";
  return "";
}

// ---------------------------------------------------------------------------
// Security & Authentication
// ---------------------------------------------------------------------------

async function loadPasswordEntry(kv) {
  const raw = await kvGet(kv, "admin_password", null);
  if (raw === null || raw === "") return { kind: "missing" };

  try {
    const parsed = JSON.parse(raw);
    if (parsed && parsed.salt && parsed.hash) {
      return { kind: "hashed", record: parsed };
    }
  } catch (_error) {
    // Legacy plaintext password format
  }

  return { kind: "legacy", password: raw };
}

async function currentPepperId(env) {
  if (!hasAuthSecret(env)) return "";
  // Short non-secret identifier of the current pepper, stored WITH the hash so
  // an AUTH_SECRET rotation is detected instead of surfacing as a bad password.
  return (await sha256Hex(`pepper-id:${env.AUTH_SECRET}`)).slice(0, 16);
}

async function createPasswordRecord(password, env) {
  const saltBytes = new Uint8Array(16);
  crypto.getRandomValues(saltBytes);
  const salt = base64UrlEncodeBytes(saltBytes);

  const hash = await hashPasswordPBKDF2(password, salt, env);

  return {
    version: 3,
    algorithm: "pbkdf2-sha256",
    iterations: PBKDF2_ITERATIONS,
    salt,
    hash,
    pepperId: await currentPepperId(env),
    createdAt: new Date().toISOString(),
  };
}

async function verifyPasswordEntry(password, entry, env) {
  if (!entry || entry.kind === "missing") return { ok: false };

  if (entry.kind === "legacy") {
    return { ok: constantTimeEqual(password, entry.password), migrated: false };
  }

  const record = entry.record;

  // v3: PBKDF2
  if (record.version === 3 || record.algorithm === "pbkdf2-sha256") {
    const expectedPepper = await currentPepperId(env);
    if ((record.pepperId || "") !== expectedPepper) {
      return { ok: false, migrated: false, pepperMismatch: true };
    }
    const computed = await hashPasswordPBKDF2(password, record.salt, env, record.iterations || PBKDF2_ITERATIONS);
    return { ok: constantTimeEqual(computed, record.hash), migrated: true };
  }

  // v2: Legacy salted SHA-256 or HMAC
  if (record.version === 2) {
    if (record.algorithm === "hmac-sha256" && !hasAuthSecret(env)) {
      // HMAC records are permanently unusable without their pepper; report it
      // clearly instead of failing as "invalid credentials" with no way to migrate.
      return { ok: false, migrated: false, pepperMismatch: true };
    }
    const computed = await hashPasswordV2Legacy(password, record.salt, env, record.algorithm);
    return { ok: constantTimeEqual(computed, record.hash), migrated: false };
  }

  return { ok: false, migrated: false };
}

async function hashPasswordPBKDF2(password, salt, env, iterations = PBKDF2_ITERATIONS) {
  const secretKey = hasAuthSecret(env) ? env.AUTH_SECRET : "";
  const combinedPassword = secretKey ? `${password}:${secretKey}` : password;
  const pwUtf8 = encodeText(combinedPassword);
  const saltUtf8 = encodeText(salt);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    pwUtf8,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltUtf8,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );

  return base64UrlEncodeBytes(new Uint8Array(derivedBits));
}

async function hashPasswordV2Legacy(password, salt, env, algorithm) {
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
  // Key on the edge-reported client IP only. Deliberately excludes User-Agent:
  // rotating UAs must never reset the failure counter. CF-Connecting-IP is set
  // by Cloudflare and cannot be spoofed by clients through the edge.
  const ip = request.headers.get("CF-Connecting-IP") || "direct-ip";
  return `login_fail:${await sha256Hex(ip)}`;
}

// Fixed-window failure tracker. NOTE: KV is eventually consistent, so parallel
// attempts can under-count; treat this as best-effort damping. Hard guarantees
// would require Durable Objects.
async function readLoginThrottle(kv, key) {
  const data = await kvGetJson(kv, key, null);
  if (!data) return { count: 0, blocked: false };

  const now = Date.now();
  const startedAt = Date.parse(data.windowStart || "") || now;
  if (now - startedAt >= LOGIN_WINDOW_SECONDS * 1000) {
    return { count: 0, blocked: false };
  }
  const count = Number(data.count || 0);
  return { count, blocked: count >= LOGIN_MAX_FAILURES };
}

async function recordLoginFailure(kv, key, _currentCount) {
  const existing = await kvGetJson(kv, key, null);
  const now = Date.now();

  let count = 1;
  let windowStart = now;
  if (existing) {
    const priorStart = Date.parse(existing.windowStart || "") || now;
    if (now - priorStart < LOGIN_WINDOW_SECONDS * 1000) {
      windowStart = priorStart;
      count = Number(existing.count || 0) + 1;
    }
  }

  await kv.put(
    key,
    JSON.stringify({
      count,
      windowStart: new Date(windowStart).toISOString(),
    }),
    { expirationTtl: LOGIN_WINDOW_SECONDS }
  );
}

async function clearLoginThrottle(kv, key) {
  await kv.delete(key);
}

async function revokeAllSessions(kv) {
  // Best-effort sweep of every active session (used after a password change).
  try {
    let cursor;
    do {
      const options = { prefix: "session:" };
      if (cursor) options.cursor = cursor;
      const page = await kv.list(options);
      for (const key of page.keys || []) {
        await kv.delete(key.name);
      }
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
  } catch (_error) {
    // Non-standard KV bindings may not support list(); sessions then simply
    // age out at their normal TTL.
  }
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

function decodeURIComponentSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch (_error) {
    return "";
  }
}

// ---------------------------------------------------------------------------
// KV Operations
// ---------------------------------------------------------------------------

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
    isEmpty: validation.isEmpty,
    warningCount: validation.warnings.length,
    // Persisted so the dashboard can reconstruct diagnostics from the cache
    // without re-running the parser on every load.
    warnings: validation.warnings.slice(0, 50),
    errors: validation.errors.slice(0, 10),
  };
}

// ---------------------------------------------------------------------------
// Subscription Content Validation & Parsing
// ---------------------------------------------------------------------------

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
    result.errors.push(`Content size (${formatBytes(byteSize)}) exceeds the 24 MiB limit.`);
  }

  if (result.isEmpty) {
    result.warnings.push("Subscription is currently empty.");
    return result;
  }

  const seen = new Set();
  let index = 0;
  let lineNumber = 1;

  // Line numbers are tracked incrementally: recomputing them per line made
  // validation quadratic on large payloads.
  while (index < text.length) {
    const trimmedIndex = skipWhitespace(text, index);
    lineNumber += countNewlinesBetween(text, index, trimmedIndex);
    index = trimmedIndex;
    if (index >= text.length) break;

    const char = text[index];
    if (char === "{" || char === "[") {
      const block = readJsonBlock(text, index);
      if (block.complete) {
        const rawBlock = text.slice(index, block.end);
        recordDuplicate(rawBlock.trim(), seen, result);
        recordJsonBlock(rawBlock, lineNumber, result);
        lineNumber += countNewlinesBetween(text, index, block.end);
        index = block.end;
        continue;
      }

      pushWarning(result, `Unclosed JSON block near line ${lineNumber}.`);
      const blockLineEnd = Math.min(nextLineIndex(text, index) + 1, text.length);
      lineNumber += countNewlinesBetween(text, index, blockLineEnd);
      index = blockLineEnd;
      continue;
    }

    const lineEnd = nextLineIndex(text, index);
    const line = text.slice(index, lineEnd).trim();
    recordLine(line, lineNumber, seen, result);
    lineNumber += countNewlinesBetween(text, index, Math.min(lineEnd + 1, text.length));
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
    pushWarning(result, `Unsupported protocol on line ${lineNumber}: ${line.slice(0, 40)}`);
    return;
  }

  pushWarning(result, `Unknown format on line ${lineNumber}: ${line.slice(0, 40)}`);
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
    pushWarning(result, `Duplicate entry detected: ${value.slice(0, 40)}...`);
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

function countNewlinesBetween(text, from, to) {
  const end = Math.min(to, text.length);
  let count = 0;
  for (let i = Math.max(from, 0); i < end; i += 1) {
    if (text[i] === "\n") count += 1;
  }
  return count;
}

function pushWarning(result, message) {
  if (result.warnings.length < 50) result.warnings.push(message);
}

// ---------------------------------------------------------------------------
// HTML Views & Redesigned Slate Blue UI
// ---------------------------------------------------------------------------

function generateAuthPage({ mode, nonce, error = "", warning = "" }) {
  const isSetup = mode === "setup";
  const title = isSetup ? "Setup admin password" : "Sign in to SubLink";
  const action = isSetup ? "/admin/setup" : "/admin/login";
  const button = isSetup ? "Set Admin Password" : "Sign In";
  const hint = isSetup
    ? "Initialize the primary administrator password for your subscription worker."
    : "Enter your admin credentials to update your proxy nodes.";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${APP_NAME} - ${title}</title>
  <style nonce="${nonce}">${baseStyles()}</style>
</head>
<body class="auth-screen">
  <div class="auth-card">
    <div class="brand-row">
      <div class="brand-badge">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
          <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
        </svg>
      </div>
      <span class="brand-title">${APP_NAME}</span>
      <span class="version-tag">v${APP_VERSION}</span>
    </div>

    <h1>${title}</h1>
    <p class="subtitle">${hint}</p>

    ${error ? `<div class="alert alert-error" role="alert">${escapeHtml(error)}</div>` : ""}
    ${warning ? `<div class="alert alert-warning" role="alert">${escapeHtml(warning)}</div>` : ""}

    <form method="POST" action="${action}" class="form-stack">
      <div class="field-group">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="${isSetup ? "new-password" : "current-password"}" placeholder="••••••••••••" required autofocus>
        ${isSetup ? '<span class="field-hint">Minimum 8 characters. Uses PBKDF2-SHA256 key derivation.</span>' : ""}
      </div>
      <button class="btn btn-primary" type="submit">${button}</button>
    </form>
  </div>
</body>
</html>`;
}

function generateAdminErrorPage({ nonce, title, details }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${APP_NAME} - Missing Configuration</title>
  <style nonce="${nonce}">${baseStyles()}</style>
</head>
<body class="auth-screen">
  <div class="auth-card">
    <div class="brand-row">
      <div class="brand-badge danger">!</div>
      <span class="brand-title">${APP_NAME}</span>
    </div>
    <h1>${escapeHtml(title)}</h1>
    <div class="alert alert-warning">
      ${details.map((item) => `<p style="margin:4px 0">${escapeHtml(item)}</p>`).join("")}
    </div>
    <p class="subtitle">Once configured, reload this page to continue.</p>
  </div>
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
  base64Url,
  hasAuthSecret,
}) {
  const initialState = {
    csrfToken,
    hasBackup,
    meta,
    validation,
    subscriptionUrl,
    base64Url,
    hasAuthSecret,
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="csrf-token" content="${escapeHtml(csrfToken)}">
  <title>${APP_NAME} - Dashboard</title>
  <style nonce="${nonce}">${baseStyles()}${dashboardStyles()}</style>
</head>
<body class="dashboard-body">
  <header class="app-header">
    <div class="header-content">
      <div class="header-brand">
        <div class="brand-badge">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
          </svg>
        </div>
        <div class="brand-text">
          <span class="brand-title">${APP_NAME}</span>
          <span class="brand-sub">Cloudflare Edge Worker</span>
        </div>
      </div>
      <div class="header-actions">
        <div id="save-status-pill" class="status-pill status-saved">Synced</div>
        <button id="logout-btn" class="btn btn-ghost btn-sm" type="button">Sign out</button>
      </div>
    </div>
  </header>

  <main class="app-layout">
    <div class="main-column">
      <section class="card editor-card">
        <div class="card-header">
          <div>
            <h2>Subscription nodes</h2>
            <p class="section-desc">Nodes served to your VPN clients. Supports URIs (vless, vmess, trojan, ss, hy2) and raw JSON.</p>
          </div>
          <div class="toolbar">
            <button id="btn-import" class="btn btn-secondary btn-sm" type="button">Import</button>
            <button id="btn-export" class="btn btn-secondary btn-sm" type="button">Export</button>
            <button id="btn-restore" class="btn btn-secondary btn-sm" type="button"${hasBackup ? "" : " disabled"}>Rollback</button>
          </div>
        </div>

        <form id="editor-form">
          <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
          <div class="textarea-wrapper">
            <textarea id="links-editor" name="links" spellcheck="false" placeholder="Paste vless://, vmess://, ss://, trojan://, hysteria2://, or JSON configs here...">${escapeHtml(links)}</textarea>
          </div>
          <div class="editor-footer">
            <div class="editor-footer-left">
              <span id="char-counter" class="mono-stat">0 lines</span>
            </div>
            <div class="editor-footer-right">
              <button id="btn-clear" class="btn btn-danger btn-sm" type="button">Clear</button>
              <button id="btn-save" class="btn btn-primary btn-sm" type="submit">Save nodes</button>
            </div>
          </div>
        </form>
      </section>
    </div>

    <aside class="side-column">
      <section class="card">
        <div class="card-header-simple">
          <h3>Quick stats</h3>
        </div>
        <div class="stat-grid">
          <div class="stat-box">
            <span class="stat-label">Nodes</span>
            <span id="stat-nodes" class="stat-val mono-stat">${validation.configCount}</span>
          </div>
          <div class="stat-box">
            <span class="stat-label">Payload</span>
            <span id="stat-size" class="stat-val mono-stat">${escapeHtml(formatBytes(validation.byteSize))}</span>
          </div>
          <div class="stat-box">
            <span class="stat-label">Issues</span>
            <span id="stat-issues" class="stat-val mono-stat">${validation.warnings.length + validation.errors.length}</span>
          </div>
          <div class="stat-box">
            <span class="stat-label">Last Saved</span>
            <span id="stat-saved" class="stat-val-sm mono-stat">${escapeHtml(formatDate(meta.updatedAt))}</span>
          </div>
        </div>
      </section>

      <section class="card">
        <div class="card-header-simple">
          <h3>Client subscription URLs</h3>
        </div>
        <div class="url-block">
          <label for="sub-url-raw">Raw Endpoint (Default)</label>
          <div class="input-action-row">
            <input id="sub-url-raw" class="mono-input" value="${escapeHtml(subscriptionUrl)}" readonly>
            <button class="btn btn-secondary btn-sm copy-btn" data-target="sub-url-raw" type="button">Copy</button>
          </div>
        </div>
        <div class="url-block" style="margin-top:12px;">
          <label for="sub-url-b64">Base64 Encoded (Shadowrocket / v2rayN)</label>
          <div class="input-action-row">
            <input id="sub-url-b64" class="mono-input" value="${escapeHtml(base64Url)}" readonly>
            <button class="btn btn-secondary btn-sm copy-btn" data-target="sub-url-b64" type="button">Copy</button>
          </div>
        </div>
      </section>

      <section class="card">
        <div class="card-header-simple">
          <h3>Protocol breakdown</h3>
        </div>
        <div id="protocol-container" class="pill-list"></div>
      </section>

      <section class="card">
        <div class="card-header-simple">
          <h3>Diagnostics</h3>
        </div>
        <div id="diagnostics-container" class="diagnostic-list"></div>
      </section>

      <section class="card">
        <div class="card-header-simple">
          <h3>Security settings</h3>
        </div>
        <p id="sec-notice" class="sec-status-text"></p>
        <form id="change-pw-form" class="form-stack compact">
          <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
          <div class="field-group">
            <label for="current_password">Current password</label>
            <input id="current_password" name="current_password" type="password" autocomplete="current-password" required>
          </div>
          <div class="field-group">
            <label for="new_password">New password</label>
            <input id="new_password" name="new_password" type="password" autocomplete="new-password" required>
          </div>
          <button class="btn btn-secondary btn-sm" type="submit">Update password</button>
        </form>
      </section>
    </aside>
  </main>

  <div id="toast-shelf" aria-live="polite" aria-atomic="true"></div>
  <input id="hidden-file-input" type="file" accept=".txt,.json,.conf" hidden>

  <script id="sublink-data" type="application/json" nonce="${nonce}">${safeJsonForScript(initialState)}</script>
  <script nonce="${nonce}">${dashboardScript()}</script>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Redesigned Slate Blue Stylesheet
// ---------------------------------------------------------------------------

function baseStyles() {
  return `
:root {
  color-scheme: dark;
  --bg: #0b0f19;
  --surface: #111827;
  --surface-raised: #1e293b;
  --surface-hover: #334155;
  --border: #1e293b;
  --border-active: #3b82f6;
  --text: #f8fafc;
  --text-muted: #94a3b8;
  --text-dim: #64748b;
  --accent: #3b82f6;
  --accent-hover: #2563eb;
  --accent-light: rgba(59, 130, 246, 0.12);
  --danger: #ef4444;
  --danger-bg: rgba(239, 68, 68, 0.12);
  --warning: #f59e0b;
  --warning-bg: rgba(245, 158, 11, 0.12);
  --success: #10b981;
  --success-bg: rgba(16, 185, 129, 0.12);
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 14px;
  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.2);
  --shadow-md: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(0, 0, 0, 0.3);
}
* { box-sizing: border-box; }
html, body { min-height: 100%; margin: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
  background-color: var(--bg);
  color: var(--text);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
h1, h2, h3, p { margin: 0; }
h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.025em; }
h2 { font-size: 16px; font-weight: 600; letter-spacing: -0.015em; }
h3 { font-size: 14px; font-weight: 600; color: var(--text); }
p { color: var(--text-muted); font-size: 13px; text-wrap: pretty; }
button, input, textarea { font: inherit; }

.mono-stat {
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-variant-numeric: tabular-nums;
}

.mono-input {
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: 12px;
  background: var(--bg);
  color: var(--text-muted);
}

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  font-weight: 500;
  font-size: 13px;
  padding: 8px 14px;
  border-radius: var(--radius-sm);
  border: 1px solid transparent;
  cursor: pointer;
  transition: all 140ms ease-in-out;
  outline: none;
}
.btn:focus-visible {
  box-shadow: 0 0 0 2px var(--bg), 0 0 0 4px var(--accent);
}
.btn:active:not(:disabled) {
  transform: scale(0.98);
}
.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.btn-sm {
  padding: 6px 10px;
  font-size: 12px;
}
.btn-primary {
  background: var(--accent);
  color: #fff;
}
.btn-primary:hover:not(:disabled) {
  background: var(--accent-hover);
}
.btn-secondary {
  background: var(--surface-raised);
  border-color: var(--border);
  color: var(--text);
}
.btn-secondary:hover:not(:disabled) {
  background: var(--surface-hover);
  border-color: var(--border-active);
}
.btn-ghost {
  background: transparent;
  color: var(--text-muted);
}
.btn-ghost:hover:not(:disabled) {
  background: var(--surface-raised);
  color: var(--text);
}
.btn-danger {
  background: var(--danger-bg);
  border-color: rgba(239, 68, 68, 0.3);
  color: #fca5a5;
}
.btn-danger:hover:not(:disabled) {
  background: rgba(239, 68, 68, 0.25);
  border-color: var(--danger);
}

.form-stack {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.form-stack.compact {
  gap: 10px;
}
.field-group {
  display: flex;
  flex-direction: column;
  gap: 5px;
}
label {
  font-size: 12px;
  font-weight: 500;
  color: var(--text-muted);
}
input[type="text"], input[type="password"] {
  width: 100%;
  padding: 8px 12px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text);
  outline: none;
  font-size: 13px;
  transition: border-color 140ms ease;
}
input[type="text"]:focus, input[type="password"]:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-light);
}
.field-hint {
  font-size: 11px;
  color: var(--text-dim);
}

.alert {
  padding: 10px 12px;
  border-radius: var(--radius-sm);
  font-size: 13px;
  line-height: 1.4;
}
.alert-error {
  background: var(--danger-bg);
  border: 1px solid rgba(239, 68, 68, 0.4);
  color: #fca5a5;
}
.alert-warning {
  background: var(--warning-bg);
  border: 1px solid rgba(245, 158, 11, 0.4);
  color: #fcd34d;
}

.auth-screen {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  background: radial-gradient(circle at top center, rgba(59, 130, 246, 0.08) 0%, transparent 60%), var(--bg);
}
.auth-card {
  width: 100%;
  max-width: 400px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 28px;
  box-shadow: var(--shadow-md);
}
.brand-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 16px;
}
.brand-badge {
  width: 32px;
  height: 32px;
  border-radius: var(--radius-sm);
  background: var(--accent-light);
  color: var(--accent);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
}
.brand-badge.danger {
  background: var(--danger-bg);
  color: var(--danger);
}
.brand-title {
  font-weight: 600;
  font-size: 15px;
  letter-spacing: -0.01em;
}
.version-tag {
  font-size: 10px;
  background: var(--surface-raised);
  padding: 2px 6px;
  border-radius: 4px;
  color: var(--text-dim);
  margin-left: auto;
}
.subtitle {
  margin: 6px 0 20px;
  font-size: 13px;
  line-height: 1.45;
}
`;
}

function dashboardStyles() {
  return `
.dashboard-body {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}
.app-header {
  position: sticky;
  top: 0;
  z-index: 20;
  background: rgba(11, 15, 25, 0.88);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
}
.header-content {
  max-width: 1400px;
  margin: 0 auto;
  padding: 12px 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.header-brand {
  display: flex;
  align-items: center;
  gap: 10px;
}
.brand-text {
  display: flex;
  flex-direction: column;
}
.brand-sub {
  font-size: 11px;
  color: var(--text-dim);
}
.header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

.status-pill {
  font-size: 11px;
  font-weight: 500;
  padding: 3px 9px;
  border-radius: 9999px;
  border: 1px solid transparent;
}
.status-saved {
  background: var(--success-bg);
  color: var(--success);
  border-color: rgba(16, 185, 129, 0.3);
}
.status-dirty {
  background: var(--warning-bg);
  color: var(--warning);
  border-color: rgba(245, 158, 11, 0.3);
}
.status-error {
  background: var(--danger-bg);
  color: var(--danger);
  border-color: rgba(239, 68, 68, 0.3);
}

.app-layout {
  max-width: 1400px;
  width: 100%;
  margin: 0 auto;
  padding: 20px;
  display: grid;
  grid-template-columns: minmax(0, 1fr) 340px;
  gap: 20px;
  flex: 1;
}

.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.editor-card {
  height: 100%;
  min-height: 600px;
}
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.card-header-simple {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-bottom: 4px;
}
.section-desc {
  font-size: 12px;
  margin-top: 2px;
}
.toolbar {
  display: flex;
  align-items: center;
  gap: 6px;
}

#editor-form {
  display: flex;
  flex-direction: column;
  flex: 1;
}
.textarea-wrapper {
  flex: 1;
  display: flex;
  position: relative;
}
textarea {
  width: 100%;
  min-height: 480px;
  height: 100%;
  background: #080c14;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text);
  padding: 14px;
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: 13px;
  line-height: 1.6;
  resize: vertical;
  outline: none;
}
textarea:focus {
  border-color: var(--border-active);
  box-shadow: 0 0 0 3px var(--accent-light);
}

.editor-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-top: 12px;
}
.editor-footer-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.stat-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}
.stat-box {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
}
.stat-label {
  font-size: 11px;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.stat-val {
  font-size: 18px;
  font-weight: 600;
  color: var(--text);
  margin-top: 2px;
}
.stat-val-sm {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 4px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.url-block label {
  display: block;
  margin-bottom: 4px;
}
.input-action-row {
  display: flex;
  gap: 6px;
}

.pill-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.proto-tag {
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 4px 8px;
  border-radius: var(--radius-sm);
  font-size: 12px;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.proto-tag strong {
  color: var(--accent);
}

.diagnostic-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
  max-height: 220px;
  overflow-y: auto;
}
.diag-item {
  font-size: 12px;
  padding: 6px 8px;
  border-radius: 4px;
  background: var(--bg);
  border-left: 3px solid var(--border);
  color: var(--text-muted);
  line-height: 1.4;
}
.diag-item.warning {
  border-left-color: var(--warning);
  color: #fcd34d;
}
.diag-item.error {
  border-left-color: var(--danger);
  color: #fca5a5;
}

.sec-status-text {
  font-size: 12px;
  color: var(--text-dim);
  line-height: 1.4;
}

#toast-shelf {
  position: fixed;
  bottom: 24px;
  right: 24px;
  z-index: 50;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.toast {
  background: var(--surface-raised);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 14px;
  color: var(--text);
  font-size: 13px;
  box-shadow: var(--shadow-md);
  animation: toast-in 160ms ease-out;
}
.toast.toast-error {
  border-color: var(--danger);
  color: #fca5a5;
}
@keyframes toast-in {
  from { transform: translateY(8px); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}

@media (max-width: 960px) {
  .app-layout {
    grid-template-columns: 1fr;
  }
  .editor-card {
    min-height: 440px;
  }
}
`;
}

function dashboardScript() {
  return `
(function () {
  "use strict";

  const SUPPORTED_PROTOCOLS = ${JSON.stringify(SUPPORTED_PROTOCOLS)};
  const MAX_EDITOR_BYTES = ${MAX_LINKS_BYTES};

  const state = JSON.parse(document.getElementById("sublink-data").textContent);
  const csrfToken = state.csrfToken;
  const editor = document.getElementById("links-editor");
  const form = document.getElementById("editor-form");
  const saveStatus = document.getElementById("save-status-pill");
  const saveBtn = document.getElementById("btn-save");
  const restoreBtn = document.getElementById("btn-restore");
  const fileInput = document.getElementById("hidden-file-input");
  const charCounter = document.getElementById("char-counter");

  let lastCleanValue = editor.value;

  function countLines(str) {
    if (!str.trim()) return 0;
    return str.split(/\\r?\\n/).filter(function (l) { return l.trim().length > 0; }).length;
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KiB";
    return (bytes / 1024 / 1024).toFixed(2) + " MiB";
  }

  async function readJson(res) {
    try {
      return await res.json();
    } catch (_error) {
      let detail = "";
      try { detail = (await res.text()).slice(0, 160); } catch (_ignored) {}
      return { ok: false, error: detail || ("HTTP " + res.status) };
    }
  }

  function toast(msg, isError) {
    const shelf = document.getElementById("toast-shelf");
    const item = document.createElement("div");
    item.className = "toast" + (isError ? " toast-error" : "");
    item.textContent = msg;
    shelf.appendChild(item);
    setTimeout(function () {
      item.style.opacity = "0";
      setTimeout(function () { item.remove(); }, 200);
    }, 4000);
  }

  function setStatus(mode, label) {
    saveStatus.className = "status-pill status-" + mode;
    saveStatus.textContent = label;
  }

  function renderStats(val, meta) {
    document.getElementById("stat-nodes").textContent = val.configCount;
    document.getElementById("stat-size").textContent = formatBytes(val.byteSize);
    document.getElementById("stat-issues").textContent =
      (val.warnings || []).length + (val.errors || []).length;
    if (meta && meta.updatedAt) {
      const dt = new Date(meta.updatedAt);
      if (!Number.isNaN(dt.getTime())) {
        // Same formatter as the server-side formatDate so SSR and live values agree.
        document.getElementById("stat-saved").textContent = dt.toLocaleString("en-US", { hour12: false });
      }
    }
    charCounter.textContent = countLines(editor.value) + " lines";

    const protoContainer = document.getElementById("protocol-container");
    protoContainer.innerHTML = "";
    const entries = Object.entries(val.protocolCounts || {});
    if (!entries.length) {
      const empty = document.createElement("span");
      empty.style.fontSize = "12px";
      empty.style.color = "var(--text-dim)";
      empty.textContent = "No active protocols";
      protoContainer.appendChild(empty);
    } else {
      entries.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; });
      entries.forEach(function (entry) {
        const pill = document.createElement("span");
        pill.className = "proto-tag";
        pill.appendChild(document.createTextNode(entry[0] + ": "));
        const strong = document.createElement("strong");
        strong.textContent = String(entry[1]);
        pill.appendChild(strong);
        protoContainer.appendChild(pill);
      });
    }

    const diagContainer = document.getElementById("diagnostics-container");
    diagContainer.innerHTML = "";
    const issues = []
      .concat((val.errors || []).map(function (m) { return { type: "error", msg: m }; }))
      .concat((val.warnings || []).map(function (m) { return { type: "warning", msg: m }; }));

    if (!issues.length) {
      const okItem = document.createElement("div");
      okItem.className = "diag-item";
      okItem.textContent = "Configs well-formed. No syntax issues.";
      diagContainer.appendChild(okItem);
    } else {
      issues.forEach(function (issue) {
        const item = document.createElement("div");
        item.className = "diag-item " + issue.type;
        item.textContent = issue.msg;
        diagContainer.appendChild(item);
      });
    }
  }

  function findJsonBlockEnd(text, start) {
    const stack = [text.charAt(start)];
    let inString = false;
    let escaped = false;
    for (let i = start + 1; i < text.length; i += 1) {
      const ch = text.charAt(i);
      if (inString) {
        if (escaped) { escaped = false; }
        else if (ch === "\\\\") { escaped = true; }
        else if (ch === '"') { inString = false; }
        continue;
      }
      if (ch === '"') { inString = true; continue; }
      if (ch === "{" || ch === "[") { stack.push(ch); continue; }
      if (ch === "}" || ch === "]") {
        const opener = stack.pop();
        if ((ch === "}" && opener !== "{") || (ch === "]" && opener !== "[")) return -1;
        if (!stack.length) return i + 1;
      }
    }
    return -1;
  }

  // Mirrors the server-side validator so live stats match saved stats:
  // same JSON-block expansion, duplicate messages, and warning cap.
  function analyzeClientSide(text) {
    if (!text.trim()) {
      return {
        byteSize: 0,
        isEmpty: true,
        configCount: 0,
        protocolCounts: {},
        warnings: ["Subscription is currently empty."],
        errors: []
      };
    }

    const byteSize = new TextEncoder().encode(text).length;
    const errors = [];
    if (byteSize > MAX_EDITOR_BYTES) {
      errors.push("Content size (" + formatBytes(byteSize) + ") exceeds the 24 MiB limit.");
    }

    const protocolCounts = {};
    const warnings = [];
    const seen = new Set();
    let configCount = 0;

    function pushWarning(message) {
      if (warnings.length < 50) warnings.push(message);
    }
    function recordDuplicate(value) {
      if (!value) return;
      if (seen.has(value)) pushWarning("Duplicate entry detected: " + value.slice(0, 40) + "...");
      else seen.add(value);
    }
    function bump(protocol, amount) {
      configCount += amount;
      protocolCounts[protocol] = (protocolCounts[protocol] || 0) + amount;
    }

    let index = 0;
    let lineNumber = 1;

    while (index < text.length) {
      while (index < text.length && /\\s/.test(text.charAt(index))) {
        if (text.charAt(index) === "\\n") lineNumber += 1;
        index += 1;
      }
      if (index >= text.length) break;

      const ch = text.charAt(index);
      if (ch === "{" || ch === "[") {
        const end = findJsonBlockEnd(text, index);
        if (end !== -1) {
          const raw = text.slice(index, end);
          recordDuplicate(raw.trim());
          try {
            const parsed = JSON.parse(raw);
            const amount = Array.isArray(parsed) ? parsed.length : 1;
            if (Array.isArray(parsed) && amount === 0) {
              pushWarning("JSON array on line " + lineNumber + " is empty.");
            }
            bump("json", Math.max(amount, 0));
          } catch (_error) {
            pushWarning("Invalid JSON block near line " + lineNumber + ".");
          }
          for (let k = index; k < end; k += 1) {
            if (text.charAt(k) === "\\n") lineNumber += 1;
          }
          index = end;
          continue;
        }
        pushWarning("Unclosed JSON block near line " + lineNumber + ".");
        let nl = text.indexOf("\\n", index);
        if (nl === -1) nl = text.length;
        for (let k = index; k <= nl && k < text.length; k += 1) {
          if (text.charAt(k) === "\\n") lineNumber += 1;
        }
        index = nl + 1;
        continue;
      }

      let nl = text.indexOf("\\n", index);
      if (nl === -1) nl = text.length;
      const line = text.slice(index, nl).trim();
      if (line) {
        const match = /^([a-z][a-z0-9+.-]*):\\/\\//i.exec(line);
        if (match && SUPPORTED_PROTOCOLS.indexOf(match[1].toLowerCase()) !== -1) {
          bump(match[1].toLowerCase(), 1);
          recordDuplicate(line);
        } else if (match) {
          pushWarning("Unsupported protocol on line " + lineNumber + ": " + line.slice(0, 40));
        } else {
          pushWarning("Unknown format on line " + lineNumber + ": " + line.slice(0, 40));
        }
      }
      for (let k = index; k <= nl && k < text.length; k += 1) {
        if (text.charAt(k) === "\\n") lineNumber += 1;
      }
      index = nl + 1;
    }

    return {
      byteSize: byteSize,
      isEmpty: false,
      configCount: configCount,
      protocolCounts: protocolCounts,
      warnings: warnings,
      errors: errors
    };
  }

  editor.addEventListener("input", function () {
    const val = analyzeClientSide(editor.value);
    renderStats(val, null);
    if (editor.value === lastCleanValue) {
      setStatus("saved", "Synced");
    } else {
      setStatus("dirty", "Unsaved");
    }
  });

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    const text = editor.value;
    const val = analyzeClientSide(text);
    if (val.isEmpty && !confirm("Save empty subscription output?")) return;

    saveBtn.disabled = true;
    setStatus("dirty", "Saving...");

    try {
      const res = await fetch("/update-links", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-csrf-token": csrfToken,
        },
        body: JSON.stringify({
          links: text,
          confirm_empty: val.isEmpty,
        }),
      });
      const data = await readJson(res);
      if (!res.ok || !data.ok) throw new Error(data.error || "Save failed");

      lastCleanValue = text;
      renderStats(data.validation, data.meta);
      setStatus("saved", "Synced");
      restoreBtn.disabled = false;
      toast(data.unchanged ? "Already up to date." : "Subscription updated successfully.");
    } catch (err) {
      setStatus("error", "Error");
      toast(err.message, true);
    } finally {
      saveBtn.disabled = false;
    }
  });

  document.getElementById("btn-clear").addEventListener("click", function () {
    if (confirm("Clear editor contents?")) {
      editor.value = "";
      editor.dispatchEvent(new Event("input"));
    }
  });

  document.getElementById("btn-import").addEventListener("click", function () {
    fileInput.click();
  });

  fileInput.addEventListener("change", function () {
    const f = fileInput.files[0];
    fileInput.value = "";
    if (!f) return;
    if (f.size > MAX_EDITOR_BYTES) {
      toast("File exceeds the " + formatBytes(MAX_EDITOR_BYTES) + " limit.", true);
      return;
    }
    if (editor.value !== lastCleanValue && !confirm("You have unsaved changes. Discard them and import this file?")) {
      return;
    }
    const r = new FileReader();
    r.onload = function () {
      editor.value = String(r.result || "");
      editor.dispatchEvent(new Event("input"));
      toast("Imported " + f.name);
    };
    r.readAsText(f);
  });

  document.getElementById("btn-export").addEventListener("click", function () {
    const b = new Blob([editor.value], { type: "text/plain;charset=utf-8" });
    const u = URL.createObjectURL(b);
    const a = document.createElement("a");
    a.href = u;
    a.download = "sublink-nodes.txt";
    a.click();
    URL.revokeObjectURL(u);
  });

  restoreBtn.addEventListener("click", async function () {
    if (!confirm("Rollback to the previously saved node list?")) return;
    const fd = new FormData();
    fd.set("csrf_token", csrfToken);
    try {
      const res = await fetch("/restore-backup", {
        method: "POST",
        headers: { "x-csrf-token": csrfToken },
        body: fd,
      });
      const data = await readJson(res);
      if (!res.ok || !data.ok) throw new Error(data.error || "Rollback failed");
      editor.value = data.links;
      lastCleanValue = data.links;
      renderStats(data.validation, data.meta);
      setStatus("saved", "Synced");
      toast("Restored previous backup.");
    } catch (err) {
      toast(err.message, true);
    }
  });

  document.querySelectorAll(".copy-btn").forEach(function (btn) {
    btn.addEventListener("click", async function () {
      const targetId = btn.getAttribute("data-target");
      const inp = document.getElementById(targetId);
      if (!inp) return;
      try {
        await navigator.clipboard.writeText(inp.value);
      } catch (_e) {
        inp.select();
        document.execCommand("copy");
      }
      toast("URL copied to clipboard.");
    });
  });

  document.getElementById("logout-btn").addEventListener("click", async function () {
    const fd = new FormData();
    fd.set("csrf_token", csrfToken);
    await fetch("/admin/logout", {
      method: "POST",
      headers: { "x-csrf-token": csrfToken },
      body: fd,
    });
    window.location.href = "/admin";
  });

  document.getElementById("change-pw-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    try {
      const res = await fetch("/admin/password", {
        method: "POST",
        headers: { "x-csrf-token": csrfToken },
        body: fd,
      });
      const data = await readJson(res);
      if (!res.ok || !data.ok) throw new Error(data.error || "Failed to update password");
      e.currentTarget.reset();
      toast(data.message || "Password updated.");
      if (data.signedOut) {
        setTimeout(function () { window.location.href = "/admin"; }, 1200);
      }
    } catch (err) {
      toast(err.message, true);
    }
  });

  document.getElementById("sec-notice").textContent = state.hasAuthSecret
    ? "AUTH_SECRET is active. Key derivation combines client secret + salt."
    : "AUTH_SECRET is not configured. PBKDF2 salt is active.";

  renderStats(state.validation, state.meta);
})();
`;
}

// ---------------------------------------------------------------------------
// Response & Header Generators
// ---------------------------------------------------------------------------

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

function base64EncodeUtf8(value) {
  const bytes = encodeText(value);
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
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
  let mismatch = a.length === b.length ? 0 : 1;
  const length = Math.max(a.length, b.length);

  for (let i = 0; i < length; i += 1) {
    const ca = i < a.length ? a.charCodeAt(i) : 0;
    const cb = i < b.length ? b.charCodeAt(i) : 0;
    mismatch |= ca ^ cb;
  }

  return mismatch === 0;
}

export const __SUBLINK_WORKER_TESTS__ = {
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
};
