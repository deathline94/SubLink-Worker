<div align="center">

# 🔗 SubLink Worker

### A high-performance Cloudflare Worker for hosting custom VPN subscription links

Paste node configs. Save to KV. Share clean subscription endpoints with auto Base64 negotiation.

[Setup](#-setup) • [Supported Protocols](#-supported-protocols) • [Client Endpoints](#-client-endpoints) • [Local Tests](#-local-tests)

</div>

---

## ✨ What It Does

**SubLink Worker** provides a secure, minimal admin panel and edge API for managing VPN subscription feeds.

- 🔐 **Hardened Auth**: PBKDF2 key derivation (100,000 iterations), automatic legacy password migration, CSRF token validation, and per-IP login throttling (best-effort under KV's eventual consistency; hard guarantees would require Durable Objects).
- 🔄 **Session Hygiene**: Changing the admin password signs out every device; stolen cookies cannot survive a credential rotation.
- 🌐 **Dual Format Delivery**: Serves raw subscription text or standard Base64 encoding via query parameter or client User-Agent negotiation (Base64 clients only — YAML-only clients like Clash always receive raw text).
- 🔒 **Optional Private Feed**: Set `SUB_TOKEN` to move the subscription behind an unguessable `/sub/<token>` path.
- ⚡ **ES Module & Legacy Runtime**: Native `export default { fetch }` with Service Worker listener fallback.
- 🎨 **Polished Dashboard**: Slate Blue theme, tabular monospace metrics, protocol breakdowns, and instant rollback.
- 🧪 **Zero-Dependency Tests**: Built-in test suite running on native Node.js (`node --test test.js`).
- 💾 **Single File Deployment**: Zero build step; copy-paste directly into Cloudflare Worker web editor.

---

## 📦 Supported Protocols

SubLink Worker validates and counts all modern proxy share links and configurations:

```text
vless://...
vmess://...
trojan://...
ss://...
ssr://...
hysteria2://... (or hy2://)
wireguard://... (or wg://)
socks5://...
http:// / https://
```

Raw JSON configurations (e.g., sing-box / Xray outbounds) are also supported and parsed for node counts.

---

## 🚀 Setup

### 1. Create a KV Namespace

In the Cloudflare Dashboard:

```text
Workers & Pages -> KV -> Create namespace
```

Namespace name: `sub`

### 2. Create a Worker

```text
Workers & Pages -> Create -> Worker
```

Delete the default code, paste the contents of [`Worker.js`](./Worker.js), and deploy.

### 3. Bind KV

Open **Worker Settings -> Variables -> KV Namespace Bindings**:

- **Variable name**: `sub`
- **KV namespace**: your created KV namespace

### 4. (Optional) Set `AUTH_SECRET`

Add an environment variable `AUTH_SECRET` with a strong random string to enable HMAC defense-in-depth key derivation.

> ⚠️ **Rotating `AUTH_SECRET`**: stored admin hashes are bound to the pepper via a recorded identifier. After rotating, sign-in reports an explicit `AUTH_SECRET changed` error instead of generic failures. To recover: delete the `admin_password` key in your KV namespace, then reload `/admin` to run setup again.

### 5. (Optional) Set `SUB_TOKEN` for a private feed

By default the subscription is public at `/`. Setting a `SUB_TOKEN` environment variable (**minimum 16 characters**; shorter values are ignored) disables the public root and serves the feed only at:

```text
https://your-worker-url/sub/<your-token>
```

The dashboard automatically advertises the tokenized URLs when this is active.

### 6. Access the Admin Panel

Visit:

```text
https://your-worker-url/admin
```

Set your admin password, paste your node links, and click **Save nodes**.

---

## 📡 Client Endpoints

SubLink Worker provides two subscription formats:

1. **Raw Text Endpoint** (Default):
   ```text
   https://your-worker-url/
   https://your-worker-url/sub
   ```
2. **Base64 Encoded Endpoint** (For Shadowrocket, v2rayN, Quantumult X, Streisand, etc.):
   ```text
   https://your-worker-url/?b64=1
   ```
   *Note: Known VPN client User-Agents requesting the root endpoint automatically receive Base64 output.*

---

## 🧪 Local Tests

Run the built-in test suite with native Node.js (v18+):

```bash
node --test test.js
```

The suite covers the validator (including JSON-block expansion and line numbering), password hashing/migration/pepper rotation, session lifecycle, CSRF enforcement, login throttling, backup/restore, and subscription negotiation.

---

## 🛠️ Operational Notes

- **Password changes sign out all devices** — including the one that performed the change. Sign back in with the new password.
- **Login throttling** keys on the edge-reported client IP and allows 8 failures per rolling 15-minute window. It is best-effort: Workers KV is eventually consistent, so perfectly parallel attacks can under-count.
- **KV write ordering**: saves commit `vpn_meta` before `vpn_links`, so a partial failure never leaves links paired with a stale fingerprint.
- **Identical re-saves are skipped** — no KV writes occur when submitted content is byte-identical to what is stored.

---

## 📄 License

MIT. See [LICENSE](./LICENSE).
