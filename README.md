<div align="center">

# 🔗 SubLink Worker

### A high-performance Cloudflare Worker for hosting custom VPN subscription links

Paste node configs. Save to KV. Share clean subscription endpoints with auto Base64 negotiation.

[Setup](#-setup) • [Supported Protocols](#-supported-protocols) • [Client Endpoints](#-client-endpoints) • [Local Tests](#-local-tests)

</div>

---

## ✨ What It Does

**SubLink Worker** provides a secure, minimal admin panel and edge API for managing VPN subscription feeds.

- 🔐 **Hardened Auth**: PBKDF2 key derivation (100,000 iterations), automatic legacy password migration, CSRF token validation, and IP-isolated rate limiting.
- 🌐 **Dual Format Delivery**: Serves raw subscription text or standard Base64 encoding via query parameter or client User-Agent negotiation.
- ⚡ **ES Module & Legacy Runtime**: Native `export default { fetch }` with Service Worker listener fallback.
- 🎨 **Polished Dashboard**: Slate Blue theme, tabular monospace metrics, protocol breakdowns, and instant rollback.
- 🧪 **Zero-Dependency Tests**: Built-in test suite running on native Node.js (`node --test`).
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

### 5. Access the Admin Panel

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

---

## 📄 License

MIT. See [LICENSE](./LICENSE).
