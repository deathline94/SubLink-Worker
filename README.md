<div align="center">

# 🔗 SubLink Worker

### A tiny Cloudflare Worker for hosting your own VPN subscription link

Paste configs. Save to KV. Share one clean subscription URL.

[Setup](#-setup) • [Supported Input](#-supported-input) • [Notes](#-notes) • [Local Checks](#-local-checks)

</div>

---

## ✨ What It Does

**SubLink Worker** gives you a simple admin panel for managing a public VPN subscription endpoint.

- 🔐 Password-protected admin panel at `/admin`
- 🌐 Public subscription output from `/` and `/sub`
- 💾 Cloudflare KV storage
- 🧾 Raw output, exactly as entered
- 📥 Import and export
- 🧪 Validation hints and protocol counts
- ♻️ Previous-save backup restore
- ⚡ One `Worker.js` file, no build step

---

## 📦 Supported Input

SubLink Worker is a **raw subscription host**. It does not convert between client formats.

You can paste normal share links:

```text
vless://...
vmess://...
trojan://...
ss://...
hysteria2://...
wireguard://...
```

You can also store JSON configs. Just be careful with mixed formats: most clients expect one subscription style at a time, so mixing URI links and full JSON configs may not import correctly.

---

## 🚀 Setup

### 1. Create a KV Namespace

In Cloudflare:

```text
Workers & Pages -> KV -> Create namespace
```

Example namespace name:

```text
sub
```

### 2. Create a Worker

```text
Workers & Pages -> Create -> Worker
```

Create a normal Worker and open the editor.

### 3. Paste the Code

Delete the starter code and paste the contents of [`Worker.js`](./Worker.js).

Save and deploy.

### 4. Bind KV

Open the Worker settings and add a KV binding:

```text
Variable name: sub
KV namespace: your KV namespace
```

The variable name must be exactly `sub`.

### 5. Open the Admin Panel

Visit:

```text
https://your-worker-url/admin
```

Set your admin password, paste your configs, and save.

Your subscription URL is:

```text
https://your-worker-url/
```

or:

```text
https://your-worker-url/sub
```

---

## 🔑 Optional `AUTH_SECRET`

For stronger password protection, add an environment variable named `AUTH_SECRET`.

Use a long random value from a password manager:

```text
AUTH_SECRET=your-long-random-secret
```

The Worker still works without it.

---

## 📝 Notes

- The subscription URL is public so VPN clients can fetch it without logging in.
- The admin panel is protected by password login.
- Cloudflare KV may take a little time to sync globally after saving.
- The Worker serves raw content. If your client expects Base64, Clash YAML, sing-box JSON, or another format, save content in that exact format.

---

## 🧪 Local Checks

No dependencies are required for a quick syntax check.

```bash
node --check Worker.js
```

---

## 📄 License

MIT. See [LICENSE](./LICENSE).
