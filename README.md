<div align="center">

# 🔗 SubLink Worker

*A modern subscription link provider powered by Cloudflare Workers*

[![JavaScript](https://img.shields.io/badge/JavaScript-100%25-yellow?style=for-the-badge&logo=javascript)](https://github.com/deathline94/SubLink-Worker)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange?style=for-the-badge&logo=cloudflare)](https://workers.cloudflare.com/)
[![MIT License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

*Convert your VPN configurations into subscription links with a beautiful web interface*

[🚀 Quick Start](#-quick-start) • [✨ Features](#-features) • [📱 Compatibility](#-compatibility) • [🛠️ Configuration](#️-configuration)

</div>

---

## ✨ Features

🎨 **Modern Admin Dashboard** - Beautiful, responsive web interface with dark theme  
🔄 **Multi-Format Support** - JSON configs, vless, vmess, trojan, shadowsocks, hysteria2  
📱 **Mobile Responsive** - Works perfectly on all devices  
🔒 **Secure Authentication** - Password-protected admin panel with sessions  
⚡ **Real-time Validation** - Instant config validation and link counting  
📊 **Base64 Encoding** - Standard subscription format compatible with all clients  
🌐 **Custom Domains** - Use your own domain with SSL support  
💾 **Import/Export** - Backup and restore your configurations easily  

---

## 🚀 Quick Start

### 1️⃣ Setup Cloudflare Account

Create a free account at [Cloudflare](https://www.cloudflare.com/) if you don't have one.

### 2️⃣ Create KV Namespace

```bash
# In Cloudflare Dashboard:
Workers → KV → Create namespace
Name: "sub"
```

📝 **Note the Namespace ID** - you'll need it in step 4b.

### 3️⃣ Create Worker

```bash
# In Cloudflare Dashboard:
Workers & Pages → Create → Worker
Name: "sublink-worker" (or your preferred name)
Template: Start from scratch
```

### 4️⃣ Configure Worker

#### a) 📤 Upload Code
1. Delete default code in the editor
2. Copy code from [`Worker.js`](https://raw.githubusercontent.com/deathline94/SubLink-Worker/main/Worker.js)
3. Paste into Cloudflare Worker editor

#### b) 🔗 Bind KV Namespace
```bash
Settings → Variables → KV Namespace Bindings → Add binding
Variable name: "sub" (lowercase required)
KV namespace: Select your "sub" namespace
```

### 5️⃣ Deploy & Access

1. Click **Save and Deploy**
2. Visit `https://your-worker-url/admin`
3. Set your admin password
4. Start adding your VPN configurations!

---

## 🛠️ Configuration

### Supported Configuration Formats

<details>
<summary><strong>📋 JSON Configurations</strong></summary>

Full Xray/Sing-box JSON configs starting with `{` and ending with `}`

```json
{
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [...]
      },
      "streamSettings": {...}
    }
  ]
}
```
</details>

<details>
<summary><strong>🔗 Protocol Links</strong></summary>

Direct protocol links:
- `vless://...`
- `vmess://...` 
- `ss://...` (Shadowsocks)
- `trojan://...`
- `hysteria2://...`
- `wireguard://...`

</details>

### Admin Dashboard Features

| Feature | Description |
|---------|-------------|
| 🔧 **Config Editor** | Syntax-highlighted editor with live validation |
| 📊 **Real-time Counter** | Shows detected configs as you type |
| ✅ **Validation** | Checks config validity before saving |
| 📁 **Import/Export** | Backup and restore configurations |
| 🗑️ **Bulk Actions** | Clear all configs with confirmation |
| 📱 **Responsive Design** | Perfect experience on mobile and desktop |

---

## 📱 Compatibility

Works seamlessly with popular VPN clients:

<div align="center">

| Platform | Clients |
|----------|---------|
| 🤖 **Android** | v2rayNG, NekoBox, SagerNet |
| 🍎 **iOS** | Shadowrocket, Quantumult X, OneClick |
| 🖥️ **Windows** | v2rayN, Clash for Windows, Netch |
| 🐧 **Linux** | v2ray, Clash |
| 🍎 **macOS** | ClashX, Qv2ray |

</div>

---

## 🔧 Advanced Setup

### Custom Domain Setup

1. **Add Domain to Cloudflare**
   ```bash
   Cloudflare Dashboard → Add Site → Enter your domain
   Update nameservers at your registrar
   ```

2. **Create DNS Record**
   ```bash
   DNS → Records → Add record
   Type: CNAME
   Name: sub (or your preferred subdomain)
   Target: your-worker-url.workers.dev
   ```

3. **Bind Domain to Worker**
   ```bash
   Workers → Your Worker → Triggers → Custom Domains → Add
   ```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `admin_password` | Stored in KV automatically | ✅ |
| `vpn_links` | Your configurations (stored in KV) | ✅ |

---

## 🔒 Security Best Practices

- 🔐 Use a **strong admin password** (12+ characters, mixed case, numbers, symbols)
- 🌐 Consider using a **custom domain** instead of the default workers.dev URL
- 🔄 **Regularly backup** your configurations using the export feature
- 👀 **Monitor access logs** in Cloudflare Analytics
- 🚫 **Don't share** your admin URL publicly

---

## 📊 Usage Statistics

Track your subscription usage through Cloudflare Analytics:

```bash
Workers → Your Worker → Analytics
```

Monitor:
- Request count
- Error rates
- Response times
- Geographic distribution

---

## 🐛 Troubleshooting

<details>
<summary><strong>Common Issues</strong></summary>

**Q: "KV namespace not found" error**  
A: Ensure the KV binding variable name is exactly `sub` (lowercase)

**Q: Admin page shows blank**  
A: Check browser console for errors, ensure Worker is deployed

**Q: Configs not converting properly**  
A: Validate JSON syntax, ensure required fields are present

**Q: Subscription not updating in client**  
A: Check client's auto-update interval, some clients cache for 24h

</details>

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**⭐ Star this repository if it helped you!**

*Made with ❤️ for the community*

</div>
