const SUB = sub;

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/admin") {
    return handleAdmin(request);
  } else if (path === "/update-links") {
    return updateLinks(request);
  } else if (path === "/" || path === "") {
    // Main domain serves the subscription content directly
    return generateSubscription(request);
  } else {
    return generateSubscription(request);
  }
}

async function handleAdmin(request) {
  if (request.method === "GET") {
    const storedPassword = await SUB.get("admin_password");
    const cookie = getCookie(request, "admin-auth");

    if (!storedPassword) {
      return new Response(generateSetPasswordPage(), {
        headers: { "content-type": "text/html; charset=UTF-8" },
      });
    } else if (cookie === "logged_in") {
      return new Response(await generateAdminDashboard(request), {
        headers: { "content-type": "text/html; charset=UTF-8" },
      });
    } else {
      return new Response(generateLoginPage(), {
        headers: { "content-type": "text/html; charset=UTF-8" },
      });
    }
  } else if (request.method === "POST") {
    const formData = await request.formData();
    const storedPassword = await SUB.get("admin_password");

    if (!storedPassword) {
      const newPassword = formData.get("password");
      await SUB.put("admin_password", newPassword);
      return new Response("Password set successfully! Now log in.", {
        headers: { "content-type": "text/plain; charset=UTF-8" },
      });
    } else {
      const password = formData.get("password");
      if (password === storedPassword) {
        const response = new Response(await generateAdminDashboard(request), {
          headers: { "content-type": "text/html; charset=UTF-8" },
        });
        response.headers.append(
          "Set-Cookie",
          `admin-auth=logged_in; Path=/; HttpOnly; Secure`
        );
        return response;
      } else {
        return new Response("Invalid password", {
          headers: { "content-type": "text/plain; charset=UTF-8" },
          status: 401,
        });
      }
    }
  }
}

function generateSetPasswordPage() {
  return `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SubLink Worker - Set Password</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
          ${modernStyles()}
        </style>
      </head>
      <body>
        <div class="auth-container">
          <div class="auth-card">
            <div class="auth-header">
              <div class="logo">
                <div class="logo-icon">🔗</div>
                <h1>SubLink Worker</h1>
              </div>
              <p>Set your admin password to get started</p>
            </div>
            <form method="POST" class="auth-form">
              <div class="input-group">
                <input type="password" name="password" placeholder="Create a secure password" required/>
                <div class="input-border"></div>
              </div>
              <button type="submit" class="btn-primary">
                <span>Set Password</span>
                <div class="btn-ripple"></div>
              </button>
            </form>
          </div>
        </div>
      </body>
    </html>
  `;
}

function generateLoginPage() {
  return `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SubLink Worker - Login</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
          ${modernStyles()}
        </style>
      </head>
      <body>
        <div class="auth-container">
          <div class="auth-card">
            <div class="auth-header">
              <div class="logo">
                <div class="logo-icon">🔗</div>
                <h1>SubLink Worker</h1>
              </div>
              <p>Enter your password to access the admin panel</p>
            </div>
            <form method="POST" class="auth-form">
              <div class="input-group">
                <input type="password" name="password" placeholder="Enter your password" required/>
                <div class="input-border"></div>
              </div>
              <button type="submit" class="btn-primary">
                <span>Login</span>
                <div class="btn-ripple"></div>
              </button>
            </form>
          </div>
        </div>
      </body>
    </html>
  `;
}

async function generateAdminDashboard(request) {
  const links = (await SUB.get("vpn_links")) || "";
  // Fix: Make subscription URL dynamic based on current request
  const url = new URL(request.url);
  const subscriptionUrl = `${url.protocol}//${url.host}`;

  return `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SubLink Worker - Dashboard</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
          ${modernStyles()}
          ${dashboardStyles()}
        </style>
      </head>
      <body>
        <div class="dashboard-container">
          <header class="dashboard-header">
            <div class="logo">
              <div class="logo-icon">🔗</div>
              <h1>SubLink Worker</h1>
            </div>
            <div class="header-actions">
              <button class="btn-secondary" onclick="showHelp()">
                <span>📖 Help</span>
              </button>
              <button class="btn-secondary" onclick="logout()">
                <span>🚪 Logout</span>
              </button>
            </div>
          </header>

          <main class="dashboard-main">
            <div class="dashboard-grid">
              <div class="card main-card">
                <div class="card-header">
                  <h2>🔧 Configuration Links</h2>
                  <div class="card-actions">
                    <button class="btn-icon" onclick="importConfig()" title="Import Config">
                      📁
                    </button>
                    <button class="btn-icon" onclick="exportConfig()" title="Export Config">
                      💾
                    </button>
                  </div>
                </div>
                <div class="card-content">
                  <form id="update-links-form" onsubmit="return saveLinks(event);">
                    <div class="textarea-container">
                      <textarea 
                        id="links-box" 
                        name="links" 
                        rows="15" 
                        placeholder="Paste your VPN links here...&#10;&#10;Supported formats:&#10;• JSON configs (full Xray/Sing-box configs)&#10;• vless://...&#10;• vmess://...&#10;• ss://...&#10;• trojan://...&#10;• hysteria2://...&#10;• wireguard://...&#10;• Custom configs with fragments and special options"
                      >${links}</textarea>
                      <div class="textarea-overlay">
                        <div class="link-counter">
                          <span id="link-count">0</span> configs detected
                        </div>
                      </div>
                    </div>
                    <div class="form-actions">
                      <button type="button" class="btn-danger" onclick="clearAllLinks()">
                        <span>🗑️ Clear All</span>
                      </button>
                      <button type="button" class="btn-secondary" onclick="validateLinks()">
                        <span>✅ Validate</span>
                      </button>
                      <button id="save-button" type="submit" class="btn-primary">
                        <span>💾 Save Links</span>
                        <div class="btn-ripple"></div>
                      </button>
                    </div>
                  </form>
                </div>
              </div>

              <div class="card info-card">
                <div class="card-header">
                  <h2>📊 Status & Info</h2>
                </div>
                <div class="card-content">
                  <div class="status-grid">
                    <div class="status-item">
                      <div class="status-icon">🔗</div>
                      <div class="status-text">
                        <span class="status-label">Subscription URL</span>
                        <div class="url-container">
                          <input type="text" id="sub-url" value="${subscriptionUrl}" readonly>
                          <button class="btn-copy" onclick="copyToClipboard('sub-url')">📋</button>
                        </div>
                      </div>
                    </div>
                    <div class="status-item">
                      <div class="status-icon">📱</div>
                      <div class="status-text">
                        <span class="status-label">Compatible Clients</span>
                        <span class="status-value">v2rayNG, v2rayN, Clash</span>
                      </div>
                    </div>
                    <div class="status-item">
                      <div class="status-icon">🔒</div>
                      <div class="status-text">
                        <span class="status-label">Encoding</span>
                        <span class="status-value">Base64 Subscription</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </main>
        </div>

        <!-- Help Modal -->
        <div id="help-modal" class="modal">
          <div class="modal-content">
            <div class="modal-header">
              <h2>📖 Help & Documentation</h2>
              <button class="modal-close" onclick="closeHelp()">&times;</button>
            </div>
            <div class="modal-body">
              <h3>Supported Formats:</h3>
              <ul>
                <li><strong>JSON configs</strong> - Full Xray/Sing-box configurations (preserved as-is)</li>
                <li><strong>vless://</strong> - VLESS protocol links</li>
                <li><strong>vmess://</strong> - VMess protocol links</li>
                <li><strong>ss://</strong> - Shadowsocks links</li>
                <li><strong>trojan://</strong> - Trojan protocol links</li>
                <li><strong>hysteria2://</strong> - Hysteria2 protocol links</li>
                <li><strong>wireguard://</strong> - WireGuard protocol links</li>
                <li><strong>Custom configs</strong> - With fragments and special options</li>
              </ul>
              <h3>How to use:</h3>
              <ol>
                <li>Paste your configs and links in the text area</li>
                <li>Custom JSON configs will be preserved exactly as entered</li>
                <li>Mix different formats as needed</li>
                <li>Click "Save Links" to update</li>
                <li>Use ${subscriptionUrl} as your subscription URL</li>
              </ol>
            </div>
          </div>
        </div>

        <!-- Notifications -->
        <div id="notifications"></div>

        <script>
          ${dashboardScript()}
        </script>
      </body>
    </html>
  `;
}

function modernStyles() {
  return `
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: linear-gradient(135deg, #0c0c0c 0%, #1a1a1a 100%);
      color: #ffffff;
      min-height: 100vh;
      overflow-x: hidden;
    }

    .auth-container {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }

    .auth-card {
      background: rgba(255, 255, 255, 0.05);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 24px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 25px 50px rgba(0, 0, 0, 0.2);
      transform: translateY(0);
      transition: all 0.3s ease;
    }

    .auth-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 35px 60px rgba(0, 0, 0, 0.3);
    }

    .logo {
      display: flex;
      align-items: center;
      justify-content: center;
      flex-direction: column;
      margin-bottom: 20px;
    }

    .logo-icon {
      font-size: 48px;
      margin-bottom: 16px;
      animation: float 3s ease-in-out infinite;
    }

    @keyframes float {
      0%, 100% { transform: translateY(0px); }
      50% { transform: translateY(-10px); }
    }

    .logo h1 {
      font-size: 28px;
      font-weight: 700;
      background: linear-gradient(135deg, #00ffcc, #0066ff);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .auth-header p {
      text-align: center;
      color: rgba(255, 255, 255, 0.7);
      margin-bottom: 30px;
      font-size: 14px;
    }

    .input-group {
      position: relative;
      margin-bottom: 24px;
    }

    .input-group input {
      width: 100%;
      padding: 16px 20px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      color: #ffffff;
      font-size: 16px;
      transition: all 0.3s ease;
    }

    .input-group input:focus {
      outline: none;
      border-color: #00ffcc;
      background: rgba(255, 255, 255, 0.08);
      box-shadow: 0 0 0 3px rgba(0, 255, 204, 0.1);
    }

    .input-border {
      position: absolute;
      bottom: 0;
      left: 0;
      right: 0;
      height: 2px;
      background: linear-gradient(135deg, #00ffcc, #0066ff);
      transform: scaleX(0);
      transition: transform 0.3s ease;
    }

    .input-group input:focus + .input-border {
      transform: scaleX(1);
    }

    .btn-primary {
      width: 100%;
      padding: 16px 24px;
      background: linear-gradient(135deg, #00ffcc, #0066ff);
      border: none;
      border-radius: 12px;
      color: #ffffff;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      position: relative;
      overflow: hidden;
      transition: all 0.3s ease;
    }

    .btn-primary:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 25px rgba(0, 255, 204, 0.3);
    }

    .btn-primary:active {
      transform: translateY(0);
    }

    .btn-ripple {
      position: absolute;
      top: 50%;
      left: 50%;
      width: 0;
      height: 0;
      background: rgba(255, 255, 255, 0.2);
      border-radius: 50%;
      transform: translate(-50%, -50%);
      transition: all 0.6s ease;
    }

    .btn-primary:active .btn-ripple {
      width: 300px;
      height: 300px;
    }
  `;
}

function dashboardStyles() {
  return `
    .dashboard-container {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    .dashboard-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 20px 30px;
      background: rgba(255, 255, 255, 0.02);
      backdrop-filter: blur(20px);
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .header-actions {
      display: flex;
      gap: 12px;
    }

    .dashboard-main {
      flex: 1;
      padding: 30px;
    }

    .dashboard-grid {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 30px;
      max-width: 1400px;
      margin: 0 auto;
    }

    .card {
      background: rgba(255, 255, 255, 0.05);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 20px;
      overflow: hidden;
      transition: all 0.3s ease;
    }

    .card:hover {
      transform: translateY(-2px);
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
    }

    .card-header {
      padding: 24px 24px 0;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .card-header h2 {
      font-size: 20px;
      font-weight: 600;
      color: #ffffff;
    }

    .card-actions {
      display: flex;
      gap: 8px;
    }

    .card-content {
      padding: 24px;
    }

    .textarea-container {
      position: relative;
      margin-bottom: 20px;
    }

    textarea {
      width: 100%;
      min-height: 350px;
      padding: 20px;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      color: #ffffff;
      font-family: 'Fira Code', monospace;
      font-size: 14px;
      line-height: 1.5;
      resize: vertical;
      transition: all 0.3s ease;
    }

    textarea:focus {
      outline: none;
      border-color: #00ffcc;
      box-shadow: 0 0 0 3px rgba(0, 255, 204, 0.1);
    }

    .textarea-overlay {
      position: absolute;
      top: 12px;
      right: 12px;
      background: rgba(0, 0, 0, 0.7);
      padding: 6px 12px;
      border-radius: 8px;
      font-size: 12px;
      color: rgba(255, 255, 255, 0.7);
    }

    .form-actions {
      display: flex;
      gap: 12px;
      justify-content: flex-end;
    }

    .btn-secondary {
      padding: 12px 20px;
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 10px;
      color: #ffffff;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.3s ease;
    }

    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }

    .btn-danger {
      padding: 12px 20px;
      background: linear-gradient(135deg, #ff416c, #ff4b2b);
      border: none;
      border-radius: 10px;
      color: #ffffff;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.3s ease;
    }

    .btn-danger:hover {
      transform: translateY(-1px);
      box-shadow: 0 8px 20px rgba(255, 65, 108, 0.3);
    }

    .btn-icon {
      width: 40px;
      height: 40px;
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 10px;
      color: #ffffff;
      font-size: 16px;
      cursor: pointer;
      transition: all 0.3s ease;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .btn-icon:hover {
      background: rgba(255, 255, 255, 0.15);
      transform: scale(1.05);
    }

    .info-card {
      height: fit-content;
    }

    .status-grid {
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    .status-item {
      display: flex;
      align-items: flex-start;
      gap: 16px;
      padding: 16px;
      background: rgba(255, 255, 255, 0.03);
      border-radius: 12px;
      border: 1px solid rgba(255, 255, 255, 0.05);
    }

    .status-icon {
      font-size: 24px;
      width: 40px;
      height: 40px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(0, 255, 204, 0.1);
      border-radius: 10px;
    }

    .status-text {
      flex: 1;
    }

    .status-label {
      display: block;
      font-size: 12px;
      color: rgba(255, 255, 255, 0.6);
      margin-bottom: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .status-value {
      font-size: 14px;
      color: #ffffff;
      font-weight: 500;
    }

    .url-container {
      display: flex;
      gap: 8px;
      margin-top: 8px;
    }

    .url-container input {
      flex: 1;
      padding: 8px 12px;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      color: #ffffff;
      font-size: 12px;
      font-family: monospace;
    }

    .btn-copy {
      padding: 8px 12px;
      background: rgba(0, 255, 204, 0.1);
      border: 1px solid rgba(0, 255, 204, 0.3);
      border-radius: 8px;
      color: #00ffcc;
      cursor: pointer;
      transition: all 0.3s ease;
    }

    .btn-copy:hover {
      background: rgba(0, 255, 204, 0.2);
    }

    .modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.8);
      backdrop-filter: blur(10px);
      z-index: 1000;
      padding: 20px;
    }

    .modal-content {
      background: rgba(255, 255, 255, 0.05);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 20px;
      max-width: 600px;
      margin: 50px auto;
      max-height: 80vh;
      overflow-y: auto;
    }

    .modal-header {
      padding: 24px 24px 0;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .modal-close {
      background: none;
      border: none;
      color: #ffffff;
      font-size: 24px;
      cursor: pointer;
      width: 40px;
      height: 40px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.3s ease;
    }

    .modal-close:hover {
      background: rgba(255, 255, 255, 0.1);
    }

    .modal-body {
      padding: 24px;
    }

    .modal-body h3 {
      color: #00ffcc;
      margin-bottom: 12px;
      font-size: 16px;
    }

    .modal-body ul, .modal-body ol {
      margin-bottom: 20px;
      padding-left: 20px;
    }

    .modal-body li {
      margin-bottom: 8px;
      color: rgba(255, 255, 255, 0.8);
    }

    #notifications {
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 1100;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .notification {
      background: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 12px;
      padding: 16px 20px;
      color: #ffffff;
      font-size: 14px;
      min-width: 300px;
      animation: slideIn 0.3s ease;
      cursor: pointer;
    }

    .notification.success {
      border-color: rgba(0, 255, 204, 0.5);
      background: rgba(0, 255, 204, 0.1);
    }

    .notification.error {
      border-color: rgba(255, 65, 108, 0.5);
      background: rgba(255, 65, 108, 0.1);
    }

    @keyframes slideIn {
      from {
        transform: translateX(100%);
        opacity: 0;
      }
      to {
        transform: translateX(0);
        opacity: 1;
      }
    }

    @media (max-width: 768px) {
      .dashboard-grid {
        grid-template-columns: 1fr;
      }
      
      .dashboard-header {
        padding: 16px 20px;
        flex-direction: column;
        gap: 16px;
      }
      
      .form-actions {
        flex-direction: column;
      }
      
      .card-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 12px;
      }
    }
  `;
}

function dashboardScript() {
  return `
    // Update link counter with improved parsing
    function updateLinkCounter() {
      const textarea = document.getElementById('links-box');
      const content = textarea.value.trim();
      
      const configs = parseConfigs(content);
      document.getElementById('link-count').textContent = configs.length;
    }

    // Parse different config types
    function parseConfigs(content) {
      const configs = [];
      const lines = content.split('\\n');
      
      for (const line of lines) {
        const trimmedLine = line.trim();
        if (!trimmedLine) continue;
        
        // Check if it's a JSON config (starts with { and appears to be JSON)
        if (trimmedLine.startsWith('{')) {
          try {
            JSON.parse(trimmedLine);
            configs.push({ type: 'json', content: trimmedLine });
          } catch (e) {
            // Invalid JSON, skip
          }
        }
        // Check for protocol links
        else if (
          trimmedLine.startsWith('vless://') ||
          trimmedLine.startsWith('vmess://') ||
          trimmedLine.startsWith('ss://') ||
          trimmedLine.startsWith('trojan://') ||
          trimmedLine.startsWith('hysteria2://') ||
          trimmedLine.startsWith('hy2://') ||
          trimmedLine.startsWith('hysteria://') ||
          trimmedLine.startsWith('tuic://') ||
          trimmedLine.startsWith('wireguard://')
        ) {
          configs.push({ type: 'link', content: trimmedLine });
        }
      }
      
      return configs;
    }

    // Save links function
    async function saveLinks(event) {
      event.preventDefault();
      const form = document.getElementById('update-links-form');
      const formData = new FormData(form);
      const saveButton = document.getElementById('save-button');
      const originalText = saveButton.innerHTML;
      
      saveButton.innerHTML = '<span>💫 Saving...</span>';
      saveButton.disabled = true;
      
      try {
        const response = await fetch('/update-links', {
          method: 'POST',
          body: formData
        });
        
        if (response.ok) {
          saveButton.innerHTML = '<span>✅ Saved!</span>';
          showNotification('Links saved successfully!', 'success');
          setTimeout(() => {
            saveButton.innerHTML = originalText;
            saveButton.disabled = false;
          }, 2000);
        } else {
          throw new Error('Failed to save');
        }
      } catch (error) {
        saveButton.innerHTML = '<span>❌ Error</span>';
        showNotification('Failed to save links. Please try again.', 'error');
        setTimeout(() => {
          saveButton.innerHTML = originalText;
          saveButton.disabled = false;
        }, 2000);
      }
    }

    // Clear all links
    function clearAllLinks() {
      if (confirm('Are you sure you want to clear all links?')) {
        document.getElementById('links-box').value = '';
        updateLinkCounter();
        showNotification('All links cleared', 'success');
      }
    }

    // Validate links with improved parsing
    function validateLinks() {
      const textarea = document.getElementById('links-box');
      const content = textarea.value.trim();
      const configs = parseConfigs(content);
      
      let validCount = 0;
      let invalidCount = 0;
      
      configs.forEach(config => {
        if (config.type === 'json') {
          try {
            const parsed = JSON.parse(config.content);
            if (parsed.outbounds || parsed.inbounds || parsed.routing) {
              validCount++;
            } else {
              invalidCount++;
            }
          } catch (e) {
            invalidCount++;
          }
        } else if (config.type === 'link') {
          validCount++;
        }
      });
      
      // Count any remaining invalid lines
      const lines = content.split('\\n');
      const totalConfigs = configs.length;
      const totalLines = lines.filter(line => line.trim()).length;
      invalidCount += Math.max(0, totalLines - totalConfigs);
      
      const message = \`Validation complete: \${validCount} valid, \${invalidCount} invalid configs\`;
      showNotification(message, invalidCount === 0 ? 'success' : 'error');
    }

    // Copy to clipboard
    async function copyToClipboard(elementId) {
      const element = document.getElementById(elementId);
      try {
        await navigator.clipboard.writeText(element.value);
        showNotification('Copied to clipboard!', 'success');
      } catch (err) {
        element.select();
        document.execCommand('copy');
        showNotification('Copied to clipboard!', 'success');
      }
    }

    // Show notification
    function showNotification(message, type = 'info') {
      const notification = document.createElement('div');
      notification.className = \`notification \${type}\`;
      notification.textContent = message;
      notification.onclick = () => notification.remove();
      
      document.getElementById('notifications').appendChild(notification);
      
      setTimeout(() => {
        notification.remove();
      }, 5000);
    }

    // Help modal functions
    function showHelp() {
      document.getElementById('help-modal').style.display = 'block';
    }

    function closeHelp() {
      document.getElementById('help-modal').style.display = 'none';
    }

    // Import/Export functions
    function importConfig() {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.txt,.json';
      input.onchange = (e) => {
        const file = e.target.files[0];
        if (file) {
          const reader = new FileReader();
          reader.onload = (e) => {
            document.getElementById('links-box').value = e.target.result;
            updateLinkCounter();
            showNotification('Configuration imported successfully!', 'success');
          };
          reader.readAsText(file);
        }
      };
      input.click();
    }

    function exportConfig() {
      const content = document.getElementById('links-box').value;
      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'sublink-config.txt';
      a.click();
      URL.revokeObjectURL(url);
      showNotification('Configuration exported successfully!', 'success');
    }

    // Logout function
    function logout() {
      if (confirm('Are you sure you want to logout?')) {
        document.cookie = 'admin-auth=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
        window.location.reload();
      }
    }

    // Initialize
    document.addEventListener('DOMContentLoaded', function() {
      const textarea = document.getElementById('links-box');
      textarea.addEventListener('input', updateLinkCounter);
      updateLinkCounter();
      
      // Close modal when clicking outside
      document.getElementById('help-modal').addEventListener('click', function(e) {
        if (e.target === this) {
          closeHelp();
        }
      });
    });
  `;
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  const cookieMap = new Map(
    cookies.split(";").map((cookie) => cookie.trim().split("="))
  );
  return cookieMap.get(name);
}

async function generateSubscription(request) {
  const rawContent = (await SUB.get("vpn_links")) || "";
  
  if (!rawContent.trim()) {
    return new Response("", {
      headers: { 
        "content-type": "text/plain; charset=UTF-8",
        "profile-update-interval": "24"
      },
    });
  }

  // Fix: Preserve custom configs instead of converting them
  const processedLines = [];
  const lines = rawContent.split('\n');
  
  for (const line of lines) {
    const trimmedLine = line.trim();
    if (!trimmedLine) continue;
    
    // Check if it's a JSON config (starts with { and appears to be JSON)
    if (trimmedLine.startsWith('{')) {
      try {
        // Validate it's proper JSON but don't convert it - preserve as-is
        JSON.parse(trimmedLine);
        processedLines.push(trimmedLine); // Keep the original JSON config
      } catch (error) {
        // If it's not valid JSON, skip it
        console.error('Invalid JSON config:', error);
      }
    }
    // Check for protocol links
    else if (
      trimmedLine.startsWith('vless://') ||
      trimmedLine.startsWith('vmess://') ||
      trimmedLine.startsWith('ss://') ||
      trimmedLine.startsWith('trojan://') ||
      trimmedLine.startsWith('hysteria2://') ||
      trimmedLine.startsWith('hy2://') ||
      trimmedLine.startsWith('hysteria://') ||
      trimmedLine.startsWith('tuic://') ||
      trimmedLine.startsWith('wireguard://')
    ) {
      processedLines.push(trimmedLine);
    }
  }

  // Encode the processed lines as base64 subscription
  const subscriptionContent = processedLines.join('\n');
  const base64Content = btoa(unescape(encodeURIComponent(subscriptionContent)));
  
  return new Response(base64Content, {
    headers: { 
      "content-type": "text/plain; charset=UTF-8",
      "profile-update-interval": "24",
      "subscription-userinfo": `upload=0; download=0; total=0; expire=0`
    },
  });
}

async function updateLinks(request) {
  const formData = await request.formData();
  const newLinks = formData.get("links");
  await SUB.put("vpn_links", newLinks);
  return new Response("Links updated successfully!", {
    headers: { "content-type": "text/plain; charset=UTF-8" },
  });
}
