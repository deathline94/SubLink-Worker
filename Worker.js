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
  } else {
    return displayLinks();
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
      return new Response(await generateAdminDashboard(), {
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
        const response = new Response(await generateAdminDashboard(), {
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
    <html>
      <head>
        <title>Set Admin Password</title>
        <style>
          ${commonStyles()}
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Set Admin Password</h2>
          <form method="POST">
            <input type="password" name="password" placeholder="Set Password" required/>
            <button type="submit">Set Password</button>
          </form>
        </div>
      </body>
    </html>
  `;
}

function generateLoginPage() {
  return `
    <html>
      <head>
        <title>Admin Login</title>
        <style>
          ${commonStyles()}
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Admin Login</h2>
          <form method="POST">
            <input type="password" name="password" placeholder="Password" required/>
            <button type="submit">Login</button>
          </form>
        </div>
      </body>
    </html>
  `;
}

async function generateAdminDashboard() {
  const links = (await SUB.get("vpn_links")) || "";

  return `
    <html>
      <head>
        <title>Admin Dashboard</title>
        <style>
          ${dashboardStyles()}
        </style>
      </head>
      <body>
        <div class="admin-container">
          <header class="header">
            <h1>Admin Dashboard</h1>
          </header>
          <div class="main-content">
            <form id="update-links-form" action="/update-links" method="POST" onsubmit="return saveLinks(event);">
              <textarea id="links-box" name="links" rows="10" style="width:100%;">${links}</textarea>
              <div class="footer-buttons">
                <button type="button" class="clear-all-button" onclick="clearAllLinks()">Clear All</button>
                <button id="save-button" type="submit" class="save-button">Save</button>
              </div>
            </form>
          </div>
        </div>
        <script>
          async function saveLinks(event) {
            event.preventDefault();
            const form = document.getElementById('update-links-form');
            const formData = new FormData(form);
            const saveButton = document.getElementById('save-button');
            
            // Send update request
            const response = await fetch('/update-links', {
              method: 'POST',
              body: formData
            });
            
            // If successful, change the save button to "Saved" briefly
            if (response.ok) {
              saveButton.textContent = "Saved !!!";
              setTimeout(() => {
                saveButton.textContent = "Save";
              }, 2000);
            }
          }

          function clearAllLinks() {
            document.getElementById('links-box').value = '';
          }
        </script>
      </body>
    </html>
  `;
}

function commonStyles() {
  return `
    body {
      font-family: 'Poppins', sans-serif;
      background-color: #0f0f0f;
      color: #fff;
    }
    .container {
      background-color: #1a1a1a;
      padding: 40px;
      margin: 60px auto;
      border-radius: 8px;
      width: 400px;
      text-align: center;
    }
    input[type='password'], textarea {
      padding: 12px;
      width: 100%;
      margin-bottom: 30px;
      border-radius: 4px;
      border: none;
      font-size: 16px;
      background-color: #2a2a2a;
      color: #fff;
    }
    button {
      background: linear-gradient(45deg, #00ffcc, #0066ff);
      color: white;
      padding: 12px 24px;
      font-size: 16px;
      border-radius: 50px;
      cursor: pointer;
    }
    button:hover {
      transform: scale(1.05);
    }
  `;
}

function dashboardStyles() {
  return `
    ${commonStyles()}
    .admin-container {
      display: flex;
      flex-direction: column;
      min-height: 100vh;
      width: 80%;
      max-width: 800px;
      margin: 0 auto;
    }
    .header {
      background: linear-gradient(45deg, #ff0066, #ffcc00);
      color: white;
      padding: 10px;
      text-align: center;
      border-radius: 25px;
      width: 100%;
      display: inline-block;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      font-size: 24px;
    }
    .header h1 {
      margin: 0;
      color: #fff; 
    }
    .main-content {
      padding: 20px;
      background-color: #0f0f0f;
      flex: 1;
    }
    .footer-buttons {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
    }
    .clear-all-button, .save-button {
      background: linear-gradient(45deg, #ff0066, #ffcc00);
      padding: 10px 20px;
      font-size: 16px;
      border-radius: 50px;
      border: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
    }
  `;
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  const cookieMap = new Map(
    cookies.split(";").map((cookie) => cookie.trim().split("="))
  );
  return cookieMap.get(name);
}

async function displayLinks() {
  const rawLinks = (await SUB.get("vpn_links")) || "";
  return new Response(rawLinks, {
    headers: { "content-type": "text/plain; charset=UTF-8" },
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
