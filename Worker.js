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
        headers: { "content-type": "text/html" },
      });
    } else if (cookie === "logged_in") {
      return new Response(await generateAdminDashboard(), {
        headers: { "content-type": "text/html" },
      });
    } else {
      return new Response(generateLoginPage(), {
        headers: { "content-type": "text/html" },
      });
    }
  } else if (request.method === "POST") {
    const formData = await request.formData();
    const storedPassword = await SUB.get("admin_password");

    if (!storedPassword) {
      const newPassword = formData.get("password");
      await SUB.put("admin_password", newPassword);
      const response = new Response("Password set successfully! Now log in.", {
        headers: { "content-type": "text/plain" },
      });
      return response;
    } else {
      const password = formData.get("password");
      if (password === storedPassword) {
        const response = new Response(await generateAdminDashboard(), {
          headers: { "content-type": "text/html" },
        });
        response.headers.append(
          "Set-Cookie",
          `admin-auth=logged_in; Path=/; HttpOnly; Secure`
        );
        return response;
      } else {
        return new Response("Invalid password", {
          headers: { "content-type": "text/plain" },
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
          /* Additional styles specific to this page */
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
          /* Additional styles specific to this page */
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
        <!-- Include Google Fonts -->
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;500;700&display=swap" rel="stylesheet">
        <!-- Include Font Awesome -->
        <link
          rel="stylesheet"
          href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css"
        />
      </head>
      <body>
        <div class="admin-container">
          <header class="header">
            <h1>Admin Dashboard</h1>
          </header>
          <div class="main-content">
            <div class="form-container">
              <form id="add-link-form" action="/update-links" method="POST">
                <textarea
                  name="links"
                  placeholder="Enter new link"
                  required
                ></textarea>
                <button type="submit" class="add-link-button">
                  <i class="fas fa-plus"></i> Add Link
                </button>
              </form>
            </div>
            <div class="links-container">
              <h3>Current Links</h3>
              <form id="links-form" action="/update-links" method="POST">
                ${generateLinkItems(links)}
              </form>
            </div>
          </div>
          <footer class="footer">
            <div class="footer-buttons">
              <button
                type="button"
                class="mass-delete-button"
                onclick="deleteSelectedLinks()"
              >
                <i class="fas fa-trash-alt"></i> Delete Selected
              </button>
              <button
                type="button"
                class="delete-all-button"
                onclick="deleteAllLinks()"
              >
                <i class="fas fa-trash"></i> Delete All
              </button>
            </div>
          </footer>
        </div>
        <script>
          ${dashboardScripts()}
        </script>
      </body>
    </html>
  `;
}

function generateLinkItems(links) {
  const linksArray = links.split("\n").filter((link) => link.trim() !== "");
  if (linksArray.length === 0) return "<p>No links available</p>";

  return linksArray
    .map((link, index) => {
      const safeLink = link.replace(/'/g, "\\'");
      return `
        <div class="link-item" id="link-item-${index}">
          <input
            type="checkbox"
            class="checkbox link-checkbox"
            value="${index}"
          />
          <div class="link-text" id="link-text-${index}">${link}</div>
          <div class="icon-container">
            <i
              class="fas fa-edit icon icon-edit"
              onclick="editLink(${index})"
              id="edit-icon-${index}"
            ></i>
          </div>
        </div>
      `;
    })
    .join("");
}

function commonStyles() {
  return `
    body {
      font-family: 'Poppins', sans-serif;
      background-color: #0f0f0f;
      margin: 0;
      padding: 0;
      color: #fff;
    }
    .container {
      background-color: #1a1a1a;
      padding: 40px;
      margin: 60px auto;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
      width: 400px;
      text-align: center;
    }
    h2 {
      margin-bottom: 30px;
      font-weight: 500;
      text-shadow: 0 0 10px #00ffcc, 0 0 20px #00ffcc;
    }
    input[type='password'] {
      padding: 12px;
      width: 100%;
      margin-bottom: 30px;
      border-radius: 4px;
      border: none;
      font-size: 16px;
      background-color: #2a2a2a;
      color: #fff;
    }
    input[type='password']:focus {
      outline: none;
      box-shadow: 0 0 10px #00ffcc;
    }
    button {
      background: linear-gradient(45deg, #00ffcc, #0066ff);
      color: white;
      border: none;
      padding: 12px 24px;
      font-size: 16px;
      border-radius: 50px;
      cursor: pointer;
      transition: transform 0.2s;
    }
    button:hover {
      transform: scale(1.05);
    }
    /* Responsive design */
    @media (max-width: 500px) {
      .container {
        width: 90%;
        padding: 20px;
      }
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
      background: linear-gradient(45deg, #0066ff, #00ffcc);
      padding: 20px;
      text-align: center;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.5);
    }
    .header h1 {
      margin: 0;
      font-weight: 500;
      color: #fff;
      text-shadow: 0 0 10px #00ffcc, 0 0 20px #00ffcc, 0 0 30px #00ffcc;
    }
    .main-content {
      flex: 1;
      padding: 20px;
      background-color: #0f0f0f;
    }
    .form-container {
      margin-bottom: 20px;
    }
    .form-container textarea {
      width: 100%;
      height: 80px;
      padding: 12px;
      border: none;
      border-radius: 4px;
      font-size: 16px;
      resize: none;
      margin-bottom: 10px;
      background-color: #1a1a1a;
      color: #fff;
    }
    .form-container textarea:focus {
      outline: none;
      box-shadow: 0 0 10px #00ffcc;
    }
    .add-link-button {
      background: linear-gradient(45deg, #00ffcc, #0066ff);
      display: inline-flex;
      align-items: center;
      border-radius: 50px;
      padding: 10px 20px;
      font-size: 16px;
      cursor: pointer;
      border: none;
      transition: transform 0.2s;
    }
    .add-link-button i {
      margin-right: 8px;
    }
    .add-link-button:hover {
      transform: scale(1.05);
    }
    .links-container {
      background-color: #1a1a1a;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.5);
      max-height: 400px;
      overflow-y: auto;
    }
    .links-container h3 {
      margin-top: 0;
      margin-bottom: 20px;
      font-weight: 500;
      color: #fff;
      text-shadow: 0 0 10px #00ffcc;
    }
    .link-item {
      display: flex;
      align-items: center;
      padding: 10px;
      border-bottom: 1px solid #2a2a2a;
    }
    .link-item:last-child {
      border-bottom: none;
    }
    .checkbox {
      margin-right: 15px;
      width: 18px;
      height: 18px;
      accent-color: #00ffcc;
    }
    .link-text {
      flex-grow: 1;
      font-size: 16px;
      color: #fff;
      word-break: break-all;
      display: flex;
      align-items: center;
    }
    .edit-input {
      width: 100%;
      background-color: #1a1a1a;
      border: none;
      border-bottom: 2px solid #00ffcc;
      color: #fff;
      font-size: 16px;
      padding: 5px;
      transition: border-color 0.3s;
    }
    .edit-input:focus {
      outline: none;
      border-bottom: 2px solid #0066ff;
    }
    .icon-container {
      margin-left: 15px;
    }
    .icon {
      font-size: 20px;
      color: #00ffcc;
      cursor: pointer;
      transition: color 0.2s;
    }
    .icon:hover {
      color: #0066ff;
    }
    .icon-save {
      color: #00ffcc;
    }
    .icon-save:hover {
      color: #00ffcc;
    }
    .footer {
      background-color: #0f0f0f;
      padding: 15px 20px;
      box-shadow: 0 -2px 6px rgba(0, 0, 0, 0.5);
    }
    .footer-buttons {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
    }
    .mass-delete-button,
    .delete-all-button {
      background: linear-gradient(45deg, #ff0066, #ffcc00);
      color: white;
      padding: 10px 20px;
      font-size: 16px;
      border-radius: 50px;
      border: none;
      cursor: pointer;
      transition: transform 0.2s;
      display: inline-flex;
      align-items: center;
    }
    .mass-delete-button i,
    .delete-all-button i {
      margin-right: 8px;
    }
    .mass-delete-button:hover,
    .delete-all-button:hover {
      transform: scale(1.05);
    }
    /* Adjust container width */
    .container,
    .admin-container {
      width: 80%;
      max-width: 800px;
      margin: 0 auto;
    }
    /* Neon text effect */
    h1, h2, h3 {
      color: #fff;
      text-shadow: 0 0 10px #00ffcc, 0 0 20px #00ffcc, 0 0 30px #00ffcc;
    }
    /* Scrollbar styling */
    ::-webkit-scrollbar {
      width: 8px;
    }
    ::-webkit-scrollbar-track {
      background: #1a1a1a;
    }
    ::-webkit-scrollbar-thumb {
      background: #00ffcc;
      border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
      background: #0066ff;
    }
    /* Responsive design */
    @media (max-width: 768px) {
      .links-container {
        max-height: 300px;
      }
      .link-text {
        font-size: 14px;
      }
      .icon {
        font-size: 18px;
      }
    }
  `;
}

function dashboardScripts() {
  return `
    function editLink(index) {
      const linkTextElement = document.getElementById('link-text-' + index);
      const currentText = linkTextElement.innerText;
      const iconElement = document.getElementById('edit-icon-' + index);
      
      if (linkTextElement.querySelector('input')) {
        // Already in edit mode, save the changes
        const input = linkTextElement.querySelector('input');
        const newValue = input.value;
        if (newValue !== currentText) {
          updateLink(index, newValue);
        } else {
          linkTextElement.innerText = currentText;
          iconElement.classList.remove('fa-save', 'icon-save');
          iconElement.classList.add('fa-edit', 'icon-edit');
        }
      } else {
        // Enter edit mode
        const input = document.createElement('input');
        input.type = 'text';
        input.value = currentText;
        input.className = 'edit-input';
        linkTextElement.innerHTML = '';
        linkTextElement.appendChild(input);
        input.focus();

        // Change icon to save icon
        iconElement.classList.remove('fa-edit', 'icon-edit');
        iconElement.classList.add('fa-save', 'icon-save');
      }
    }

    function updateLink(index, newLink) {
      const form = document.createElement('form');
      form.method = 'POST';
      form.action = '/update-links';

      const editInput = document.createElement('input');
      editInput.type = 'hidden';
      editInput.name = 'edit';
      editInput.value = 'true';
      form.appendChild(editInput);

      const indexInput = document.createElement('input');
      indexInput.type = 'hidden';
      indexInput.name = 'index';
      indexInput.value = index;
      form.appendChild(indexInput);

      const newLinkInput = document.createElement('input');
      newLinkInput.type = 'hidden';
      newLinkInput.name = 'newLink';
      newLinkInput.value = newLink;
      form.appendChild(newLinkInput);

      document.body.appendChild(form);
      form.submit();
    }

    function deleteSelectedLinks() {
      const checkboxes = document.querySelectorAll('.link-checkbox');
      const selectedIndexes = [];
      checkboxes.forEach((checkbox) => {
        if (checkbox.checked) {
          selectedIndexes.push(checkbox.value);
        }
      });
      if (selectedIndexes.length > 0) {
        if (confirm('Are you sure you want to delete the selected links?')) {
          const form = document.createElement('form');
          form.method = 'POST';
          form.action = '/update-links';

          selectedIndexes.forEach((index) => {
            const deleteInput = document.createElement('input');
            deleteInput.type = 'hidden';
            deleteInput.name = 'deleteIndexes';
            deleteInput.value = index;
            form.appendChild(deleteInput);
          });

          document.body.appendChild(form);
          form.submit();
        }
      } else {
        alert('Please select at least one link to delete.');
      }
    }

    function deleteAllLinks() {
      if (confirm('Are you sure you want to delete ALL links? This action cannot be undone.')) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/update-links';

        const deleteAllInput = document.createElement('input');
        deleteAllInput.type = 'hidden';
        deleteAllInput.name = 'deleteAll';
        deleteAllInput.value = 'true';
        form.appendChild(deleteAllInput);

        document.body.appendChild(form);
        form.submit();
      }
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
  const links = (await SUB.get("vpn_links")) || "";
  return new Response(links, {
    headers: { "content-type": "text/plain" },
  });
}

async function updateLinks(request) {
  const formData = await request.formData();
  const deleteIndexes = formData.getAll("deleteIndexes");
  const editFlag = formData.get("edit");
  const deleteAllFlag = formData.get("deleteAll");
  let links = (await SUB.get("vpn_links")) || "";
  let linksArray = links.split("\n").filter((link) => link.trim() !== "");

  if (deleteAllFlag) {
    await SUB.put("vpn_links", "");
  } else if (deleteIndexes.length > 0) {
    deleteIndexes.sort((a, b) => b - a);
    deleteIndexes.forEach((index) => {
      const idx = parseInt(index);
      if (!isNaN(idx)) {
        linksArray.splice(idx, 1);
      }
    });
    await SUB.put("vpn_links", linksArray.join("\n"));
  } else if (editFlag) {
    const indexToEdit = parseInt(formData.get("index"));
    const newLink = formData.get("newLink");
    if (!isNaN(indexToEdit) && newLink) {
      linksArray[indexToEdit] = newLink.trim();
      await SUB.put("vpn_links", linksArray.join("\n"));
    }
  } else if (formData.get("links")) {
    const newLink = formData.get("links");
    if (newLink) {
      linksArray.push(newLink.trim());
      await SUB.put("vpn_links", linksArray.join("\n"));
    }
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: "/admin",
    },
  });
}
