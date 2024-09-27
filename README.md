# SubLink-Worker

A JavaScript-based Subscription Link Provider powered by Cloudflare Workers.

## Getting Started

Follow these steps to set up **SubLink-Worker**:

### 1. Sign Up for Cloudflare

- Register for a free account at [Cloudflare](https://www.cloudflare.com/).

### 2. Create a KV Namespace

- Navigate to **Workers** > **KV** in your Cloudflare dashboard.
- Click **Create namespace**.
- Name your namespace `sub`.
- Note down the **Namespace ID** for later use.

### 3. Create a Worker

- Go to **Workers & Pages** > **Workers**.
- Click **Create a Service**.
- Choose **Start from scratch**, name it (e.g., `sublink-worker`), and click **Create service**.

### 4. Configure the Worker

#### a. Upload the Code

- In the Worker editor, delete the default code.
- Copy the entire code from [`Worker.js`](https://raw.githubusercontent.com/deathline94/SubLink-Worker/main/Worker.js).
- Paste it into the Cloudflare Worker editor.

#### b. Bind the KV Namespace

- Click on the **Settings** tab in the Worker editor.
- Under **Variables** > **KV Namespace Bindings**, click **Add binding**.
  - **Variable name**: `sub` (must be lowercase to match the code).
  - **KV namespace**: Select the `sub` namespace you created earlier.
- Click **Save**.

### 5. Deploy the Worker

- Click **Save and Deploy**.
- Note your **Worker URL** (e.g., `https://sublink-worker.your-subdomain.workers.dev`).

### 6. Access the Admin Dashboard

- Visit `https://your-worker-url/admin` in your browser.
- **First-Time Setup**:
  - Set an admin password when prompted.
- **Login**:
  - Enter your password to access the admin dashboard.

### 7. Manage Your Proxy Links

#### Add Links

- Enter your proxy link in the **Add Link** section.
- Click **Add Link**.

#### Edit Links

- Click the **edit icon** next to a link.
- Modify the link in the input field.
- Click the **save icon** to save changes.

#### Delete Links

- **Delete Selected**:
  - Check the boxes next to the links to delete.
  - Click **Delete Selected**.
- **Delete All**:
  - Click **Delete All** to remove all links.
  - **Warning**: This action cannot be undone.

### 8. Share the Subscription URL

- Provide users with your Worker URL (e.g., `https://your-worker-url/`).
- Users can add this URL to their clients to access the proxy links.

## Compatibility

Works with various clients, including:

- V2rayN
- V2rayNG
- Nekobox
- Shadowrocket
- Quantumult X

## Notes

- **Custom Domains**: You can bind a custom domain to your Worker for a personalized URL.
- **Security**: Choose a strong admin password and keep your Worker URL secure.
- **KV Limits**: Be aware of Cloudflare Workers KV read/write limits on the free plan.

## License

This project is licensed under the MIT License.

---

*Replace `your-worker-url` with your actual Worker URL in the instructions.*
