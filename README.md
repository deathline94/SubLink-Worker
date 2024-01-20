### SubLink-Worker
A JavaScript-based Subscription Link Provider for Cloudflare Workers

## Getting Started
Follow these steps to set up SubLink-Worker:

1. **Sign Up**: Register for a free account on [Cloudflare](https://www.cloudflare.com/).

2. **Navigate to Workers**: Go to the 'Workers and Pages' section in your Cloudflare dashboard.

3. **Create a Worker**: Initiate a new Worker using the basic template provided by Cloudflare.

4. **Upload Code**: Edit the new Worker and replace its contents with the code from [`Worker.js`](https://raw.githubusercontent.com/deathline94/SubLink-Worker/main/Worker.js) in this repository.

5. **Configure Proxy Links**:
   - Edit line 8 in [`Worker.js`](https://raw.githubusercontent.com/deathline94/SubLink-Worker/main/Worker.js). 
   - Remove the existing content on this line.
   - Add your proxy links, placing one link per line. (Refer to the image below for guidance.)
   - Share the Worker URL with others to integrate into their clients. It's that simple!

   ![Configuration Steps](https://raw.githubusercontent.com/deathline94/SubLink-Worker/main/help.png)

## Compatibility
SubLink-Worker is compatible with a variety of clients, including V2rayN, V2rayNG, Nekobox, and more.
