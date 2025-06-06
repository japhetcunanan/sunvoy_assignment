// Import the error function from console for throwing errors
import { error } from 'console';
// Import Node's filesystem module to read/write files
import * as fs from 'fs';
// Import crypto module for HMAC hash generation
import crypto from 'crypto';

// Define the file path to store/reuse the cookie
const AUTH_FILE = 'authentication.json';
// Base URL of the Sunvoy challenge app
const sunvoyUrl = 'https://challenge.sunvoy.com/';

async function loginAndFetchUsers() {
  // Load previously saved cookie
  let cookie = loadAuth();

  // If a saved cookie exists and it's still valid, reuse it
  if (cookie && await isCookieValid(cookie)) {
    console.log('Reusing saved cookie');
  } else {
    // Otherwise, perform login
    console.log('Logging in...');
    
    // Get the login page to extract the nonce
    const loginAccessRes = await fetch(`${sunvoyUrl}`);
    const loginPageHtml = await loginAccessRes.text();

    // Extract nonce token from HTML
    const nonce = extractNonceFromHtml(loginPageHtml);
    if (!nonce) throw error("Nonce not found");

    // Post login credentials and nonce to the server
    const postLoginRes = await fetch(`${sunvoyUrl}login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      redirect: 'manual',
      body: new URLSearchParams({
        username: 'demo@example.org',
        password: 'test',
        nonce: nonce,
      }),
    });

    // Extract set-cookie from login response
    cookie = postLoginRes.headers.get('set-cookie') ?? '';
    
    // Save cookie for future reuse
    saveAuth(cookie);
  }

  // Use the cookie to access protected users API
  const usersAccessRes = await fetch(`${sunvoyUrl}api/users`, {
    headers: {
      'Cookie': cookie,
    },
    method: 'POST'
  });

  // Parse the JSON response with users data
  const usersData = await usersAccessRes.json();

  // Fetch the tokens page to extract hidden credentials
  const settingsTokenRes = await fetch(`${sunvoyUrl}settings/tokens`, {
    method: 'GET',
    headers: {
      'Cookie': cookie,
    }
  });
  
  // Parse the token HTML page
  const tokenHTML = await settingsTokenRes.text();
  
  // Extract necessary fields from the HTML using regex
  const access_token = tokenHTML.match(/id="access_token"\s+value="([^"]+)"/)?.[1];
  const openId = tokenHTML.match(/id="openId"\s+value="([^"]+)"/)?.[1];
  const userId = tokenHTML.match(/id="userId"\s+value="([^"]+)"/)?.[1];
  const apiuser = tokenHTML.match(/id="apiuser"\s+value="([^"]+)"/)?.[1];
  const operateId = tokenHTML.match(/id="operateId"\s+value="([^"]+)"/)?.[1];
  const language = tokenHTML.match(/id="language"\s+value="([^"]+)"/)?.[1];

  // Create a signed request with HMAC-based checkcode
  const request = createSignedRequest({
    access_token,
    apiuser,
    language,
    openId,
    operateId,
    userId
  });

  // Use all extracted and signed values to POST to secure settings API
  const settingsAccessRes = await fetch('https://api.challenge.sunvoy.com/api/settings', {
    headers: {
        "Content-Type": "application/json",
        "Cookie": cookie,
    },
    method: 'POST',
    body: JSON.stringify({
      access_token,
      apiuser,
      language,
      openId,
      operateId,
      userId,
      timestamp: request.timestamp,
      checkcode: request.checkcode
    })
  });

  // Parse the authenticated user settings response
  const authenticatedUser = await settingsAccessRes.json();

  // Combine users and authenticated user data
  const combinedData = {
      users: usersData,
      authenticatedUser: authenticatedUser
  };

  // Format combined data as pretty JSON
  const prettyJson = JSON.stringify(combinedData, null, 2);

  // Write the output to a file
  fs.writeFileSync('users.json', prettyJson, 'utf8');
  console.log('All Data saved to users.json');

  // Exit process once complete
  process.exit(0);
}

// Extract nonce value from HTML login page
function extractNonceFromHtml(html: string): string | null {
  let match = html.match(/<input[^>]*name=["']?nonce["']?[^>]*value=["']?([^"'>]*)["']?/i);
  const element = match?.[0] ?? '';
  match = element.match(/<input[^>]*name=["']nonce["'][^>]*value=["']([^"']+)["']/);
  return match?.[1];
}

// Create HMAC-signed request payload with checkcode
function createSignedRequest(t) {
  const e = Math.floor(Date.now() / 1e3); // Current timestamp in seconds
  const i = { ...t, timestamp: e.toString() };
  const n = Object.keys(i).sort().map(t => `${t}=${encodeURIComponent(i[t])}`).join("&");
  const o = crypto.createHmac("sha1", "mys3cr3t"); // Create HMAC with secret
  o.update(n);
  const h = o.digest("hex").toUpperCase(); // Final checkcode in uppercase hex
  return {
      payload: n,
      checkcode: h,
      fullPayload: `${n}&checkcode=${h}`,
      timestamp: e
  }
}

// Save cookie to file
function saveAuth(cookie: string) {
  fs.writeFileSync(AUTH_FILE, JSON.stringify({
    cookie,
    savedAt: Date.now()
  }, null, 2));
}

// Load cookie from file (if exists)
function loadAuth(): string | null {
  if (!fs.existsSync(AUTH_FILE)) return null;
  const { cookie } = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
  return cookie;
}

// Check if the stored cookie is still valid by hitting a protected endpoint
async function isCookieValid(cookie: string): Promise<boolean> {
  try {
    const res = await fetch(`${sunvoyUrl}api/users`, {
      method: 'POST',
      headers: {
        'Cookie': cookie
      }
    });
    return res.ok; // Valid if server returns 200 OK
  } catch {
    return false;
  }
}

// Start the script
loginAndFetchUsers().catch(console.error);
