# 🔐 JWT Refresher — Burp Suite Extension

A comprehensive Burp Suite extension for managing JWT token lifecycles during penetration testing. Handles automatic token refresh, multiple response formats, multi-session tracking, and **Broken Access Control (BAC) testing** — all from a single UI.

Built with Jython for Burp Suite's Extender API.

---

## ✨ Features

### Core
- **Two Operating Modes** — Active (single-session, manual refresh) and Passive (auto-learning, multi-session)
- **Three Extraction Modes** — JSON Path, Regex Pattern, String-Escaped JSON
- **Auto-Refresh** — Based on JWT `exp` claim or fixed time intervals
- **Thread-Safe** — All token operations are lock-protected for concurrent Burp tool access
- **Scope-Aware Injection** — Only inject tokens for in-scope hosts

### BAC Testing
- **Built-in BAC Mode** — Select a low-privilege session and auto-inject its token into high-privilege requests
- **Tool-Specific Control** — Apply BAC swaps to Repeater only, all tools, or all except Proxy
- **Rich Visibility** — decoded JWT claims, old→new swap details, session identity summaries

### Token Extraction
| Mode | Use Case | Example |
|------|----------|---------|
| **JSON Path** | Standard JSON responses | `jwt.token` → `{"jwt": {"token": "eyJ..."}}` |
| **Regex Pattern** | Any text format | `"JWTToken"\s*:\s*"([^"]+)"` |
| **String-Escaped JSON** | Double-encoded JSON | `"{\"key\":\"val\"}"` — auto-unescapes |

---

## 📦 Installation

### Prerequisites
- Burp Suite Professional or Community Edition
- Jython standalone JAR ([Download](https://www.jython.org/download))

### Steps

1. **Configure Jython in Burp Suite:**
   - Go to **Extender → Options → Python Environment**
   - Set the path to your Jython standalone JAR file

2. **Load the Extension:**
   - Go to **Extender → Extensions → Add**
   - Extension Type: **Python**
   - Extension File: Select `JWTrefresher_v2.py`

3. A new **"JWT Refresher"** tab will appear in Burp Suite.

---

## 🔧 Modes Explained

### Active Mode (Single Session)

Best for: **Single user testing, API testing, long-running scans**

```
You ──paste refresh token──→ Extension ──POST──→ Token Endpoint
                                    ↓
                              Stores new access token
                                    ↓
                           Injects into all requests
```

**How it works:**
1. Paste your refresh token into the UI
2. Configure the token endpoint URL
3. Click "Refresh" or enable auto-refresh
4. The extension calls the endpoint, extracts new tokens, and injects them into outgoing requests

**Auto-Refresh Options:**
- **On JWT Expiry** — Reads the `exp` claim and refreshes N seconds before expiry
- **Fixed Interval** — Refreshes every N minutes regardless
- **On Trigger** — Refreshes when a configurable string appears in any response (e.g., "token expired")

### Passive Mode (Multi-Session)

Best for: **Multi-user testing, BAC testing, complex apps**

```
Browser A (User1) ──→ Burp Proxy ──→ App
Browser B (User2) ──→ Burp Proxy ──→ App
                          ↓
                   Extension watches responses
                   from token endpoint
                          ↓
                   Learns & stores tokens
                   per user identity
                          ↓
                   Keeps all sessions fresh
```

**How it works:**
1. Configure the token endpoint URL
2. Set Session Identifier Claims (e.g., `sub`, `user_id`) to distinguish users
3. Browse the app normally through Burp's proxy
4. The extension watches responses, decodes JWTs, and maps tokens to user identities
5. When a request contains a stale token, it's replaced with the latest one for that user

---

## 🎯 BAC Testing (Broken Access Control)

The killer feature for access control testing with two accounts.

### Setup

1. Switch to **Passive Mode**
2. Set **Session Identifier Claims** (e.g., `sub` or `user_id`)
3. Enable **Token Handling** (checkbox)
4. Log in as **User A** (low-privilege) through Burp proxy
5. Log in as **User B** (admin) through Burp proxy
6. The extension learns both sessions automatically

### Testing

1. In the **BAC Testing** panel:
   - ✅ Enable BAC Testing
   - **Inject As:** Select the low-privilege user from the dropdown
   - **Apply To:** "Repeater Only" (recommended)

2. Browse as the admin user, find admin-only endpoints
3. Send any admin request to **Repeater → Send**
4. The extension **automatically replaces** the admin token with the low-privilege user's token
5. If the request succeeds → **BAC vulnerability found!**

### What You See in the Logs

```
[20:15:30] [PASSIVE] NEW session captured: 101
             Identity: sub=101, email=user@test.com, role=user (exp: 590s)
             Token:    eyJhbGciOiJSUzI1Ni...xKz_8mJqR5Fw2N

[20:15:45] [PASSIVE] NEW session captured: 202
             Identity: sub=202, email=admin@test.com, role=admin (exp: 580s)
             Token:    eyJhbGciOiJSUzI1Ni...yQ3pLm7Rw9Kx

[20:22:10] [BAC] Repeater | sub=202, role=admin => sub=101, role=user
             Old: eyJhbGciOiJSUzI1Ni...adminToken5Fw2
             New: eyJhbGciOiJSUzI1Ni...userToken9Kx3
```

### Apply To Options

| Option | Behavior |
|--------|----------|
| **Repeater Only** | Safest — only swaps tokens in Repeater. Normal proxy browsing unaffected |
| **All Tools** | Swaps everywhere — Proxy, Scanner, Intruder, Repeater |
| **All Except Proxy** | Keeps normal browsing working, swaps in Repeater/Scanner/Intruder |

---

## ⚙️ Configuration Reference

### Common Configuration
| Field | Description |
|-------|-------------|
| **Token Endpoint URL** | The URL to send refresh requests to (Active) or watch responses from (Passive) |
| **Injection Header Name** | Header to inject the token into (default: `Authorization`) |
| **Injection Header Value** | Format string using `{{token}}` placeholder (default: `Bearer {{token}}`) |
| **Scope Hosts** | Comma-separated list of hosts to inject tokens for (blank = all/Burp scope) |

### Response Token Extraction
| Field | Description |
|-------|-------------|
| **Extraction Mode** | JSON Path, Regex Pattern, or String-Escaped JSON |
| **Access Token JSON Path** | Dot-notation path to the access token in JSON (e.g., `jwt.token`) |
| **Refresh Token JSON Path** | Dot-notation path to the refresh token (Active mode only) |
| **Access Token Regex** | Regex with capture group `()` around the token value |
| **Refresh Token Regex** | Regex for refresh token extraction (Active mode only) |

### Active Mode Configuration
| Field | Description |
|-------|-------------|
| **Initial Refresh Token** | Paste the raw refresh token value |
| **Custom Request Headers** | Additional headers, one per line in `Key: Value` format |
| **Custom Body Parameters** | Additional body params, one per line in `key: value` format. Use `{{timestamp}}` for dynamic values |
| **Request Refresh Token Key** | JSON key name for the refresh token in the request body |
| **Auto-Refresh Trigger** | String to detect in responses that triggers automatic refresh |
| **Expiry Buffer** | Seconds before JWT expiry to trigger refresh (default: 30) |
| **Interval** | Fixed refresh interval in minutes (default: 5) |

### Passive Mode Configuration
| Field | Description |
|-------|-------------|
| **Session Identifier Claims** | JWT payload claims used to identify users (one per line, e.g., `sub`, `user_id`). Leave blank for single-session mode |

---

## 🧪 Handling Non-Standard Responses

### Standard JSON
```json
{"access_token": "eyJ...", "refresh_token": "eyJ..."}
```
→ Use **JSON Path** mode: `access_token`

### Nested JSON
```json
{"data": {"auth": {"jwt": {"token": "eyJ..."}}}}
```
→ Use **JSON Path** mode: `data.auth.jwt.token`

### String-Escaped JSON
```
"{\"JWTToken\":\"eyJ...\",\"refreshtoken\":\"\"}"
```
→ Use **String-Escaped JSON** mode: `JWTToken`

### Non-JSON / Mixed Format
```
JWTToken":"eyJhbGciOiJ...",refreshtoken":""}
```
→ Use **Regex** mode: `JWTToken":"([^"]+)"`

### Token in XML/HTML
```xml
<token>eyJhbGciOiJ...</token>
```
→ Use **Regex** mode: `<token>([^<]+)</token>`

---

## 🛡️ Security Notes

- This extension is designed for **authorized security testing only**
- Tokens are stored in-memory only — they do not persist to disk
- The extension makes HTTP requests only in Active Mode (to the configured endpoint)
- In Passive Mode, no outbound requests are made — it only observes proxy traffic

---

## 📋 Changelog

### v3.0 (Current)
- Three extraction modes (JSON Path, Regex, String-Escaped JSON)
- BAC Testing Mode with session selection and tool-specific control
- Auto-refresh based on JWT `exp` claim
- Fixed-interval auto-refresh
- Rich JWT visibility — decoded claims, old→new swap logs
- Scope-aware token injection
- Thread-safe token cache with dedicated locks
- Extension unload listener for clean shutdown
- Connection timeouts (10s connect, 15s read)
- Proper resource cleanup (connection disconnect)
- Base64 URL-safe character handling for JWT decoding

### v2.0
- Active and Passive operating modes
- Multi-session support with composite identifiers
- Custom headers and body parameters
- Auto-refresh on trigger string detection

---

## 📄 License

This project is provided for educational and authorized security testing purposes.

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.
