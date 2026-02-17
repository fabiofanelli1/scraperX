# 🛡️ ScrapeX — X.com Vulnerability Monitor

Real-time monitoring of vulnerability disclosures on X.com (Twitter). Runs automated searches every 5 or X minutes and surfaces only new tweets — no API keys required.

## What is VulnWatch

ScrapeX is a command-line tool built for **security analysts**, **SOC teams**, and **sysadmins** who need to know in real time when new vulnerabilities are disclosed for the products they manage.

The problem is straightforward: information about new CVEs, exploits, and zero-days often surfaces on X.com (Twitter) **hours or days before** official vendor advisories. Security researchers, threat intelligence accounts, and infosec journalists publish details, PoCs, and analyses that can make the difference between a system patched in time and a security incident.

### What It Does

- **Monitors X.com automatically** — Every 5 minutes (configurable), the script runs targeted searches on X.com looking for tweets that contain both the vendor name (Fortinet, Microsoft, Cisco) and the word "vulnerability", filtered by English and Italian language and limited to the last 2 days
- **Shows only new results** — Thanks to a built-in deduplication system, each tweet is displayed only once. If the script runs for hours, you'll only see new tweets compared to previous cycles
- **Requires no API keys** — VulnWatch doesn't use X's official APIs (which are paid and heavily rate-limited). It uses Selenium to simulate a real browser and navigate search pages just like a regular user would
- **Protects your credentials** — X session cookies are encrypted on disk with AES-256 and are never stored in plaintext. The session auto-renews on every cycle, so you only need to export cookies from your browser once
- **Is easily extensible** — You can add new vendors, modify queries, change languages, or adjust the monitoring interval by editing a few lines of configuration

### Real-World Usage Example

You're a sysadmin managing Fortinet firewalls and Windows servers. You launch VulnWatch in a terminal (or in the background via tmux):

```
$ python x_search.py --headless
🔐 Cookie password: ********
✅ Cookie-based login successful!
✅ Monitor started. Press Ctrl+C to stop.

🔄 CYCLE #1 — 2026-02-17 09:00:01
───── [1/3] "Fortinet" "vulnerability" (lang:en OR lang:it) ─────
✅ 2 new tweets found

╭─ #1 ─────────────────────────────────────────────────────────╮
│ @watchTowr  •  2026-02-17 07:22                              │
│                                                              │
│ 🚨 New Fortinet vulnerability CVE-2026-XXXXX — FortiOS RCE  │
│ in SSL VPN. Auth bypass, pre-auth, CVSS 9.8. Patch NOW.     │
│ Full analysis thread 🧵👇                                    │
│                                                              │
│ 💬 34  🔁 289  ❤️ 512  👁 45K                                │
│ https://x.com/watchTowr/status/123456789                     │
╰──────────────────────────────────────────────────────────────╯

───── [2/3] "Microsoft" "vulnerability" (lang:en OR lang:it) ─────
ℹ️  No new tweets (8 already seen)

───── [3/3] "Cisco" "vulnerability" (lang:en OR lang:it) ─────
✅ 1 new tweet found
...

⏳ Next cycle in 5m 0s... Press Ctrl+C to stop.
```

5 minutes later the cycle repeats, showing only any new tweets that appeared in the meantime.

---

## How It Works

ScrapeX uses Selenium to simulate a real browser session on X.com. It cycles through predefined search queries targeting vulnerability disclosures for major vendors, deduplicates results across runs, and displays only new findings in your terminal.

```
"Fortinet" "vulnerability" (lang:en OR lang:it) since:2026-02-15
"Microsoft" "vulnerability" (lang:en OR lang:it) since:2026-02-15
"Cisco" "vulnerability" (lang:en OR lang:it) since:2026-02-15
```

Each query enforces **AND matching** (both words must appear), filters to **English and Italian** tweets only, and limits results to the **last 2 days**.

Session cookies are stored encrypted on disk (AES-256) and **auto-refreshed** after every monitoring cycle — you only need to export cookies from your browser once.

---

## Features

- **Automated monitoring** — runs in a loop every 5 minutes (configurable)
- **Smart deduplication** — only shows tweets you haven't seen before
- **Encrypted cookie storage** — AES-256 via Fernet/PBKDF2, chmod 600
- **Cookie auto-refresh** — browser session tokens are re-saved to disk after each cycle, no manual re-export needed
- **Secure cleanup** — cookies wiped from browser, memory garbage-collected on exit
- **Vendor filtering** — monitor all vendors or pick specific ones
- **Rich terminal output** — colored, formatted output with tweet stats
- **Headless mode** — run without a GUI for servers and background tasks
- **Single search mode** — one-off keyword search when needed

---

## Requirements

- **Python** 3.10+
- **Chrome** or **Chromium** browser installed
- **X.com account** (free tier is fine)

### Python Dependencies

```bash
pip install selenium rich cryptography
```

| Package | Purpose |
|---|---|
| `selenium` | Browser automation (4.10+ includes built-in driver manager) |
| `rich` | Colored terminal output (optional but recommended) |
| `cryptography` | AES-256 cookie encryption |

### Chromium on Fedora

```bash
sudo dnf install chromium
```

On Ubuntu/Debian:

```bash
sudo apt install chromium-browser
```

Selenium 4.10+ automatically downloads the matching ChromeDriver — no manual driver setup needed.

---

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/vulnwatch.git
cd vulnwatch
pip install selenium rich cryptography
```

### 2. Export Cookies from Your Browser (One Time Only)

Since X.com blocks automated login, VulnWatch uses your existing browser session via cookies.

1. Install the **[Get cookies.txt LOCALLY](https://chromewebstore.google.com/detail/get-cookiestxt-locally/cclelndahbckbenkjhflpdbgdldlbecc)** browser extension (Chrome/Firefox)
2. Go to [x.com](https://x.com) and log in normally
3. Click the extension icon → **Export** → save as `cookies.txt` in the project folder

### 3. Encrypt the Cookies

```bash
python x_search.py --encrypt cookies.txt
```

This will:
- Ask you to set a password (min 8 characters)
- Generate `cookies.enc` (AES-256 encrypted)
- **Securely delete** `cookies.txt` (3-pass overwrite + removal)
- Set file permissions to `600` (owner read/write only)

> ⚠️ **Remember your password** — you'll need it every time you start the monitor.

### 4. Run

```bash
python x_search.py
```

```
🔐 Cookie password: ********
✅ 23 cookies loaded.
✅ Cookie-based login successful!
🔄 Updated cookies saved to cookies.enc (23 cookies)
✅ Monitor started. Press Ctrl+C to stop.

═══════════════════════════════════════════════════════════════
  🔄 CYCLE #1  —  2026-02-17 14:32:01
═══════════════════════════════════════════════════════════════

──── [1/3]  "Fortinet" "vulnerability" (lang:en OR lang:it) ────
✅ 3 new tweets found (out of 10 total)
╭─ #1 ──────────────────────────────────────────────────────╮
│ @security_researcher  •  2026-02-17 09:15                 │
│                                                           │
│ Critical Fortinet vulnerability CVE-2026-XXXX allows...   │
│                                                           │
│ 💬 12  🔁 45  ❤️ 89  👁 2.3K                              │
│ https://x.com/security_researcher/status/123456789        │
╰───────────────────────────────────────────────────────────╯
```

---

## Usage

### Monitor Mode (Default)

```bash
# All vendors, every 5 minutes
python x_search.py

# Specific vendors only
python x_search.py --vendor fortinet cisco

# Custom interval (10 minutes)
python x_search.py --interval 600

# Headless (no browser window — ideal for servers)
python x_search.py --headless

# Custom cookie file path
python x_search.py --cookies /path/to/cookies.enc

# More results per query
python x_search.py --max 20
```

### Single Search Mode

```bash
python x_search.py --mode single "FortiGate RCE"
python x_search.py --mode single "Exchange Server zero-day" --max 20
```

### All CLI Options

| Flag | Default | Description |
|---|---|---|
| `--mode` | `monitor` | `monitor` (loop) or `single` (one-off search) |
| `--vendor` | `all` | `fortinet`, `microsoft`, `cisco`, or `all` |
| `--interval` | `300` | Seconds between monitoring cycles |
| `--max` | `10` | Max tweets per query |
| `--lang` | — | Additional language filter (e.g., `en`) |
| `--headless` | `false` | Run without browser GUI |
| `--cookies` | auto-detect | Path to `.enc` or `.txt` cookie file |
| `--no-login` | `false` | Run without authentication (limited results) |
| `--encrypt` | — | Encrypt a cookies.txt file and exit |

---

## Security

VulnWatch handles session tokens that are equivalent to passwords. Here's how they're protected:

### Encryption at Rest
Cookies are encrypted with **AES-256-GCM** using the `cryptography` library's Fernet scheme. The encryption key is derived from your password via **PBKDF2-HMAC-SHA256** with 480,000 iterations (per OWASP 2023 guidelines) and a random 16-byte salt.

### Cookie Auto-Refresh
After every monitoring cycle, VulnWatch extracts the latest cookies from the browser session (X.com renews tokens during navigation) and re-encrypts them into the `.enc` file. This means **you never need to re-export cookies from your browser** — the file stays current automatically.

### File Permissions
The `.enc` file is set to `chmod 600` (owner read/write only). The script verifies permissions on every startup and auto-corrects if other users have read access.

### Secure Deletion
When encrypting cookies, the original plaintext `cookies.txt` is overwritten with 3 passes of random data before deletion.

### Memory Cleanup
On exit (normal, Ctrl+C, or SIGTERM), the script:
- Deletes all cookies from the browser instance
- Clears browser localStorage/sessionStorage
- Closes the Selenium driver
- Erases passwords and decrypted data from memory via `gc.collect()`

### What's NOT Logged
Full search URLs are never printed to the terminal, preventing cookie or session tokens from leaking into terminal logs, tmux scrollback, or systemd journals.

---

## Customization

### Adding Vendors or Queries

Edit the `VULN_QUERIES` list in the script:

```python
VULN_QUERIES = [
    '"Fortinet" "vulnerability" (lang:en OR lang:it)',
    '"Microsoft" "vulnerability" (lang:en OR lang:it)',
    '"Cisco" "vulnerability" (lang:en OR lang:it)',
    # Add your own:
    '"Palo Alto" "vulnerability" (lang:en OR lang:it)',
    '"VMware" "CVE" (lang:en OR lang:it)',
]
```

Remember to update the `--vendor` filter keywords in `vendor_keywords` inside `main()` if you add new vendors.

### Changing the Time Window

The `max_days_ago` parameter in `search_x()` controls how far back to search (default: 2 days). You can change the default or pass it as needed.

### Adjusting Rate Limits

To avoid triggering X.com's anti-scraping:

| Setting | Default | Where |
|---|---|---|
| `SCROLL_PAUSE` | 2.5s | Pause between page scrolls |
| `MAX_SCROLLS` | 15 | Max scrolls per query |
| `MONITOR_INTERVAL` | 300s | Pause between full cycles |
| Inter-query pause | 3-6s (random) | In `run_monitor_cycle()` |

---

## Running as a Background Service

### Using systemd

Create `/etc/systemd/system/vulnwatch.service`:

```ini
[Unit]
Description=VulnWatch - X.com Vulnerability Monitor
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/home/youruser/vulnwatch
ExecStart=/usr/bin/python3 x_search.py --headless
Restart=on-failure
RestartSec=60
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

> **Note:** Since the script requires a password at startup, you'll need to either run it interactively or adapt the `CookieManager` to read the password from a secure keyring.

### Using tmux/screen

```bash
tmux new -s vulnwatch
python x_search.py --headless
# Ctrl+B, D to detach
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `ChromeDriver version mismatch` | Update Selenium: `pip install --upgrade selenium` |
| `session not created` | Make sure Chromium is installed: `sudo dnf install chromium` |
| `Expired or invalid cookies` | Re-export cookies from browser and re-encrypt |
| `No tweets found` | Try without `--headless` to see if X is showing a CAPTCHA |
| Login blocked by X | X detected automation — use cookie-based auth (default) |
| Permission denied on cookies.enc | Run: `chmod 600 cookies.enc` |

---

## Project Structure

```
vulnwatch/
├── x_search.py       # Main script (single file, no external modules)
├── cookies.enc       # Encrypted session cookies (generated, gitignored)
├── cookies.txt       # Raw cookies (temporary, deleted after encryption)
├── README.md
├── .gitignore
└── LICENSE
```

### Recommended .gitignore

```
cookies.txt
cookies.enc
__pycache__/
*.pyc
```

---

## Disclaimer

This tool is intended for **security research and awareness** purposes. Scraping X.com may violate their [Terms of Service](https://x.com/en/tos). Use responsibly, at your own risk, and respect rate limits. The authors are not responsible for any misuse or account restrictions resulting from the use of this tool.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
