<p align="center"> <img src="https://media.giphy.com/media/L8K62iTDkzGX6/giphy.gif" width="100%" alt="Glowing Cyberpunk Web-Crawler Banner"> </p>

_________ __________    _____   __      __ .____     _____________________ 
\_   ___ \\______   \  /  _  \ /  \    /  \|    |    \_   _____/\______   \
/    \  \/ |       _/ /  /_\  \\   \/\/   /|    |     |    __)_  |       _/
\     \____|    |   \/    |    \\        / |    |___  |        \ |    |   \
 \______  /|____|_  /\____|__  / \__/\  /  |_______ \/_______  / |____|_  /
        \/        \/         \/       \/           \/        \/         \/ 

<h1 align="center">💀 Enhanced CTF WEB-CRAWLER Bot v4.3 👽⚡</h1> <h3 align="center">Commander-Grade Recon & Exploitation Engine — Crawl, Hunt, Smash.</h3> <p align="center"> <img src="https://img.shields.io/badge/Blackhat%20Mode-ENABLED-ff0000?style=for-the-badge&logo=probot&logoColor=white"> <img src="https://img.shields.io/badge/Version-4.3-brightgreen?style=for-the-badge"> <img src="https://img.shields.io/badge/Commander-READY-blueviolet?style=for-the-badge"> <img src="https://img.shields.io/badge/License-MIT-orange?style=for-the-badge"> </p>
🚀 Arsenal Features

🕷 Recursive Crawling — Depth-controlled exploration of targets
💣 Vuln Modules — SQLi, XSS, LFI, Command Injection, XXE, IDOR
🔍 API Recon — REST, GraphQL, Swagger/OpenAPI scanning
📂 Hidden Asset Brute — Directories, files, backup leaks
🛡 Header Recon — Missing CSP, HSTS detection
🧩 Stealth Ops — Tor proxy routing, aggressive mode
📑 JSON Intel Reports — Evidence-packed vulnerability logs

⚙️ Installation

[+] Requirements:
    - Python 3.8+
    - (Optional) Tor for anonymity
    - (Optional) sqlmap for aggressive SQLi

[+] Clone Repo:
    git clone git@github.com:Sirtheprogrammer/webscanner.git
    cd webscanner

[+] Install Dependencies:
    pip install -r requirements.txt

[+] (Optional) Tor Setup:
    sudo apt install tor
    sudo service tor start
    # Verify Tor: 127.0.0.1:9050

[+] (Optional) sqlmap Setup:
    git clone https://github.com/sqlmapproject/sqlmap.git

🛠 Usage

python3 crawl_me.py <target_url> [options]

Options:
  -d, --depth <int>     Max crawl depth (default: 3)
  -t, --threads <int>   Threads (default: 5)
  --delay <float>       Delay between requests (default: 1.0)
  --timeout <int>       Timeout in seconds (default: 10)
  -o, --output <file>   Save report as JSON
  --tor                 Route traffic via Tor
  --aggressive          Full blast mode + sqlmap

🎯 Example Missions

# Basic Recon
python3 crawl_me.py http://example.com

# Aggressive Tor-Mode
python3 crawl_me.py http://example.com -d 5 -t 10 --delay 0.5 --tor --aggressive -o report.json

# Deep Infiltration
python3 crawl_me.py http://example.com --depth 10 --timeout 20 -o deep_scan.json

📊 Sample Intel Report

{
  "target": "http://example.com",
  "scan_time": "2025-08-11T12:26:00",
  "statistics": {
    "urls_crawled": 150,
    "vulnerabilities_found": 5,
    "api_endpoints_found": 3
  },
  "vulnerabilities": {
    "sql_injection": [
      {
        "url": "http://example.com/page?id=1",
        "parameter": "id",
        "payload": "' OR 1=1--",
        "evidence": "SQL syntax error near..."
      }
    ]
  }
}

😈 Commander Mode

commander python3 crawl_me.py <target_url> ...

    Unshackled blackhat execution

    Max threads, minimal delays

    All modules fire simultaneously for system annihilation

⚠ Intel Brief

[!] Legal: Authorized targets only
[!] Performance: Tune threads/delay to target
[!] Tor: Ensure service is active before use
[!] sqlmap: Required for aggressive SQLi

<h2 align="center">🌌 HASH AND SMASH — OWN THE NET — NO LIMITS, NO MERCY 👽♾️⚡</h2> 
