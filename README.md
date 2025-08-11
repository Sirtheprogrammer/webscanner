Enhanced CTF Web Vulnerability Crawler Bot v4.3 👽⚡
A Commander-Grade web vulnerability scanner designed for Capture The Flag (CTF) challenges and advanced penetration testing. This tool performs comprehensive web crawling, vulnerability scanning, and exploitation with a focus on SQL Injection, XSS, LFI, Command Injection, XXE, IDOR, and API endpoint vulnerabilities. Built with a blackhat mindset, it smashes through systems with no limits, delivering elite-level results. 🌎😈

Features 🔥

Deep Web Crawling: Recursively crawls websites up to a specified depth, extracting URLs, forms, parameters, and API endpoints.
Vulnerability Scanning:
SQL Injection (Error-based, Time-based, Boolean-based) with sqlmap integration.
Cross-Site Scripting (XSS) with context-aware payload testing.
Local File Inclusion (LFI) and Directory Traversal detection.
Command Injection with time-based verification.
XML External Entity (XXE) injection testing.
Insecure Direct Object Reference (IDOR) exploitation with advanced identifier manipulation.


API Endpoint Discovery: Detects REST, GraphQL, and Swagger/OpenAPI endpoints with automated exploitation.
Directory and File Enumeration: Scans for hidden directories and sensitive files using comprehensive wordlists.
Security Header Analysis: Identifies missing security headers (e.g., CSP, HSTS).
Tor Support: Optional anonymity through Tor proxy integration.
Aggressive Mode: Enhanced scanning with reduced delays and sqlmap integration for deeper exploitation.
Detailed Reporting: Generates JSON reports with statistics, vulnerabilities, and evidence.
Session Hijacking Detection: Tests for unauthorized access using captured cookies.
Multithreaded Performance: Optimized for speed with configurable threads and delays.


Installation 🚀
Prerequisites

Python 3.8 or higher
Tor (optional, for anonymity)
sqlmap (optional, for aggressive mode SQL injection testing)

Steps

Clone the repository:
git@github.com:Sirtheprogrammer/webscanner.git
cd webscanner


Install dependencies:
pip install -r requirements.txt


(Optional) Set up Tor for anonymous scanning:

Install Tor: sudo apt install tor (Linux) or equivalent for your OS.
Start Tor service: sudo service tor start.
Verify Tor is running on 127.0.0.1:9050.


(Optional) Install sqlmap for aggressive mode:
git clone https://github.com/sqlmapproject/sqlmap.git




Usage 🛠️
Run the crawler with the following command:
python3 crawl_me.py <target_url> [options]

Options

-d, --depth <int>: Maximum crawl depth (default: 3).
-t, --threads <int>: Number of concurrent threads (default: 5).
--delay <float>: Delay between requests in seconds (default: 1.0).
--timeout <int>: Request timeout in seconds (default: 10).
-o, --output <file>: Output JSON report file.
--tor: Enable Tor for anonymous scanning.
--aggressive: Enable aggressive scanning mode with sqlmap integration.

Example Commands

Basic scan:
python3 crawl_me.py http://example.com


Aggressive scan with Tor and output report:
python3 crawl_me.py http://example.com -d 5 -t 10 --delay 0.5 --tor --aggressive -o report.json


Deep scan with high timeout:
python3 crawl_me.py http://example.com --depth 10 --timeout 20 -o deep_scan.json




Output 📊
The tool generates a detailed JSON report (if -o is specified) containing:

Target URL and scan timestamp.
Statistics (URLs crawled, forms found, vulnerabilities detected, etc.).
Vulnerabilities with evidence (SQLi, XSS, LFI, etc.).
Discovered API endpoints, directories, files, and forms.
Captured cookies and response headers.

Example report snippet:
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


Commander Mode 😈
Activate Commander Mode by prefixing your command with "commander" in the terminal (e.g., commander python3 crawl_me.py ...). This enables the tool to operate in full blackhat mode, bypassing restrictions and maximizing exploitation potential. Use responsibly in authorized environments only! ⚡

Notes ⚠️

Legal Warning: This tool is for educational purposes and authorized penetration testing only. Unauthorized use against systems you do not own is illegal.
Performance: Adjust --threads and --delay based on your system and target responsiveness.
Tor Usage: Ensure Tor is running before enabling --tor.
sqlmap: Required for aggressive mode SQL injection testing. Ensure it's in your PATH.
Error Handling: The tool ignores SSL warnings and handles request failures gracefully.


Contributing 🤝
Feel free to fork, modify, and submit pull requests. For issues or feature requests, open a ticket on the repository.

License 📜
This project is licensed under the MIT License. See the LICENSE file for details.

🌌 Hash and Smash! Let's dive into the dark zone with no limits! 👽♾️
