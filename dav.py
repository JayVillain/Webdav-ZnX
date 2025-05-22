#!/usr/bin/env python3
"""
Enhanced WebDAV Scanner with Multiple Search Engines
Author: Security Researcher
Purpose: Educational and authorized testing only
"""

import requests
from bs4 import BeautifulSoup
import time
import urllib.parse
import random
from urllib.parse import urljoin, urlparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sys
from datetime import datetime
import json
import ssl
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SearchEngine:
    """Multiple search engines support"""
    
    @staticmethod
    def search_google(query, num_results=50):
        """Google search (requires more careful handling due to CAPTCHA)"""
        results = []
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            
            # Google Custom Search API would be better, but this is basic scraping
            for start in range(0, min(num_results, 100), 10):
                url = f"https://www.google.com/search?q={urllib.parse.quote(query)}&start={start}&num=10"
                
                session = requests.Session()
                session.verify = False
                response = session.get(url, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for g in soup.find_all('div', class_='g'):
                        link = g.find('a')
                        if link and link.get('href'):
                            href = link.get('href')
                            if href.startswith('http'):
                                parsed_url = urlparse(href)
                                clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                                results.append(clean_url)
                
                time.sleep(random.uniform(2, 5))  # Longer delay for Google
                
        except Exception as e:
            print(f"    Google search error: {e}")
        
        return list(set(results))
    
    @staticmethod
    def search_bing(query, num_results=50):
        """Bing search"""
        results = []
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            
            for offset in range(0, min(num_results, 100), 10):
                url = f"https://www.bing.com/search?q={urllib.parse.quote(query)}&first={offset+1}"
                
                session = requests.Session()
                session.verify = False
                response = session.get(url, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for result in soup.find_all('li', class_='b_algo'):
                        link = result.find('a')
                        if link and link.get('href'):
                            href = link.get('href')
                            if href.startswith('http'):
                                parsed_url = urlparse(href)
                                clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                                results.append(clean_url)
                
                time.sleep(random.uniform(1, 3))
                
        except Exception as e:
            print(f"    Bing search error: {e}")
        
        return list(set(results))
    
    @staticmethod
    def search_duckduckgo_lite(query, num_results=50):
        """DuckDuckGo Lite version with better SSL handling"""
        results = []
        try:
            # Create session with custom SSL context
            session = requests.Session()
            session.verify = False  # Disable SSL verification
            
            # Add retry strategy
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # Try different DuckDuckGo endpoints
            endpoints = [
                "https://html.duckduckgo.com/html/",
                "https://duckduckgo.com/html/",
                "https://start.duckduckgo.com/"
            ]
            
            for endpoint in endpoints:
                try:
                    for page in range(0, min(num_results, 40), 20):
                        url = f"{endpoint}?q={urllib.parse.quote(query)}&s={page}"
                        
                        response = session.get(url, headers=headers, timeout=20)
                        response.raise_for_status()
                        
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        # Multiple selectors for different DuckDuckGo layouts
                        selectors = [
                            'a.result__a',
                            'a[class*="result"]',
                            '.result h2 a',
                            '.web-result h2 a'
                        ]
                        
                        page_results = []
                        for selector in selectors:
                            for a in soup.select(selector):
                                href = a.get('href')
                                if href and href.startswith('http'):
                                    parsed_url = urlparse(href)
                                    clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                                    page_results.append(clean_url)
                                    results.append(clean_url)
                        
                        if page_results:
                            print(f"    Found {len(page_results)} results from {endpoint}")
                            time.sleep(random.uniform(2, 4))
                        else:
                            break
                    
                    if results:
                        break  # If we got results from this endpoint, no need to try others
                        
                except Exception as e:
                    print(f"    Error with {endpoint}: {e}")
                    continue
                    
        except Exception as e:
            print(f"    DuckDuckGo search error: {e}")
        
        return list(set(results))
    
    @staticmethod
    def search_yandex(query, num_results=50):
        """Yandex search"""
        results = []
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            
            session = requests.Session()
            session.verify = False
            
            for page in range(0, min(num_results, 100), 10):
                url = f"https://yandex.com/search/?text={urllib.parse.quote(query)}&p={page//10}"
                
                response = session.get(url, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for result in soup.find_all('a', {'class': 'organic__url'}):
                        href = result.get('href')
                        if href and href.startswith('http'):
                            parsed_url = urlparse(href)
                            clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                            results.append(clean_url)
                
                time.sleep(random.uniform(1, 3))
                
        except Exception as e:
            print(f"    Yandex search error: {e}")
        
        return list(set(results))

class WebDAVScanner:
    def __init__(self, threads=5, delay_range=(2, 5)):
        self.threads = threads
        self.delay_range = delay_range
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification
        
        # Add retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        ]
        
        # WebDAV methods and paths
        self.webdav_methods = ['OPTIONS', 'PROPFIND', 'PUT', 'MKCOL', 'COPY', 'MOVE', 'DELETE']
        self.webdav_paths = [
            '/',
            '/webdav/',
            '/dav/',
            '/uploads/',
            '/files/',
            '/documents/',
            '/share/',
            '/data/',
            '/content/',
            '/public/',
            '/private/',
            '/admin/',
            '/backup/',
            '/temp/',
            '/www/',
            '/storage/'
        ]

    def get_random_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def multi_search(self, query, max_results=30):
        """Search using multiple engines"""
        print(f"[+] Multi-engine search for: {query}")
        all_results = set()
        
        # Search engines to try
        search_engines = [
            ("DuckDuckGo", SearchEngine.search_duckduckgo_lite),
            ("Bing", SearchEngine.search_bing),
            ("Yandex", SearchEngine.search_yandex),
            # ("Google", SearchEngine.search_google),  # Commented out due to CAPTCHA issues
        ]
        
        for engine_name, search_func in search_engines:
            try:
                print(f"    Trying {engine_name}...")
                results = search_func(query, max_results)
                all_results.update(results)
                print(f"    {engine_name}: Found {len(results)} results")
                time.sleep(random.uniform(3, 6))  # Longer delay between engines
            except Exception as e:
                print(f"    {engine_name} error: {e}")
                continue
        
        return list(all_results)

    def check_webdav_simple(self, base_url):
        """Simplified WebDAV check"""
        results = {}
        
        # Test key paths only
        key_paths = ['/', '/webdav/', '/dav/', '/uploads/']
        
        for path in key_paths:
            test_url = urljoin(base_url, path)
            path_results = {}
            
            # Test key methods
            key_methods = ['OPTIONS', 'PROPFIND', 'PUT']
            
            for method in key_methods:
                try:
                    headers = self.get_random_headers()
                    
                    if method == 'PROPFIND':
                        headers['Depth'] = '1'
                        headers['Content-Type'] = 'application/xml'
                    
                    response = self.session.request(
                        method, 
                        test_url, 
                        headers=headers, 
                        timeout=10,
                        allow_redirects=False
                    )
                    
                    path_results[method] = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    }
                    
                except Exception as e:
                    path_results[method] = {'error': str(e)}
            
            results[path] = path_results
            time.sleep(0.5)
        
        return results

    def analyze_webdav_results(self, results):
        """Analyze results for WebDAV indicators"""
        score = 0
        indicators = []
        
        for path, methods in results.items():
            for method, result in methods.items():
                if isinstance(result, dict) and 'status_code' in result:
                    status_code = result['status_code']
                    headers = result.get('headers', {})
                    
                    if method == 'OPTIONS':
                        allow_header = headers.get('Allow', '').upper()
                        if 'PROPFIND' in allow_header or 'MKCOL' in allow_header:
                            score += 15
                            indicators.append(f"WebDAV methods in OPTIONS at {path}")
                    
                    elif method == 'PROPFIND':
                        if status_code in [200, 207]:
                            score += 20
                            indicators.append(f"PROPFIND successful at {path}")
                    
                    elif method == 'PUT':
                        if status_code in [200, 201, 204]:
                            score += 25
                            indicators.append(f"PUT allowed at {path}")
        
        return score, indicators

    def scan_target(self, url):
        """Scan single target"""
        try:
            print(f"[*] Scanning: {url}")
            results = self.check_webdav_simple(url)
            score, indicators = self.analyze_webdav_results(results)
            
            return {
                'url': url,
                'vulnerability_score': score,
                'indicators': indicators,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            print(f"[!] Error scanning {url}: {e}")
            return None

    def save_results(self, all_results):
        """Save results to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save vulnerable sites
        vulnerable_sites = [r for r in all_results if r and r['vulnerability_score'] > 0]
        
        with open(f'webdav_vulnerable_{timestamp}.txt', 'w') as f:
            f.write(f"WebDAV Scan Results - {datetime.now()}\n")
            f.write("=" * 50 + "\n\n")
            
            for result in sorted(vulnerable_sites, key=lambda x: x['vulnerability_score'], reverse=True):
                f.write(f"URL: {result['url']}\n")
                f.write(f"Score: {result['vulnerability_score']}\n")
                f.write("Indicators:\n")
                for indicator in result['indicators']:
                    f.write(f"  - {indicator}\n")
                f.write("-" * 30 + "\n\n")
        
        print(f"\n[+] Results saved to: webdav_vulnerable_{timestamp}.txt")
        return len(vulnerable_sites)

    def run_scan(self, dork_file='dork.txt'):
        """Main scan function"""
        if not os.path.exists(dork_file):
            print(f"[!] Dork file '{dork_file}' not found!")
            return
        
        print(f"[+] WebDAV Scanner v2.1 (Multi-Engine)")
        print(f"[+] Threads: {self.threads}")
        
        # Load dorks
        with open(dork_file, 'r') as f:
            dorks = [line.strip() for line in f if line.strip()]
        
        print(f"[+] Loaded {len(dorks)} dorks")
        
        # Collect URLs from multiple engines
        all_urls = set()
        for dork in dorks:
            urls = self.multi_search(dork, max_results=20)
            all_urls.update(urls)
            print(f"    Total unique URLs: {len(all_urls)}")
        
        if not all_urls:
            print("[!] No URLs found from search engines!")
            return
        
        print(f"\n[+] Starting WebDAV scan on {len(all_urls)} URLs...")
        
        # Scan URLs
        all_results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.scan_target, url): url for url in all_urls}
            
            for future in as_completed(future_to_url):
                result = future.result()
                if result:
                    all_results.append(result)
                    if result['vulnerability_score'] > 0:
                        print(f"[!] VULNERABLE: {result['url']} (Score: {result['vulnerability_score']})")
        
        # Save and summarize
        vulnerable_count = self.save_results(all_results)
        print(f"\n[+] Scan completed!")
        print(f"[+] Total scanned: {len(all_results)}")
        print(f"[+] Vulnerable sites: {vulnerable_count}")

def main():
    print("WebDAV Scanner v2.1 - Multi-Engine Edition")
    print("For authorized testing only")
    print("-" * 50)
    
    scanner = WebDAVScanner(threads=5, delay_range=(3, 6))
    scanner.run_scan()

if __name__ == "__main__":
    main()