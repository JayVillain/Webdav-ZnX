#!/usr/bin/env python3
"""
Enhanced WebDAV Scanner for Penetration Testing
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

class WebDAVScanner:
    def __init__(self, threads=10, delay_range=(1, 3)):
        self.threads = threads
        self.delay_range = delay_range
        self.session = requests.Session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0'
        ]
        
        # WebDAV methods to test
        self.webdav_methods = ['OPTIONS', 'PROPFIND', 'PUT', 'MKCOL', 'COPY', 'MOVE', 'DELETE', 'LOCK', 'UNLOCK']
        
        # Common WebDAV paths to check
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
            '/home/',
            '/users/',
            '/remote/',
            '/storage/'
        ]

    def get_random_headers(self):
        """Generate random headers to avoid detection"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def search_duckduckgo(self, query, max_results=50):
        """Enhanced DuckDuckGo search with pagination"""
        print(f"[+] Searching: {query}")
        all_links = set()
        
        try:
            # Search multiple pages
            for page in range(0, min(max_results, 100), 20):  # DuckDuckGo uses 20 results per page
                url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}&s={page}"
                headers = self.get_random_headers()
                
                response = self.session.get(url, headers=headers, timeout=15)
                response.raise_for_status()
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract links
                page_links = []
                for a in soup.find_all('a', {'class': 'result__a'}):
                    href = a.get('href')
                    if href and href.startswith('http'):
                        # Clean URL
                        parsed_url = urlparse(href)
                        clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                        page_links.append(clean_url)
                        all_links.add(clean_url)
                
                print(f"    Page {page//20 + 1}: Found {len(page_links)} results")
                
                # If no results found, break
                if not page_links:
                    break
                
                # Random delay between pages
                time.sleep(random.uniform(*self.delay_range))
                
        except Exception as e:
            print(f"    Error searching: {e}")
        
        return list(all_links)

    def check_webdav_comprehensive(self, base_url):
        """Comprehensive WebDAV detection"""
        results = {}
        
        # Test multiple paths
        for path in self.webdav_paths:
            test_url = urljoin(base_url, path)
            path_results = {}
            
            # Test each WebDAV method
            for method in self.webdav_methods:
                try:
                    headers = self.get_random_headers()
                    
                    # Special headers for specific methods
                    if method == 'PROPFIND':
                        headers['Depth'] = '1'
                        headers['Content-Type'] = 'application/xml'
                    elif method == 'PUT':
                        headers['Content-Type'] = 'text/plain'
                    
                    response = self.session.request(
                        method, 
                        test_url, 
                        headers=headers, 
                        timeout=10,
                        allow_redirects=False
                    )
                    
                    path_results[method] = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'content_length': len(response.content)
                    }
                    
                except Exception as e:
                    path_results[method] = {'error': str(e)}
            
            results[path] = path_results
            
            # Small delay between path tests
            time.sleep(0.5)
        
        return results

    def analyze_webdav_results(self, results):
        """Analyze WebDAV test results to determine vulnerability"""
        vulnerability_score = 0
        indicators = []
        
        for path, methods in results.items():
            for method, result in methods.items():
                if isinstance(result, dict) and 'status_code' in result:
                    status_code = result['status_code']
                    headers = result.get('headers', {})
                    
                    # Check for WebDAV indicators
                    if method == 'OPTIONS':
                        allow_header = headers.get('Allow', '').upper()
                        if any(webdav_method in allow_header for webdav_method in ['PROPFIND', 'MKCOL', 'COPY', 'MOVE']):
                            vulnerability_score += 10
                            indicators.append(f"WebDAV methods in OPTIONS Allow header at {path}")
                    
                    elif method == 'PROPFIND':
                        if status_code in [200, 207, 301, 302]:  # 207 is Multi-Status for WebDAV
                            vulnerability_score += 15
                            indicators.append(f"PROPFIND successful at {path} (HTTP {status_code})")
                    
                    elif method in ['PUT', 'MKCOL']:
                        if status_code in [200, 201, 204]:
                            vulnerability_score += 20
                            indicators.append(f"{method} method allowed at {path} (HTTP {status_code})")
                    
                    elif method in ['COPY', 'MOVE', 'DELETE']:
                        if status_code in [200, 201, 204]:
                            vulnerability_score += 15
                            indicators.append(f"{method} method allowed at {path} (HTTP {status_code})")
                    
                    # Check for specific WebDAV server headers
                    server_header = headers.get('Server', '').lower()
                    if any(webdav_server in server_header for webdav_server in ['apache', 'nginx', 'microsoft-iis']):
                        if 'dav' in server_header or 'webdav' in server_header:
                            vulnerability_score += 5
                            indicators.append(f"WebDAV server detected: {headers.get('Server')}")
        
        return vulnerability_score, indicators

    def scan_target(self, url):
        """Scan a single target for WebDAV"""
        try:
            print(f"[*] Scanning: {url}")
            results = self.check_webdav_comprehensive(url)
            score, indicators = self.analyze_webdav_results(results)
            
            return {
                'url': url,
                'vulnerability_score': score,
                'indicators': indicators,
                'raw_results': results,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            print(f"[!] Error scanning {url}: {e}")
            return None

    def save_results(self, all_results):
        """Save results to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save all results to JSON
        with open(f'webdav_scan_results_{timestamp}.json', 'w') as f:
            json.dump(all_results, f, indent=2)
        
        # Save vulnerable sites
        vulnerable_sites = [r for r in all_results if r and r['vulnerability_score'] > 0]
        
        with open(f'webdav_vulnerable_{timestamp}.txt', 'w') as f:
            f.write(f"WebDAV Vulnerability Scan Results - {datetime.now()}\n")
            f.write("=" * 60 + "\n\n")
            
            for result in sorted(vulnerable_sites, key=lambda x: x['vulnerability_score'], reverse=True):
                f.write(f"URL: {result['url']}\n")
                f.write(f"Vulnerability Score: {result['vulnerability_score']}\n")
                f.write("Indicators:\n")
                for indicator in result['indicators']:
                    f.write(f"  - {indicator}\n")
                f.write("-" * 40 + "\n\n")
        
        # Save summary
        with open(f'webdav_summary_{timestamp}.txt', 'w') as f:
            f.write(f"WebDAV Scan Summary - {datetime.now()}\n")
            f.write("=" * 40 + "\n")
            f.write(f"Total URLs scanned: {len([r for r in all_results if r])}\n")
            f.write(f"Vulnerable sites found: {len(vulnerable_sites)}\n")
            f.write(f"High-risk sites (score > 20): {len([r for r in vulnerable_sites if r['vulnerability_score'] > 20])}\n")
        
        print(f"\n[+] Results saved:")
        print(f"    - Detailed results: webdav_scan_results_{timestamp}.json")
        print(f"    - Vulnerable sites: webdav_vulnerable_{timestamp}.txt")
        print(f"    - Summary: webdav_summary_{timestamp}.txt")

    def run_scan(self, dork_file='dork.txt'):
        """Main scanning function"""
        if not os.path.exists(dork_file):
            print(f"[!] Dork file '{dork_file}' not found!")
            return
        
        print(f"[+] Starting WebDAV Scanner")
        print(f"[+] Threads: {self.threads}")
        print(f"[+] Delay range: {self.delay_range} seconds")
        
        # Load dorks
        with open(dork_file, 'r') as f:
            dorks = [line.strip() for line in f if line.strip()]
        
        print(f"[+] Loaded {len(dorks)} dorks")
        
        # Collect all URLs
        all_urls = set()
        for dork in dorks:
            urls = self.search_duckduckgo(dork)
            all_urls.update(urls)
            print(f"    Total unique URLs so far: {len(all_urls)}")
            time.sleep(random.uniform(*self.delay_range))
        
        print(f"\n[+] Found {len(all_urls)} unique URLs")
        print(f"[+] Starting WebDAV scans...")
        
        # Scan URLs using thread pool
        all_results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.scan_target, url): url for url in all_urls}
            
            for future in as_completed(future_to_url):
                result = future.result()
                if result:
                    all_results.append(result)
                    if result['vulnerability_score'] > 0:
                        print(f"[!] VULNERABLE: {result['url']} (Score: {result['vulnerability_score']})")
        
        # Save results
        self.save_results(all_results)
        
        # Print summary
        vulnerable_count = len([r for r in all_results if r['vulnerability_score'] > 0])
        print(f"\n[+] Scan completed!")
        print(f"[+] Total scanned: {len(all_results)}")
        print(f"[+] Vulnerable sites: {vulnerable_count}")

def main():
    """Main function"""
    print("WebDAV Scanner v2.0")
    print("For authorized penetration testing only")
    print("-" * 40)
    
    # Configuration
    threads = 10
    delay_range = (2, 5)  # Random delay between 2-5 seconds
    
    scanner = WebDAVScanner(threads=threads, delay_range=delay_range)
    scanner.run_scan()

if __name__ == "__main__":
    main()