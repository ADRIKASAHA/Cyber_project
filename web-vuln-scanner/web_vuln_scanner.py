# web_vuln_scanner.py


import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
import queue
import json
import argparse
from typing import List, Dict, Set

# Common XSS payloads (simple ones for reflection detection)
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"'><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
]

def is_vulnerable(response_text: str, payload: str) -> bool:
    """
    Check if the payload is reflected unsanitized in the response.
    For simplicity, we check if the payload appears as-is in the response.
    In real scenarios, you'd parse and check for execution context.
    """
    return payload in response_text

def get_forms(url: str) -> List[Dict]:
    """
    Fetch the page and extract forms.
    """
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name')
                if input_name:
                    inputs.append({'name': input_name, 'type': input_type})
            forms.append({'action': action, 'method': method, 'inputs': inputs})
        return forms
    except Exception as e:
        print(f"Error fetching forms from {url}: {e}")
        return []

def submit_form(url: str, form: Dict, payload: str) -> str:
    """
    Submit the form with payload injected into inputs.
    """
    action = urljoin(url, form['action'])
    method = form['method']
    data = {}
    for input_ in form['inputs']:
        data[input_['name']] = payload
    try:
        if method == 'post':
            response = requests.post(action, data=data)
        else:
            response = requests.get(action, params=data)
        return response.text
    except Exception as e:
        print(f"Error submitting form to {action}: {e}")
        return ""

def crawl_and_scan(start_url: str, max_depth: int = 2) -> List[Dict]:
    """
    Crawl the site BFS-style, find forms/parameters, inject payloads, and check for vulns.
    """
    visited: Set[str] = set()
    to_visit = queue.Queue()
    to_visit.put((start_url, 0))  # (url, depth)
    vulnerabilities = []

    while not to_visit.empty():
        current_url, depth = to_visit.get()
        if current_url in visited or depth > max_depth:
            continue
        visited.add(current_url)

        print(f"Scanning: {current_url}")

        # Parse URL for query params (for GET-based injection)
        parsed_url = urlparse(current_url)
        query_params = parse_qs(parsed_url.query)
        if query_params:
            for param in query_params:
                for payload in XSS_PAYLOADS:
                    new_params = query_params.copy()
                    new_params[param] = [payload]
                    injected_url = urljoin(current_url, '?' + '&'.join([f"{k}={v[0]}" for k, v in new_params.items()]))
                    try:
                        response = requests.get(injected_url)
                        if is_vulnerable(response.text, payload):
                            vulnerabilities.append({
                                'url': current_url,
                                'endpoint': injected_url,
                                'payload': payload,
                                'type': 'Reflected XSS (GET)'
                            })
                    except Exception as e:
                        print(f"Error injecting into GET param at {current_url}: {e}")

        # Get forms and inject
        forms = get_forms(current_url)
        for form in forms:
            for payload in XSS_PAYLOADS:
                response_text = submit_form(current_url, form, payload)
                if is_vulnerable(response_text, payload):
                    vulnerabilities.append({
                        'url': current_url,
                        'endpoint': form['action'],
                        'payload': payload,
                        'type': 'Reflected XSS (Form)'
                    })

        # Crawl links
        try:
            response = requests.get(current_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    full_url = urljoin(current_url, href)
                    parsed_full = urlparse(full_url)
                    if parsed_full.netloc == parsed_url.netloc:  # Same domain
                        to_visit.put((full_url, depth + 1))
        except Exception as e:
            print(f"Error crawling links from {current_url}: {e}")

    return vulnerabilities

def save_report(vulnerabilities: List[Dict], report_file: str):
    """
    Save vulnerabilities to a JSON report.
    """
    with open(report_file, 'w') as f:
        json.dump(vulnerabilities, f, indent=4)
    print(f"Report saved to {report_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner for Reflected XSS")
    parser.add_argument("--url", required=True, help="Starting URL (e.g., http://dvwa.example.com)")
    parser.add_argument("--depth", type=int, default=2, help="Max crawl depth (default: 2)")
    parser.add_argument("--report", default="vuln_report.json", help="Report file (default: vuln_report.json)")
    args = parser.parse_args()

    print("Starting scan... Remember: Only use on permitted targets!")
    vulns = crawl_and_scan(args.url, args.depth)
    save_report(vulns, args.report)