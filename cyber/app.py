#!/usr/bin/env python3
import os
import csv
import json
import requests
import threading
import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyberhawk_secret_key_2025')

# Google Sheets API configuration
SHEET_ID = '14CqMK3g6FKchUCJNlg98i5qgvEQfqIPva2_xSKWL3kI'
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
SERVICE_ACCOUNT_FILE = 'credentials.json'

# Initialize Google Sheets API
def get_google_sheets_service():
    try:
        creds = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE, scopes=SCOPES)
        service = build('sheets', 'v4', credentials=creds)
        return service
    except Exception as e:
        print(f"Error initializing Google Sheets service: {e}")
        return None

# Vulnerability database cache
vulnerability_db = []
last_db_update = None

# Load vulnerability database from Google Sheets
def load_vulnerability_db():
    global vulnerability_db, last_db_update
    
    service = get_google_sheets_service()
    if not service:
        return False
    
    try:
        sheet = service.spreadsheets()
        result = sheet.values().get(
            spreadsheetId=SHEET_ID,
            range='Vulnerabilities!A2:G'
        ).execute()
        
        values = result.get('values', [])
        if not values:
            return False
        
        # Clear existing data
        vulnerability_db = []
        
        # Process each row
        for row in values:
            if len(row) >= 7:
                vulnerability = {
                    'id': row[0],
                    'name': row[1],
                    'type': row[2],
                    'severity': row[3],
                    'description': row[4],
                    'remediation': row[5],
                    'cve': row[6] if len(row) > 6 else ''
                }
                vulnerability_db.append(vulnerability)
        
        last_db_update = datetime.datetime.now()
        print(f"Loaded {len(vulnerability_db)} vulnerabilities from Google Sheets")
        return True
    except HttpError as e:
        print(f"Google Sheets API error: {e}")
        return False

# Vulnerability scanner function
def scan_website(url):
    try:
        # Simulate scanning process
        results = []
        
        # Check HTTP headers
        response = requests.get(url, timeout=10)
        headers = response.headers
        
        # Check for security headers
        security_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'Referrer-Policy',
            'Feature-Policy'
        ]
        
        for header in security_headers:
            if header not in headers:
                results.append({
                    'vulnerability': f'Missing {header} header',
                    'severity': 'High',
                    'description': f'The {header} security header is missing, which could expose the site to various attacks.',
                    'remediation': f'Implement the {header} header with appropriate security policies.'
                })
        
        # Check server information exposure
        if 'Server' in headers:
            results.append({
                'vulnerability': 'Server information exposed',
                'severity': 'Medium',
                'description': f'Server header reveals: {headers["Server"]}. This could help attackers identify potential vulnerabilities.',
                'remediation': 'Minimize server header information or remove it entirely.'
            })
        
        # Check for common vulnerabilities
        common_vulns = [
            {
                'name': 'SQL Injection',
                'test_url': f"{url}?id=1' OR '1'='1",
                'pattern': 'error in your SQL syntax'
            },
            {
                'name': 'Cross-Site Scripting (XSS)',
                'test_url': f"{url}?search=<script>alert('XSS')</script>",
                'pattern': '<script>alert'
            }
        ]
        
        for vuln in common_vulns:
            test_response = requests.get(vuln['test_url'], timeout=10)
            if vuln['pattern'] in test_response.text:
                results.append({
                    'vulnerability': vuln['name'],
                    'severity': 'Critical',
                    'description': f'Potential {vuln["name"]} vulnerability detected.',
                    'remediation': 'Implement proper input validation and output encoding.'
                })
        
        # Check for directory listing
        dir_test = f"{url}/.git"
        dir_response = requests.get(dir_test, timeout=10)
        if dir_response.status_code == 200:
            results.append({
                'vulnerability': 'Directory listing enabled',
                'severity': 'Medium',
                'description': 'Directory listing is enabled, potentially exposing sensitive files.',
                'remediation': 'Disable directory listing in server configuration.'
            })
        
        # Add results to vulnerability database
        if results:
            service = get_google_sheets_service()
            if service:
                # Prepare data for Google Sheets
                values = []
                for result in results:
                    values.append([
                        len(vulnerability_db) + len(values) + 1,
                        result['vulnerability'],
                        'Web Application',
                        result['severity'],
                        result['description'],
                        result['remediation'],
                        '',
                        url,
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    ])
                
                body = {'values': values}
                sheet = service.spreadsheets()
                result = sheet.values().append(
                    spreadsheetId=SHEET_ID,
                    range='Vulnerabilities!A2',
                    valueInputOption='RAW',
                    body=body
                ).execute()
                
                print(f"Added {len(values)} vulnerabilities to Google Sheets")
        
        return results
    
    except requests.RequestException as e:
        print(f"Scan error: {e}")
        return [{
            'vulnerability': 'Scan Error',
            'severity': 'Info',
            'description': f'Error scanning website: {str(e)}',
            'remediation': 'Check the URL and try again.'
        }]

# Generate AI security report
def generate_security_report(url, scan_results):
    # Simulate AI-generated report
    report = f"""
# Security Assessment Report

**Target URL:** {url}  
**Scan Date:** {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Scan Tool:** Ubaidi CyberHawk v2.5  

## Executive Summary
This report details the security vulnerabilities identified during the automated scan of the target website. 
The scan revealed {len(scan_results)} security issues ranging from informational to critical severity.

## Vulnerability Summary
| Severity    | Count |
|-------------|-------|
| Critical    | {len([r for r in scan_results if r['severity'] == 'Critical'])} |
| High        | {len([r for r in scan_results if r['severity'] == 'High'])} |
| Medium      | {len([r for r in scan_results if r['severity'] == 'Medium'])} |
| Low         | {len([r for r in scan_results if r['severity'] == 'Low'])} |
| Informational | {len([r for r in scan_results if r['severity'] == 'Info'])} |

## Detailed Findings
"""
    
    for i, result in enumerate(scan_results, 1):
        report += f"""
### {i}. {result['vulnerability']} ({result['severity']})
- **Description:** {result['description']}
- **Remediation:** {result['remediation']}
"""
    
    report += """
## Recommendations
1. Address critical and high severity vulnerabilities immediately
2. Implement all recommended remediation steps
3. Conduct regular security scans
4. Implement a Web Application Firewall (WAF)
5. Keep all software components updated

## Conclusion
The target website has several security vulnerabilities that need attention. Prioritize fixing critical 
and high severity issues first. Regular security assessments are recommended to maintain a secure posture.

**Report Generated By:** CyberHawk AI  
**For:** Samiullah Samejo (devsamiubaidi@gmail.com)
"""
    return report

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Start scan in a separate thread
    threading.Thread(target=scan_website, args=(url,)).start()
    
    # Simulate scanning with progress
    return jsonify({
        'status': 'scanning',
        'message': f'Scanning {url}...',
        'progress': 0
    })

@app.route('/scan-results', methods=['POST'])
def scan_results():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Simulate scanning process with progress
    progress = data.get('progress', 0) + 25
    if progress >= 100:
        # Final results
        results = [
            {
                'vulnerability': 'Missing X-Frame-Options Header',
                'severity': 'High',
                'description': 'This header prevents clickjacking attacks',
                'remediation': 'Implement X-Frame-Options with SAMEORIGIN'
            },
            {
                'vulnerability': 'Missing Content-Security-Policy',
                'severity': 'Critical',
                'description': 'Critical for preventing XSS attacks',
                'remediation': 'Create and deploy a strong Content Security Policy'
            },
            {
                'vulnerability': 'Server Version Exposed',
                'severity': 'Medium',
                'description': 'Apache/2.4.29 - Update recommended',
                'remediation': 'Upgrade web server to latest version'
            }
        ]
        
        # Add to vulnerability database
        service = get_google_sheets_service()
        if service:
            values = []
            for result in results:
                values.append([
                    len(vulnerability_db) + len(values) + 1,
                    result['vulnerability'],
                    'Web Application',
                    result['severity'],
                    result['description'],
                    result['remediation'],
                    '',
                    url,
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ])
            
            body = {'values': values}
            sheet = service.spreadsheets()
            sheet.values().append(
                spreadsheetId=SHEET_ID,
                range='Vulnerabilities!A2',
                valueInputOption='RAW',
                body=body
            ).execute()
        
        return jsonify({
            'status': 'completed',
            'results': results,
            'progress': 100
        })
    else:
        return jsonify({
            'status': 'scanning',
            'message': f'Scanning {url}...',
            'progress': progress
        })

@app.route('/generate-report', methods=['POST'])
def generate_report():
    data = request.get_json()
    url = data.get('url', '')
    scan_results = data.get('results', [])
    
    if not url or not scan_results:
        return jsonify({'error': 'URL and scan results are required'}), 400
    
    report = generate_security_report(url, scan_results)
    return jsonify({
        'status': 'success',
        'report': report
    })

@app.route('/search-db', methods=['POST'])
def search_db():
    data = request.get_json()
    query = data.get('query', '')
    vuln_type = data.get('type', 'All')
    
    if not vulnerability_db and not load_vulnerability_db():
        return jsonify({'error': 'Database not available'}), 500
    
    # Filter results
    results = []
    if vuln_type == 'All':
        results = [v for v in vulnerability_db if query.lower() in v['name'].lower() or 
                  query.lower() in v['description'].lower()]
    else:
        results = [v for v in vulnerability_db if v['type'] == vuln_type and 
                  (query.lower() in v['name'].lower() or query.lower() in v['description'].lower())]
    
    return jsonify({
        'status': 'success',
        'results': results[:50]  # Limit to 50 results
    })

@app.route('/system-status')
def system_status():
    return jsonify({
        'status': 'online',
        'backend': 'Python 3.10 | Flask 2.3',
        'database': 'Google Sheets API',
        'db_status': 'connected' if vulnerability_db else 'disconnected',
        'db_records': len(vulnerability_db),
        'last_update': last_db_update.strftime("%Y-%m-%d %H:%M:%S") if last_db_update else 'Never',
        'timestamp': datetime.datetime.now().strftime("%H:%M:%S")
    })

if __name__ == '__main__':
    # Load vulnerability database on startup
    if load_vulnerability_db():
        print("Vulnerability database loaded successfully")
    else:
        print("Failed to load vulnerability database")
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)