#!/usr/bin/env python3
"""
Unified HexaWebScanner Runner
Uses existing HexaWebScanner folder capabilities with single command
Usage: python run_hexa_web_scanner.py <target_url>
"""

import sys
import os
import json
import subprocess
from datetime import datetime
from pathlib import Path

def parse_vulnerabilities_from_output(output):
    """Parse vulnerabilities directly from scanner output"""
    vulnerabilities = []
    
    # Common vulnerability patterns to look for
    patterns = [
        (r'\[XSS FOUND\].*?URL: (.*?)(?:\n|$)', 'Cross-Site Scripting (XSS)', 'HIGH'),
        (r'\[SQL INJECTION\].*?URL: (.*?)(?:\n|$)', 'SQL Injection', 'CRITICAL'),
        (r'\[CSRF\].*?URL: (.*?)(?:\n|$)', 'Cross-Site Request Forgery', 'MEDIUM'),
        (r'\[DIRECTORY TRAVERSAL\].*?URL: (.*?)(?:\n|$)', 'Directory Traversal', 'HIGH'),
        (r'\[COMMAND INJECTION\].*?URL: (.*?)(?:\n|$)', 'Command Injection', 'CRITICAL'),
        (r'\[VULNERABILITY FOUND\].*?(.*?)(?:\n|$)', 'Security Vulnerability', 'MEDIUM'),
        (r'CRITICAL.*?found.*?at (.*?)(?:\n|$)', 'Critical Security Issue', 'CRITICAL'),
        (r'HIGH.*?risk.*?at (.*?)(?:\n|$)', 'High Risk Vulnerability', 'HIGH')
    ]
    
    for pattern, vuln_type, severity in patterns:
        matches = re.findall(pattern, output, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            url = match if isinstance(match, str) else match[0] if match else 'Unknown'
            vulnerabilities.append({
                'type': vuln_type,
                'severity': severity,
                'url': url.strip(),
                'description': f'{vuln_type} vulnerability detected',
                'cwe': get_cwe_for_type(vuln_type),
                'owasp': get_owasp_for_type(vuln_type)
            })
    
    return vulnerabilities

def get_cwe_for_type(vuln_type):
    """Get CWE ID for vulnerability type"""
    cwe_mapping = {
        'Cross-Site Scripting (XSS)': 'CWE-79',
        'SQL Injection': 'CWE-89',
        'Cross-Site Request Forgery': 'CWE-352',
        'Directory Traversal': 'CWE-22',
        'Command Injection': 'CWE-78'
    }
    return cwe_mapping.get(vuln_type, 'CWE-Unknown')

def get_owasp_for_type(vuln_type):
    """Get OWASP category for vulnerability type"""
    owasp_mapping = {
        'Cross-Site Scripting (XSS)': 'A03:2021 – Injection',
        'SQL Injection': 'A03:2021 – Injection',
        'Cross-Site Request Forgery': 'A01:2021 – Broken Access Control',
        'Directory Traversal': 'A01:2021 – Broken Access Control',
        'Command Injection': 'A03:2021 – Injection'
    }
    return owasp_mapping.get(vuln_type, 'OWASP Top 10')

def run_hexa_web_scanner(target_url):
    """Run HexaWebScanner with unified command"""
    print(f"STARTING: HexaWebScanner for: {target_url}")
    print("=" * 80)
    
    # Change to HexaWebScanner directory
    hexa_dir = Path("HexaWebScanner")
    if not hexa_dir.exists():
        print("ERROR: HexaWebScanner folder not found!")
        return None
    
    original_dir = os.getcwd()
    
    try:
        os.chdir(hexa_dir)
        
        # Run the main scanner
        print("SCANNING: Running comprehensive web vulnerability scan...")
        
        # Execute the main run.py with target URL
        # Set environment variables for automated mode
        env = os.environ.copy()
        env['HUGGINGFACE_API_KEY'] = 'auto_skip'
        env['AUTOMATED_MODE'] = 'true'
        
        # Use Popen for better control over input/output
        process = subprocess.Popen([
            sys.executable, "run.py", target_url
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
           text=True, env=env, encoding='utf-8', errors='replace')
        
        # Auto-skip API key prompt after 10 seconds
        try:
            result_stdout, result_stderr = process.communicate(timeout=600)
            result = type('Result', (), {
                'stdout': result_stdout,
                'stderr': result_stderr,
                'returncode': process.returncode
            })()
        except subprocess.TimeoutExpired:
            process.kill()
            result_stdout, result_stderr = process.communicate()
            result = type('Result', (), {
                'stdout': result_stdout,
                'stderr': result_stderr,
                'returncode': 1
            })()
        
        print("OUTPUT: Scan Output:")
        print(result.stdout)
        
        if result.stderr:
            print("⚠️ Warnings/Errors:")
            print(result.stderr)
        
        # Parse the advanced scanner results
        report_data = {
            "target": target_url,
            "timestamp": datetime.now().isoformat(),
            "scanner": "Advanced OWASP Scanner v2.0",
            "status": "completed" if result.returncode in [0, 1, 2] else "error",
            "output": result.stdout,
            "errors": result.stderr if result.stderr else None,
            "vulnerabilities": [],
            "findings": [],
            "risk_level": "MEDIUM",
            "scan_time": 0,
            "endpoints_discovered": 0,
            "forms_discovered": 0,
            "owasp_coverage": "Top 150 Vulnerabilities"
        }
        
        # Enhanced JSON results extraction with multiple fallback methods
        vulnerabilities_found = []
        advanced_results = None
        
        try:
            # Method 1: Look for JSON file mentioned in output
            import re
            json_match = re.search(r'advanced_owasp_scan_(\d+_\d+)\.json', result.stdout)
            if json_match:
                possible_paths = [
                    f"advanced_owasp_scan_{json_match.group(1)}.json",
                    f"../HexaWebScanner/advanced_owasp_scan_{json_match.group(1)}.json",
                    f"HexaWebScanner/advanced_owasp_scan_{json_match.group(1)}.json"
                ]
                
                for json_path in possible_paths:
                    if os.path.exists(json_path):
                        print(f"[JSON FOUND] Loading results from: {json_path}")
                        with open(json_path, 'r', encoding='utf-8') as f:
                            advanced_results = json.load(f)
                        break
            
            # Method 2: Look for any recent JSON files in current directory
            if not advanced_results:
                import glob
                json_files = glob.glob("advanced_owasp_scan_*.json")
                if json_files:
                    # Get the most recent JSON file
                    latest_json = max(json_files, key=os.path.getmtime)
                    print(f"[JSON FOUND] Loading latest JSON: {latest_json}")
                    with open(latest_json, 'r', encoding='utf-8') as f:
                        advanced_results = json.load(f)
            
            # Method 3: Parse vulnerabilities directly from output
            if not advanced_results:
                print("[PARSING] Extracting vulnerabilities from scan output...")
                vulnerabilities_found = parse_vulnerabilities_from_output(result.stdout)
                if vulnerabilities_found:
                    print(f"[PARSED] Found {len(vulnerabilities_found)} vulnerabilities from output")
            
            # Process advanced results if found
            if advanced_results:
                vulnerabilities = advanced_results.get("vulnerabilities", [])
                if vulnerabilities:
                    vulnerabilities_found = vulnerabilities
                    print(f"[SUCCESS] Loaded {len(vulnerabilities)} vulnerabilities from JSON")
                    
                    # Update report data with comprehensive information
                    report_data.update({
                        "vulnerabilities": vulnerabilities,
                        "findings": vulnerabilities,
                        "scan_time": advanced_results.get("scan_time", 0),
                        "endpoints_discovered": advanced_results.get("endpoints_discovered", 0),
                        "forms_discovered": advanced_results.get("forms_discovered", 0),
                        "scan_summary": advanced_results.get("scan_summary", {}),
                        "vulnerabilities_found": len(vulnerabilities),
                        "owasp_categories": advanced_results.get("owasp_categories", []),
                        "cwe_categories": advanced_results.get("cwe_categories", [])
                    })
                    
                    # Display vulnerability summary
                    severity_counts = {}
                    for vuln in vulnerabilities[:10]:  # Show first 10
                        severity = vuln.get('severity', 'UNKNOWN')
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                        print(f"  [VULNERABILITY FOUND] {vuln.get('type', 'Unknown')} ({severity})")
                        print(f"    URL: {vuln.get('url', 'N/A')}")
                        if vuln.get('parameter'):
                            print(f"    Parameter: {vuln.get('parameter')}")
                        if vuln.get('cwe'):
                            print(f"    CWE: {vuln.get('cwe')}")
                    
                    if len(vulnerabilities) > 10:
                        print(f"  ... and {len(vulnerabilities) - 10} more vulnerabilities")
                    
                    print(f"[SUMMARY] Severity breakdown: {severity_counts}")
            
            # Update vulnerabilities in report data
            if vulnerabilities_found:
                report_data["vulnerabilities"] = vulnerabilities_found
                report_data["findings"] = vulnerabilities_found
                report_data["vulnerabilities_found"] = len(vulnerabilities_found)
                
                # Determine risk level based on actual vulnerabilities
                critical_count = sum(1 for v in vulnerabilities_found if v.get("severity") == "CRITICAL")
                high_count = sum(1 for v in vulnerabilities_found if v.get("severity") == "HIGH")
                medium_count = sum(1 for v in vulnerabilities_found if v.get("severity") == "MEDIUM")
                
                if critical_count > 0:
                    report_data["risk_level"] = "CRITICAL"
                elif high_count > 0:
                    report_data["risk_level"] = "HIGH"
                elif medium_count > 0:
                    report_data["risk_level"] = "MEDIUM"
                else:
                    report_data["risk_level"] = "LOW"
                
                print(f"[RISK ASSESSMENT] Risk Level: {report_data['risk_level']} ({len(vulnerabilities_found)} vulnerabilities)")
            else:
                print("[INFO] No vulnerabilities detected in scan")
                report_data["risk_level"] = "LOW"
        except Exception as e:
            print(f"⚠️ Could not parse advanced results: {e}")
            # Fallback to basic parsing
            if "vulnerabilities found" in result.stdout.lower():
                report_data["risk_level"] = "HIGH"
        
        # Check if database exists and extract results
        db_file = Path("hexa_vuln_scanner.db")
        if db_file.exists():
            print("SUCCESS: Database found - extracting results...")
            try:
                import sqlite3
                conn = sqlite3.connect("hexa_vuln_scanner.db")
                cursor = conn.cursor()
                
                # Try to get scan results
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                
                report_data["database_tables"] = [table[0] for table in tables]
                
                # Try to get vulnerability data if table exists
                try:
                    cursor.execute("SELECT * FROM vulnerabilities ORDER BY id DESC LIMIT 50;")
                    vulnerabilities = cursor.fetchall()
                    if vulnerabilities:
                        report_data["vulnerabilities"] = [
                            {
                                "id": vuln[0] if len(vuln) > 0 else None,
                                "type": vuln[1] if len(vuln) > 1 else None,
                                "severity": vuln[2] if len(vuln) > 2 else None,
                                "description": vuln[3] if len(vuln) > 3 else None
                            } for vuln in vulnerabilities
                        ]
                except:
                    pass
                
                conn.close()
            except Exception as e:
                print(f"⚠️ Database read error: {e}")
        
        # Save JSON report for frontend consumption
        print("GENERATING: Creating JSON report for frontend...")
        json_report_path = save_json_report(report_data)
        if json_report_path:
            report_data["json_report"] = json_report_path
            print(f"SUCCESS: JSON report saved: {json_report_path}")
        
        # Generate professional HTML report with AI analysis
        print("GENERATING: Creating professional HTML report with AI analysis...")
        html_report_path = generate_html_report(report_data)
        if html_report_path:
            report_data["html_report"] = html_report_path
            print(f"SUCCESS: Professional HTML report generated: reports/html/{html_report_path}")
        else:
            print("WARNING: HTML report generation failed")
        
        return report_data
        
    except subprocess.TimeoutExpired:
        print("⚠️ Scan timeout - process took too long")
        return None
    except Exception as e:
        print(f"ERROR: Error running scanner: {e}")
        return None
    finally:
        os.chdir(original_dir)

def save_json_report(report_data):
    """Save JSON report for frontend consumption"""
    try:
        # Create reports directory if it doesn't exist
        os.makedirs("../reports", exist_ok=True)
        
        # Generate filename
        from urllib.parse import urlparse
        target_domain = urlparse(report_data["target"]).netloc or "unknown"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"hexa_web_scan_{target_domain}_{timestamp}.json"
        filepath = os.path.join("../reports", filename)
        
        # Prepare comprehensive JSON data for frontend
        json_data = {
            "scan_info": {
                "target": report_data["target"],
                "timestamp": report_data["timestamp"],
                "scanner": report_data["scanner"],
                "status": report_data["status"],
                "scan_time": report_data.get("scan_time", 0),
                "risk_level": report_data["risk_level"]
            },
            "statistics": {
                "total_vulnerabilities": len(report_data.get("vulnerabilities", [])),
                "endpoints_discovered": report_data.get("endpoints_discovered", 0),
                "forms_discovered": report_data.get("forms_discovered", 0),
                "owasp_coverage": report_data.get("owasp_coverage", "Top 150")
            },
            "vulnerabilities": report_data.get("vulnerabilities", []),
            "findings": report_data.get("findings", []),
            "scan_summary": report_data.get("scan_summary", {}),
            "raw_output": report_data.get("output", ""),
            "html_report": report_data.get("html_report", None)
        }
        
        # Save JSON file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        print(f"[JSON] Saved comprehensive JSON report: {filepath}")
        return filename
        
    except Exception as e:
        print(f"[ERROR] JSON report save error: {e}")
        return None

def generate_html_report(report_data):
    """Generate professional HTML report using AI-powered generator"""
    try:
        # Import the professional report generator
        sys.path.append('..')
        from ai_report_generator import generate_professional_report
        
        print(f"[REPORT] Generating AI-powered report for {len(report_data.get('vulnerabilities', []))} vulnerabilities...")
        
        # Generate professional report with API key if available
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key or api_key in ['test_key', 'auto_skip']:
            api_key = None
            print("[REPORT] No Gemini API key - using enhanced fallback analysis")
        else:
            print("[REPORT] Using Gemini AI for professional analysis")
        
        filename = generate_professional_report(report_data, api_key)
        return filename
        
    except Exception as e:
        print(f"[ERROR] Professional report generation error: {e}")
        import traceback
        traceback.print_exc()
        # Fallback to basic report
        return generate_basic_html_report(report_data)

def generate_basic_html_report(report_data):
    """Generate basic HTML report as fallback"""
    try:
        from urllib.parse import urlparse
        
        # Create reports directory if it doesn't exist
        os.makedirs("reports/html", exist_ok=True)
        
        target_domain = urlparse(report_data["target"]).netloc or "unknown"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"pentesting_report_{target_domain}_{timestamp}.html"
        filepath = os.path.join("reports/html", filename)
        
        # Generate basic HTML content
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {report_data["target"]}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; color: #333; border-bottom: 2px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }}
        .section {{ margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 5px; }}
        .finding {{ background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #dc3545; }}
        pre {{ background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Assessment Report</h1>
            <p>Target: {report_data["target"]}</p>
            <p>Generated: {report_data["timestamp"]}</p>
        </div>
        
        <div class="section">
            <h2>📊 Summary</h2>
            <p><strong>Scanner:</strong> {report_data["scanner"]}</p>
            <p><strong>Status:</strong> {report_data["status"].upper()}</p>
            <p><strong>Vulnerabilities:</strong> {len(report_data.get("vulnerabilities", []))}</p>
        </div>
        
        <div class="section">
            <h2>🔍 Scan Output</h2>
            <pre>{report_data.get("output", "No output available")}</pre>
        </div>
        
        <div class="section">
            <h2>📋 Recommendations</h2>
            <div class="finding">
                <h4>Security Recommendations</h4>
                <ul>
                    <li>Review and address any identified vulnerabilities</li>
                    <li>Implement regular security updates</li>
                    <li>Conduct periodic security assessments</li>
                    <li>Follow security best practices</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"📄 Basic HTML Report generated: {filepath}")
        return filename
        
    except Exception as e:
        print(f"⚠️ Basic report generation error: {e}")
        return None

def save_json_report(report_data):
    """Save unified JSON report"""
    if not report_data:
        return None
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"hexa_web_scan_unified_report_{timestamp}.json"
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    print(f"📄 Unified JSON Report saved: {filename}")
    return filename

def main():
    if len(sys.argv) != 2:
        print("Usage: python run_hexa_web_scanner.py <target_url>")
        print("Example: python run_hexa_web_scanner.py http://testhtml5.vulnweb.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    try:
        # Run the scanner
        results = run_hexa_web_scanner(target_url)
        
        if results:
            # Save unified report
            report_file = save_json_report(results)
            
            print("\n" + "=" * 80)
            print("SUCCESS: HexaWebScanner completed successfully!")
            print(f"REPORT: Unified report saved to: {report_file}")
            print("=" * 80)
        else:
            print("ERROR: Scanner failed to complete")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()