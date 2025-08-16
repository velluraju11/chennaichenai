# HexaWebScanner 🌐

## Advanced Web Vulnerability Scanner & Security Assessment Tool

HexaWebScanner is a comprehensive web application security scanner designed to identify vulnerabilities, security misconfigurations, and potential threats in web applications and websites.

---

## 🚀 Features

### Core Scanning Capabilities
- **OWASP Top 10 Detection** - Complete coverage of OWASP vulnerabilities
- **SQL Injection Testing** - Advanced SQLi detection with multiple payloads
- **Cross-Site Scripting (XSS)** - Reflected, Stored, and DOM-based XSS detection
- **Cross-Site Request Forgery (CSRF)** - CSRF token validation and bypass testing
- **Directory Traversal** - Path traversal and file inclusion vulnerability detection
- **Authentication Bypass** - Login form and authentication mechanism testing

### Advanced Security Features
- **SSL/TLS Analysis** - Certificate validation and cipher suite assessment
- **HTTP Header Security** - Security header analysis and recommendations
- **Cookie Security** - HttpOnly, Secure, and SameSite attribute validation
- **Content Security Policy (CSP)** - CSP implementation and bypass detection
- **Subdomain Enumeration** - Comprehensive subdomain discovery
- **Port Scanning** - Network service discovery and banner grabbing

### Database Integration
- **CVE Lookup** - Real-time vulnerability database integration
- **Wayback Machine** - Historical vulnerability analysis
- **Threat Intelligence** - Integration with security feeds and databases

---

## 📁 Project Structure

```
HexaWebScanner/
├── comprehensive_scanner.py    # Main scanning engine
├── enhanced_owasp_scan.py     # OWASP vulnerability scanner
├── enhanced_cve_scan.py       # CVE database integration
├── enhanced_database_scan.py  # Database vulnerability scanner
├── enhanced_db_wayback_scan.py # Historical analysis
├── sql_injection_scanner.py   # SQL injection testing module
├── cve_lookup.py              # CVE database lookup
├── db_manager.py              # Database management
├── report_generator.py        # HTML/PDF report generation
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

---

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- pip package manager
- Internet connection for CVE lookups

### Setup Instructions

1. **Clone or Navigate to HexaWebScanner Directory**
   ```bash
   cd HexaWebScanner/
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize Database** (if required)
   ```bash
   python db_manager.py --init
   ```

---

## 🔧 Usage

### Command Line Interface

#### Basic Web Scan
```bash
python comprehensive_scanner.py --url https://example.com
```

#### Advanced Scan with Options
```bash
python comprehensive_scanner.py --url https://example.com \
    --scan-type full \
    --output-format html \
    --include-subdomains \
    --check-ssl
```

#### SQL Injection Testing
```bash
python sql_injection_scanner.py --url https://example.com/login \
    --method POST \
    --data "username=admin&password=pass"
```

### Integration with HPTA Suite

#### Via Unified Scanner
```bash
# From main project directory
python scripts/unified_scanner.py hexa https://example.com
```

#### Via Web Frontend
1. Access the HPTA dashboard at `http://127.0.0.1:5000`
2. Enter scan command: "Scan https://example.com for web vulnerabilities"
3. View real-time results and generated reports

---

## 📊 Scan Types

### 1. Quick Scan
- Basic vulnerability detection
- OWASP Top 10 coverage
- SSL/TLS validation
- **Duration:** 2-5 minutes

### 2. Standard Scan
- Comprehensive vulnerability testing
- Directory enumeration
- Form testing and injection detection
- **Duration:** 10-15 minutes

### 3. Full Scan
- Complete security assessment
- Subdomain enumeration
- Historical vulnerability analysis
- Advanced payload testing
- **Duration:** 30-60 minutes

---

## 🎯 Vulnerability Detection

### Web Application Vulnerabilities
- **A01: Broken Access Control**
- **A02: Cryptographic Failures**
- **A03: Injection Flaws**
- **A04: Insecure Design**
- **A05: Security Misconfiguration**
- **A06: Vulnerable Components**
- **A07: Authentication Failures**
- **A08: Software Integrity Failures**
- **A09: Logging Failures**
- **A10: Server-Side Request Forgery**

### Network & Infrastructure
- Open ports and services
- SSL/TLS configuration issues
- HTTP security headers
- Cookie security settings
- DNS configuration problems

---

## 📈 Reporting

### Output Formats
- **HTML Reports** - Interactive web-based reports
- **JSON Data** - Machine-readable scan results
- **PDF Reports** - Professional security assessment documents
- **XML Export** - Integration with other security tools

### Report Sections
1. **Executive Summary** - High-level findings overview
2. **Vulnerability Details** - Technical vulnerability descriptions
3. **Risk Assessment** - CVSS scores and impact analysis
4. **Remediation Guide** - Step-by-step fix instructions
5. **Technical Appendix** - Raw scan data and evidence

---

## ⚙️ Configuration

### Scanner Settings
```python
# comprehensive_scanner.py configuration
SCAN_TIMEOUT = 30          # Request timeout in seconds
MAX_THREADS = 10           # Concurrent scanning threads
USER_AGENT = "HexaWebScanner/1.0"
FOLLOW_REDIRECTS = True
VERIFY_SSL = True
```

### Payload Customization
```python
# Custom SQL injection payloads
CUSTOM_SQL_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "'; DROP TABLE users--"
]
```

---

## 🔒 Security & Ethics

### Responsible Use
- **Only scan systems you own or have permission to test**
- Comply with local laws and regulations
- Respect rate limits and server resources
- Report vulnerabilities responsibly

### Legal Disclaimer
This tool is for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any systems.

---

## 🐛 Troubleshooting

### Common Issues

#### Connection Timeouts
```bash
# Increase timeout values
python comprehensive_scanner.py --url https://example.com --timeout 60
```

#### SSL Certificate Errors
```bash
# Disable SSL verification for testing
python comprehensive_scanner.py --url https://example.com --no-verify-ssl
```

#### Rate Limiting
```bash
# Reduce scan speed
python comprehensive_scanner.py --url https://example.com --delay 2
```

---

## 📞 Support & Contributing

### Getting Help
- Check the troubleshooting section above
- Review scan logs for detailed error information
- Ensure target URL is accessible and responsive

### Contributing
- Report bugs and security issues
- Submit feature requests
- Contribute new vulnerability detection modules
- Improve documentation and examples

---

## 📋 Dependencies

### Core Requirements
```
requests>=2.28.0
urllib3>=1.26.0
beautifulsoup4>=4.11.0
lxml>=4.9.0
colorama>=0.4.5
tabulate>=0.9.0
```

### Optional Dependencies
```
selenium>=4.0.0      # For JavaScript-heavy applications
sqlparse>=0.4.0      # For SQL query analysis
cryptography>=3.4.0 # For SSL/TLS analysis
```

---

## 🏷️ Version History

- **v1.0.0** - Initial release with basic OWASP scanning
- **v1.1.0** - Added SQL injection detection and CVE lookup
- **v1.2.0** - Enhanced reporting and database integration
- **v1.3.0** - Subdomain enumeration and SSL analysis
- **v2.0.0** - Complete rewrite with advanced features
- **v2.1.0** - HPTA suite integration and web frontend

---

**HexaWebScanner** - Part of the HPTA Security Suite
*Advanced Web Application Security Testing Made Simple*
