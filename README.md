# 🛡️ HPTA Security Suite

**High-Performance Threat Analysis Security Suite** - Enterprise cybersecurity platform powered by AI.

## 🎯 Overview

HPTA Security Suite is a comprehensive security platform combining three powerful analysis tools:

### 🔧 Core Components

1. **🌐 HexaWebScanner** - Advanced web vulnerability scanner
   - OWASP Top 10 vulnerability detection
   - SQL injection and XSS analysis
   - Multi-threaded scanning engine

2. **🦠 Ryha Malware Analyzer** - Comprehensive malware analysis
   - Static and dynamic analysis
   - IOC scanning and threat detection
   - Professional reporting

3. **🔧 Reverse Engineering Tool** - Binary analysis platform
   - 13 built-in reverse engineering tools
   - Security risk assessment
   - Professional HTML/JSON reporting

## 🚀 Quick Start

### Installation
```bash
# Install dependencies
pip install -r requirements_hpta.txt

# Start the security suite
python start_hpta.py
```

### Docker Deployment
```bash
cd docker
docker-compose up -d
```

## 🎯 Usage

### Web Interface
```bash
python hpta_security_suite.py
# Access: http://localhost:5000
```

### Command Line Tools
```bash
# Web vulnerability scanning
python scripts/run_hexa_web_scanner.py https://target.com

# Malware analysis
python scripts/run_ryha_malware_analyzer.py sample.exe

# Reverse engineering
python scripts/run_reverse_engineering.py binary.exe
```

## 📁 Project Structure

```
HPTA/
├── 🌐 HexaWebScanner/          # Web vulnerability scanner
├── 🦠 ryha-malware-analyzer/   # Malware analysis engine
├── 🔧 reverseengineering/      # Reverse engineering tools
├── 📜 scripts/                 # Integration scripts
├── 🐳 docker/                  # Docker deployment
├── 📚 docs/                    # Documentation
├── 🧪 tests/                   # Test suites
├── 📊 templates/               # Web templates
├── 📄 reports/                 # Generated reports
└── 📋 Core files               # Main application
```

## 🔧 Configuration

Set environment variables:
```bash
export GEMINI_API_KEY="your_gemini_api_key"
export VT_API_KEY="your_virustotal_api_key"
```

## 📊 Features

- **🤖 AI-Powered Analysis**: Gemini AI integration
- **📊 Professional Reporting**: JSON, HTML, PDF formats
- **🐳 Docker Ready**: Complete containerization
- **🔄 API Integration**: REST API endpoints
- **⚙️ Extensible**: Modular architecture

## 📝 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

We welcome contributions! Please submit pull requests.

---

**⚡ HPTA Security Suite - Advanced Threat Analysis Made Simple**