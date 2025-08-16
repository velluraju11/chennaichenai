#!/usr/bin/env python3
"""
HPTA SECURITY SCANNER FRONTEND WITH GEMINI AI
Real-time Security Scanning Dashboard with AI-Powered Analysis
"""

import sys
import os
import json
import time
import datetime
import subprocess
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional

# Check for required packages
try:
    from flask import Flask, render_template, request, jsonify, send_from_directory
    from flask_socketio import SocketIO, emit
    import google.generativeai as genai
    from dotenv import load_dotenv
    import markdown
except ImportError as e:
    print("Required packages not installed. Please run:")
    print("pip install flask flask-socketio google-generativeai python-dotenv markdown")
    sys.exit(1)

# Load environment variables
load_dotenv()

class HPTASecurityFrontend:
    """HPTA Security Scanner Web Frontend with Google Gemini AI Integration"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'hpta-security-scanner-2025')
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Initialize paths
        self.base_dir = Path(__file__).parent
        self.unified_scanner = self.base_dir / "unified_scanner.py"
        self.reports_dir = self.base_dir / "reports"
        self.reports_dir.mkdir(exist_ok=True)
        
        # Initialize Google Gemini AI
        self.gemini_model = None
        self.init_gemini_ai()
        
        # Available scanners
        self.scanners = {
            "ultra": {
                "name": "Ultra Malware Scanner V3.0",
                "description": "Quantum AI-Enhanced Malware Detection",
                "type": "malware",
                "icon": "shield-check"
            },
            "hexa": {
                "name": "HexaWebScanner",
                "description": "Advanced Web Vulnerability Scanner", 
                "type": "web",
                "icon": "globe"
            },
            "ryha": {
                "name": "RYHA Malware Analyzer",
                "description": "Deep Malware Analysis System",
                "type": "malware",
                "icon": "bug"
            },
            "reverse": {
                "name": "Reverse Engineering Analyzer", 
                "description": "Binary Analysis and Reverse Engineering",
                "type": "reverse", 
                "icon": "code"
            },
            "all": {
                "name": "Comprehensive Scan",
                "description": "Run All Applicable Scanners",
                "type": "comprehensive",
                "icon": "layers"
            }
        }
        
        # Active scans tracking
        self.active_scans = {}
        
        # Setup Flask routes
        self.setup_routes()
        
    def init_gemini_ai(self):
        """Initialize Google Gemini AI"""
        try:
            api_key = os.environ.get('GOOGLE_API_KEY')
            if api_key:
                genai.configure(api_key=api_key)
                self.gemini_model = genai.GenerativeModel('gemini-1.5-flash')
                print("Google Gemini AI initialized successfully")
            else:
                print("Google API key not found. AI analysis will be disabled.")
        except Exception as e:
            print(f"Failed to initialize Gemini AI: {e}")
            self.gemini_model = None
            
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            return self.render_dashboard()
            
        @self.app.route('/api/scanners')
        def get_scanners():
            return jsonify(self.scanners)
            
        @self.app.route('/api/scan', methods=['POST'])
        def start_scan():
            data = request.get_json()
            scanner_type = data.get('scanner', 'all')
            target = data.get('target', '')
            
            if not target.strip():
                return jsonify({'error': 'Target is required'}), 400
                
            scan_id = f"scan_{int(time.time())}"
            
            # Start scan in background thread
            thread = threading.Thread(
                target=self.run_scan_thread,
                args=(scan_id, scanner_type, target)
            )
            thread.daemon = True
            thread.start()
            
            return jsonify({
                'scan_id': scan_id,
                'status': 'started',
                'scanner': scanner_type,
                'target': target
            })
            
        @self.app.route('/api/scan/<scan_id>/status')
        def get_scan_status(scan_id):
            if scan_id in self.active_scans:
                return jsonify(self.active_scans[scan_id])
            else:
                return jsonify({'error': 'Scan not found'}), 404
                
        @self.app.route('/api/reports')
        def get_reports():
            reports = []
            for report_file in self.reports_dir.glob('*.json'):
                try:
                    with open(report_file, 'r') as f:
                        report_data = json.load(f)
                    reports.append({
                        'filename': report_file.name,
                        'timestamp': report_data.get('timestamp', ''),
                        'target': report_data.get('target', ''),
                        'scanners': report_data.get('scanners_run', []),
                        'success': report_data.get('success', False)
                    })
                except Exception as e:
                    print(f"Error reading report {report_file}: {e}")
            
            # Sort by timestamp descending
            reports.sort(key=lambda x: x['timestamp'], reverse=True)
            return jsonify(reports)
            
        @self.app.route('/api/report/<filename>')
        def get_report(filename):
            report_path = self.reports_dir / filename
            if report_path.exists():
                try:
                    with open(report_path, 'r') as f:
                        return jsonify(json.load(f))
                except Exception as e:
                    return jsonify({'error': f'Failed to read report: {e}'}), 500
            else:
                return jsonify({'error': 'Report not found'}), 404
                
        @self.app.route('/api/analyze', methods=['POST'])
        def analyze_with_ai():
            if not self.gemini_model:
                return jsonify({'error': 'AI analysis not available'}), 503
                
            data = request.get_json()
            report_data = data.get('report', {})
            
            try:
                analysis = self.analyze_report_with_gemini(report_data)
                return jsonify({
                    'analysis': analysis,
                    'timestamp': datetime.datetime.now().isoformat()
                })
            except Exception as e:
                return jsonify({'error': f'AI analysis failed: {e}'}), 500
                
    def render_dashboard(self):
        """Render the main dashboard HTML"""
        html_template = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>HPTA Security Scanner Dashboard</title>
            <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
            <style>
                body { background-color: #0a0e27; color: #ffffff; }
                .navbar { background-color: #1a1e3a !important; border-bottom: 2px solid #00d4ff; }
                .card { background-color: #1a1e3a; border: 1px solid #00d4ff; }
                .btn-primary { background-color: #00d4ff; border-color: #00d4ff; color: #000; }
                .btn-primary:hover { background-color: #00a8cc; border-color: #00a8cc; }
                .progress-bar { background-color: #00d4ff; }
                .alert-success { background-color: #155724; border-color: #155724; }
                .alert-danger { background-color: #721c24; border-color: #721c24; }
                .alert-warning { background-color: #856404; border-color: #856404; }
                .log-output { background-color: #000; color: #00ff00; font-family: monospace; height: 300px; overflow-y: auto; }
                .threat-high { color: #ff4757; font-weight: bold; }
                .threat-medium { color: #ffa502; font-weight: bold; }
                .threat-low { color: #2ed573; font-weight: bold; }
                .scanner-card { transition: transform 0.2s; cursor: pointer; }
                .scanner-card:hover { transform: translateY(-5px); }
                .live-scan { border-left: 4px solid #00d4ff; }
                .ai-analysis { background: linear-gradient(45deg, #1a1e3a, #2a2e4a); border-radius: 10px; padding: 20px; }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-dark">
                <div class="container-fluid">
                    <span class="navbar-brand mb-0 h1">
                        <i class="bi bi-shield-check"></i> HPTA Security Scanner Dashboard
                    </span>
                    <span class="navbar-text">
                        <i class="bi bi-cpu"></i> Quantum AI Enhanced | <i class="bi bi-lightning"></i> Real-time Analysis
                    </span>
                </div>
            </nav>

            <div class="container-fluid mt-4">
                <div class="row">
                    <div class="col-md-8">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="bi bi-play-circle"></i> Start New Scan</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <label class="form-label">Target (File/URL)</label>
                                        <input type="text" class="form-control" id="scanTarget" placeholder="Enter file path or URL">
                                    </div>
                                    <div class="col-md-4">
                                        <label class="form-label">Scanner</label>
                                        <select class="form-select" id="scannerSelect">
                                            <option value="all">All Scanners</option>
                                            <option value="ultra">Ultra Malware Scanner V3.0</option>
                                            <option value="hexa">HexaWebScanner</option>
                                            <option value="ryha">RYHA Analyzer</option>
                                            <option value="reverse">Reverse Engineering</option>
                                        </select>
                                    </div>
                                    <div class="col-md-2">
                                        <label class="form-label">&nbsp;</label>
                                        <button class="btn btn-primary w-100" onclick="startScan()">
                                            <i class="bi bi-play"></i> Start Scan
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="card mt-4" id="liveScanCard" style="display: none;">
                            <div class="card-header live-scan">
                                <h5><i class="bi bi-activity"></i> Live Scan Progress</h5>
                            </div>
                            <div class="card-body">
                                <div class="progress mb-3">
                                    <div class="progress-bar progress-bar-animated" role="progressbar" id="scanProgress"></div>
                                </div>
                                <div class="log-output" id="scanOutput"></div>
                                <div class="mt-3">
                                    <button class="btn btn-success" onclick="analyzeWithAI()" id="aiAnalyzeBtn" style="display: none;">
                                        <i class="bi bi-robot"></i> Analyze with Gemini AI
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div class="card mt-4" id="aiAnalysisCard" style="display: none;">
                            <div class="card-header ai-analysis">
                                <h5><i class="bi bi-brain"></i> Gemini AI Analysis</h5>
                            </div>
                            <div class="card-body" id="aiAnalysisContent">
                                <div class="d-flex justify-content-center">
                                    <div class="spinner-border text-primary" role="status">
                                        <span class="visually-hidden">Analyzing...</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="bi bi-list-check"></i> Available Scanners</h5>
                            </div>
                            <div class="card-body" id="scannersInfo">
                                <div class="scanner-card card mb-2" onclick="selectScanner('ultra')">
                                    <div class="card-body p-3">
                                        <h6><i class="bi bi-shield-check"></i> Ultra Malware Scanner V3.0</h6>
                                        <small class="text-muted">Quantum AI-Enhanced Detection</small>
                                    </div>
                                </div>
                                <div class="scanner-card card mb-2" onclick="selectScanner('hexa')">
                                    <div class="card-body p-3">
                                        <h6><i class="bi bi-globe"></i> HexaWebScanner</h6>
                                        <small class="text-muted">Web Vulnerability Scanner</small>
                                    </div>
                                </div>
                                <div class="scanner-card card mb-2" onclick="selectScanner('ryha')">
                                    <div class="card-body p-3">
                                        <h6><i class="bi bi-bug"></i> RYHA Malware Analyzer</h6>
                                        <small class="text-muted">Deep Malware Analysis</small>
                                    </div>
                                </div>
                                <div class="scanner-card card mb-2" onclick="selectScanner('reverse')">
                                    <div class="card-body p-3">
                                        <h6><i class="bi bi-code"></i> Reverse Engineering</h6>
                                        <small class="text-muted">Binary Analysis</small>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="card mt-4">
                            <div class="card-header">
                                <h5><i class="bi bi-clock-history"></i> Recent Scans</h5>
                            </div>
                            <div class="card-body">
                                <div id="recentScans">
                                    <p class="text-muted">No recent scans</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            <script>
                const socket = io();
                let currentScan = null;
                let currentScanData = null;

                function selectScanner(scanner) {
                    document.getElementById('scannerSelect').value = scanner;
                }

                function startScan() {
                    const target = document.getElementById('scanTarget').value.trim();
                    const scanner = document.getElementById('scannerSelect').value;
                    
                    if (!target) {
                        alert('Please enter a target file or URL');
                        return;
                    }
                    
                    // Show live scan card
                    document.getElementById('liveScanCard').style.display = 'block';
                    document.getElementById('scanOutput').innerHTML = '';
                    document.getElementById('scanProgress').style.width = '0%';
                    document.getElementById('aiAnalyzeBtn').style.display = 'none';
                    document.getElementById('aiAnalysisCard').style.display = 'none';
                    
                    // Start scan
                    fetch('/api/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ scanner: scanner, target: target })
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            appendToOutput('Error: ' + data.error, 'error');
                        } else {
                            currentScan = data.scan_id;
                            appendToOutput('Scan started: ' + data.scan_id, 'info');
                            appendToOutput('Scanner: ' + data.scanner, 'info');
                            appendToOutput('Target: ' + data.target, 'info');
                        }
                    })
                    .catch(error => {
                        appendToOutput('Failed to start scan: ' + error, 'error');
                    });
                }

                function appendToOutput(message, type = 'info') {
                    const output = document.getElementById('scanOutput');
                    const timestamp = new Date().toLocaleTimeString();
                    const colorClass = type === 'error' ? 'text-danger' : type === 'success' ? 'text-success' : 'text-info';
                    output.innerHTML += `<div class="${colorClass}">[${timestamp}] ${message}</div>`;
                    output.scrollTop = output.scrollHeight;
                }

                function analyzeWithAI() {
                    if (!currentScanData) {
                        alert('No scan data available for analysis');
                        return;
                    }
                    
                    document.getElementById('aiAnalysisCard').style.display = 'block';
                    document.getElementById('aiAnalysisContent').innerHTML = `
                        <div class="d-flex justify-content-center">
                            <div class="spinner-border text-primary" role="status">
                                <span class="visually-hidden">Analyzing...</span>
                            </div>
                        </div>
                        <p class="text-center mt-2">Gemini AI is analyzing the scan results...</p>
                    `;
                    
                    fetch('/api/analyze', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ report: currentScanData })
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            document.getElementById('aiAnalysisContent').innerHTML = 
                                `<div class="alert alert-danger">${data.error}</div>`;
                        } else {
                            document.getElementById('aiAnalysisContent').innerHTML = 
                                `<div class="ai-analysis">${data.analysis}</div>`;
                        }
                    })
                    .catch(error => {
                        document.getElementById('aiAnalysisContent').innerHTML = 
                            `<div class="alert alert-danger">AI analysis failed: ${error}</div>`;
                    });
                }

                // Socket.IO event handlers
                socket.on('scan_progress', function(data) {
                    if (data.scan_id === currentScan) {
                        document.getElementById('scanProgress').style.width = data.progress + '%';
                        appendToOutput(data.message, data.type || 'info');
                    }
                });

                socket.on('scan_completed', function(data) {
                    if (data.scan_id === currentScan) {
                        currentScanData = data.results;
                        document.getElementById('scanProgress').style.width = '100%';
                        appendToOutput('Scan completed successfully!', 'success');
                        document.getElementById('aiAnalyzeBtn').style.display = 'inline-block';
                        
                        // Display results summary
                        if (data.results && data.results.results) {
                            appendToOutput('=== SCAN RESULTS ===', 'success');
                            for (const [scanner, result] of Object.entries(data.results.results)) {
                                const status = result.success ? 'SUCCESS' : 'CHECK OUTPUT';
                                const statusType = result.success ? 'success' : 'warning';
                                appendToOutput(`${scanner.toUpperCase()}: ${status}`, statusType);
                            }
                        }
                    }
                });

                socket.on('scan_failed', function(data) {
                    if (data.scan_id === currentScan) {
                        document.getElementById('scanProgress').style.width = '100%';
                        document.getElementById('scanProgress').classList.remove('progress-bar-animated');
                        document.getElementById('scanProgress').style.backgroundColor = '#dc3545';
                        appendToOutput('Scan failed: ' + data.error, 'error');
                    }
                });

                // Load recent scans on page load
                window.onload = function() {
                    loadRecentScans();
                };

                function loadRecentScans() {
                    fetch('/api/reports')
                    .then(response => response.json())
                    .then(reports => {
                        const container = document.getElementById('recentScans');
                        if (reports.length === 0) {
                            container.innerHTML = '<p class="text-muted">No recent scans</p>';
                        } else {
                            container.innerHTML = reports.slice(0, 5).map(report => `
                                <div class="card mb-2">
                                    <div class="card-body p-2">
                                        <small>
                                            <strong>${report.target}</strong><br>
                                            Scanners: ${report.scanners.join(', ')}<br>
                                            Status: <span class="${report.success ? 'text-success' : 'text-warning'}">${report.success ? 'Success' : 'Warning'}</span>
                                        </small>
                                    </div>
                                </div>
                            `).join('');
                        }
                    })
                    .catch(error => {
                        console.error('Failed to load recent scans:', error);
                    });
                }
            </script>
        </body>
        </html>
        '''
        return html_template
        
    def run_scan_thread(self, scan_id: str, scanner_type: str, target: str):
        """Run scan in background thread with real-time updates"""
        self.active_scans[scan_id] = {
            'status': 'running',
            'progress': 0,
            'scanner': scanner_type,
            'target': target,
            'started_at': datetime.datetime.now().isoformat()
        }
        
        try:
            # Emit progress update
            self.socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'progress': 10,
                'message': f'Starting {scanner_type.upper()} scanner...',
                'type': 'info'
            })
            
            # Run the unified scanner
            cmd = [
                sys.executable, 
                str(self.unified_scanner),
                scanner_type,
                target
            ]
            
            self.socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'progress': 30,
                'message': 'Executing scanner command...',
                'type': 'info'
            })
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            self.socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'progress': 80,
                'message': 'Processing scan results...',
                'type': 'info'
            })
            
            # Try to find the latest report file
            latest_report = None
            for report_file in sorted(self.reports_dir.glob('hpta_scan_*.json'), key=lambda x: x.stat().st_mtime, reverse=True):
                try:
                    with open(report_file, 'r') as f:
                        report_data = json.load(f)
                    if report_data.get('target') == target:
                        latest_report = report_data
                        break
                except Exception:
                    continue
            
            self.active_scans[scan_id].update({
                'status': 'completed',
                'progress': 100,
                'output': result.stdout,
                'errors': result.stderr,
                'return_code': result.returncode,
                'completed_at': datetime.datetime.now().isoformat()
            })
            
            # Emit completion
            self.socketio.emit('scan_completed', {
                'scan_id': scan_id,
                'results': latest_report,
                'output': result.stdout
            })
            
        except subprocess.TimeoutExpired:
            self.active_scans[scan_id].update({
                'status': 'timeout',
                'progress': 100,
                'error': 'Scan timed out (10 minutes)',
                'completed_at': datetime.datetime.now().isoformat()
            })
            
            self.socketio.emit('scan_failed', {
                'scan_id': scan_id,
                'error': 'Scan timed out after 10 minutes'
            })
            
        except Exception as e:
            self.active_scans[scan_id].update({
                'status': 'failed',
                'progress': 100,
                'error': str(e),
                'completed_at': datetime.datetime.now().isoformat()
            })
            
            self.socketio.emit('scan_failed', {
                'scan_id': scan_id,
                'error': str(e)
            })
            
    def analyze_report_with_gemini(self, report_data: Dict[str, Any]) -> str:
        """Analyze scan results with Google Gemini AI"""
        if not self.gemini_model:
            return "AI analysis not available - Gemini API not configured"
            
        # Prepare the analysis prompt
        prompt = f'''
        You are a cybersecurity expert analyzing malware scan results. Please provide a comprehensive analysis of the following scan data:

        Scan Target: {report_data.get('target', 'Unknown')}
        Scan Timestamp: {report_data.get('timestamp', 'Unknown')}
        Scanners Used: {', '.join(report_data.get('scanners_run', []))}

        Results:
        {json.dumps(report_data, indent=2)}

        Please provide:
        1. Executive Summary of findings
        2. Threat Assessment and Risk Level
        3. Key Technical Indicators
        4. Recommended Actions
        5. Additional Context and Insights

        Format your response in clear, professional markdown with appropriate headers and bullet points.
        '''
        
        try:
            response = self.gemini_model.generate_content(prompt)
            # Convert markdown to HTML for display
            html_response = markdown.markdown(response.text)
            return html_response
        except Exception as e:
            return f"AI analysis failed: {str(e)}"
    
    def run(self, host='127.0.0.1', port=5000, debug=False):
        """Run the web application"""
        try:
            print(f"Starting HPTA Security Scanner Frontend...")
            print(f"Access the dashboard at: http://{host}:{port}")
            print(f"Press Ctrl+C to stop the server")
            
            self.socketio.run(
                self.app, 
                host=host, 
                port=port, 
                debug=debug,
                allow_unsafe_werkzeug=True
            )
        except Exception as e:
            print(f"Server error: {e}")


def main():
    """Main application entry point"""
    frontend = HPTASecurityFrontend()
    
    # Default configuration
    host = '127.0.0.1'
    port = 5000
    debug = False
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        if '--host' in sys.argv:
            idx = sys.argv.index('--host')
            if idx + 1 < len(sys.argv):
                host = sys.argv[idx + 1]
                
        if '--port' in sys.argv:
            idx = sys.argv.index('--port')
            if idx + 1 < len(sys.argv):
                port = int(sys.argv[idx + 1])
                
        if '--debug' in sys.argv:
            debug = True
    
    frontend.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    main()
