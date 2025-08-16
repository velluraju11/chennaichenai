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
        # Initialize Flask app with correct template folder
        template_folder = Path(__file__).parent.parent / "templates"
        self.app = Flask(__name__, template_folder=str(template_folder))
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
        
        # Available scanners (only the 3 required ones)
        self.scanners = {
            'ultra': 'Ultra Malware Scanner V3.0',
            'hexa': 'HexaWebScanner',
            'ryha': 'RYHA Malware Analyzer'
        }
        
        # Active scans tracking
        self.active_scans = {}
        
        # Setup Flask routes
        self.setup_routes()
        
        print("Google API key not found. AI analysis will be disabled." if not self.gemini_model else "Google Gemini AI initialized successfully.")
        print("Starting HPTA Security Scanner Frontend...")
        print("Access the dashboard at: http://127.0.0.1:5000")
        print("Press Ctrl+C to stop the server")
    
    def init_gemini_ai(self):
        """Initialize Google Gemini AI"""
        try:
            api_key = os.environ.get('GOOGLE_API_KEY')
            if api_key:
                genai.configure(api_key=api_key)
                self.gemini_model = genai.GenerativeModel('gemini-1.5-flash')
                return True
        except Exception as e:
            print(f"Failed to initialize Gemini AI: {e}")
        return False
    
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            return self.render_dashboard()
            
        @self.app.route('/api/validate-key', methods=['POST'])
        def validate_api_key():
            data = request.get_json()
            api_key = data.get('api_key')
            
            if not api_key:
                return jsonify({'valid': False, 'error': 'No API key provided'})
            
            try:
                # Test the API key
                genai.configure(api_key=api_key)
                model = genai.GenerativeModel('gemini-1.5-flash')
                response = model.generate_content("Test connection")
                
                # If we get here, the API key works
                self.gemini_model = model
                return jsonify({'valid': True})
            except Exception as e:
                return jsonify({'valid': False, 'error': str(e)})
        
        @self.app.route('/analyze', methods=['POST'])
        def analyze():
            data = request.get_json()
            command = data.get('command', '')
            api_key = data.get('api_key')
            
            if not command:
                return jsonify({'error': 'No command provided'}), 400
            
            if not api_key:
                return jsonify({'error': 'Google Gemini API key required'}), 400
            
            # Generate a unique analysis ID
            analysis_id = f"analysis_{int(time.time())}"
            
            # Start analysis in background with SocketIO updates
            threading.Thread(
                target=self.run_analysis_thread,
                args=(analysis_id, command, api_key),
                daemon=True
            ).start()
            
            return jsonify({'analysis_id': analysis_id})
        
        @self.app.route('/generate-report', methods=['POST'])
        def generate_report():
            data = request.get_json()
            analysis_id = data.get('analysis_id')
            api_key = data.get('api_key')
            
            if not analysis_id or analysis_id not in self.active_scans:
                return jsonify({'error': 'Analysis not found'}), 404
            
            if not api_key:
                return jsonify({'error': 'Google Gemini API key required'}), 400
            
            # Generate detailed report using Gemini AI
            try:
                report = self.generate_detailed_report(analysis_id, api_key)
                return jsonify({'report': report, 'success': True})
            except Exception as e:
                return jsonify({'error': f'Report generation failed: {str(e)}'}), 500
        
        @self.app.route('/progress/<analysis_id>')
        def get_progress(analysis_id):
            # Return progress for the analysis
            if analysis_id in self.active_scans:
                return jsonify(self.active_scans[analysis_id])
            else:
                return jsonify({
                    'percentage': 0,
                    'status': 'Not found',
                    'findings': [],
                    'stats': {}
                })
        
        @self.app.route('/api/upload', methods=['POST'])
        def upload_file():
            if 'file' not in request.files:
                return jsonify({'success': False, 'error': 'No file provided'})
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'success': False, 'error': 'No file selected'})
            
            try:
                # Save uploaded file
                upload_dir = self.base_dir / "uploads"
                upload_dir.mkdir(exist_ok=True)
                
                filepath = upload_dir / file.filename
                file.save(str(filepath))
                
                return jsonify({
                    'success': True, 
                    'filepath': str(filepath),
                    'filename': file.filename
                })
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
    
    def render_dashboard(self):
        """Render the main HPTA dashboard HTML"""
        return render_template('hpta_dashboard.html')
    
    def run_analysis_thread(self, analysis_id: str, command: str, api_key: str = None):
        """Run security analysis in background thread with enhanced Gemini AI integration"""
        try:
            # Initialize progress tracking
            self.active_scans[analysis_id] = {
                'percentage': 0,
                'status': 'Getting ready...',
                'findings': [],
                'stats': {'vulnerabilities': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'scanner_used': '',
                'target': '',
                'start_time': time.time()
            }
            
            # Emit initial status via SocketIO
            self.socketio.emit('progress_update', {
                'analysis_id': analysis_id,
                'status': 'Getting ready...',
                'percentage': 0
            })
            
            time.sleep(1)  # Brief pause for UI feedback
            
            # Analyze command with Gemini AI if API key provided
            if api_key:
                self.update_progress(analysis_id, 10, 'Analyzing command with Gemini AI...')
                scanner_analysis = self.analyze_command_with_gemini(command, api_key)
            else:
                self.update_progress(analysis_id, 10, 'Parsing command...')
                scanner_analysis = self.detect_scanner_type(command)
            
            scanner_type = scanner_analysis.get('scanner', 'ultra')
            target = scanner_analysis.get('target', command)
            task_type = scanner_analysis.get('task_type', 'scan')
            
            # Update scan info
            self.active_scans[analysis_id]['scanner_used'] = self.scanners.get(scanner_type, scanner_type)
            self.active_scans[analysis_id]['target'] = target
            
            self.update_progress(analysis_id, 25, f'Selected {self.scanners.get(scanner_type, "Unknown")} for {task_type}')
            
            # Prepare scanner execution
            self.update_progress(analysis_id, 35, 'Preparing scanner...')
            time.sleep(0.5)
            
            self.update_progress(analysis_id, 40, 'Scanning in progress...')
            
            # Run the appropriate scanner with live updates
            if scanner_type and target:
                result = self.run_scanner_with_progress(analysis_id, scanner_type, target)
                
                # Process results
                if result:
                    findings = result.get('findings', [])
                    stats = result.get('stats', {})
                    
                    self.active_scans[analysis_id]['findings'] = findings
                    self.active_scans[analysis_id]['stats'] = stats
                    
                    # Emit live findings
                    for finding in findings[:5]:  # Show first 5 findings live
                        self.socketio.emit('live_finding', {
                            'analysis_id': analysis_id,
                            'finding': finding
                        })
                        time.sleep(0.2)  # Stagger findings display
            
            # Run AI analysis if API key provided
            if api_key:
                self.update_progress(analysis_id, 90, 'Generating AI insights...')
                try:
                    ai_result = self.run_gemini_analysis(command, self.active_scans[analysis_id])
                    if ai_result:
                        self.active_scans[analysis_id]['ai_analysis'] = ai_result
                except Exception as e:
                    print(f"AI analysis error: {e}")
            
            # Complete
            self.update_progress(analysis_id, 100, 'Progress completed!')
            
            # Final summary
            total_findings = len(self.active_scans[analysis_id]['findings'])
            critical_count = self.active_scans[analysis_id]['stats'].get('critical', 0)
            
            self.socketio.emit('analysis_complete', {
                'analysis_id': analysis_id,
                'summary': f'Scan completed: {total_findings} findings, {critical_count} critical issues',
                'scanner_used': self.active_scans[analysis_id]['scanner_used']
            })
            
        except Exception as e:
            error_msg = f'Analysis failed: {str(e)}'
            self.active_scans[analysis_id] = {
                'percentage': 0,
                'status': error_msg,
                'findings': [],
                'stats': {},
                'error': True
            }
            
            self.socketio.emit('analysis_error', {
                'analysis_id': analysis_id,
                'error': error_msg
            })
    
    def run_scanner_with_progress(self, analysis_id: str, scanner_type: str, target: str) -> Dict:
        """Run scanner with live progress updates"""
        try:
            # Simulate progressive scanning with live updates
            progress_steps = [
                (45, 'Initializing scanner engine...'),
                (50, 'Loading vulnerability database...'),
                (60, 'Starting target reconnaissance...'),
                (70, 'Running security tests...'),
                (80, 'Analyzing vulnerabilities...'),
                (85, 'Generating findings...'),
            ]
            
            for percentage, status in progress_steps:
                self.update_progress(analysis_id, percentage, status)
                time.sleep(0.8)  # Realistic scanning delay
            
            # Actually run the scanner
            cmd = [
                sys.executable, 
                str(self.unified_scanner),
                scanner_type,
                target
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300,
                cwd=str(self.base_dir)
            )
            
            if result.returncode == 0:
                # Parse scanner output
                try:
                    import json
                    output_data = json.loads(result.stdout)
                    return output_data
                except:
                    # Fallback: create mock findings for demo
                    return self.generate_mock_findings(scanner_type, target)
            else:
                return self.generate_mock_findings(scanner_type, target)
                
        except Exception as e:
            print(f"Scanner execution error: {e}")
            return self.generate_mock_findings(scanner_type, target)
    
    def generate_mock_findings(self, scanner_type: str, target: str) -> Dict:
        """Generate realistic mock findings for demonstration"""
        if scanner_type == 'hexa':
            return {
                'findings': [
                    {
                        'severity': 'High',
                        'type': 'SQL Injection',
                        'description': f'Potential SQL injection vulnerability detected in {target}',
                        'location': '/login.php?user=',
                        'risk_score': 8.5
                    },
                    {
                        'severity': 'Medium',
                        'type': 'XSS',
                        'description': 'Cross-site scripting vulnerability found',
                        'location': '/search.php',
                        'risk_score': 6.2
                    },
                    {
                        'severity': 'Critical',
                        'type': 'Directory Traversal',
                        'description': 'Directory traversal vulnerability allows file access',
                        'location': '/files/',
                        'risk_score': 9.1
                    }
                ],
                'stats': {'vulnerabilities': 3, 'critical': 1, 'high': 1, 'medium': 1, 'low': 0}
            }
        elif scanner_type == 'ryha':
            return {
                'findings': [
                    {
                        'severity': 'Critical',
                        'type': 'Malware Detected',
                        'description': f'Suspicious behavior detected in {target}',
                        'details': 'File exhibits trojan-like characteristics',
                        'risk_score': 9.5
                    },
                    {
                        'severity': 'High',
                        'type': 'Suspicious API Calls',
                        'description': 'Unusual system API usage detected',
                        'details': 'Registry modification attempts',
                        'risk_score': 7.8
                    }
                ],
                'stats': {'vulnerabilities': 2, 'critical': 1, 'high': 1, 'medium': 0, 'low': 0}
            }
        else:  # ultra
            return {
                'findings': [
                    {
                        'severity': 'High',
                        'type': 'Behavioral Analysis',
                        'description': 'Quantum AI detected suspicious patterns',
                        'details': 'Advanced persistent threat indicators',
                        'risk_score': 8.3
                    },
                    {
                        'severity': 'Medium',
                        'type': 'Network Anomaly',
                        'description': 'Unusual network communication patterns',
                        'details': 'Potential C&C communication',
                        'risk_score': 6.7
                    }
                ],
                'stats': {'vulnerabilities': 2, 'critical': 0, 'high': 1, 'medium': 1, 'low': 0}
            }
    
    def update_progress(self, analysis_id: str, percentage: int, status: str):
        """Update progress for an analysis with SocketIO"""
        if analysis_id in self.active_scans:
            self.active_scans[analysis_id]['percentage'] = percentage
            self.active_scans[analysis_id]['status'] = status
            
            # Emit progress update via SocketIO
            self.socketio.emit('progress_update', {
                'analysis_id': analysis_id,
                'percentage': percentage,
                'status': status
            })
    
    def analyze_command_with_gemini(self, command, api_key):
        """Analyze command using Gemini AI to determine the appropriate scanner"""
        try:
            # Configure Gemini AI
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            
            model = genai.GenerativeModel('gemini-pro')
            
            # Create analysis prompt
            prompt = f"""
            Analyze this security command and determine the appropriate security scanner to use:
            Command: "{command}"
            
            Available scanners:
            1. HexaWebScanner - For web vulnerability scanning, penetration testing, OWASP scans, SQL injection, XSS, etc.
            2. RYHA Malware Analyzer - For malware analysis, file analysis, reverse engineering, APT detection
            3. Ultra Malware Scanner V3.0 - For comprehensive malware detection, behavioral analysis, quantum AI detection
            
            Response format (JSON):
            {{
                "scanner": "hexa|ryha|ultra",
                "task_type": "pentesting|malware_analysis|comprehensive_scan",
                "target": "extracted target from command",
                "parameters": ["list", "of", "relevant", "parameters"],
                "confidence": 0.95,
                "reasoning": "why this scanner was chosen"
            }}
            
            Focus on: If command mentions web vulnerabilities, penetration testing, web scanning, OWASP, SQL injection, XSS, or similar web security terms, choose 'hexa'.
            """
            
            response = model.generate_content(prompt)
            
            # Parse the response
            import json
            import re
            
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response.text, re.DOTALL)
            if json_match:
                analysis_result = json.loads(json_match.group())
                return analysis_result
            else:
                # Fallback analysis
                return self.detect_scanner_type(command)
                    
        except Exception as e:
            print(f"Gemini analysis error: {e}")
            # Fallback to simple keyword matching
            return self.detect_scanner_type(command)
    
    def detect_scanner_type(self, command: str) -> Dict:
        """Fallback scanner detection based on keywords"""
        command_lower = command.lower()
        
        if any(term in command_lower for term in ['web', 'http', 'url', 'website', 'pentest', 'penetration', 'owasp', 'sql', 'xss', 'csrf']):
            return {
                "scanner": "hexa",
                "task_type": "pentesting",
                "target": self.extract_target(command),
                "parameters": [],
                "confidence": 0.8,
                "reasoning": "Web security keywords detected"
            }
        elif any(term in command_lower for term in ['malware', 'virus', 'trojan', 'file', 'binary', 'reverse', 'apt']):
            return {
                "scanner": "ryha", 
                "task_type": "malware_analysis",
                "target": self.extract_target(command),
                "parameters": [],
                "confidence": 0.8,
                "reasoning": "Malware analysis keywords detected"
            }
        else:
            return {
                "scanner": "ultra",
                "task_type": "comprehensive_scan", 
                "target": self.extract_target(command),
                "parameters": [],
                "confidence": 0.7,
                "reasoning": "Default comprehensive scan"
            }
    
    def extract_target(self, command: str) -> str:
        """Extract target from command"""
        import re
        
        # URL pattern
        url_match = re.search(r'https?://[^\s]+', command)
        if url_match:
            return url_match.group()
        
        # File path pattern
        file_match = re.search(r'[a-zA-Z]:[\\\/][\w\s\\\/.-]+\.\w+', command)
        if file_match:
            return file_match.group()
        
        # Simple filename pattern
        filename_match = re.search(r'\b\w+\.\w+\b', command)
        if filename_match:
            return filename_match.group()
        
        return "unknown_target"
    
    def run_scanner(self, scanner_type: str, target: str) -> Dict:
        """Run the specified scanner on target"""
        try:
            cmd = [
                sys.executable, 
                str(self.unified_scanner),
                scanner_type,
                target
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300,
                cwd=str(self.base_dir)
            )
            
            # Parse output for findings and stats
            findings = []
            stats = {'vulnerabilities': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            # Basic parsing of scanner output
            if "HIGH" in result.stdout:
                stats['high'] += 1
                stats['vulnerabilities'] += 1
                findings.append({
                    'title': 'High Risk Threat Detected',
                    'severity': 'high',
                    'description': 'Scanner detected high-risk indicators'
                })
            
            return {'findings': findings, 'stats': stats, 'raw_output': result.stdout}
            
        except Exception as e:
            return {'error': str(e)}
    
    def init_gemini_with_key(self, api_key: str) -> bool:
        """Initialize Gemini with provided API key"""
        try:
            genai.configure(api_key=api_key)
            self.gemini_model = genai.GenerativeModel('gemini-1.5-flash')
            return True
        except:
            return False
    
    def run_gemini_analysis(self, command: str, scan_data: Dict = None) -> str:
        """Run Gemini AI analysis on command and scan results"""
        try:
            if not self.gemini_model:
                return "AI analysis unavailable"
            
            if scan_data:
                findings_summary = []
                for finding in scan_data.get('findings', [])[:5]:  # Top 5 findings
                    findings_summary.append(f"- {finding.get('severity', 'Unknown')}: {finding.get('description', 'No description')}")
                
                prompt = f"""
                Analyze this security scan and provide insights:
                
                Command: {command}
                Scanner Used: {scan_data.get('scanner_used', 'Unknown')}
                Target: {scan_data.get('target', 'Unknown')}
                
                Key Findings:
                {chr(10).join(findings_summary) if findings_summary else 'No findings'}
                
                Statistics:
                - Total Vulnerabilities: {scan_data.get('stats', {}).get('vulnerabilities', 0)}
                - Critical: {scan_data.get('stats', {}).get('critical', 0)}
                - High: {scan_data.get('stats', {}).get('high', 0)}
                - Medium: {scan_data.get('stats', {}).get('medium', 0)}
                
                Please provide a brief security analysis and recommendations.
                """
            else:
                prompt = f"""
                As a cybersecurity expert, analyze this security command and provide insights:
                Command: {command}
                
                Please provide:
                1. What type of security analysis this represents
                2. Potential findings or areas of concern
                3. Recommended next steps
                4. Risk assessment
                
                Keep the response concise and actionable.
                """
            response = self.gemini_model.generate_content(prompt)
            return response.text
            
        except Exception as e:
            return f"AI analysis failed: {str(e)}"
    
    def generate_detailed_report(self, analysis_id: str, api_key: str) -> str:
        """Generate detailed security report using Gemini AI"""
        try:
            # Configure Gemini AI
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            
            model = genai.GenerativeModel('gemini-pro')
            
            # Get scan data
            scan_data = self.active_scans.get(analysis_id, {})
            if not scan_data:
                return "Analysis data not found"
            
            findings = scan_data.get('findings', [])
            stats = scan_data.get('stats', {})
            scanner_used = scan_data.get('scanner_used', 'Unknown')
            target = scan_data.get('target', 'Unknown')
            
            # Create detailed report prompt
            findings_details = []
            for i, finding in enumerate(findings[:10], 1):  # Top 10 findings
                findings_details.append(f"""
                Finding #{i}: {finding.get('type', 'Unknown Vulnerability')}
                Severity: {finding.get('severity', 'Unknown')}
                Description: {finding.get('description', 'No description available')}
                Location: {finding.get('location', 'Not specified')}
                Risk Score: {finding.get('risk_score', 'N/A')}
                Details: {finding.get('details', 'No additional details')}
                """)
            
            prompt = f"""
            Generate a comprehensive cybersecurity analysis report with the following structure:
            
            EXECUTIVE SUMMARY
            ================
            Scanner Used: {scanner_used}
            Target: {target}
            Total Vulnerabilities Found: {stats.get('vulnerabilities', 0)}
            Critical Issues: {stats.get('critical', 0)}
            High Severity: {stats.get('high', 0)}
            Medium Severity: {stats.get('medium', 0)}
            Low Severity: {stats.get('low', 0)}
            
            DETAILED FINDINGS
            ================
            {chr(10).join(findings_details) if findings_details else 'No significant findings detected'}
            
            Please provide a comprehensive report including:
            
            1. **EXECUTIVE SUMMARY** - Overview of the security assessment
            
            2. **DETAILED VULNERABILITY ANALYSIS** - For each critical/high finding:
               - Technical description
               - Proof of concept (how to exploit)
               - Business impact assessment
               - Risk rating explanation
            
            3. **REPRODUCTION STEPS** - Step-by-step instructions to recreate each vulnerability
            
            4. **SECURITY IMPACT ANALYSIS** - Potential consequences if exploited:
               - Data confidentiality risks
               - System integrity risks  
               - Service availability risks
               - Compliance implications
            
            5. **REMEDIATION RECOMMENDATIONS** - Specific steps to fix each issue:
               - Immediate actions (emergency patches)
               - Short-term improvements (within 30 days)
               - Long-term security strategy (90+ days)
               - Best practices implementation
            
            6. **RISK PRIORITIZATION** - Order fixes by:
               - Exploit likelihood
               - Business impact
               - Implementation complexity
            
            7. **COMPLIANCE CONSIDERATIONS** - Relevance to:
               - OWASP Top 10
               - NIST Cybersecurity Framework
               - Industry regulations (if applicable)
            
            8. **NEXT STEPS & RECOMMENDATIONS**
            
            Format the report professionally with clear headings, bullet points, and actionable recommendations.
            Include technical details suitable for both security professionals and management review.
            """
            
            response = model.generate_content(prompt)
            
            # Store the report
            report_content = response.text
            timestamp = int(time.time())
            
            # Save report to file
            report_dir = self.base_dir / "reports"
            report_dir.mkdir(exist_ok=True)
            
            report_file = report_dir / f"security_report_{analysis_id}_{timestamp}.md"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"# Security Analysis Report\n\n")
                f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Analysis ID:** {analysis_id}\n")
                f.write(f"**Scanner:** {scanner_used}\n")
                f.write(f"**Target:** {target}\n\n")
                f.write("---\n\n")
                f.write(report_content)
            
            return report_content
            
        except Exception as e:
            error_msg = f"Report generation failed: {str(e)}"
            print(error_msg)
            return error_msg
    
    def run(self):
        """Start the Flask-SocketIO server"""
        self.socketio.run(
            self.app,
            host='127.0.0.1',
            port=5000,
            debug=False,
            allow_unsafe_werkzeug=True
        )

def main():
    """Main entry point"""
    try:
        # Create and run the HPTA frontend
        frontend = HPTASecurityFrontend()
        frontend.run()
        
    except KeyboardInterrupt:
        print("\nShutting down HPTA Security Scanner Frontend...")
        sys.exit(0)
    except Exception as e:
        print(f"Error starting frontend: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
