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
            
            # Generate a unique analysis ID
            analysis_id = f"analysis_{int(time.time())}"
            
            # Start analysis in background
            threading.Thread(
                target=self.run_analysis_thread,
                args=(analysis_id, command, api_key),
                daemon=True
            ).start()
            
            return jsonify({'analysis_id': analysis_id})
        
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
        """Run security analysis in background thread"""
        try:
            # Initialize progress tracking
            self.active_scans[analysis_id] = {
                'percentage': 0,
                'status': 'Starting analysis...',
                'findings': [],
                'stats': {'vulnerabilities': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            }
            
            # Update progress
            self.update_progress(analysis_id, 10, 'Parsing command...')
            
            # Determine which scanner to use based on command
            scanner_type = self.detect_scanner_type(command)
            target = self.extract_target(command)
            
            self.update_progress(analysis_id, 25, f'Using {self.scanners.get(scanner_type, "Unknown")} scanner...')
            
            # Run the appropriate scanner
            if scanner_type and target:
                result = self.run_scanner(scanner_type, target)
                self.update_progress(analysis_id, 75, 'Processing scan results...')
                
                # Process results
                if result:
                    self.active_scans[analysis_id]['findings'] = result.get('findings', [])
                    self.active_scans[analysis_id]['stats'] = result.get('stats', {})
            
            # Run AI analysis if API key provided
            if api_key and self.init_gemini_with_key(api_key):
                self.update_progress(analysis_id, 90, 'Running AI analysis...')
                ai_result = self.run_gemini_analysis(command)
                if ai_result:
                    self.active_scans[analysis_id]['ai_analysis'] = ai_result
            
            # Complete
            self.update_progress(analysis_id, 100, 'Analysis completed successfully!')
            
        except Exception as e:
            self.active_scans[analysis_id] = {
                'percentage': 0,
                'status': f'Error: {str(e)}',
                'findings': [],
                'stats': {}
            }
    
    def update_progress(self, analysis_id: str, percentage: int, status: str):
        """Update progress for an analysis"""
        if analysis_id in self.active_scans:
            self.active_scans[analysis_id]['percentage'] = percentage
            self.active_scans[analysis_id]['status'] = status
    
    def detect_scanner_type(self, command: str) -> str:
        """Detect which scanner to use based on command"""
        command_lower = command.lower()
        
        if any(term in command_lower for term in ['malware', 'virus', 'trojan', 'analyze', 'binary']):
            if 'ultra' in command_lower:
                return 'ultra'
            elif 'ryha' in command_lower:
                return 'ryha'
            else:
                return 'ultra'  # Default malware scanner
        elif any(term in command_lower for term in ['http', 'web', 'url', 'website', 'scan']):
            return 'hexa'
        else:
            return 'ultra'  # Default
    
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
    
    def run_gemini_analysis(self, command: str) -> str:
        """Run Gemini AI analysis"""
        try:
            if not self.gemini_model:
                return "AI analysis unavailable"
            
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
