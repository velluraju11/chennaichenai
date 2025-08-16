#!/usr/bin/env python3
"""
HPTA Security Suite - Production Launcher
Production-ready launcher with environment configuration
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Import the main application
from hpta_security_suite import HPTASecuritySuite

def create_app():
    """Create and configure the Flask application"""
    app = HPTASecuritySuite()
    return app.app, app.socketio

def main():
    """Main entry point for both development and production"""
    
    # Get configuration from environment
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    print("🛡️  HPTA Security Suite")
    print("=" * 50)
    print("🚀 Starting AI-powered security analysis platform...")
    print(f"🌐 Dashboard will open at: http://{host}:{port}")
    print("🤖 Make sure you have your Google Gemini API key ready!")
    print("=" * 50)
    
    # Create application instance
    suite = HPTASecuritySuite()
    
    # Production configuration
    if not debug:
        print("🏭 Running in PRODUCTION mode")
        # Disable file reloader in production
        suite.socketio.run(
            suite.app,
            host=host,
            port=port,
            debug=False,
            use_reloader=False
        )
    else:
        print("🛠️  Running in DEVELOPMENT mode")
        # Development with custom file watching (excluding uploads)
        extra_dirs = ['templates/']
        extra_files = []
        for extra_dir in extra_dirs:
            for dirname, dirs, files in os.walk(extra_dir):
                for filename in files:
                    filepath = os.path.join(dirname, filename)
                    if os.path.isfile(filepath):
                        extra_files.append(filepath)
        
        suite.socketio.run(
            suite.app,
            host=host,
            port=port,
            debug=False,  # Custom debug handling
            extra_files=extra_files,
            use_reloader=False
        )

# For Gunicorn (production WSGI server)
app, socketio = create_app()

if __name__ == '__main__':
    main()
