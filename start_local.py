#!/usr/bin/env python3
"""
Simple startup script for testing HPTA Security Suite locally
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def main():
    """Simple startup for local testing"""
    print("🧪 HPTA Security Suite - Local Test Mode")
    
    # Set environment
    port = int(os.environ.get('PORT', 5000))
    host = '127.0.0.1'  # Local only
    
    # Set defaults
    if not os.environ.get('SECRET_KEY'):
        os.environ['SECRET_KEY'] = 'local_test_key_2024'
    
    # Create directories
    directories = ['uploads', 'reports', 'temp_reports', 'templates', 'sessions']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    print(f"🌐 Starting on http://{host}:{port}")
    print("⚠️  This is for LOCAL TESTING ONLY - not production!")
    
    # Import and start
    from hpta_security_suite import HPTASecuritySuite
    
    app_instance = HPTASecuritySuite()
    app_instance.app.config['DEBUG'] = True
    
    # Allow unsafe Werkzeug for local testing
    app_instance.socketio.run(
        app_instance.app,
        host=host,
        port=port,
        debug=True,
        use_reloader=True,
        allow_unsafe_werkzeug=True
    )

if __name__ == '__main__':
    main()
