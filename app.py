#!/usr/bin/env python3
"""
HPTA Security Suite - Gunicorn Production Server for Render
High-performance WSGI server deployment
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def create_app():
    """Create and configure the Flask application for Gunicorn"""
    
    print("🚀 HPTA Security Suite - Gunicorn Production Mode")
    
    # Setup environment
    port = int(os.environ.get('PORT', 10000))
    
    # Set default environment variables
    if not os.environ.get('SECRET_KEY'):
        os.environ['SECRET_KEY'] = 'render_hpta_security_suite_2024_production'
    
    if not os.environ.get('PYTHON_ENV'):
        os.environ['PYTHON_ENV'] = 'production'
    
    # Create required directories
    directories = ['uploads', 'reports', 'temp_reports', 'templates', 'sessions']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created directory: {directory}")
    
    # Import and create application
    from hpta_security_suite import HPTASecuritySuite
    
    # Create application instance
    app_instance = HPTASecuritySuite()
    
    # Configure for production
    app_instance.app.config.update({
        'DEBUG': False,
        'TESTING': False,
        'ENV': 'production',
        'SERVER_NAME': None,
        'APPLICATION_ROOT': '/',
        'PREFERRED_URL_SCHEME': 'https',
        'MAX_CONTENT_LENGTH': 100 * 1024 * 1024,  # 100MB
    })
    
    print("🛡️ HPTA Security Suite initialized successfully!")
    print("📦 All security modules loaded")
    print(f"🌐 Port: {port}")
    
    return app_instance.app

# Create the app instance for Gunicorn
app = create_app()

if __name__ == '__main__':
    # Fallback to direct run if not using Gunicorn
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
