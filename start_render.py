#!/usr/bin/env python3
"""
HPTA Security Suite - Render Production Deployment
Optimized for Render.com hosting platform
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def setup_render_environment():
    """Setup environment variables for Render deployment"""
    
    # Render automatically sets PORT
    port = int(os.environ.get('PORT', 10000))
    host = '0.0.0.0'  # Render requires 0.0.0.0
    
    # Set default environment variables if not provided
    if not os.environ.get('SECRET_KEY'):
        os.environ['SECRET_KEY'] = 'render_hpta_security_suite_2024_production'
    
    if not os.environ.get('PYTHON_ENV'):
        os.environ['PYTHON_ENV'] = 'production'
    
    # Create required directories
    directories = ['uploads', 'reports', 'temp_reports', 'templates', 'sessions']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created directory: {directory}")
    
    return host, port

def main():
    """Main entry point for Render deployment"""
    print("🚀 HPTA Security Suite - Starting on Render...")
    print("🔧 Platform: Render.com")
    print("🐍 Python Environment: Production")
    
    try:
        # Setup environment
        host, port = setup_render_environment()
        
        print(f"🌐 Host: {host}")
        print(f"🔌 Port: {port}")
        print("📦 Loading HPTA Security Suite...")
        
        # Import and start the application
        from hpta_security_suite import HPTASecuritySuite
        
        # Create application instance
        app_instance = HPTASecuritySuite()
        print("✅ HPTA Security Suite initialized successfully!")
        
        # Additional Render-specific configurations
        app_instance.app.config.update({
            'DEBUG': False,
            'TESTING': False,
            'ENV': 'production',
            'SERVER_NAME': None,  # Let Render handle this
            'APPLICATION_ROOT': '/',
            'PREFERRED_URL_SCHEME': 'https',
            'MAX_CONTENT_LENGTH': 100 * 1024 * 1024,  # 100MB
        })
        
        print("🛡️ Security modules loaded:")
        print("   • HexaWebScanner - Web Vulnerability Scanner")
        print("   • RYHA Malware Analyzer - Advanced Threat Detection") 
        print("   • Ultra Malware Scanner - Multi-Engine Analysis")
        print("   • Reverse Engineering Toolkit - Binary Analysis")
        
        print(f"🎯 Starting server on {host}:{port}...")
        print("🌟 HPTA Security Suite is now LIVE on Render!")
        
        # Start the application with SocketIO - Production Ready
        app_instance.socketio.run(
            app_instance.app,
            host=host,
            port=port,
            debug=False,
            use_reloader=False,
            log_output=True,
            allow_unsafe_werkzeug=True  # Allow Werkzeug in production for Render
        )
        
    except Exception as e:
        print(f"❌ Startup error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
