#!/usr/bin/env python3
"""
HPTA Security Suite - Docker Container Startup Script
Optimized for containerized deployment with health checks
"""

import os
import sys
import signal
import time
from pathlib import Path

def setup_environment():
    """Setup container environment"""
    print("🐳 HPTA Security Suite - Docker Container")
    print("=" * 50)
    print("🚀 Initializing containerized security platform...")
    print("🌐 Frontend + Backend + CLI Server + Security Tools")
    print("=" * 50)
    
    # Create necessary directories
    directories = ['uploads', 'reports', 'temp_reports', 'static', 'config']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Directory ready: {directory}")
    
    # Check security tools
    tools = [
        ('HexaWebScanner', 'HexaWebScanner/run.py'),
        ('Reverse Engineering', 'reverseengineering/windows_reverse_analyzer.py'),
        ('Ryha Malware Analyzer', 'ryha-malware-analyzer/cli.py')
    ]
    
    print("\n🔧 Checking security tools...")
    for tool_name, tool_path in tools:
        if Path(tool_path).exists():
            print(f"✅ {tool_name}: Ready")
        else:
            print(f"⚠️  {tool_name}: Not found at {tool_path}")
    
    # Environment info
    print(f"\n🐳 Container Environment:")
    print(f"   Python: {sys.version.split()[0]}")
    print(f"   Working Directory: {os.getcwd()}")
    print(f"   User: {os.getenv('USER', 'container')}")
    print(f"   Host: {os.getenv('HOSTNAME', 'docker-container')}")

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    print(f"\n🛑 Received signal {signum}, shutting down gracefully...")
    sys.exit(0)

def main():
    """Main container startup function"""
    
    # Setup signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Setup environment
    setup_environment()
    
    try:
        print("\n📦 Importing HPTA Security Suite...")
        from hpta_security_suite import HPTASecuritySuite
        print("✅ Import successful!")
        
        print("🔧 Initializing application...")
        suite = HPTASecuritySuite()
        print("✅ Application initialized!")
        
        print("🌐 Starting web server...")
        print("📡 Server will be available at:")
        print("   - Internal: http://localhost:5000")
        print("   - External: http://0.0.0.0:5000")
        print("   - Health Check: http://localhost:5000/api/health")
        print("\n🤖 AI-powered security analysis ready!")
        print("🔑 Remember to provide your Google Gemini API key in the web interface")
        print("=" * 50)
        
        # Start the Flask application
        suite.run(
            host='0.0.0.0',  # Bind to all interfaces for Docker
            port=5000,
            debug=False      # Production mode
        )
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure all dependencies are installed")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Startup error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()