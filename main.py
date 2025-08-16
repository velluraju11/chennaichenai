#!/usr/bin/env python3
"""
HPTA Security Suite - Main Entry Point for Railway Deployment
Advanced Penetration Testing and Security Analysis Platform

Team: HPTA Security Research Division - Chennai
Project Lead: Vellu Raju
Date: August 2025
"""

import os
import sys

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the main application
from hpta_security_suite import HPTASecuritySuite

def main():
    """Main entry point for Railway deployment"""
    try:
        # Initialize the HPTA Security Suite
        hpta_app = HPTASecuritySuite()
        
        # Get port from environment (Railway sets this automatically)
        port = int(os.environ.get('PORT', 5000))
        host = os.environ.get('HOST', '0.0.0.0')
        
        print(f"🚀 Starting HPTA Security Suite on {host}:{port}")
        print("🔒 Advanced Security Testing Platform")
        print("👥 6-Person Development Team - Chennai Division")
        
        # Run the application
        hpta_app.run(host=host, port=port, debug=False)
        
    except Exception as e:
        print(f"❌ Error starting HPTA Security Suite: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
