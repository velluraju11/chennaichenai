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

def main():
    """Main entry point for Railway deployment"""
    try:
        # Get port from environment (Railway sets this automatically)
        port = int(os.environ.get('PORT', 5000))
        host = os.environ.get('HOST', '0.0.0.0')
        
        print(f"🚀 Starting HPTA Security Suite on {host}:{port}")
        print("🔒 Advanced Security Testing Platform")
        print("👥 6-Person Development Team - Chennai Division")
        
        # Import and run the production launcher
        from start_hpta_production import main as prod_main
        
        # Set production environment variables
        os.environ['FLASK_ENV'] = 'production'
        os.environ['FLASK_DEBUG'] = 'False'
        os.environ['HOST'] = host
        os.environ['PORT'] = str(port)
        
        # Run the production application
        prod_main()
        
    except Exception as e:
        print(f"❌ Error starting HPTA Security Suite: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
