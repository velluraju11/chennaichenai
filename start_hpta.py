#!/usr/bin/env python3
"""
HPTA Security Suite Launcher
Quick start script for the security suite
"""

import os
import sys
from pathlib import Path

def main():
    print("🛡️  HPTA Security Suite")
    print("=" * 50)
    print("🚀 Starting AI-powered security analysis platform...")
    print("🌐 Dashboard will open at: http://localhost:5000")
    print("🤖 Make sure you have your Google Gemini API key ready!")
    print("=" * 50)
    
    # Import and run the suite
    try:
        from hpta_security_suite import HPTASecuritySuite
        suite = HPTASecuritySuite()
        suite.run(debug=False)
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure you've installed the requirements:")
        print("   pip install -r requirements_hpta.txt")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error starting suite: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()