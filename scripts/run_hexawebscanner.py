#!/usr/bin/env python3
"""
🔥 HEXAWEBSCANNER LAUNCHER v3.0 🔥
Ultra-Fast OWASP Top 150 Vulnerability Scanner
Professional Bug Bounty Hunting Tool

Usage:
  python run_hexawebscanner.py <target_url>
  python run_hexawebscanner.py http://testhtml5.vulnweb.com
  python run_hexawebscanner.py https://example.com
"""

import sys
import os
import subprocess
from pathlib import Path

def main():
    print("🔥 HEXAWEBSCANNER LAUNCHER v3.0")
    print("⚡ Ultra-Fast OWASP Top 150 Vulnerability Scanner")
    print("🏆 Professional Bug Bounty Hunting Tool")
    print("=" * 60)
    
    # Check if target URL is provided
    if len(sys.argv) < 2:
        print("❌ ERROR: Please provide a target URL")
        print("\n📋 Usage Examples:")
        print("  python run_hexawebscanner.py http://testhtml5.vulnweb.com")
        print("  python run_hexawebscanner.py https://example.com")
        print("  python run_hexawebscanner.py https://your-target.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    # Validate URL format
    if not (target_url.startswith('http://') or target_url.startswith('https://')):
        print("❌ ERROR: URL must start with http:// or https://")
        print(f"   You provided: {target_url}")
        print("   Example: http://testhtml5.vulnweb.com")
        sys.exit(1)
    
    # Get the path to HexaWebScanner
    script_dir = Path(__file__).parent
    hexascanner_dir = script_dir.parent / "HexaWebScanner"
    hexascanner_script = hexascanner_dir / "hexawebscanner.py"
    
    # Check if HexaWebScanner exists
    if not hexascanner_script.exists():
        print(f"❌ ERROR: HexaWebScanner not found at {hexascanner_script}")
        print("   Make sure HexaWebScanner folder exists in the parent directory")
        sys.exit(1)
    
    print(f"🎯 Target: {target_url}")
    print(f"🚀 Launching HexaWebScanner...")
    print(f"📁 Scanner Location: {hexascanner_script}")
    print("=" * 60)
    
    try:
        # Change to HexaWebScanner directory and run the scanner
        os.chdir(hexascanner_dir)
        result = subprocess.run([
            sys.executable, 
            "hexawebscanner.py", 
            target_url
        ], check=True)
        
        print("\n🎉 HexaWebScanner completed successfully!")
        
    except subprocess.CalledProcessError as e:
        print(f"\n❌ HexaWebScanner failed with exit code: {e.returncode}")
        sys.exit(e.returncode)
        
    except FileNotFoundError:
        print("❌ ERROR: Python executable not found")
        print("   Make sure Python is installed and in your PATH")
        sys.exit(1)
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
