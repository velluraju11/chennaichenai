#!/usr/bin/env python3
"""
HPTA Security Suite Installation Script
Installs all required dependencies and sets up the environment
"""

import subprocess
import sys
import os
from pathlib import Path

def install_requirements():
    """Install required Python packages"""
    print("🔧 Installing HPTA Security Suite dependencies...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements_hpta.txt"
        ])
        print("✅ Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    print("📁 Creating necessary directories...")
    
    directories = [
        "templates",
        "uploads", 
        "reports",
        "temp_reports",
        "static"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created directory: {directory}")

def check_existing_tools():
    """Check if the three security tools exist"""
    print("🔍 Checking existing security tools...")
    
    tools = [
        ("HexaWebScanner", "HexaWebScanner/run.py"),
        ("Reverse Engineering", "reverseengineering/windows_reverse_analyzer.py"),
        ("Ryha Malware Analyzer", "ryha-malware-analyzer/cli.py")
    ]
    
    all_tools_exist = True
    
    for tool_name, tool_path in tools:
        if Path(tool_path).exists():
            print(f"✅ {tool_name}: Found")
        else:
            print(f"❌ {tool_name}: Not found at {tool_path}")
            all_tools_exist = False
    
    return all_tools_exist

def create_startup_script():
    """Create startup script for easy launching"""
    print("🚀 Creating startup script...")
    
    startup_content = '''#!/usr/bin/env python3
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
'''
    
    with open("start_hpta.py", "w", encoding='utf-8') as f:
        f.write(startup_content)
    
    print("✅ Created start_hpta.py launcher")

def main():
    """Main installation function"""
    print("🛡️  HPTA Security Suite Installation")
    print("=" * 50)
    
    # Create directories
    create_directories()
    
    # Check existing tools
    if not check_existing_tools():
        print("\n⚠️  Warning: Some security tools are missing!")
        print("💡 Make sure you have the following folders in the same directory:")
        print("   - HexaWebScanner/")
        print("   - reverseengineering/") 
        print("   - ryha-malware-analyzer/")
        print("\n🔄 Continuing with installation...")
    
    # Install requirements
    if not install_requirements():
        print("❌ Installation failed!")
        sys.exit(1)
    
    # Create startup script
    create_startup_script()
    
    print("\n" + "=" * 50)
    print("✅ HPTA Security Suite installed successfully!")
    print("=" * 50)
    print("\n🚀 To start the suite:")
    print("   python start_hpta.py")
    print("\n🌐 Then open: http://localhost:5000")
    print("\n🔑 You'll need a Google Gemini API key:")
    print("   Get one at: https://makersuite.google.com/app/apikey")
    print("\n🎯 Features:")
    print("   • AI-powered natural language commands")
    print("   • Real-time security analysis")
    print("   • Professional HTML reports")
    print("   • Web pentesting, malware analysis, reverse engineering")
    print("\n🎉 Happy hacking!")

if __name__ == "__main__":
    main()