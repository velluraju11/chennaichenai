#!/usr/bin/env python3
"""
🚀 HPTA Security Scanner Setup & Installation Script
Installs all required dependencies for the unified security scanning platform
"""

import sys
import subprocess
import os
from pathlib import Path

def install_package(package):
    """Install a Python package using pip"""
    try:
        print(f"📦 Installing {package}...")
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", package
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✅ {package} installed successfully")
            return True
        else:
            print(f"❌ Failed to install {package}: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error installing {package}: {e}")
        return False

def main():
    """Main setup function"""
    print("🛡️ HPTA Security Scanner - Setup & Installation")
    print("=" * 60)
    
    # Required packages for the security scanner
    packages = [
        "flask",
        "flask-socketio",
        "google-generativeai",
        "python-dotenv",
        "requests",
        "rich",
        "asyncio"
    ]
    
    print("🚀 Installing required packages...")
    print(f"📋 Packages to install: {len(packages)}")
    print()
    
    success_count = 0
    for package in packages:
        if install_package(package):
            success_count += 1
        print()
    
    print("=" * 60)
    print(f"📊 Installation Summary:")
    print(f"✅ Successfully installed: {success_count}/{len(packages)} packages")
    
    if success_count == len(packages):
        print("🎉 All packages installed successfully!")
        
        # Setup environment file
        env_example = Path(__file__).parent / ".env.example"
        env_file = Path(__file__).parent / ".env"
        
        if not env_file.exists() and env_example.exists():
            print("\n🔧 Setting up environment file...")
            with open(env_example) as f:
                env_content = f.read()
            
            with open(env_file, 'w') as f:
                f.write(env_content)
            
            print(f"✅ Created .env file at: {env_file}")
            print("⚠️  Please edit .env file and add your Google Gemini API key!")
        
        print("\n🚀 Setup completed! You can now run:")
        print("   python unified_scanner.py help")
        print("   python security_frontend.py")
        
    else:
        print("❌ Some packages failed to install. Please check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
