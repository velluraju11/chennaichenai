#!/usr/bin/env python3
"""
Test script to demonstrate HPTA Security Suite V1 staged progress system
"""

import requests
import json
import time
from datetime import datetime

def test_staged_progress_system():
    """Test the staged progress system with a sample security analysis"""
    
    base_url = "http://localhost:5000"
    
    print("🧪 Testing HPTA Security Suite V1 - Staged Progress System")
    print("=" * 60)
    
    # Test data
    test_commands = [
        {
            "command": "scan website https://example.com for vulnerabilities",
            "description": "Web Security Scan Test"
        },
        {
            "command": "analyze malware in uploaded file", 
            "description": "Malware Analysis Test"
        },
        {
            "command": "perform comprehensive security audit on network",
            "description": "Comprehensive Security Test"
        }
    ]
    
    # Note: You'll need a valid Gemini API key for testing
    api_key = input("Enter your Gemini API key (or press Enter to skip): ").strip()
    
    if not api_key:
        print("⚠️ No API key provided. This demo will show the system structure.")
        print("📋 Available test commands:")
        for i, cmd in enumerate(test_commands, 1):
            print(f"   {i}. {cmd['description']}: '{cmd['command']}'")
        return
    
    # Validate API key first
    print("\n🔑 Validating API key...")
    validate_response = requests.post(f"{base_url}/api/validate-key", 
                                    json={"api_key": api_key})
    
    if validate_response.status_code != 200:
        print("❌ API key validation failed")
        return
    
    print("✅ API key validated successfully")
    
    # Test each command
    for i, test_cmd in enumerate(test_commands, 1):
        print(f"\n🚀 Test {i}/3: {test_cmd['description']}")
        print("-" * 40)
        print(f"Command: {test_cmd['command']}")
        
        # Start analysis
        analysis_data = {
            "command": test_cmd['command'],
            "api_key": api_key
        }
        
        print("📤 Starting analysis...")
        start_time = datetime.now()
        
        try:
            response = requests.post(f"{base_url}/analyze", 
                                   json=analysis_data, 
                                   timeout=10)
            
            if response.status_code != 200:
                print(f"❌ Failed to start analysis: {response.text}")
                continue
                
            result = response.json()
            analysis_id = result.get('analysis_id')
            print(f"✅ Analysis started with ID: {analysis_id}")
            
            # Monitor progress with staged updates
            print("\n📊 Monitoring staged progress:")
            last_stage = ""
            
            for attempt in range(60):  # Monitor for up to 60 seconds
                try:
                    progress_response = requests.get(f"{base_url}/progress/{analysis_id}", 
                                                   timeout=5)
                    
                    if progress_response.status_code == 200:
                        progress_data = progress_response.json()
                        stage = progress_data.get('stage', 'Unknown')
                        progress = progress_data.get('percentage', 0)
                        status = progress_data.get('status', 'unknown')
                        
                        # Only print when stage changes
                        if stage != last_stage:
                            timestamp = datetime.now().strftime("%H:%M:%S")
                            print(f"[{timestamp}] 🔄 {stage} - {progress}% ({status})")
                            last_stage = stage
                        
                        # Check if completed
                        if status in ['completed', 'error']:
                            break
                            
                    time.sleep(2)  # Check every 2 seconds
                    
                except requests.exceptions.Timeout:
                    print("⏰ Progress check timeout")
                    break
                except Exception as e:
                    print(f"❌ Progress check error: {str(e)}")
                    break
            
            # Final status
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"⏱️ Analysis completed in {elapsed:.1f} seconds")
            
            # Get final results if available
            try:
                final_response = requests.get(f"{base_url}/progress/{analysis_id}")
                if final_response.status_code == 200:
                    final_data = final_response.json()
                    findings = final_data.get('findings', [])
                    print(f"🔍 Found {len(findings)} security findings")
                    
                    if findings:
                        print("📋 Sample findings:")
                        for j, finding in enumerate(findings[:3], 1):  # Show first 3
                            severity = finding.get('severity', 'Unknown').upper()
                            title = finding.get('title', 'Unknown Issue')
                            print(f"   {j}. [{severity}] {title}")
            except Exception as e:
                print(f"⚠️ Could not retrieve final results: {str(e)}")
                
        except requests.exceptions.Timeout:
            print("❌ Analysis request timeout")
        except Exception as e:
            print(f"❌ Analysis failed: {str(e)}")
        
        if i < len(test_commands):
            print("\n⏳ Waiting 5 seconds before next test...")
            time.sleep(5)
    
    print("\n✅ Staged progress system testing completed!")
    print("🌐 View real-time progress at: http://localhost:5000")

if __name__ == "__main__":
    test_staged_progress_system()
