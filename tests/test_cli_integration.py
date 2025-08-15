#!/usr/bin/env python3
"""
Test CLI Integration with HPTA Security Suite
Demonstrates AI-powered command analysis and execution
"""

import os
import sys
import time
from perfect_cli_server import PerfectHPTACLIServer

def test_cli_server():
    """Test the CLI server functionality"""
    
    print("🧪 Testing HPTA CLI Server Integration")
    print("=" * 50)
    
    # Get API key
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        print("⚠️  No GEMINI_API_KEY found in environment")
        api_key = input("Enter Gemini API key (or press Enter to skip AI): ").strip()
    
    # Initialize CLI server
    cli_server = HPTACLIServer(api_key or "test_key")
    
    # Test cases
    test_cases = [
        {
            'name': 'Web Pentesting Request',
            'input': 'Scan example.com for security vulnerabilities',
            'expected_tool': 'PENTESTING'
        },
        {
            'name': 'Malware Analysis Request',
            'input': 'Check if this file is malicious',
            'expected_tool': 'MALWARE_ANALYSIS',
            'attached_file': 'suspicious_file.exe'
        },
        {
            'name': 'Reverse Engineering Request',
            'input': 'Analyze the binary structure of this executable',
            'expected_tool': 'REVERSE_ENGINEERING',
            'attached_file': 'binary_file.exe'
        },
        {
            'name': 'Natural Language Web Test',
            'input': 'I want to test the security of my website https://mysite.com',
            'expected_tool': 'PENTESTING'
        },
        {
            'name': 'Unclear Request',
            'input': 'Help me with security',
            'expected_tool': None
        }
    ]
    
    print(f"\n🚀 Running {len(test_cases)} test cases...\n")
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test {i}: {test_case['name']}")
        print(f"Input: '{test_case['input']}'")
        
        # Process request
        result = cli_server.process_user_request(
            test_case['input'], 
            test_case.get('attached_file')
        )
        
        # Display results
        print(f"Result Type: {result['type']}")
        
        if result['type'] == 'execution':
            analysis = result['analysis']
            print(f"✅ Tool Selected: {analysis['tool']}")
            print(f"✅ Command: {analysis['command']}")
            print(f"✅ Confidence: {analysis['confidence']}%")
            print(f"✅ Reasoning: {analysis['reasoning']}")
            print(f"✅ Expected: {analysis['expected_outcome']}")
            print(f"✅ Safety: {analysis['safety_assessment']}")
            
            # Check if correct tool was selected
            if analysis['tool'] == test_case['expected_tool']:
                print("🎯 PASS: Correct tool selected")
            else:
                print(f"❌ FAIL: Expected {test_case['expected_tool']}, got {analysis['tool']}")
                
        elif result['type'] == 'clarification':
            print(f"❓ Clarification needed: {result['analysis']['response']}")
            if test_case['expected_tool'] is None:
                print("🎯 PASS: Correctly identified unclear request")
            else:
                print("❌ FAIL: Should have selected a tool")
                
        else:
            print(f"🚫 No action: {result['analysis']['response']}")
        
        print("-" * 50)
    
    print("\n🎉 CLI Server testing completed!")
    
    # Interactive mode
    print("\n💬 Interactive Mode (type 'quit' to exit):")
    while True:
        try:
            user_input = input("\n> ").strip()
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                break
            
            if not user_input:
                continue
            
            print("🤖 Processing with AI...")
            result = cli_server.process_user_request(user_input)
            
            if result['type'] == 'execution':
                analysis = result['analysis']
                print(f"\n🎯 AI Analysis:")
                print(f"   Tool: {analysis['tool']}")
                print(f"   Command: {analysis['command']}")
                print(f"   Confidence: {analysis['confidence']}%")
                print(f"   Reasoning: {analysis['reasoning']}")
                print(f"   Safety: {analysis['safety_assessment']}")
                
                # Ask if user wants to execute
                execute = input("\n🚀 Execute this command? (y/n): ").lower().startswith('y')
                
                if execute:
                    print("⏳ Executing command...")
                    session_id = result['session_id']
                    
                    # Monitor execution
                    while True:
                        status = cli_server.get_session_status(session_id)
                        print(f"Progress: {status['progress']}% - {status['status']}")
                        
                        if status['status'] in ['completed', 'error', 'timeout']:
                            print(f"\n✅ Results:")
                            if 'results' in status:
                                print(f"Summary: {status['results'].get('summary', 'No summary')}")
                                print(f"Risk Level: {status['results'].get('risk_level', 'Unknown')}")
                                for finding in status['results'].get('findings', []):
                                    print(f"- {finding}")
                            break
                        
                        time.sleep(2)
                else:
                    print("❌ Command execution cancelled")
            else:
                print(f"\n💬 Response: {result['analysis']['response']}")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_cli_server()