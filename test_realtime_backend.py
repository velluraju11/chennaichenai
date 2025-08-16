#!/usr/bin/env python3
"""
🧪 HPTA Real-time Terminal Test Script
Tests the real-time backend server functionality
"""

import asyncio
import websockets
import json

async def test_backend():
    """Test the HPTA real-time backend server"""
    uri = "ws://localhost:8765"
    
    try:
        async with websockets.connect(uri) as websocket:
            print("✅ Connected to HPTA real-time backend!")
            
            # Test commands
            test_commands = [
                "help",
                "status", 
                "components",
                "scan https://example.com",
                "hexa https://testphp.vulnweb.com",
                "ultra malicious_test_sample.py"
            ]
            
            for command in test_commands:
                print(f"\n🔍 Testing command: {command}")
                
                # Send command
                await websocket.send(json.dumps({
                    "type": "command",
                    "command": command
                }))
                
                # Wait for responses
                for _ in range(5):  # Get up to 5 responses per command
                    try:
                        response = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                        message = json.loads(response)
                        
                        if message["type"] == "terminal_output":
                            print(f"📟 {message['content']}")
                        elif message["type"] == "vulnerability_found":
                            vuln = message["vulnerability"]
                            print(f"🚨 VULNERABILITY FOUND: {vuln['name']} ({vuln['severity']})")
                            print(f"   Description: {vuln['description']}")
                            print(f"   Target: {vuln['target']}")
                            
                    except asyncio.TimeoutError:
                        break
                
                await asyncio.sleep(1)
                
    except ConnectionRefusedError:
        print("❌ Could not connect to backend server")
        print("   Please make sure the server is running:")
        print("   python scripts/realtime_terminal_server.py")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    print("🧪 HPTA Real-time Backend Test")
    print("=" * 40)
    asyncio.run(test_backend())
    print("\n✅ Test completed!")
