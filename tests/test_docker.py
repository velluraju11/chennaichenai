#!/usr/bin/env python3
"""
HPTA Security Suite - Docker Deployment Test
Tests the containerized deployment
"""

import requests
import time
import json
import sys

def test_docker_deployment():
    """Test the Docker deployment"""
    
    print("🧪 Testing HPTA Security Suite Docker Deployment")
    print("=" * 50)
    
    base_url = "http://localhost:5000"
    
    tests = [
        {
            'name': 'Health Check',
            'url': f'{base_url}/api/health',
            'method': 'GET',
            'expected_status': 200
        },
        {
            'name': 'Main Dashboard',
            'url': f'{base_url}/',
            'method': 'GET',
            'expected_status': 200
        },
        {
            'name': 'Chat API (without key)',
            'url': f'{base_url}/api/chat',
            'method': 'POST',
            'data': {'message': 'test', 'gemini_key': ''},
            'expected_status': 200
        }
    ]
    
    print(f"🌐 Testing deployment at: {base_url}")
    print("⏳ Waiting for services to be ready...")
    time.sleep(5)
    
    passed = 0
    total = len(tests)
    
    for i, test in enumerate(tests, 1):
        print(f"\nTest {i}: {test['name']}")
        
        try:
            if test['method'] == 'GET':
                response = requests.get(test['url'], timeout=10)
            else:
                response = requests.post(
                    test['url'], 
                    json=test.get('data', {}),
                    timeout=10
                )
            
            if response.status_code == test['expected_status']:
                print(f"✅ PASS - Status: {response.status_code}")
                passed += 1
                
                # Show response preview for health check
                if 'health' in test['url']:
                    try:
                        health_data = response.json()
                        print(f"   Health Status: {health_data.get('status', 'unknown')}")
                    except:
                        pass
                        
            else:
                print(f"❌ FAIL - Expected: {test['expected_status']}, Got: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print("❌ FAIL - Connection refused (service not running?)")
        except requests.exceptions.Timeout:
            print("❌ FAIL - Request timeout")
        except Exception as e:
            print(f"❌ FAIL - Error: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Docker deployment is working correctly.")
        print("\n🌐 Access your HPTA Security Suite at:")
        print(f"   {base_url}")
        print("\n🔑 Next steps:")
        print("   1. Get your Gemini API key: https://makersuite.google.com/app/apikey")
        print("   2. Enter it in the web interface")
        print("   3. Start analyzing with natural language commands!")
        return True
    else:
        print("⚠️  Some tests failed. Check the Docker deployment.")
        print("\n🔧 Troubleshooting:")
        print("   - Check if containers are running: docker-compose ps")
        print("   - View logs: docker-compose logs -f")
        print("   - Restart services: docker-compose restart")
        return False

def test_api_functionality():
    """Test API functionality with mock data"""
    
    print("\n🧪 Testing API Functionality")
    print("-" * 30)
    
    base_url = "http://localhost:5000"
    
    # Test file upload
    try:
        print("📤 Testing file upload...")
        files = {'file': ('test.txt', b'test content', 'text/plain')}
        response = requests.post(f'{base_url}/api/upload', files=files, timeout=10)
        
        if response.status_code == 200:
            print("✅ File upload working")
        else:
            print(f"⚠️  File upload status: {response.status_code}")
            
    except Exception as e:
        print(f"❌ File upload error: {e}")
    
    # Test chat with mock Gemini key
    try:
        print("💬 Testing chat API...")
        chat_data = {
            'message': 'scan example.com for vulnerabilities',
            'gemini_key': 'test_key'
        }
        response = requests.post(f'{base_url}/api/chat', json=chat_data, timeout=10)
        
        if response.status_code == 200:
            print("✅ Chat API responding")
            try:
                result = response.json()
                if 'error' in result:
                    print(f"   Note: {result['error']} (expected without real API key)")
                else:
                    print("   Chat API working correctly")
            except:
                pass
        else:
            print(f"⚠️  Chat API status: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Chat API error: {e}")

if __name__ == "__main__":
    success = test_docker_deployment()
    
    if success:
        test_api_functionality()
        print("\n🎊 Docker deployment test completed successfully!")
    else:
        print("\n❌ Docker deployment test failed!")
        sys.exit(1)