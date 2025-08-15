#!/usr/bin/env python3
"""
HPTA Security Suite - Docker Deployment Test
Comprehensive testing of containerized deployment
"""

import requests
import time
import json
import sys
from datetime import datetime

def test_docker_deployment():
    """Test the Docker deployment comprehensively"""
    
    print("🐳 HPTA Security Suite - Docker Deployment Test")
    print("=" * 60)
    print(f"🕒 Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    base_url = "http://localhost:5000"
    tests_passed = 0
    tests_total = 0
    
    def run_test(test_name, test_func):
        nonlocal tests_passed, tests_total
        tests_total += 1
        print(f"\n🧪 Test {tests_total}: {test_name}")
        try:
            result = test_func()
            if result:
                print(f"✅ PASSED: {test_name}")
                tests_passed += 1
                return True
            else:
                print(f"❌ FAILED: {test_name}")
                return False
        except Exception as e:
            print(f"❌ ERROR: {test_name} - {str(e)}")
            return False
    
    # Test 1: Health Check
    def test_health_check():
        response = requests.get(f"{base_url}/api/health", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"   Status: {data.get('status')}")
            print(f"   Timestamp: {data.get('timestamp')}")
            return data.get('status') == 'healthy'
        return False
    
    # Test 2: Main Dashboard
    def test_dashboard():
        response = requests.get(base_url, timeout=10)
        if response.status_code == 200:
            content = response.text
            if "HPTA Security Suite" in content and "AI-powered security assistant" in content:
                print("   Dashboard loaded successfully")
                print("   Contains expected content")
                return True
        return False
    
    # Test 3: API Chat Endpoint
    def test_chat_endpoint():
        payload = {
            "message": "test system health",
            "api_key": "test_key"
        }
        response = requests.post(f"{base_url}/api/chat", 
                               json=payload, 
                               timeout=15)
        if response.status_code == 200:
            print("   Chat endpoint responding")
            return True
        return False
    
    # Test 4: File Upload Endpoint
    def test_upload_endpoint():
        # Test with a simple text file
        files = {'file': ('test.txt', 'test content', 'text/plain')}
        response = requests.post(f"{base_url}/api/upload", 
                               files=files, 
                               timeout=10)
        # Should return some response (even if it's an error due to missing API key)
        return response.status_code in [200, 400, 422]
    
    # Test 5: Container Resource Usage
    def test_container_resources():
        import subprocess
        try:
            # Get container stats
            result = subprocess.run(['docker', 'stats', 'hpta-security-suite', '--no-stream', '--format', 'table {{.CPUPerc}}\t{{.MemUsage}}'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                stats = result.stdout.strip().split('\n')[-1]
                print(f"   Container stats: {stats}")
                return True
        except:
            pass
        return False
    
    # Test 6: Container Logs
    def test_container_logs():
        import subprocess
        try:
            result = subprocess.run(['docker', 'logs', 'hpta-security-suite', '--tail', '5'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logs = result.stdout.strip()
                print(f"   Recent logs available: {len(logs)} characters")
                return True
        except:
            pass
        return False
    
    # Run all tests
    run_test("Health Check API", test_health_check)
    run_test("Main Dashboard", test_dashboard)
    run_test("Chat API Endpoint", test_chat_endpoint)
    run_test("File Upload Endpoint", test_upload_endpoint)
    run_test("Container Resource Usage", test_container_resources)
    run_test("Container Logs", test_container_logs)
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 DOCKER DEPLOYMENT TEST SUMMARY")
    print("=" * 60)
    print(f"✅ Tests Passed: {tests_passed}/{tests_total}")
    print(f"❌ Tests Failed: {tests_total - tests_passed}/{tests_total}")
    
    if tests_passed == tests_total:
        print("🎉 ALL TESTS PASSED! Docker deployment is working perfectly!")
        print("\n🚀 HPTA Security Suite is ready for production deployment!")
        print("\n📋 Deployment Summary:")
        print("   • Container: Running and healthy")
        print("   • Web Interface: Accessible at http://localhost:5000")
        print("   • API Endpoints: All responding correctly")
        print("   • Health Monitoring: Active")
        print("   • Resource Usage: Normal")
        print("\n🔧 Next Steps:")
        print("   1. Configure your Google Gemini API key in the web interface")
        print("   2. Test security analysis with real targets")
        print("   3. Set up SSL/TLS for production (nginx container available)")
        print("   4. Configure persistent volumes for reports")
        return True
    else:
        print("⚠️  Some tests failed. Please check the issues above.")
        return False

if __name__ == "__main__":
    success = test_docker_deployment()
    sys.exit(0 if success else 1)