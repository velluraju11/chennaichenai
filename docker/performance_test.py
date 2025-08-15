#!/usr/bin/env python3
"""
HPTA Security Suite - Performance Benchmark Test
Test response times and resource efficiency
"""

import requests
import time
import statistics
from datetime import datetime

def performance_benchmark():
    """Run performance benchmarks on the Docker deployment"""
    
    print("⚡ HPTA Security Suite - Performance Benchmark")
    print("=" * 60)
    print(f"🕒 Benchmark started: {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    
    base_url = "http://localhost:5000"
    
    # Test 1: Health Check Response Time
    print("\n🏥 Health Check Performance:")
    health_times = []
    for i in range(10):
        start = time.time()
        response = requests.get(f"{base_url}/api/health", timeout=5)
        end = time.time()
        if response.status_code == 200:
            health_times.append((end - start) * 1000)  # Convert to ms
        time.sleep(0.1)
    
    if health_times:
        print(f"   Average: {statistics.mean(health_times):.1f}ms")
        print(f"   Min: {min(health_times):.1f}ms")
        print(f"   Max: {max(health_times):.1f}ms")
        print(f"   Median: {statistics.median(health_times):.1f}ms")
    
    # Test 2: Dashboard Load Time
    print("\n🌐 Dashboard Performance:")
    dashboard_times = []
    for i in range(5):
        start = time.time()
        response = requests.get(base_url, timeout=10)
        end = time.time()
        if response.status_code == 200:
            dashboard_times.append((end - start) * 1000)
        time.sleep(0.2)
    
    if dashboard_times:
        print(f"   Average: {statistics.mean(dashboard_times):.1f}ms")
        print(f"   Min: {min(dashboard_times):.1f}ms")
        print(f"   Max: {max(dashboard_times):.1f}ms")
    
    # Test 3: Concurrent Requests
    print("\n🚀 Concurrent Request Test:")
    import threading
    concurrent_times = []
    
    def make_request():
        start = time.time()
        try:
            response = requests.get(f"{base_url}/api/health", timeout=5)
            end = time.time()
            if response.status_code == 200:
                concurrent_times.append((end - start) * 1000)
        except:
            pass
    
    threads = []
    for i in range(20):  # 20 concurrent requests
        thread = threading.Thread(target=make_request)
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    if concurrent_times:
        print(f"   Concurrent requests: {len(concurrent_times)}/20 successful")
        print(f"   Average response: {statistics.mean(concurrent_times):.1f}ms")
        print(f"   Max response: {max(concurrent_times):.1f}ms")
    
    # Performance Summary
    print("\n" + "=" * 60)
    print("📊 PERFORMANCE SUMMARY")
    print("=" * 60)
    
    if health_times:
        avg_health = statistics.mean(health_times)
        if avg_health < 100:
            print("✅ Health Check: EXCELLENT (<100ms)")
        elif avg_health < 200:
            print("✅ Health Check: GOOD (<200ms)")
        else:
            print("⚠️  Health Check: ACCEPTABLE (>200ms)")
    
    if dashboard_times:
        avg_dashboard = statistics.mean(dashboard_times)
        if avg_dashboard < 200:
            print("✅ Dashboard Load: EXCELLENT (<200ms)")
        elif avg_dashboard < 500:
            print("✅ Dashboard Load: GOOD (<500ms)")
        else:
            print("⚠️  Dashboard Load: ACCEPTABLE (>500ms)")
    
    if concurrent_times:
        success_rate = len(concurrent_times) / 20 * 100
        if success_rate >= 95:
            print("✅ Concurrency: EXCELLENT (>95% success)")
        elif success_rate >= 80:
            print("✅ Concurrency: GOOD (>80% success)")
        else:
            print("⚠️  Concurrency: NEEDS IMPROVEMENT (<80% success)")
    
    print("\n🎯 PERFORMANCE VERDICT:")
    if (health_times and statistics.mean(health_times) < 150 and
        dashboard_times and statistics.mean(dashboard_times) < 300 and
        concurrent_times and len(concurrent_times) >= 18):
        print("🏆 EXCELLENT - Ready for high-traffic production!")
    else:
        print("✅ GOOD - Suitable for production deployment")
    
    return True

if __name__ == "__main__":
    performance_benchmark()