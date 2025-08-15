#!/usr/bin/env python3
"""
HPTA Security Suite - Production Docker Startup with Gunicorn
High-performance WSGI server for production deployment
"""

import os
import sys
import multiprocessing
from pathlib import Path

def setup_production_environment():
    """Setup production environment"""
    print("🐳 HPTA Security Suite - Production Mode")
    print("=" * 50)
    print("🚀 High-performance containerized deployment")
    print("🌐 Gunicorn WSGI Server + Flask Application")
    print("=" * 50)
    
    # Create necessary directories
    directories = ['uploads', 'reports', 'temp_reports', 'static', 'config', 'logs']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    
    # Set production environment variables
    os.environ['FLASK_ENV'] = 'production'
    os.environ['PYTHONPATH'] = '/app'

def create_gunicorn_config():
    """Create Gunicorn configuration"""
    
    # Calculate optimal worker count
    workers = multiprocessing.cpu_count() * 2 + 1
    workers = min(workers, 8)  # Cap at 8 workers for container
    
    config = f"""
# Gunicorn Configuration for HPTA Security Suite
import multiprocessing

# Server socket
bind = "0.0.0.0:5000"
backlog = 2048

# Worker processes
workers = {workers}
worker_class = "gevent"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
preload_app = True

# Timeout
timeout = 120
keepalive = 2

# Logging
accesslog = "/app/logs/access.log"
errorlog = "/app/logs/error.log"
loglevel = "info"
access_log_format = '%%(h)s %%(l)s %%(u)s %%(t)s "%%(r)s" %%(s)s %%(b)s "%%(f)s" "%%(a)s" %%(D)s'

# Process naming
proc_name = "hpta-security-suite"

# Server mechanics
daemon = False
pidfile = "/app/logs/gunicorn.pid"
user = 1000
group = 1000
tmp_upload_dir = "/app/uploads"

# SSL (uncomment for HTTPS)
# keyfile = "/app/ssl/key.pem"
# certfile = "/app/ssl/cert.pem"
"""
    
    with open('/app/gunicorn.conf.py', 'w') as f:
        f.write(config)
    
    print(f"✅ Gunicorn configured with {workers} workers")

def main():
    """Main production startup function"""
    
    setup_production_environment()
    create_gunicorn_config()
    
    try:
        print("📦 Testing application import...")
        from hpta_security_suite import HPTASecuritySuite
        print("✅ Application import successful!")
        
        print("🚀 Starting Gunicorn WSGI server...")
        print("📡 Server configuration:")
        print(f"   - Workers: {multiprocessing.cpu_count() * 2 + 1}")
        print(f"   - Worker Class: gevent")
        print(f"   - Bind: 0.0.0.0:5000")
        print(f"   - Timeout: 120s")
        print("=" * 50)
        
        # Start Gunicorn
        os.system("gunicorn --config /app/gunicorn.conf.py hpta_security_suite:app")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Startup error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()