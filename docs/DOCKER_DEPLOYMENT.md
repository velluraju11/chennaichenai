# 🐳 HPTA Security Suite - Docker Deployment Guide

## 🚀 **Complete Containerized Solution**

The HPTA Security Suite is now fully containerized with Docker, providing a complete frontend + backend + CLI server + security tools solution in a single container.

---

## 📦 **What's Included**

### **Complete Stack**
- 🌐 **Frontend**: Modern web interface with AI chatbot
- 🖥️ **Backend**: Flask API server with real-time updates
- 🤖 **CLI Server**: AI-powered command analysis with Gemini
- 🛡️ **Security Tools**: HexaWebScanner, Malware Analyzer, Reverse Engineering
- 🔄 **Reverse Proxy**: Nginx for production deployment
- 📊 **Monitoring**: Health checks and logging

### **Production Features**
- ⚡ **High Performance**: Gunicorn WSGI server with gevent workers
- 🔒 **Security**: Non-root user, security headers, rate limiting
- 📈 **Scalability**: Multi-worker configuration
- 🔍 **Monitoring**: Health checks and comprehensive logging
- 💾 **Persistence**: Volume mounts for data persistence

---

## 🚀 **Quick Start**

### **1. One-Command Deployment**
```bash
# Make build script executable
chmod +x docker_build.sh

# Build and deploy everything
./docker_build.sh
```

### **2. Manual Deployment**
```bash
# Build the image
docker build -t hpta-security-suite:latest .

# Start with Docker Compose
docker-compose up -d

# Check status
docker-compose ps
```

### **3. Access the Application**
```
🌐 Main Application: http://localhost:5000
🔧 With Nginx Proxy: http://localhost:80
💚 Health Check: http://localhost:5000/api/health
```

---

## 🏗️ **Architecture**

### **Container Structure**
```
HPTA Docker Container
├── 🐍 Python 3.11 Base
├── 🌐 Flask Web Server
├── 🤖 Gemini AI Integration
├── 🛡️ Security Tools
│   ├── HexaWebScanner
│   ├── Reverse Engineering Analyzer
│   └── Ryha Malware Analyzer
├── 📊 Nginx Reverse Proxy
├── 💾 Persistent Volumes
└── 🔍 Health Monitoring
```

### **Network Architecture**
```
Internet → Nginx (Port 80/443) → Flask App (Port 5000) → Security Tools
                ↓
        Rate Limiting & Security Headers
                ↓
        Load Balancing & SSL Termination
```

---

## 📁 **File Structure**

### **Docker Configuration**
```
├── Dockerfile                    # Main container definition
├── docker-compose.yml           # Multi-service orchestration
├── docker_start.py              # Container startup script
├── docker_production_start.py   # Production Gunicorn startup
├── docker_requirements.txt      # Optimized dependencies
├── nginx.conf                   # Reverse proxy configuration
├── .dockerignore                # Docker build exclusions
└── docker_build.sh             # Automated build script
```

### **Data Persistence**
```
docker-data/
├── reports/          # Generated security reports
├── uploads/          # User uploaded files
├── temp_reports/     # Temporary analysis data
├── config/           # Custom configurations
└── ssl/             # SSL certificates (optional)
```

---

## ⚙️ **Configuration Options**

### **Environment Variables**
```bash
# Optional: Set default Gemini API key
GEMINI_API_KEY=your_api_key_here

# Flask configuration
FLASK_ENV=production
PYTHONPATH=/app

# Custom port (default: 5000)
PORT=5000
```

### **Docker Compose Override**
Create `docker-compose.override.yml` for custom settings:
```yaml
version: '3.8'
services:
  hpta-security-suite:
    environment:
      - GEMINI_API_KEY=your_api_key_here
    ports:
      - "8080:5000"  # Custom port
```

---

## 🔧 **Management Commands**

### **Basic Operations**
```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# Restart services
docker-compose restart

# View logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f hpta-security-suite
```

### **Maintenance**
```bash
# Update containers
docker-compose pull
docker-compose up -d

# Rebuild from source
docker-compose build --no-cache
docker-compose up -d

# Clean up
docker-compose down -v
docker system prune -f
```

### **Monitoring**
```bash
# Check container status
docker-compose ps

# Check resource usage
docker stats

# Health check
curl http://localhost:5000/api/health

# Container shell access
docker-compose exec hpta-security-suite bash
```

---

## 🔒 **Security Features**

### **Container Security**
- ✅ **Non-root user**: Runs as user ID 1000
- ✅ **Minimal base image**: Python 3.11 slim
- ✅ **Security headers**: Implemented in Nginx
- ✅ **Rate limiting**: API endpoint protection
- ✅ **Input validation**: File upload restrictions

### **Network Security**
```nginx
# Security headers automatically added
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
```

### **SSL/HTTPS Setup** (Optional)
```bash
# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout docker-data/ssl/key.pem \
  -out docker-data/ssl/cert.pem

# Uncomment HTTPS section in nginx.conf
# Update docker-compose.yml to expose port 443
```

---

## 📊 **Performance Optimization**

### **Production Configuration**
- **Gunicorn WSGI Server**: High-performance Python WSGI HTTP Server
- **Gevent Workers**: Asynchronous worker class for better concurrency
- **Multi-worker Setup**: Automatically scales based on CPU cores
- **Connection Pooling**: Efficient database and API connections
- **Static File Caching**: Nginx handles static content efficiently

### **Resource Limits**
```yaml
# Add to docker-compose.yml
services:
  hpta-security-suite:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
```

---

## 🔍 **Monitoring & Logging**

### **Health Checks**
```bash
# Container health check
docker-compose ps

# Application health check
curl http://localhost:5000/api/health

# Detailed health information
curl -s http://localhost:5000/api/health | jq
```

### **Log Management**
```bash
# Application logs
docker-compose logs -f hpta-security-suite

# Nginx access logs
docker-compose logs -f nginx

# Follow specific log files
docker-compose exec hpta-security-suite tail -f /app/logs/access.log
docker-compose exec hpta-security-suite tail -f /app/logs/error.log
```

### **Log Rotation** (Production)
```bash
# Add to docker-compose.yml
services:
  hpta-security-suite:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

---

## 🚀 **Production Deployment**

### **1. Server Preparation**
```bash
# Install Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### **2. Deploy Application**
```bash
# Clone repository
git clone <repository-url>
cd hpta-security-suite

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Deploy
./docker_build.sh
```

### **3. Domain Setup** (Optional)
```bash
# Update nginx.conf with your domain
server_name your-domain.com;

# Setup SSL with Let's Encrypt
docker run --rm -v $(pwd)/docker-data/ssl:/etc/letsencrypt \
  certbot/certbot certonly --standalone -d your-domain.com
```

---

## 🧪 **Testing the Deployment**

### **Automated Tests**
```bash
# Test container build
docker build -t hpta-test .

# Test application startup
docker run --rm -p 5000:5000 hpta-test

# Test API endpoints
curl http://localhost:5000/api/health
curl -X POST http://localhost:5000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "test", "gemini_key": "test"}'
```

### **Load Testing**
```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Basic load test
ab -n 100 -c 10 http://localhost:5000/

# API load test
ab -n 50 -c 5 -p test_data.json -T application/json http://localhost:5000/api/chat
```

---

## 🔧 **Troubleshooting**

### **Common Issues**

**Container won't start:**
```bash
# Check logs
docker-compose logs hpta-security-suite

# Check resource usage
docker stats

# Rebuild container
docker-compose build --no-cache
```

**Port conflicts:**
```bash
# Check what's using port 5000
sudo netstat -tulpn | grep :5000

# Use different port
docker-compose up -d -p 8080:5000
```

**Permission issues:**
```bash
# Fix volume permissions
sudo chown -R 1000:1000 docker-data/
```

**Memory issues:**
```bash
# Increase Docker memory limit
# Docker Desktop: Settings > Resources > Memory
# Linux: Edit /etc/docker/daemon.json
```

### **Debug Mode**
```bash
# Run in debug mode
docker-compose -f docker-compose.yml -f docker-compose.debug.yml up

# Access container shell
docker-compose exec hpta-security-suite bash

# Check Python environment
docker-compose exec hpta-security-suite python -c "import sys; print(sys.path)"
```

---

## 📈 **Scaling & High Availability**

### **Horizontal Scaling**
```yaml
# docker-compose.yml
services:
  hpta-security-suite:
    deploy:
      replicas: 3
    
  nginx:
    depends_on:
      - hpta-security-suite
```

### **Load Balancer Configuration**
```nginx
upstream hpta_backend {
    server hpta-security-suite_1:5000;
    server hpta-security-suite_2:5000;
    server hpta-security-suite_3:5000;
}
```

---

## 🎉 **Success Indicators**

### **Deployment Successful When:**
✅ Container builds without errors  
✅ All services show "Up" status  
✅ Health check returns 200 OK  
✅ Web interface loads at http://localhost:5000  
✅ API endpoints respond correctly  
✅ File uploads work properly  
✅ Security tools execute successfully  
✅ Reports generate and download  

### **Performance Benchmarks:**
- **Startup Time**: < 30 seconds
- **Response Time**: < 500ms for API calls
- **Memory Usage**: < 2GB under normal load
- **CPU Usage**: < 50% during analysis
- **Concurrent Users**: 50+ simultaneous users

---

## 🎊 **Ready for Production!**

Your HPTA Security Suite is now fully containerized and production-ready with:

🐳 **Complete Docker Integration**  
🌐 **Frontend + Backend in One Container**  
🤖 **AI-Powered CLI Server**  
🛡️ **All Security Tools Included**  
🔒 **Production Security Features**  
📊 **Monitoring & Health Checks**  
⚡ **High Performance Configuration**  

```bash
# Deploy now with one command!
./docker_build.sh

# Access your containerized security suite
open http://localhost:5000
```

**Happy containerized hacking! 🚀🐳**