@echo off
REM HPTA Security Suite - Docker Build Script for Windows

echo 🐳 HPTA Security Suite - Docker Build ^& Deploy
echo ================================================

REM Check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

REM Check if Docker Compose is installed
docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker Compose is not installed. Please install Docker Compose first.
    pause
    exit /b 1
)

REM Create necessary directories
echo 📁 Creating Docker data directories...
if not exist "docker-data" mkdir docker-data
if not exist "docker-data\reports" mkdir docker-data\reports
if not exist "docker-data\uploads" mkdir docker-data\uploads
if not exist "docker-data\temp_reports" mkdir docker-data\temp_reports
if not exist "docker-data\config" mkdir docker-data\config
if not exist "docker-data\ssl" mkdir docker-data\ssl
echo ✅ Directories created

REM Build the Docker image
echo 🔨 Building HPTA Security Suite Docker image...
docker build -t hpta-security-suite:latest .
if errorlevel 1 (
    echo ❌ Docker build failed
    pause
    exit /b 1
)
echo ✅ Docker image built successfully

REM Stop existing containers if running
echo 🛑 Stopping existing containers...
docker-compose down >nul 2>&1

REM Start the services
echo 🚀 Starting HPTA Security Suite services...
docker-compose up -d
if errorlevel 1 (
    echo ❌ Failed to start services
    pause
    exit /b 1
)

REM Wait for services to be ready
echo ⏳ Waiting for services to be ready...
timeout /t 15 /nobreak >nul

REM Check service health
echo 🔍 Checking service health...
curl -f http://localhost:5000/api/health >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Service might still be starting up...
) else (
    echo ✅ HPTA Security Suite is running and healthy!
)

echo.
echo ================================================
echo ✅ HPTA Security Suite deployed successfully!
echo ================================================
echo.
echo 🌐 Access URLs:
echo    - Main Application: http://localhost:5000
echo    - With Nginx Proxy: http://localhost:80
echo    - Health Check: http://localhost:5000/api/health
echo.
echo 🔧 Management Commands:
echo    - View logs: docker-compose logs -f
echo    - Stop services: docker-compose down
echo    - Restart: docker-compose restart
echo.
echo 📁 Data Directories:
echo    - Reports: .\docker-data\reports\
echo    - Uploads: .\docker-data\uploads\
echo    - Config: .\docker-data\config\
echo.
echo 🔑 Don't forget to:
echo    1. Get your Google Gemini API key from: https://makersuite.google.com/app/apikey
echo    2. Enter it in the web interface
echo    3. Start analyzing with natural language commands!
echo.
echo ✅ Happy hacking! 🚀
pause