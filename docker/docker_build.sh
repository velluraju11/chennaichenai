#!/bin/bash
# HPTA Security Suite - Docker Build Script

echo "🐳 HPTA Security Suite - Docker Build & Deploy"
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
print_status "Creating Docker data directories..."
mkdir -p docker-data/{reports,uploads,temp_reports,config,ssl}
print_success "Directories created"

# Build the Docker image
print_status "Building HPTA Security Suite Docker image..."
docker build -t hpta-security-suite:latest . || {
    print_error "Docker build failed"
    exit 1
}
print_success "Docker image built successfully"

# Check if containers are already running
if docker-compose ps | grep -q "Up"; then
    print_warning "Containers are already running. Stopping them first..."
    docker-compose down
fi

# Start the services
print_status "Starting HPTA Security Suite services..."
docker-compose up -d || {
    print_error "Failed to start services"
    exit 1
}

# Wait for services to be ready
print_status "Waiting for services to be ready..."
sleep 10

# Check service health
print_status "Checking service health..."
if curl -f http://localhost:5000/api/health &> /dev/null; then
    print_success "HPTA Security Suite is running and healthy!"
else
    print_warning "Service might still be starting up..."
fi

echo ""
echo "================================================"
print_success "HPTA Security Suite deployed successfully!"
echo "================================================"
echo ""
echo "🌐 Access URLs:"
echo "   - Main Application: http://localhost:5000"
echo "   - With Nginx Proxy: http://localhost:80"
echo "   - Health Check: http://localhost:5000/api/health"
echo ""
echo "🔧 Management Commands:"
echo "   - View logs: docker-compose logs -f"
echo "   - Stop services: docker-compose down"
echo "   - Restart: docker-compose restart"
echo "   - Update: docker-compose pull && docker-compose up -d"
echo ""
echo "📁 Data Directories:"
echo "   - Reports: ./docker-data/reports/"
echo "   - Uploads: ./docker-data/uploads/"
echo "   - Config: ./docker-data/config/"
echo ""
echo "🔑 Don't forget to:"
echo "   1. Get your Google Gemini API key from: https://makersuite.google.com/app/apikey"
echo "   2. Enter it in the web interface"
echo "   3. Start analyzing with natural language commands!"
echo ""
print_success "Happy hacking! 🚀"