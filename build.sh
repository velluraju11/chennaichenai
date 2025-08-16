#!/bin/bash
# Render Build Script for HPTA Security Suite

echo "🚀 HPTA Security Suite - Render Build Starting..."
echo "📦 Installing Python dependencies..."

# Upgrade pip
python -m pip install --upgrade pip

# Install requirements
pip install -r requirements.txt

echo "📁 Creating necessary directories..."
mkdir -p uploads
mkdir -p reports  
mkdir -p temp_reports
mkdir -p templates
mkdir -p sessions

echo "🔧 Setting up project structure..."
# Ensure Python can find all modules
export PYTHONPATH="${PYTHONPATH}:."

echo "✅ Build completed successfully!"
echo "🌟 HPTA Security Suite ready for deployment on Render!"
