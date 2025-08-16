#!/bin/bash
# Quick deployment script for HPTA Security Suite

echo "🚀 HPTA Security Suite - Quick Deploy Script"
echo "============================================="

# Function to deploy to Heroku
deploy_heroku() {
    echo "📦 Deploying to Heroku..."
    
    # Check if Heroku CLI is installed
    if ! command -v heroku &> /dev/null; then
        echo "❌ Heroku CLI not installed. Please install it first:"
        echo "   https://devcenter.heroku.com/articles/heroku-cli"
        exit 1
    fi
    
    # Login and create app
    echo "🔐 Logging into Heroku..."
    heroku login
    
    echo "🏗️  Creating Heroku app..."
    heroku create hpta-security-suite-$(date +%s)
    
    # Set environment variables
    echo "⚙️  Setting environment variables..."
    read -p "Enter your Gemini API key: " GEMINI_KEY
    heroku config:set GEMINI_API_KEY=$GEMINI_KEY
    heroku config:set FLASK_ENV=production
    heroku config:set SECRET_KEY=$(openssl rand -base64 32)
    
    # Deploy
    echo "🚀 Deploying to Heroku..."
    git add .
    git commit -m "Deploy to Heroku"
    git push heroku main
    
    echo "✅ Deployment complete!"
    heroku open
}

# Function to deploy to Railway
deploy_railway() {
    echo "📦 Deploying to Railway..."
    echo "1. Go to https://railway.app"
    echo "2. Connect your GitHub account"
    echo "3. Import your repository: chennaichenai"
    echo "4. Set environment variables:"
    echo "   - GEMINI_API_KEY=your_api_key"
    echo "   - FLASK_ENV=production"
    echo "5. Deploy automatically!"
    
    read -p "Press Enter when done..."
}

# Function to deploy to Render
deploy_render() {
    echo "📦 Deploying to Render..."
    echo "1. Go to https://render.com"
    echo "2. Connect your GitHub repository"
    echo "3. Create a new Web Service"
    echo "4. Configure:"
    echo "   - Build Command: pip install -r requirements_production.txt"
    echo "   - Start Command: python start_hpta_production.py"
    echo "5. Set environment variables in Render dashboard"
    
    read -p "Press Enter when done..."
}

# Function to setup VPS
deploy_vps() {
    echo "📦 Setting up VPS deployment..."
    read -p "Enter your VPS IP address: " VPS_IP
    read -p "Enter your VPS username: " VPS_USER
    
    echo "🔐 Copying files to VPS..."
    scp -r . $VPS_USER@$VPS_IP:~/hpta-security-suite/
    
    echo "⚙️  Setting up VPS..."
    ssh $VPS_USER@$VPS_IP << 'EOF'
        cd ~/hpta-security-suite
        sudo apt update
        sudo apt install -y python3 python3-pip nginx
        pip3 install -r requirements_production.txt
        
        # Create systemd service
        sudo tee /etc/systemd/system/hpta.service > /dev/null <<EOL
[Unit]
Description=HPTA Security Suite
After=network.target

[Service]
User=$USER
WorkingDirectory=$HOME/hpta-security-suite
ExecStart=/usr/bin/python3 start_hpta_production.py
Restart=always

[Install]
WantedBy=multi-user.target
EOL
        
        sudo systemctl daemon-reload
        sudo systemctl enable hpta
        sudo systemctl start hpta
        
        echo "✅ HPTA service started!"
EOF
}

# Main menu
echo "Choose deployment option:"
echo "1. Heroku (Easy, $7/month)"
echo "2. Railway (Modern, $5/month)"
echo "3. Render (Developer-friendly, $7/month)"
echo "4. VPS Setup (Custom, $5-50/month)"
echo "5. Exit"

read -p "Enter your choice (1-5): " choice

case $choice in
    1) deploy_heroku ;;
    2) deploy_railway ;;
    3) deploy_render ;;
    4) deploy_vps ;;
    5) echo "👋 Goodbye!"; exit 0 ;;
    *) echo "❌ Invalid choice"; exit 1 ;;
esac
