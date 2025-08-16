@echo off
REM Windows deployment script for HPTA Security Suite

echo 🚀 HPTA Security Suite - Windows Deploy Script
echo ==============================================

:menu
echo.
echo Choose deployment option:
echo 1. Heroku (Easy, $7/month)
echo 2. Railway (Modern, $5/month)  
echo 3. Render (Developer-friendly, $7/month)
echo 4. Local Production Setup
echo 5. Exit

set /p choice=Enter your choice (1-5): 

if "%choice%"=="1" goto heroku
if "%choice%"=="2" goto railway
if "%choice%"=="3" goto render
if "%choice%"=="4" goto local
if "%choice%"=="5" goto exit
echo ❌ Invalid choice
goto menu

:heroku
echo 📦 Deploying to Heroku...
echo.
echo Installing Heroku CLI...
echo Please download and install from: https://devcenter.heroku.com/articles/heroku-cli
echo.
pause
echo.
echo 🔐 Login to Heroku...
heroku login
echo.
echo 🏗️ Creating Heroku app...
heroku create hpta-security-suite-%RANDOM%
echo.
set /p GEMINI_KEY=Enter your Gemini API key: 
heroku config:set GEMINI_API_KEY=%GEMINI_KEY%
heroku config:set FLASK_ENV=production
echo.
echo 🚀 Deploying...
git add .
git commit -m "Deploy to Heroku"
git push heroku main
echo.
echo ✅ Deployment complete!
heroku open
goto end

:railway
echo 📦 Deploying to Railway...
echo.
echo 1. Go to https://railway.app
echo 2. Connect your GitHub account
echo 3. Import your repository: chennaichenai
echo 4. Set environment variables:
echo    - GEMINI_API_KEY=your_api_key
echo    - FLASK_ENV=production
echo 5. Deploy automatically!
echo.
pause
goto end

:render
echo 📦 Deploying to Render...
echo.
echo 1. Go to https://render.com
echo 2. Connect your GitHub repository
echo 3. Create a new Web Service
echo 4. Configure:
echo    - Build Command: pip install -r requirements_production.txt
echo    - Start Command: python start_hpta_production.py
echo 5. Set environment variables in Render dashboard
echo.
pause
goto end

:local
echo 📦 Setting up local production environment...
echo.
echo Installing production requirements...
pip install -r requirements_production.txt
echo.
set /p GEMINI_KEY=Enter your Gemini API key: 
echo GEMINI_API_KEY=%GEMINI_KEY%> .env
echo FLASK_ENV=production>> .env
echo SECRET_KEY=your_secret_key_change_this>> .env
echo.
echo ✅ Local production environment ready!
echo Run with: python start_hpta_production.py
goto end

:exit
echo 👋 Goodbye!
goto end

:end
pause
