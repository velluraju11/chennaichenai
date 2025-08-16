@echo off
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                      HPTA 3-SERVER ARCHITECTURE LAUNCHER                    ║
echo ║                         Windows Batch Launcher                              ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

echo 🚀 Starting HPTA 3-Server Architecture...
echo.

cd /d "%~dp0.."

echo 📦 Installing required packages...
pip install websockets flask asyncio

echo.
echo 🎯 Launching servers...
python scripts/start_3_server_architecture.py

pause
