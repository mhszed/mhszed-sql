@echo off
rem 本文件使用 GBK 编码保存，请不要用 UTF-8 另存。
setlocal
cd /d "%~dp0"

if not exist "backend\venv\Scripts\python.exe" (
    echo [ERROR] 未找到后端虚拟环境 backend\venv
    echo 请先运行 setup.bat 初始化依赖。
    pause
    exit /b 1
)
if not exist "frontend\node_modules" (
    echo [ERROR] 未找到前端依赖 frontend\node_modules
    echo 请先运行 setup.bat 初始化依赖。
    pause
    exit /b 1
)

echo [1/3] 启动后端 (8787)...
start "mhszed-sql backend 8787" /D "%~dp0backend" cmd /k "venv\Scripts\python -m uvicorn app.main:app --port 8787"

echo [2/3] 启动前端 (5173)...
start "mhszed-sql frontend 5173" /D "%~dp0frontend" cmd /k "npm run dev"

echo [3/3] 等待服务启动...
"%SystemRoot%\System32\timeout.exe" /t 8 /nobreak >nul
start "" "http://localhost:5173"

echo.
echo ==========================================
echo   访问地址: http://localhost:5173
echo   接口文档: http://127.0.0.1:8787/docs
echo   默认账号: admin / admin123
echo ==========================================
pause
