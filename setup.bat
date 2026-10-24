@echo off
rem 本文件使用 GBK 编码保存，请不要用 UTF-8 另存。
setlocal
cd /d "%~dp0"

echo ==========================================
echo   mhszed-sql 环境初始化
echo ==========================================

where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] 未找到 python，请安装 Python 3.10+ 并加入 PATH。
    pause
    exit /b 1
)
python -c "import sys;raise SystemExit(0 if sys.version_info>=(3,10) else 1)"
if errorlevel 1 (
    echo [ERROR] Python 版本过低，需要 3.10 或以上。
    pause
    exit /b 1
)

where npm >nul 2>&1
if errorlevel 1 (
    echo [ERROR] 未找到 npm，请安装 Node.js 18+。
    pause
    exit /b 1
)

echo [1/3] 准备后端虚拟环境...
if not exist "backend\venv\Scripts\python.exe" (
    python -m venv backend\venv
    if errorlevel 1 ( pause & exit /b 1 )
) else (
    echo       已存在，跳过创建。
)

echo [2/3] 安装后端依赖...
backend\venv\Scripts\python -m pip install --upgrade pip
backend\venv\Scripts\python -m pip install -r backend\requirements.txt
if errorlevel 1 ( pause & exit /b 1 )

echo [3/3] 安装前端依赖...
pushd frontend
call npm install
if errorlevel 1 ( popd & pause & exit /b 1 )
popd

echo.
echo 环境初始化完成。运行 start.bat 启动服务。
pause
