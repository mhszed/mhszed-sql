@echo off
chcp 936 >nul
rem 本文件使用 GBK 编码保存，请勿转为 UTF-8。
setlocal EnableExtensions
cd /d "%~dp0"

set "AUTO=0"
if /i "%~1"=="--auto" set "AUTO=1"

echo ==========================================
echo   mhszed-sql 环境初始化
echo ==========================================
echo.

rem ---------- 1. 查找可用的 Python ----------
set "PY_CMD="
where python >nul 2>&1
if not errorlevel 1 (
    python -c "import sys;raise SystemExit(0 if sys.version_info>=(3,10) else 1)" >nul 2>&1
    if not errorlevel 1 set "PY_CMD=python"
)
if not defined PY_CMD (
    where py >nul 2>&1
    if not errorlevel 1 (
        py -3 -c "import sys;raise SystemExit(0 if sys.version_info>=(3,10) else 1)" >nul 2>&1
        if not errorlevel 1 set "PY_CMD=py -3"
    )
)
if not defined PY_CMD (
    echo [ERROR] 未找到 Python 3.10 或更高版本，请安装后加入 PATH。
    goto :fail
)

rem ---------- 2. 检查 Node.js ----------
where npm >nul 2>&1
if errorlevel 1 (
    echo [ERROR] 未找到 npm，请安装 Node.js 18 或更高版本并加入 PATH。
    goto :fail
)
node -e "process.exit(parseInt(process.versions.node,10)>=18?0:1)" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js 版本过低，需要 18 或更高版本。
    goto :fail
)

rem ---------- 3. 后端虚拟环境 ----------
echo [1/4] 检查后端虚拟环境...
if not exist "backend\venv\Scripts\python.exe" (
    echo       创建 backend\venv...
    %PY_CMD% -m venv "backend\venv"
    if errorlevel 1 (
        echo [ERROR] 创建虚拟环境失败。
        goto :fail
    )
) else (
    echo       已存在，跳过。
)

rem 验证虚拟环境可运行
"backend\venv\Scripts\python.exe" -c "import sys" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] backend\venv 已损坏或无法运行，请删除该目录后重试。
    goto :fail
)

rem ---------- 4. 后端依赖 ----------
echo [2/4] 检查后端依赖...
set "NEED_PIP=0"
if not exist "backend\venv\.mhszed-requirements" set "NEED_PIP=1"
if exist "backend\venv\.mhszed-requirements" (
    fc /b "backend\requirements.txt" "backend\venv\.mhszed-requirements" >nul 2>&1
    if errorlevel 1 set "NEED_PIP=1"
)
"backend\venv\Scripts\python.exe" -c "import fastapi, uvicorn, sqlalchemy, httpx" >nul 2>&1
if errorlevel 1 set "NEED_PIP=1"
if "%NEED_PIP%"=="1" (
    echo       安装 requirements.txt，可能需要几分钟...
    "backend\venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r "backend\requirements.txt"
    if errorlevel 1 (
        echo [ERROR] 后端依赖安装失败，请检查网络或 pip 源后重试。
        goto :fail
    )
    copy /y "backend\requirements.txt" "backend\venv\.mhszed-requirements" >nul
) else (
    echo       已就绪，跳过。
)

rem ---------- 5. 前端依赖 ----------
echo [3/4] 检查前端依赖...
set "NEED_NPM=0"
if not exist "frontend\node_modules\.mhszed-lock" set "NEED_NPM=1"
if exist "frontend\node_modules\.mhszed-lock" (
    fc /b "frontend\package-lock.json" "frontend\node_modules\.mhszed-lock" >nul 2>&1
    if errorlevel 1 set "NEED_NPM=1"
)
if not exist "frontend\node_modules\vite\bin\vite.js" set "NEED_NPM=1"
if "%NEED_NPM%"=="1" (
    echo       安装前端依赖，可能需要几分钟...
    pushd "%~dp0frontend"
    if exist "package-lock.json" (
        call npm ci --no-audit --no-fund
    ) else (
        call npm install --no-audit --no-fund
    )
    if errorlevel 1 (
        echo       安装失败，尝试 npm install 重试...
        call npm install --no-audit --no-fund
    )
    if errorlevel 1 (
        popd
        echo [ERROR] 前端依赖安装失败，请检查网络或 npm 源后重试。
        goto :fail
    )
    if exist "package-lock.json" copy /y "package-lock.json" "node_modules\.mhszed-lock" >nul
    popd
) else (
    echo       已就绪，跳过。
)

echo [4/4] 环境初始化完成。
echo.
if "%AUTO%"=="0" (
    echo 现在可以双击 启动mhszed-sql.bat 或 start.bat 启动系统。
    pause
)
exit /b 0

:fail
echo.
echo 环境初始化失败，请根据上方提示处理后重试。
if "%AUTO%"=="0" pause
exit /b 1
