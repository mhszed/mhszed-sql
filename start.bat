@echo off
chcp 936 >nul
rem 本文件使用 GBK 编码保存，请勿转为 UTF-8。
setlocal EnableExtensions
cd /d "%~dp0"
title mhszed-sql 一键启动

echo ==========================================
echo   mhszed-sql 一键启动
echo ==========================================
echo.

echo [1/4] 检查运行环境...
call "%~dp0setup.bat" --auto
if errorlevel 1 (
    echo.
    echo [ERROR] 运行环境初始化失败，请根据上方提示处理后重试。
    goto :fail
)
echo.

set "BACKEND_RUNNING="
set "FRONTEND_RUNNING="

call :http_ok "http://127.0.0.1:8787/api/health" "mhszed-sql"
if not errorlevel 1 set "BACKEND_RUNNING=1"

call :http_ok "http://127.0.0.1:5173/" "mhszed-sql"
if not errorlevel 1 set "FRONTEND_RUNNING=1"

if defined BACKEND_RUNNING (
    echo [2/4] 后端已在运行，直接复用 8787 端口。
) else (
    call :port_open 8787
    if not errorlevel 1 (
        echo.
        echo [ERROR] 端口 8787 已被其他程序占用，请先关闭占用该端口的程序。
        goto :fail
    )
    echo [2/4] 启动后端 8787...
    start "mhszed-sql backend 8787" /D "%~dp0backend" cmd /k "venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8787"
)

if defined FRONTEND_RUNNING (
    echo [3/4] 前端已在运行，直接复用 5173 端口。
) else (
    call :port_open 5173
    if not errorlevel 1 (
        echo.
        echo [ERROR] 端口 5173 已被其他程序占用，请先关闭占用该端口的程序。
        goto :fail
    )
    echo [3/4] 启动前端 5173...
    start "mhszed-sql frontend 5173" /D "%~dp0frontend" cmd /k "npm run dev -- --port 5173 --strictPort"
)

echo [4/4] 等待服务就绪...
if not defined BACKEND_RUNNING (
    call :wait_http "http://127.0.0.1:8787/api/health" "mhszed-sql" 90
    if errorlevel 1 (
        echo.
        echo [ERROR] 后端在 90 秒内未就绪，请查看 “mhszed-sql backend 8787” 窗口中的报错。
        goto :fail
    )
)
if not defined FRONTEND_RUNNING (
    call :wait_http "http://127.0.0.1:5173/" "mhszed-sql" 120
    if errorlevel 1 (
        echo.
        echo [ERROR] 前端在 120 秒内未就绪，请查看 “mhszed-sql frontend 5173” 窗口中的报错。
        goto :fail
    )
)

echo.
echo ==========================================
echo   启动完成
echo   访问地址：http://localhost:5173
echo   接口文档：http://127.0.0.1:8787/docs
echo   默认账号：admin / admin123
echo   提示：关闭本窗口不会停止服务；
echo         如需停止，请关闭两个服务窗口。
echo ==========================================
start "" "http://localhost:5173"
echo.
echo 本窗口将在 5 秒后自动关闭...
ping -n 6 127.0.0.1 >nul
exit /b 0

:fail
echo.
echo ==========================================
echo   启动失败，请根据上方提示排查后重试。
echo ==========================================
pause
exit /b 1

rem ---------- 以下为内部函数 ----------

:http_ok
rem %1 = URL，%2 = 响应中应包含的关键字
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri '%~1'; if ($r.StatusCode -eq 200 -and $r.Content -match '%~2') { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
exit /b %errorlevel%

:port_open
rem %1 = 端口号；端口已被监听时返回 0
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', %~1); $c.Close(); exit 0 } catch { exit 1 }" >nul 2>&1
exit /b %errorlevel%

:wait_http
rem %1 = URL，%2 = 关键字，%3 = 最长等待秒数
set "WAITED=0"
:wait_http_loop
call :http_ok "%~1" "%~2"
if not errorlevel 1 exit /b 0
set /a WAITED+=1
if %WAITED% GEQ %~3 exit /b 1
ping -n 2 127.0.0.1 >nul
goto :wait_http_loop
