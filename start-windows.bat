@echo off
REM ================================================================
REM  Fortis Intelligence Hub — Windows Startup Script
REM  Starts Flask (waitress), Celery worker, and Celery beat
REM  Requires: Redis running on localhost:6379
REM ================================================================

echo.
echo === Fortis Intelligence Hub (Windows) ===
echo.

REM Check Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found in PATH. Install Python 3.12+.
    pause
    exit /b 1
)

REM Activate venv if present
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
    echo [OK] Virtual environment activated
) else (
    echo [WARN] No .venv found — using system Python
)

REM Check Redis connectivity
python -c "import redis; r=redis.Redis(); r.ping(); print('[OK] Redis connected')" 2>nul
if %errorlevel% neq 0 (
    echo [WARN] Redis not reachable on localhost:6379
    echo        Feed monitoring requires Redis. Start Redis or install via:
    echo          winget install Redis.Redis
    echo          OR use Docker: docker run -d -p 6379:6379 redis:7-alpine
    echo.
    echo        Continuing without Celery — monitors will not poll.
    echo.

    echo Starting Flask app on http://127.0.0.1:5000 ...
    python run.py
    goto :end
)

REM Start Celery worker in background (--pool=solo required on Windows)
echo Starting Celery worker (--pool=solo for Windows)...
start "Celery Worker" cmd /c "celery -A app.celery_app:celery_app worker -l info -Q fortis_monitor --pool=solo"

REM Start Celery beat in background
echo Starting Celery beat scheduler...
start "Celery Beat" cmd /c "celery -A app.celery_app:celery_app beat -l info"

REM Wait for workers to start
timeout /t 3 /nobreak >nul

REM Start Flask app (foreground)
echo.
echo Starting Flask app on http://127.0.0.1:5000 ...
echo Press Ctrl+C to stop.
echo.
python run.py

:end
echo.
echo Shutting down...
taskkill /FI "WINDOWTITLE eq Celery Worker" >nul 2>&1
taskkill /FI "WINDOWTITLE eq Celery Beat" >nul 2>&1
echo Done.
