# SentinelGate Demo Script
# Starts test app, gateway, collector, dashboard, and runs attack simulator

Write-Host "=== SentinelGate Demo ===" -ForegroundColor Cyan
Write-Host ""

# Create logs directory
if (-not (Test-Path "logs")) {
    New-Item -ItemType Directory -Path "logs" | Out-Null
}

# Check if venv is activated
if (-not $env:VIRTUAL_ENV) {
    Write-Host "[!] Activating virtual environment..." -ForegroundColor Yellow
    & .\.venv\Scripts\Activate.ps1
}

# Start test app (Flask on port 5000)
Write-Host "[1] Starting test app on port 5000..." -ForegroundColor Green
$testapp = Start-Process python -ArgumentList "-m", "testapp.app" -NoNewWindow -PassThru -RedirectStandardOutput "logs\testapp.log" -RedirectStandardError "logs\testapp_err.log"
Start-Sleep -Seconds 2

# Start gateway (FastAPI on port 8000)
Write-Host "[2] Starting gateway on port 8000..." -ForegroundColor Green
$gateway = Start-Process python -ArgumentList "-m", "uvicorn", "gateway.main:app", "--host", "127.0.0.1", "--port", "8000" -NoNewWindow -PassThru -RedirectStandardOutput "logs\gateway.log" -RedirectStandardError "logs\gateway_err.log"
Start-Sleep -Seconds 3

# Start collector
Write-Host "[3] Starting SIEM collector..." -ForegroundColor Green
$collector = Start-Process python -ArgumentList "-m", "siem.collector", "--follow" -NoNewWindow -PassThru -RedirectStandardOutput "logs\collector.log" -RedirectStandardError "logs\collector_err.log"
Start-Sleep -Seconds 1

# Run simulator (mixed scenario)
Write-Host "[4] Running attack simulator (mixed scenario)..." -ForegroundColor Yellow
Write-Host ""
python -m simulator.run mixed --target http://127.0.0.1:8000 --count 30

Write-Host ""
Write-Host "[5] Checking results..." -ForegroundColor Green

# Query database for events
$db_path = "logs\siem.db"
if (Test-Path $db_path) {
    $events = & sqlite3 $db_path "SELECT COUNT(*) FROM events"
    $alerts = & sqlite3 $db_path "SELECT COUNT(*) FROM alerts"
    $blocked = & sqlite3 $db_path "SELECT COUNT(*) FROM blocklist"

    Write-Host "    Events logged: $events" -ForegroundColor Cyan
    Write-Host "    Alerts raised: $alerts" -ForegroundColor Cyan
    Write-Host "    IPs blocked:   $blocked" -ForegroundColor Cyan
} else {
    Write-Host "    Database not found. Events may still be processing." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[6] Starting dashboard (Streamlit on port 8501)..." -ForegroundColor Green
Write-Host "    Dashboard will open at http://localhost:8501" -ForegroundColor Cyan
Write-Host ""
Write-Host "    Press Ctrl+C to stop all services." -ForegroundColor Yellow
Write-Host ""

# Start dashboard (foreground, blocking)
try {
    python -m streamlit run dashboard\app.py
} finally {
    # Cleanup on exit
    Write-Host ""
    Write-Host "[*] Stopping services..." -ForegroundColor Yellow
    Stop-Process -Id $testapp.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $gateway.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $collector.Id -Force -ErrorAction SilentlyContinue
    Write-Host "[✓] Demo stopped." -ForegroundColor Green
}
