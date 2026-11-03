# Quick Deploy Script for SentinelGate
# This script performs a quick local deployment for testing

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  SentinelGate Quick Deploy         " -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Check if venv exists
if (-not (Test-Path ".venv")) {
    Write-Host "[!] Virtual environment not found. Running setup..." -ForegroundColor Yellow
    .\tasks.ps1 setup
}

# Activate venv
Write-Host "[1] Activating virtual environment..." -ForegroundColor Green
& .\.venv\Scripts\Activate.ps1

# Check if .env exists
if (-not (Test-Path ".env")) {
    Write-Host "[2] Creating .env from template..." -ForegroundColor Green
    Copy-Item ".env.example" ".env"
    Write-Host "    ⚠️  Please edit .env and set DASHBOARD_PASSWORD!" -ForegroundColor Yellow
} else {
    Write-Host "[2] .env file exists" -ForegroundColor Green
}

# Create logs directory
Write-Host "[3] Creating logs directory..." -ForegroundColor Green
New-Item -ItemType Directory -Path "logs" -Force | Out-Null

# Train ML model if not exists
if (-not (Test-Path "models/iforest.joblib")) {
    Write-Host "[4] Training ML model (synthetic baseline)..." -ForegroundColor Green
    python -m ml.train --synthetic --output models/iforest.joblib
} else {
    Write-Host "[4] ML model exists" -ForegroundColor Green
}

# Check ports
Write-Host "[5] Checking if ports are available..." -ForegroundColor Green
$ports = @(5000, 8000, 8501)
$portsInUse = @()

foreach ($port in $ports) {
    $connection = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($connection) {
        $portsInUse += $port
    }
}

if ($portsInUse.Count -gt 0) {
    Write-Host "    ⚠️  Ports in use: $($portsInUse -join ', ')" -ForegroundColor Yellow
    Write-Host "    Please stop services using these ports or they will fail to start." -ForegroundColor Yellow
    $continue = Read-Host "    Continue anyway? (y/n)"
    if ($continue -ne 'y') {
        Write-Host "[!] Deployment cancelled" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Starting Services                 " -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Start test app
Write-Host "[*] Starting test app (port 5000)..." -ForegroundColor Green
$testapp = Start-Process python -ArgumentList "-m", "testapp.app" -NoNewWindow -PassThru -RedirectStandardOutput "logs\testapp.log" -RedirectStandardError "logs\testapp_err.log"
Start-Sleep -Seconds 3

# Check if test app started
try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:5000/" -TimeoutSec 2 -ErrorAction Stop
    Write-Host "    ✓ Test app running" -ForegroundColor Green
} catch {
    Write-Host "    ✗ Test app failed to start. Check logs\testapp_err.log" -ForegroundColor Red
}

# Start gateway
Write-Host "[*] Starting gateway (port 8000)..." -ForegroundColor Green
$gateway = Start-Process python -ArgumentList "-m", "uvicorn", "gateway.main:app", "--host", "127.0.0.1", "--port", "8000" -NoNewWindow -PassThru -RedirectStandardOutput "logs\gateway.log" -RedirectStandardError "logs\gateway_err.log"
Start-Sleep -Seconds 4

# Check if gateway started
try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8000/health" -TimeoutSec 2 -ErrorAction Stop
    Write-Host "    ✓ Gateway running" -ForegroundColor Green
} catch {
    Write-Host "    ✗ Gateway failed to start. Check logs\gateway_err.log" -ForegroundColor Red
}

# Start collector
Write-Host "[*] Starting SIEM collector..." -ForegroundColor Green
$collector = Start-Process python -ArgumentList "-m", "siem.collector", "--follow" -NoNewWindow -PassThru -RedirectStandardOutput "logs\collector.log" -RedirectStandardError "logs\collector_err.log"
Start-Sleep -Seconds 2
Write-Host "    ✓ Collector running" -ForegroundColor Green

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Deployment Complete!               " -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Services:" -ForegroundColor White
Write-Host "  • Test App:  http://localhost:5000" -ForegroundColor Cyan
Write-Host "  • Gateway:   http://localhost:8000" -ForegroundColor Cyan
Write-Host "  • Dashboard: Starting next..." -ForegroundColor Cyan
Write-Host ""
Write-Host "Process IDs:" -ForegroundColor White
Write-Host "  • Test App:  $($testapp.Id)" -ForegroundColor Gray
Write-Host "  • Gateway:   $($gateway.Id)" -ForegroundColor Gray
Write-Host "  • Collector: $($collector.Id)" -ForegroundColor Gray
Write-Host ""
Write-Host "Quick Test:" -ForegroundColor Yellow
Write-Host "  curl http://localhost:8000/health" -ForegroundColor Gray
Write-Host "  python -m simulator.run mixed --count 20" -ForegroundColor Gray
Write-Host ""
Write-Host "To stop services:" -ForegroundColor Yellow
Write-Host "  Stop-Process -Id $($testapp.Id),$($gateway.Id),$($collector.Id)" -ForegroundColor Gray
Write-Host ""
Write-Host "[*] Starting dashboard..." -ForegroundColor Green
Write-Host "    Dashboard will open at http://localhost:8501" -ForegroundColor Cyan
Write-Host "    Default password: admin (change in .env)" -ForegroundColor Yellow
Write-Host ""
Write-Host "    Press Ctrl+C to stop all services" -ForegroundColor Yellow
Write-Host ""

# Start dashboard (foreground)
try {
    python -m streamlit run dashboard\app.py
} finally {
    # Cleanup
    Write-Host ""
    Write-Host "[*] Stopping services..." -ForegroundColor Yellow
    Stop-Process -Id $testapp.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $gateway.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $collector.Id -Force -ErrorAction SilentlyContinue
    Write-Host "[✓] All services stopped" -ForegroundColor Green
}
