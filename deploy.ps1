# SentinelGate - Simple Deployment
# Run this script to start all services

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  SentinelGate Deployment            " -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Check venv
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    & .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt
}

# Activate venv
Write-Host "Activating virtual environment..." -ForegroundColor Green
& .\.venv\Scripts\Activate.ps1

# Create .env if needed
if (-not (Test-Path ".env")) {
    Write-Host "Creating .env file..." -ForegroundColor Green
    Copy-Item ".env.example" ".env"
}

# Create logs directory
New-Item -ItemType Directory -Path "logs" -Force | Out-Null

# Train ML model if needed
if (-not (Test-Path "models/iforest.joblib")) {
    Write-Host "Training ML model..." -ForegroundColor Green
    python -m ml.train --synthetic --output models/iforest.joblib
}

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Starting Services                  " -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Start services
Write-Host "Starting test app on port 5000..." -ForegroundColor Green
Start-Process python -ArgumentList "-m", "testapp.app" -NoNewWindow

Start-Sleep -Seconds 2

Write-Host "Starting gateway on port 8000..." -ForegroundColor Green
Start-Process python -ArgumentList "-m", "uvicorn", "gateway.main:app", "--host", "127.0.0.1", "--port", "8000" -NoNewWindow

Start-Sleep -Seconds 3

Write-Host "Starting collector..." -ForegroundColor Green
Start-Process python -ArgumentList "-m", "siem.collector", "--follow" -NoNewWindow

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Services Started!                  " -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Access points:" -ForegroundColor White
Write-Host "  Test App:  http://localhost:5000" -ForegroundColor Cyan
Write-Host "  Gateway:   http://localhost:8000" -ForegroundColor Cyan
Write-Host "  Dashboard: Starting..." -ForegroundColor Cyan
Write-Host ""
Write-Host "Testing gateway..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8000/health" -TimeoutSec 5
    Write-Host "  Gateway is healthy!" -ForegroundColor Green
} catch {
    Write-Host "  Gateway not responding yet (may need more time)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Starting dashboard (this will block)..." -ForegroundColor Green
Write-Host "Dashboard will open at http://localhost:8501" -ForegroundColor Cyan
Write-Host "Default password: admin" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C to stop all services" -ForegroundColor Yellow
Write-Host ""

# Start dashboard in foreground
python -m streamlit run dashboard\app.py
