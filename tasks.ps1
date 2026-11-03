# SentinelGate PowerShell Tasks
# Convenience commands for development and deployment

param(
    [Parameter(Position=0)]
    [ValidateSet('setup', 'test', 'lint', 'run', 'demo', 'docker-build', 'docker-up', 'docker-down', 'clean')]
    [string]$Command = 'help'
)

function Show-Help {
    Write-Host "SentinelGate Tasks" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage: .\tasks.ps1 <command>" -ForegroundColor White
    Write-Host ""
    Write-Host "Commands:" -ForegroundColor Yellow
    Write-Host "  setup         - Create venv and install dependencies"
    Write-Host "  test          - Run pytest with coverage"
    Write-Host "  lint          - Run ruff linter"
    Write-Host "  run           - Start all services (gateway, collector, dashboard)"
    Write-Host "  demo          - Run full demo (same as demo.ps1)"
    Write-Host "  docker-build  - Build Docker images"
    Write-Host "  docker-up     - Start Docker Compose stack"
    Write-Host "  docker-down   - Stop Docker Compose stack"
    Write-Host "  clean         - Remove logs, cache, and temporary files"
}

function Invoke-Setup {
    Write-Host "[*] Setting up SentinelGate..." -ForegroundColor Green

    if (-not (Test-Path ".venv")) {
        Write-Host "    Creating virtual environment..." -ForegroundColor Cyan
        python -m venv .venv
    }

    Write-Host "    Activating venv..." -ForegroundColor Cyan
    & .\.venv\Scripts\Activate.ps1

    Write-Host "    Installing dependencies..." -ForegroundColor Cyan
    pip install -r requirements.txt

    Write-Host "    Creating logs directory..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path "logs" -Force | Out-Null

    Write-Host "[OK] Setup complete!" -ForegroundColor Green
}

function Invoke-Test {
    Write-Host "[*] Running tests..." -ForegroundColor Green
    & .\.venv\Scripts\Activate.ps1
    python -m pytest --cov=. --cov-report=html --cov-report=term
}

function Invoke-Lint {
    Write-Host "[*] Running linter..." -ForegroundColor Green
    & .\.venv\Scripts\Activate.ps1
    python -m ruff check .
}

function Invoke-Run {
    Write-Host "[*] Starting SentinelGate services..." -ForegroundColor Green
    & .\.venv\Scripts\Activate.ps1

    # Start services in background
    Start-Process python -ArgumentList "-m", "testapp.app" -NoNewWindow
    Start-Sleep -Seconds 2
    Start-Process python -ArgumentList "-m", "uvicorn", "gateway.main:app", "--host", "127.0.0.1", "--port", "8000" -NoNewWindow
    Start-Sleep -Seconds 2
    Start-Process python -ArgumentList "-m", "siem.collector", "--follow" -NoNewWindow
    Start-Sleep -Seconds 1

    Write-Host "[OK] Services started" -ForegroundColor Green
    Write-Host "    Test app: http://localhost:5000" -ForegroundColor Cyan
    Write-Host "    Gateway:  http://localhost:8000" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Starting dashboard..." -ForegroundColor Green
    python -m streamlit run dashboard\app.py
}

function Invoke-Demo {
    Write-Host "[*] Running demo..." -ForegroundColor Green
    .\demo.ps1
}

function Invoke-DockerBuild {
    Write-Host "[*] Building Docker images..." -ForegroundColor Green
    docker build -t sentinelgate:latest .
    Write-Host "[OK] Build complete!" -ForegroundColor Green
}

function Invoke-DockerUp {
    Write-Host "[*] Starting Docker Compose stack..." -ForegroundColor Green
    docker-compose up -d
    Write-Host "[OK] Stack started!" -ForegroundColor Green
    Write-Host "    Gateway:   http://localhost:8000" -ForegroundColor Cyan
    Write-Host "    Dashboard: http://localhost:8501" -ForegroundColor Cyan
    Write-Host "    Landing:   http://localhost:8080" -ForegroundColor Cyan
}

function Invoke-DockerDown {
    Write-Host "[*] Stopping Docker Compose stack..." -ForegroundColor Green
    docker-compose down
    Write-Host "[OK] Stack stopped!" -ForegroundColor Green
}

function Invoke-Clean {
    Write-Host "[*] Cleaning up..." -ForegroundColor Green

    # Remove logs
    if (Test-Path "logs") {
        Write-Host "    Removing logs..." -ForegroundColor Cyan
        Remove-Item -Recurse -Force "logs\*.log", "logs\*.jsonl", "logs\*.db" -ErrorAction SilentlyContinue
    }

    # Remove cache
    Write-Host "    Removing cache..." -ForegroundColor Cyan
    Get-ChildItem -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Recurse -Filter "*.pyc" | Remove-Item -Force -ErrorAction SilentlyContinue

    # Remove coverage
    if (Test-Path "htmlcov") {
        Remove-Item -Recurse -Force "htmlcov"
    }
    if (Test-Path ".coverage") {
        Remove-Item -Force ".coverage"
    }

    Write-Host "[OK] Cleanup complete!" -ForegroundColor Green
}

# Main execution
switch ($Command) {
    'setup' { Invoke-Setup }
    'test' { Invoke-Test }
    'lint' { Invoke-Lint }
    'run' { Invoke-Run }
    'demo' { Invoke-Demo }
    'docker-build' { Invoke-DockerBuild }
    'docker-up' { Invoke-DockerUp }
    'docker-down' { Invoke-DockerDown }
    'clean' { Invoke-Clean }
    default { Show-Help }
}
