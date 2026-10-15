# ========================================================
# VOID // SENTINEL — Complete 3-Person Hackathon Demo Launcher
# (Windows PowerShell)
# ========================================================

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  VOID // SENTINEL — Cyber-Deception System Demo" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$jobs = @()

# 1. Start Person 1 Backend on port 8000 if not already running
$p1_running = $false
try {
    $resp = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
    if ($resp.status -eq "ok") {
        $p1_running = $true
        Write-Host "[OK] Person 1 Backend already active on http://127.0.0.1:8000" -ForegroundColor Green
    }
} catch {}

if (-not $p1_running) {
    Write-Host "[*] Starting Person 1 Backend on http://127.0.0.1:8000..." -ForegroundColor Yellow
    $p1_job = Start-Process -FilePath "python" -ArgumentList "-m uvicorn app.main:app --host 127.0.0.1 --port 8000" -WorkingDirectory "person2\void-backend" -PassThru -NoNewWindow
    $jobs += $p1_job
    Start-Sleep -Seconds 3
}

# 2. Start Person 2 React Dashboard Server on port 8080 if not already running
$p2_running = $false
try {
    $resp2 = Invoke-RestMethod -Uri "http://127.0.0.1:8080/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
    if ($resp2.status -eq "VOID SENTINEL online") {
        $p2_running = $true
        Write-Host "[OK] Person 2 Dashboard Server already active on http://localhost:8080" -ForegroundColor Green
    }
} catch {}

if (-not $p2_running) {
    Write-Host "[*] Starting Person 2 Dashboard Server on http://localhost:8080..." -ForegroundColor Yellow
    $p2_job = Start-Process -FilePath "python" -ArgumentList "-m uvicorn void_server:app --app-dir person1 --host 0.0.0.0 --port 8080" -PassThru -NoNewWindow
    $jobs += $p2_job
    Start-Sleep -Seconds 2
}

# 3. Start Person 3 Dashboard Bridge API on port 8001
$bridge_running = $false
try {
    $resp3 = Invoke-RestMethod -Uri "http://127.0.0.1:8001/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
    if ($resp3.status -eq "healthy") {
        $bridge_running = $true
        Write-Host "[OK] Dashboard Bridge API already active on http://127.0.0.1:8001" -ForegroundColor Green
    }
} catch {}

if (-not $bridge_running) {
    Write-Host "[*] Starting Dashboard Bridge API on http://127.0.0.1:8001..." -ForegroundColor Yellow
    $bridge_job = Start-Process -FilePath "python" -ArgumentList "-m uvicorn bridge_api:app --host 127.0.0.1 --port 8001 --log-level warning" -PassThru -NoNewWindow
    $jobs += $bridge_job
    Start-Sleep -Seconds 2
}

# 4. Start Person 3 Integration Poller
Write-Host "[*] Starting Event Integration Poller (Person 1 -> Person 3)..." -ForegroundColor Yellow
$poller_job = Start-Process -FilePath "python" -ArgumentList "integration.py --poll --interval 2.5" -PassThru -NoNewWindow
$jobs += $poller_job
Start-Sleep -Seconds 2

Write-Host "`n[+] VOID // SENTINEL System Mesh ONLINE:" -ForegroundColor Green
Write-Host "    - [Person 1] Core Defense Backend : http://127.0.0.1:8000"
Write-Host "    - [Person 3] Dashboard Bridge API  : http://127.0.0.1:8001"
Write-Host "    - [Person 2] React Command Center  : http://localhost:8080"
Write-Host "------------------------------------------------------------`n"

# 5. Run the adversary attack simulation suite
Write-Host "[*] Launching Adversary Attack Simulation (python simulate_attack.py --mode all)...`n" -ForegroundColor Cyan
python simulate_attack.py --mode all

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  Adversary simulation complete!" -ForegroundColor Green
Write-Host "  Open http://localhost:8080 to observe live telemetry in the Dashboard." -ForegroundColor Yellow
Write-Host "  To stop services started in this session, kill PIDs: $($jobs.Id -join ', ')" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan
