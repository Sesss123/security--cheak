# Security Platform — Startup Script

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   SECURITY PLATFORM AUTO-START SYSTEM       " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Starting Docker Infrastructure
Write-Host "[*] Step 1: Starting Docker containers (PostgreSQL, Redis, Qdrant)..." -ForegroundColor Yellow
docker compose up postgres redis qdrant -d --remove-orphans
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Error: Failed to start docker containers. Make sure Docker Desktop is running!" -ForegroundColor Red
    Exit
}
Write-Host "[+] Docker containers started successfully!" -ForegroundColor Green
Write-Host ""

# 2. Building Rust Scanner
Write-Host "[*] Step 2: Checking and compiling Rust Scanner Engine..." -ForegroundColor Yellow
Set-Location scanner
cargo build --release
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Error: Rust compilation failed!" -ForegroundColor Red
    Set-Location ..
    Exit
}
Set-Location ..
Write-Host "[+] Rust Scanner Engine compiled successfully!" -ForegroundColor Green
Write-Host ""

# 3. Running NestJS Database Updates
Write-Host "[*] Step 3: Running database migrations and columns updates..." -ForegroundColor Yellow
Set-Location api-nest
node update-db.js
Set-Location ..
Write-Host "[+] Database setup complete!" -ForegroundColor Green
Write-Host ""

# 4. Spawning NestJS API, Worker & Dashboard
Write-Host "[*] Step 4: Spawning API Server, Worker Node, and React Frontend in new windows..." -ForegroundColor Yellow

# Start NestJS API Server (Port 3001)
Write-Host " -> Launching API Server on Port 3001..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd api-nest; npm run start:dev" -WindowStyle Normal

# Start NestJS Worker Node (BullMQ Processor)
Write-Host " -> Launching Queue Worker Node..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd api-nest; npm run start:worker:dev" -WindowStyle Normal

# Start React Frontend Dashboard (Port 3000/5173)
Write-Host " -> Launching React Dashboard..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd dashboard; npm run dev" -WindowStyle Normal

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "   🚀 ALL SYSTEMS BOOTED SUCCESSFULLY!        " -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "[*] API Server: http://localhost:3001" -ForegroundColor Gray
Write-Host "[*] React Dashboard: check your browser window" -ForegroundColor Gray
Write-Host "[*] Press any key to exit this installer window." -ForegroundColor Gray
