#Requires -Version 5.1
<#
.SYNOPSIS
    Overlord installer for Windows.

.DESCRIPTION
    Two modes:
      Docker  — pull and run the pre-built container image via Docker Desktop.
                Easiest, but Docker Desktop is virtualized; see the README note.
      Native  — install Bun + Go, build from source, run directly on Windows.
                Recommended for best performance and feature availability.

    One-liner examples (run in PowerShell):

      # Docker mode
      iwr -useb https://raw.githubusercontent.com/doesntbreaktos/Overlord/main/install.ps1 | iex

      # Native mode (save locally, pass flag)
      iwr -useb https://raw.githubusercontent.com/doesntbreaktos/Overlord/main/install.ps1 -OutFile install.ps1
      .\install.ps1 -Mode native

.PARAMETER Mode
    'docker' or 'native'.  Omit for an interactive menu.

.PARAMETER InstallDir
    Where to clone the repository when running outside an existing checkout.
    Default: %USERPROFILE%\overlord
#>
param(
    [ValidateSet('docker', 'native', '')]
    [string]$Mode = '',

    [string]$InstallDir = "$env:USERPROFILE\overlord"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoUrl     = 'https://github.com/doesntbreaktos/Overlord.git'
$ComposeUrl  = 'https://raw.githubusercontent.com/doesntbreaktos/Overlord/main/docker-compose.windows.yml'
$GoMinVer    = [version]'1.21.0'

function Write-Step { Write-Host "[overlord] $args" -ForegroundColor Cyan }
function Write-Ok   { Write-Host "[ok] $args"       -ForegroundColor Green }
function Write-Warn { Write-Host "[warn] $args"     -ForegroundColor Yellow }
function Write-Fail { Write-Host "[error] $args"    -ForegroundColor Red; exit 1 }

function Have($cmd) { [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

function Reload-Path {
    $m = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    $u = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$m;$u"
}

function Ensure-Winget {
    if (-not (Have winget)) {
        Write-Fail "winget not found.  Install 'App Installer' from the Microsoft Store, then retry."
    }
}

# ── mode selection ─────────────────────────────────────────────────────────────

if (-not $Mode) {
    Write-Host ""
    Write-Host "How do you want to install Overlord?" -ForegroundColor White
    Write-Host ""
    Write-Host "  1) Docker  — pull the pre-built image via Docker Desktop"
    Write-Host "               (easy, but virtualized — see README for trade-offs)"
    Write-Host "  2) Native  — build from source with Bun + Go (recommended for Windows)"
    Write-Host ""
    $choice = Read-Host "Enter 1 or 2"
    switch ($choice) {
        '1' { $Mode = 'docker' }
        '2' { $Mode = 'native' }
        default { Write-Fail "Invalid choice: $choice" }
    }
}

Write-Host ""
Write-Host "╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Overlord Installer — Windows       ║" -ForegroundColor Cyan
Write-Host ("║   Mode: {0,-30}║" -f $Mode)             -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
#  DOCKER MODE
# ═══════════════════════════════════════════════════════════════════════════════

function Docker-Mode {
    # ── check Docker ─────────────────────────────────────────────────────────
    if (-not (Have docker)) {
        Write-Step "Docker not found — installing Docker Desktop via winget..."
        Ensure-Winget
        winget install -e --id Docker.DockerDesktop --accept-source-agreements --accept-package-agreements
        Reload-Path
        Write-Warn "Docker Desktop was just installed."
        Write-Warn "Please start Docker Desktop once, wait for it to finish initialising,"
        Write-Warn "then re-run this script."
        exit 0
    }

    try {
        $null = docker compose version 2>&1
    } catch {
        Write-Fail "docker compose plugin not found.  Make sure Docker Desktop is up to date."
    }
    Write-Ok "Docker $(docker --version | Select-String -Pattern '[0-9]+\.[0-9]+\.[0-9]+' | ForEach-Object { $_.Matches.Value }) with Compose ready"

    # ── get the compose file ─────────────────────────────────────────────────
    $composeFile = $null
    if (Test-Path 'docker-compose.windows.yml') {
        Write-Ok "Already inside the Overlord repository — using local docker-compose.windows.yml"
        $composeFile = 'docker-compose.windows.yml'
    } else {
        $composeDir = "$InstallDir-docker"
        New-Item -ItemType Directory -Force -Path $composeDir | Out-Null
        $composeFile = "$composeDir\docker-compose.windows.yml"
        Write-Step "Downloading docker-compose.windows.yml → $composeFile ..."
        Invoke-WebRequest -Uri $ComposeUrl -OutFile $composeFile -UseBasicParsing
        Set-Location $composeDir
        Write-Ok "Compose file ready at $(Get-Location)"
    }

    # ── pull and start ───────────────────────────────────────────────────────
    Write-Step "Pulling latest image..."
    docker compose -f $composeFile pull

    Write-Step "Starting Overlord..."
    docker compose -f $composeFile up -d

    Write-Host ""
    Write-Ok "Overlord is running."
    Write-Host ""
    Write-Host "Get the initial admin password:" -ForegroundColor Cyan
    Write-Host "  docker compose -f $composeFile exec overlord-server grep bootstrapPassword /app/data/save.json"
    Write-Host ""
    Write-Host "Open the panel:  https://localhost:5173" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Update later:" -ForegroundColor Cyan
    Write-Host "  docker compose -f $composeFile pull"
    Write-Host "  docker compose -f $composeFile up -d"
    Write-Host ""
    Write-Host "Stop:" -ForegroundColor Cyan
    Write-Host "  docker compose -f $composeFile down"
    Write-Host ""
}

# ═══════════════════════════════════════════════════════════════════════════════
#  NATIVE MODE
# ═══════════════════════════════════════════════════════════════════════════════

function Install-Bun {
    Write-Step "Installing Bun via winget..."
    Ensure-Winget
    winget install -e --id Oven-sh.Bun --accept-source-agreements --accept-package-agreements
    Reload-Path
    if (-not (Have bun)) { Write-Fail "Bun installed but not in PATH — open a new terminal and retry." }
    Write-Ok "Bun $(bun --version) installed"
}

function Check-Bun {
    if (Have bun) { Write-Ok "Bun $(bun --version) found" }
    else { Install-Bun }
}

function Install-Go {
    Write-Step "Installing Go via winget..."
    Ensure-Winget
    winget install -e --id GoLang.Go --accept-source-agreements --accept-package-agreements
    Reload-Path
    if (-not (Have go)) { Write-Fail "Go installed but not in PATH — open a new terminal and retry." }
    Write-Ok "Go $(go version) installed"
}

function Check-Go {
    if (Have go) {
        $raw = (go version) -replace 'go version go([0-9]+\.[0-9]+(\.[0-9]+)?).*','$1'
        try { $ver = [version]$raw } catch { $ver = [version]'0.0' }
        if ($ver -ge $GoMinVer) { Write-Ok "Go $ver found"; return }
        Write-Warn "Go $ver < $GoMinVer — reinstalling"
    }
    Install-Go
}

function Check-Git {
    if (-not (Have git)) {
        Write-Step "Installing Git via winget..."
        Ensure-Winget
        winget install -e --id Git.Git --accept-source-agreements --accept-package-agreements
        Reload-Path
        if (-not (Have git)) { Write-Fail "Git installed but not in PATH — open a new terminal and retry." }
    }
    Write-Ok "Git $(git --version) found"
}

function Ensure-Repo {
    if (Test-Path 'Overlord-Server\package.json') {
        Write-Ok "Already inside the Overlord repository"
        return
    }
    if (Test-Path "$InstallDir\.git") {
        Write-Step "Pulling latest at $InstallDir ..."
        git -C $InstallDir pull --ff-only
    } else {
        Write-Step "Cloning $RepoUrl → $InstallDir ..."
        git clone --depth=1 $RepoUrl $InstallDir
    }
    Set-Location $InstallDir
    Write-Ok "Repository ready at $(Get-Location)"
}

function Native-Mode {
    Check-Git
    Check-Bun
    Check-Go
    Ensure-Repo

    Write-Step "Installing server dependencies..."
    Push-Location Overlord-Server
    bun install --frozen-lockfile

    Write-Step "Building server (production)..."
    bun run build
    bun run build:prod:win

    Write-Step "Copying client source for runtime agent builds..."
    Pop-Location
    if (-not (Test-Path 'Overlord-Server\dist\Overlord-Client')) {
        New-Item -ItemType Directory -Force -Path 'Overlord-Server\dist\Overlord-Client' | Out-Null
    }
    robocopy Overlord-Client Overlord-Server\dist\Overlord-Client /E /XD build .git .vscode /NFL /NDL /NJH /NJS | Out-Null
    # robocopy exits 0-7 on success
    if ($LASTEXITCODE -ge 8) { Write-Fail "robocopy failed copying client source" }
    Write-Ok "Build complete"

    Write-Host ""
    Write-Ok "Installation complete."
    Write-Host ""
    Write-Host "Start the server:" -ForegroundColor Cyan
    Write-Host "  scripts\start-prod.bat"
    Write-Host ""
    Write-Host "Get the initial admin password (first run only):" -ForegroundColor Cyan
    Write-Host '  (Get-Content "$env:APPDATA\Overlord\save.json" | ConvertFrom-Json).auth.bootstrapPassword'
    Write-Host ""
    Write-Host "Open the panel:  https://localhost:5173" -ForegroundColor Cyan
    Write-Host ""
}

# ── dispatch ───────────────────────────────────────────────────────────────────
switch ($Mode) {
    'docker' { Docker-Mode }
    'native' { Native-Mode }
}
