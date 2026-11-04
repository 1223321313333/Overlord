#Requires -Version 5.1
<#
.SYNOPSIS
    Overlord native Windows installer.

.DESCRIPTION
    Installs prerequisites (Bun, Go), clones the repository if needed,
    builds the server and Windows agent, then prints first-run instructions.

    One-liner usage (run in an elevated or user PowerShell window):

        iwr -useb https://raw.githubusercontent.com/doesntbreaktos/Overlord/main/install.ps1 | iex

    Or, if you already have the repo:

        .\install.ps1

.NOTES
    Winget is used to install Bun and Go when they are missing.
    Requires internet access.  Run as your normal user (no elevation needed
    unless winget itself requires it on your machine).
#>
param(
    [string]$InstallDir = "$env:USERPROFILE\overlord"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoUrl  = 'https://github.com/doesntbreaktos/Overlord.git'
$GoMinVer = [version]'1.21.0'
$BunMinVer = [version]'1.0.0'

function Write-Step  { Write-Host "[overlord] $args" -ForegroundColor Cyan }
function Write-Ok    { Write-Host "[ok] $args" -ForegroundColor Green }
function Write-Warn  { Write-Host "[warn] $args" -ForegroundColor Yellow }
function Write-Fail  { Write-Host "[error] $args" -ForegroundColor Red; exit 1 }

function Have-Command($cmd) {
    return [bool](Get-Command $cmd -ErrorAction SilentlyContinue)
}

# ── Reload PATH from registry (picks up winget installs without restarting) ──
function Reload-Path {
    $machinePath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath    = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path    = "$machinePath;$userPath"
}

# ── winget helper ─────────────────────────────────────────────────────────────
function Ensure-Winget {
    if (-not (Have-Command winget)) {
        Write-Fail "winget not found. Install 'App Installer' from the Microsoft Store, then retry."
    }
}

# ── Bun ───────────────────────────────────────────────────────────────────────
function Install-Bun {
    Write-Step "Installing Bun via winget..."
    Ensure-Winget
    winget install -e --id Oven-sh.Bun --accept-source-agreements --accept-package-agreements
    Reload-Path
    if (Have-Command bun) {
        Write-Ok "Bun $(bun --version) installed"
    } else {
        Write-Fail "Bun install succeeded but 'bun' is still not in PATH. Open a new terminal and retry."
    }
}

function Check-Bun {
    if (Have-Command bun) {
        Write-Ok "Bun $(bun --version) found"
    } else {
        Install-Bun
    }
}

# ── Go ────────────────────────────────────────────────────────────────────────
function Install-Go {
    Write-Step "Installing Go via winget..."
    Ensure-Winget
    winget install -e --id GoLang.Go --accept-source-agreements --accept-package-agreements
    Reload-Path
    if (Have-Command go) {
        Write-Ok "Go $(go version) installed"
    } else {
        Write-Fail "Go install succeeded but 'go' is still not in PATH. Open a new terminal and retry."
    }
}

function Check-Go {
    if (Have-Command go) {
        $rawVer = (go version) -replace 'go version go([0-9]+\.[0-9]+(\.[0-9]+)?).*', '$1'
        try { $ver = [version]$rawVer } catch { $ver = [version]'0.0' }
        if ($ver -ge $GoMinVer) {
            Write-Ok "Go $ver found"
        } else {
            Write-Warn "Go $ver is older than required $GoMinVer — reinstalling"
            Install-Go
        }
    } else {
        Install-Go
    }
}

# ── Git ───────────────────────────────────────────────────────────────────────
function Check-Git {
    if (-not (Have-Command git)) {
        Write-Step "Installing Git via winget..."
        Ensure-Winget
        winget install -e --id Git.Git --accept-source-agreements --accept-package-agreements
        Reload-Path
        if (-not (Have-Command git)) {
            Write-Fail "Git install succeeded but 'git' is not in PATH. Open a new terminal and retry."
        }
    }
    Write-Ok "Git $(git --version) found"
}

# ── Repo ──────────────────────────────────────────────────────────────────────
function Ensure-Repo {
    if (Test-Path 'Overlord-Server\package.json') {
        Write-Ok "Already inside the Overlord repository"
        return
    }
    if (Test-Path "$InstallDir\.git") {
        Write-Step "Found existing clone at $InstallDir, pulling latest..."
        git -C $InstallDir pull --ff-only
    } else {
        Write-Step "Cloning $RepoUrl → $InstallDir ..."
        git clone --depth=1 $RepoUrl $InstallDir
    }
    Set-Location $InstallDir
    Write-Ok "Repository ready at $(Get-Location)"
}

# ── Build ─────────────────────────────────────────────────────────────────────
function Build-Server {
    Write-Step "Installing server dependencies..."
    Push-Location Overlord-Server
    bun install --frozen-lockfile
    Write-Step "Building server (production)..."
    bun run build
    Pop-Location
    Write-Ok "Server built → Overlord-Server\dist\"
}

function Build-Agent {
    Write-Step "Building Go agent (windows/amd64)..."
    if (-not (Test-Path 'Overlord-Server\data\builds')) {
        New-Item -ItemType Directory -Force -Path 'Overlord-Server\data\builds' | Out-Null
    }
    Push-Location Overlord-Client
    $env:GOOS   = 'windows'
    $env:GOARCH = 'amd64'
    go build -trimpath -ldflags='-s -w' -o '..\Overlord-Server\data\builds\agent.exe' '.\cmd\agent\'
    Remove-Item Env:\GOOS, Env:\GOARCH -ErrorAction SilentlyContinue
    Pop-Location
    Write-Ok "Agent built → Overlord-Server\data\builds\agent.exe"
}

# ── Main ──────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      Overlord Installer          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Check-Git
Check-Bun
Check-Go
Ensure-Repo
Build-Server
Build-Agent

Write-Host ""
Write-Ok "Installation complete."
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Start the server:"
Write-Host "       scripts\start-prod.bat"
Write-Host ""
Write-Host "  2. Get the initial admin password (first run only):"
Write-Host '       (Get-Content "$env:APPDATA\Overlord\save.json" | ConvertFrom-Json).auth.bootstrapPassword'
Write-Host ""
Write-Host "  3. Open the panel:"
Write-Host "       https://localhost:5173"
Write-Host ""
