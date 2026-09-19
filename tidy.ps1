# ============================================================
#  tidy.ps1 - regenerate go.mod / go.sum for the platforms this
#  project actually ships, so the committed go.sum is a superset.
#
#  Why this exists:
#    `go mod tidy` resolves dependencies for the host platform only.
#    This module builds for Windows (the agent uses syscall into
#    Npcap) and for Linux (the control-plane image), so a Linux-only
#    tidy drops hashes a Windows build needs, and a Windows-only tidy
#    adds hashes a Linux build does not want. CI runs on Linux, so a
#    tidy generated on Windows will not match it byte for byte.
#
#  Rather than fight that, generate go.sum for every target and keep
#  the union. A superset is valid for all of them: the extra lines are
#  unused hashes, not conflicts.
#
#  Usage:  powershell -NoProfile -File .\tidy.ps1
# ============================================================

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

Write-Host 'Regenerating go.sum for every shipped platform...'

# Start from the host, which also prunes anything genuinely unused.
go mod tidy
if ($LASTEXITCODE -ne 0) { throw 'go mod tidy failed' }

$targets = @(
    @{ os = 'windows'; arch = 'amd64' },   # the agent
    @{ os = 'linux';   arch = 'amd64' },   # the control-plane image
    @{ os = 'linux';   arch = 'arm64' }    # the control-plane image, arm
)

foreach ($t in $targets) {
    $env:GOOS = $t.os
    $env:GOARCH = $t.arch
    Write-Host ("  resolving for {0}/{1}" -f $t.os, $t.arch)
    # A full build pulls in every dependency of every package, which is what
    # causes the platform-specific hashes to be recorded.
    go build ./... 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw ("build failed for {0}/{1}" -f $t.os, $t.arch) }
}

Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue

$lines = (Get-Content go.sum | Where-Object { $_.Trim() -ne '' }).Count
Write-Host "`ngo.sum now holds $lines hashes (superset across all targets)."
Write-Host 'Run `go build ./...` and `go test ./...` to confirm, then commit.'
