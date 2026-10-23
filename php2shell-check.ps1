#Requires -Version 5.1
<#
.SYNOPSIS
    php2shell CVE-2026-109618 / CVE-2026-109619 — Windows version checker
.DESCRIPTION
    Fixed: PHP 8.2.35 | 8.3.36 | 8.4.27 | 8.5.12
    Checks PATH, common install dirs, AMP stacks, package managers,
    IIS FastCGI config, registry, and running processes.
.PARAMETER Url
    Optional — checks X-Powered-By response header.
.EXAMPLE
    .\php2shell-check.ps1
    .\php2shell-check.ps1 -Url https://mydomain.com
.NOTES
    Run as Administrator for IIS config and process module access.
#>
[CmdletBinding()]
param([string]$Url = '')

$Fixed  = @{ '8.2'='8.2.35'; '8.3'='8.3.36'; '8.4'='8.4.27'; '8.5'='8.5.12' }
$Seen   = @{}
$script:Found = 0

# ── helpers ──────────────────────────────────────────────────────────────────

function Get-PhpVer([string]$text) {
    if ($text -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
    return $null
}

function Test-VerGte([string]$a, [string]$b) {
    try   { return [System.Version]$a -ge [System.Version]$b }
    catch { return $false }
}

function Get-FixCmd([string]$minor) {
    if (Get-Command choco  -ErrorAction SilentlyContinue) { return 'choco upgrade php' }
    if (Get-Command winget -ErrorAction SilentlyContinue) { return 'winget upgrade PHP.PHP' }
    if (Get-Command scoop  -ErrorAction SilentlyContinue) { return 'scoop update php' }
    return "Download PHP $($Fixed[$minor]) from https://windows.php.net/download/"
}

function Write-Result([string]$label, [string]$ver) {
    if (-not $ver) { return }
    $key = "${label}::${ver}"
    if ($Seen.ContainsKey($key)) { return }
    $Seen[$key] = $true
    $script:Found++

    $p     = $ver.Split('.')
    $minor = "$($p[0]).$($p[1])"
    $major = [int]$p[0]
    $mn    = [int]$p[1]

    if ($Fixed.ContainsKey($minor)) {
        $fix = $Fixed[$minor]
        if (Test-VerGte $ver $fix) {
            Write-Host ("  [SAFE]       {0,-26}  PHP {1} >= {2}" -f $label,$ver,$fix) -ForegroundColor Green
        } else {
            Write-Host ("  [VULNERABLE] {0,-26}  PHP {1} < {2}" -f $label,$ver,$fix) -ForegroundColor Red
            Write-Host ("               fix: {0}" -f (Get-FixCmd $minor)) -ForegroundColor Yellow
        }
    } elseif ($major -lt 8 -or ($major -eq 8 -and $mn -le 1)) {
        Write-Host ("  [VULNERABLE] {0,-26}  PHP {1}  EOL — no patch, upgrade to 8.2.35+" -f $label,$ver) -ForegroundColor Red
    } else {
        Write-Host ("  [UNKNOWN]    {0,-26}  PHP {1}  branch not in fixed version map" -f $label,$ver) -ForegroundColor Yellow
    }
}

function Test-Bin([string]$label, [string]$path) {
    if (-not (Test-Path $path -PathType Leaf -ErrorAction SilentlyContinue)) { return }
    try   { $real = (Resolve-Path $path -ErrorAction Stop).Path }
    catch { $real = $path }
    $rkey = "bin::$real"
    if ($Seen.ContainsKey($rkey)) { return }
    $Seen[$rkey] = $true
    try {
        $out = & $path -v 2>&1 | Out-String
        Write-Result $label (Get-PhpVer $out)
    } catch {}
}

function Hr { Write-Host ('-' * 58) }

# ── header ───────────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '  .----------------------------------------------------.'
Write-Host '  |  [PHP2SHELL] CVE-2026-109618 / CVE-2026-109619    |'
Write-Host '  |  Fixed: 8.2.35 | 8.3.36 | 8.4.27 | 8.5.12        |'
Write-Host '  |                                      by Kowalski  |'
Write-Host "  '----------------------------------------------------'"
Write-Host ''

# warn if not admin — some checks need it
$isAdmin = ([Security.Principal.WindowsPrincipal]
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '  [!] Not running as Administrator — IIS and process checks may be incomplete.' -ForegroundColor Yellow
    Write-Host ''
}

# ── 1. PATH ──────────────────────────────────────────────────────────────────

Write-Host '  [PATH]'
$inPath = Get-Command php -ErrorAction SilentlyContinue
if ($inPath) { Test-Bin 'php (PATH)' $inPath.Source }
else         { Write-Host '  php not found in PATH' }

# ── 2. Common install directories ────────────────────────────────────────────

Write-Host ''
Write-Host '  [Common directories]'
@(
    'C:\php',
    'C:\PHP',
    'C:\Program Files\PHP',
    'C:\Program Files (x86)\PHP'
) | ForEach-Object {
    Test-Bin "$_\php.exe"     "$_\php.exe"
    Test-Bin "$_\php-cgi.exe" "$_\php-cgi.exe"
}

# ── 3. AMP stacks ────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '  [AMP stacks — XAMPP / WAMP / Laragon]'

# XAMPP
Test-Bin 'XAMPP'         'C:\xampp\php\php.exe'
Test-Bin 'XAMPP:php-cgi' 'C:\xampp\php\php-cgi.exe'

# WAMP / WAMP64 — multiple side-by-side PHP versions
foreach ($root in @('C:\wamp', 'C:\wamp64')) {
    $phpDir = Join-Path $root 'bin\php'
    if (Test-Path $phpDir -ErrorAction SilentlyContinue) {
        Get-ChildItem $phpDir -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Test-Bin "WAMP:$($_.Name)" (Join-Path $_.FullName 'php.exe') }
    }
}

# Laragon — multiple side-by-side PHP versions
$laragonPhp = 'C:\laragon\bin\php'
if (Test-Path $laragonPhp -ErrorAction SilentlyContinue) {
    Get-ChildItem $laragonPhp -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { Test-Bin "Laragon:$($_.Name)" (Join-Path $_.FullName 'php.exe') }
}

# ── 4. Package managers ──────────────────────────────────────────────────────

Write-Host ''
Write-Host '  [Package managers]'

# Chocolatey — check lib dir for actual binaries
$chocoLib = 'C:\ProgramData\chocolatey\lib'
if (Test-Path $chocoLib -ErrorAction SilentlyContinue) {
    Get-ChildItem $chocoLib -Filter 'php*' -Directory -ErrorAction SilentlyContinue |
        ForEach-Object {
            Test-Bin "choco:$($_.Name)" (Join-Path $_.FullName 'tools\php.exe')
        }
} elseif (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host '  Chocolatey not detected'
}

# Scoop — current symlink + explicit version dirs
foreach ($base in @("$env:USERPROFILE\scoop\apps\php", "$env:SCOOP\apps\php", 'C:\scoop\apps\php')) {
    if ($base -and (Test-Path $base -ErrorAction SilentlyContinue)) {
        Get-ChildItem $base -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Test-Bin "scoop:$($_.Name)" (Join-Path $_.FullName 'php.exe') }
    }
}

# Winget — PHP lands in Program Files; binary check above covers it.
# Version string from winget list as a fallback if binary wasn't found.
if (Get-Command winget -ErrorAction SilentlyContinue) {
    $wl = winget list --id PHP.PHP 2>$null | Where-Object { $_ -match '\d+\.\d+\.\d+' }
    foreach ($line in $wl) {
        $ver = Get-PhpVer $line
        if ($ver) { Write-Result 'winget:PHP' $ver }
    }
}

# ── 5. IIS FastCGI ───────────────────────────────────────────────────────────

Write-Host ''
Write-Host '  [IIS FastCGI]'
$iisConf = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
if (Test-Path $iisConf -ErrorAction SilentlyContinue) {
    $content = Get-Content $iisConf -Raw -ErrorAction SilentlyContinue
    if ($content) {
        [regex]::Matches($content, 'fullPath="([^"]*php[^"]*\.exe)"') |
            ForEach-Object { Test-Bin 'IIS:FastCGI' $_.Groups[1].Value }
    }
} else {
    Write-Host '  IIS not detected or no read access'
}

# ── 6. Registry ──────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '  [Registry]'
$regFound = 0
@(
    'HKLM:\SOFTWARE\PHP',
    'HKLM:\SOFTWARE\WOW6432Node\PHP',
    'HKCU:\SOFTWARE\PHP'
) | ForEach-Object {
    if (Test-Path $_ -ErrorAction SilentlyContinue) {
        $val    = Get-ItemProperty $_ -ErrorAction SilentlyContinue
        $phpDir = if ($val.InstallDir) { $val.InstallDir } else { $val.Path }
        if ($phpDir) {
            Test-Bin "reg:$_" (Join-Path $phpDir 'php.exe')
            $regFound++
        }
    }
}
if ($regFound -eq 0) { Write-Host '  no PHP registry entries found' }

# ── 7. Running processes ─────────────────────────────────────────────────────

Write-Host ''
Write-Host '  [Running processes]'
$procN = 0
Get-Process | Where-Object { $_.Name -match '^php' } | ForEach-Object {
    try {
        $exe = $_.MainModule.FileName
        if ($exe) {
            Test-Bin "proc:$($_.Name)" $exe
            $procN++
        }
    } catch {}
}
if ($procN -eq 0) { Write-Host '  none detected' }

# ── 8. HTTP response header (optional) ──────────────────────────────────────

if ($Url) {
    Write-Host ''
    Write-Host "  [HTTP: $Url]"
    try {
        $resp = Invoke-WebRequest -Uri $Url -Method Head `
                                  -UseBasicParsing -TimeoutSec 8 `
                                  -ErrorAction Stop
        $hdr = $resp.Headers['X-Powered-By']
        $ver = Get-PhpVer ($hdr -join ' ')
        if ($ver) { Write-Result 'x-powered-by' $ver }
        else       { Write-Host '  no PHP version in X-Powered-By header' }
    } catch {
        Write-Host "  request failed: $($_.Exception.Message)"
    }
}

# ── summary ──────────────────────────────────────────────────────────────────

Write-Host ''
Hr
if ($script:Found -eq 0) { Write-Host '  no PHP installations detected' }
Write-Host ''
