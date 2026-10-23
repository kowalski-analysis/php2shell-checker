# Changelog

## 1.0.0 - 2026-10-23

Initial release.

**php2shell-check.sh**
- CLI and FPM binary enumeration across PATH and `/usr/sbin`
- Package manager support: `dpkg-query` (apt), `rpm`, `apk`
- Running process enumeration via `ps`
- Deduplication by resolved canonical binary path
- HTTP header check via `curl` (optional, pass URL as argument)
- Coloured output: green for safe, red for vulnerable, yellow for unknown
- Patch command output for detected package manager

**php2shell-check.ps1**
- PATH resolution via `Get-Command`
- Common directory scan: `C:\php`, `C:\Program Files\PHP`
- AMP stack support: XAMPP, WAMP, WAMP64, Laragon (all side-by-side versions)
- Package manager support: Chocolatey, Scoop, Winget
- IIS FastCGI path extraction from `applicationHost.config`
- Registry key check: `HKLM\SOFTWARE\PHP` and `WOW6432Node` equivalent
- Running process enumeration via `Get-Process`
- HTTP header check via `Invoke-WebRequest` (optional, `-Url` parameter)
- Administrator check with warning if rights are absent

**Fixed version map (both scripts)**
- PHP 8.2: 8.2.35
- PHP 8.3: 8.3.36
- PHP 8.4: 8.4.27
- PHP 8.5: 8.5.12
