# php2shell-checker

Detection tooling for CVE-2026-109618 and CVE-2026-109619 (php2shell). Enumerates PHP installations across all discoverable locations on a host, compares each version against the patched release for its branch, and prints the remediation command for the detected package manager.

Two scripts, identical in detection logic, built for different host environments.

| Script | Platform | Interpreter |
|---|---|---|
| `php2shell-check.sh` | Linux, macOS | bash 4.0+ |
| `php2shell-check.ps1` | Windows Server, Windows 10/11 | PowerShell 5.1+ |

---

## Background

CVE-2026-109618 is a use-after-free in PHP's OOM error path. When the process hits its memory limit mid-request, the cleanup routine can operate on partially initialised internal state, producing a type-confusion primitive. CVE-2026-109619 is a related flaw in which stale per-worker global state survives across requests under specific conditions, including via the `session.upload_progress` write path and, on PHP 8.5, via fatal error backtraces. Both vulnerabilities are reachable without authentication on a default PHP configuration and lead to remote code execution.

CVSS score: 9.2 Critical (CVE-2026-109618).

PHP issued fixes on 21 October 2026.

## Fixed versions

| Branch | Patched release |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

PHP 8.1 and earlier are end-of-life. No patch will be issued for those branches. Hosts on EOL versions must be upgraded to a supported branch at or above the fixed release.

---

## Linux

### Requirements

- bash 4.0 or later
- coreutils: `cut`, `grep`, `sort`, `tr`, `ps`
- One of: `dpkg-query` (Debian/Ubuntu), `rpm` (RHEL/Fedora/CentOS/AlmaLinux), `apk` (Alpine)
- `curl` — optional, for the HTTP header check
- `readlink -f` — GNU coreutils; on macOS install via `brew install coreutils`

Run as root or via `sudo` to ensure `/usr/sbin` is in PATH and to allow process module enumeration.

### Usage

```bash
chmod +x php2shell-check.sh

sudo ./php2shell-check.sh

sudo ./php2shell-check.sh https://target.example.com
```

### Detection coverage

| Source | Detail |
|---|---|
| CLI binaries | `php` and `php8.x` / `php7.x` variants resolved via PATH and `/usr/sbin` |
| FPM binaries | `phpX.Y-fpm` and `php-fpmX.Y` naming conventions |
| Package manager | `dpkg-query`, `rpm`, or `apk` — one result per unique installed PHP version |
| Running processes | PHP binaries under `/usr` or `/opt` found in the process table |
| HTTP header | `X-Powered-By` response header from a supplied URL |

Binaries are deduplicated by resolved canonical path. A symlink and its target are reported once.

---

## Windows

### Requirements

- PowerShell 5.1 or later (ships with Windows Server 2016 and later)
- Administrator rights for IIS `applicationHost.config` access and process module enumeration

### Usage

```powershell
.\php2shell-check.ps1

.\php2shell-check.ps1 -Url https://target.example.com
```

If the execution policy blocks unsigned scripts:

```powershell
powershell -ExecutionPolicy Bypass -File .\php2shell-check.ps1
```

### Detection coverage

| Source | Detail |
|---|---|
| PATH | `php.exe` resolved via `Get-Command` |
| Common directories | `C:\php`, `C:\Program Files\PHP`, 32-bit equivalent |
| XAMPP | `C:\xampp\php\` — `php.exe` and `php-cgi.exe` |
| WAMP / WAMP64 | All side-by-side PHP version directories under `bin\php\` |
| Laragon | All side-by-side PHP version directories under `bin\php\` |
| Chocolatey | `C:\ProgramData\chocolatey\lib\php*\tools\php.exe` |
| Scoop | Per-user and global scoop app directories |
| Winget | Version string parsed from `winget list --id PHP.PHP` |
| IIS FastCGI | `fullPath` attributes in `applicationHost.config` |
| Registry | `HKLM\SOFTWARE\PHP` and `WOW6432Node` equivalent, `InstallDir` / `Path` keys |
| Running processes | PHP process binary paths from `Get-Process` module enumeration |
| HTTP header | `X-Powered-By` response header from a supplied URL |

---

## Output

Each detected PHP installation produces one of four verdicts.

`SAFE` — installed version meets or exceeds the patched release for its branch.

`VULNERABLE` — installed version is below the patched release. The remediation command for the detected package manager is printed on the following line.

`EOL` — version is from a branch that has reached end-of-life (8.1 or earlier). The vulnerability is present and no patch will be issued.

`UNKNOWN` — the minor version is not in the fixed-version map. This occurs when a version from a branch released after this tool was last updated is detected. Verify against the PHP security advisories directly.

Example output on a vulnerable Debian host:

```
  .----------------------------------------------------.
  |  [PHP2SHELL] CVE-2026-109618 / CVE-2026-109619    |
  |  Fixed: 8.2.35 | 8.3.36 | 8.4.27 | 8.5.12        |
  |                                      by Kowalski  |
  '----------------------------------------------------'

  [CLI]
  [VULNERABLE] php                      PHP 8.3.35 < 8.3.36
               fix: apt-get install --only-upgrade php8.3 php8.3-fpm

  [FPM]
  [VULNERABLE] php8.3-fpm               PHP 8.3.35 < 8.3.36
               fix: apt-get install --only-upgrade php8.3 php8.3-fpm

  [Packages]
  [VULNERABLE] pkg(apt)                 PHP 8.3.35 < 8.3.36
               fix: apt-get install --only-upgrade php8.3 php8.3-fpm
```

---

## Temporary mitigations

Patching is the only complete remediation. The following `php.ini` settings reduce the attack surface while a patch window is scheduled. They do not eliminate the vulnerability.

| Setting | Value | Effect |
|---|---|---|
| `session.upload_progress.enabled` | `Off` | Blocks the demonstrated CVE-2026-109619 session chain |
| `memory_limit` | `-1` | Removes the OOM trigger CVE-2026-109618 relies on |
| `fatal_error_backtraces` | `Off` | Blocks the CVE-2026-109619 backtrace path (PHP 8.5 only) |

All three settings together provide the broadest partial coverage. Each one individually addresses only a subset of the attack surface, and the underlying vulnerable code remains unchanged in either case.

Restart the PHP-FPM service or web server after editing `php.ini`:

```bash
# Debian/Ubuntu
sudo systemctl restart php8.3-fpm

# RHEL/Fedora/AlmaLinux
sudo systemctl restart php-fpm

# Apache with mod_php
sudo systemctl restart apache2   # or httpd
```

---

## Limitations

The scripts report on PHP installations they can discover. They do not cover every possible deployment method.

Known gaps:

- PHP compiled from source into a non-standard path with no package manager record and not in PATH
- PHP running inside a container — the host script cannot inspect container process tables or filesystems
- PHP-FPM pools under a non-standard binary path not matching the expected name patterns
- The HTTP header check reflects only the PHP version of the specific endpoint queried and requires `expose_php = On` in `php.ini`
- On Windows, 32-bit PHP processes may not expose `MainModule.FileName` to a 64-bit PowerShell session

Regarding passive network scanners: an `INCONCLUSIVE` result from tools such as `assetnote/php2shell-scanner` is not equivalent to `SAFE`. A 413 status indicates the probe was rejected upstream before reaching PHP; the PHP version on that host is unknown from that scan alone. Direct host inspection resolves the ambiguity.

---

## References

- PHP security advisories: https://www.php.net/security
- NVD CVE-2026-109618: https://nvd.nist.gov/vuln/detail/CVE-2026-109618
- NVD CVE-2026-109619: https://nvd.nist.gov/vuln/detail/CVE-2026-109619
- Datadog Security Labs analysis: https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
- watchTowr FAQ: https://watchtowr.com/intelligence/php-cve-2026-109618-faq/
- JFrog Security Research: https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/
- Passive network scanner: https://github.com/assetnote/php2shell-scanner

---

## Author

[Kowalski Analysis](https://github.com/kowalski-analysis)
