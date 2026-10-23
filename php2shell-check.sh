#!/usr/bin/env bash
# php2shell CVE-2026-109618 / CVE-2026-109619 — version checker
# Fixed: PHP 8.2.35 | 8.3.36 | 8.4.27 | 8.5.12
# Usage: ./php2shell-check.sh [url]
#   url  optional — checks X-Powered-By response header

PATH="/usr/sbin:/usr/local/sbin:$PATH"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLD='\033[1m'
RST='\033[0m'

declare -A FIXED=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)
declare -A SEEN=()
found=0

# ── helpers ─────────────────────────────────────────────────────────────────

parse_ver() { grep -oE '[0-9]+\.[0-9]+\.[0-9]+' <<< "$1" | head -1; }

ver_gte() {
  local IFS=.
  read -ra a <<< "$1"
  read -ra b <<< "$2"
  for i in 0 1 2; do
    (( 10#${a[i]:-0} > 10#${b[i]:-0} )) && return 0
    (( 10#${a[i]:-0} < 10#${b[i]:-0} )) && return 1
  done
  return 0
}

fix_cmd() {
  local m="$1"
  if   command -v apt-get &>/dev/null; then echo "apt-get install --only-upgrade php${m} php${m}-fpm"
  elif command -v dnf     &>/dev/null; then echo "dnf update php"
  elif command -v yum     &>/dev/null; then echo "yum update php"
  elif command -v apk     &>/dev/null; then echo "apk upgrade php$(tr -d . <<< "$m")"
  elif command -v pkg     &>/dev/null; then echo "pkg upgrade php$(tr -d . <<< "$m")"
  else                                      echo "upgrade PHP to ${FIXED[$m]} via your package manager"
  fi
}

report() {
  local label="$1" ver="$2"
  [[ -z "$ver" ]] && return
  local key="${label}::${ver}"
  [[ -n "${SEEN[$key]+x}" ]] && return
  SEEN[$key]=1
  found=$(( found + 1 ))

  local minor major mn
  minor=$(cut -d. -f1-2 <<< "$ver")
  major=$(cut -d. -f1   <<< "$ver")
  mn=$(   cut -d. -f2   <<< "$ver")

  if [[ -n "${FIXED[$minor]+x}" ]]; then
    local fix="${FIXED[$minor]}"
    if ver_gte "$ver" "$fix"; then
      printf "  ${GRN}[SAFE]      ${RST} %-24s  PHP %s >= %s\n"    "$label" "$ver" "$fix"
    else
      printf "  ${RED}[VULNERABLE]${RST} %-24s  PHP %s < %s\n"     "$label" "$ver" "$fix"
      printf "               ${BLD}fix:${RST} %s\n"                "$(fix_cmd "$minor")"
    fi
  elif (( major < 8 || (major == 8 && mn <= 1) )); then
    printf "  ${RED}[VULNERABLE]${RST} %-24s  PHP %s  EOL — no patch, upgrade to 8.2.35+\n" "$label" "$ver"
  else
    printf "  ${YLW}[UNKNOWN]   ${RST} %-24s  PHP %s  branch not in fixed version map\n"    "$label" "$ver"
  fi
}

check_bin() {
  local label="$1" bin="$2"
  command -v "$bin" &>/dev/null || return 0
  local real
  real=$(readlink -f "$(command -v "$bin")" 2>/dev/null) || real="$(command -v "$bin")"
  local rkey="bin::${real}"
  [[ -n "${SEEN[$rkey]+x}" ]] && return 0
  SEEN[$rkey]=1
  report "$label" "$(parse_ver "$("$bin" -v 2>/dev/null)")"
}

hr() { printf '%56s\n' '' | tr ' ' '─'; }

# ── header ───────────────────────────────────────────────────────────────────

printf '\n'
printf '  .----------------------------------------------------.\n'
printf '  |  [PHP2SHELL] CVE-2026-109618 / CVE-2026-109619    |\n'
printf '  |  Fixed: 8.2.35 | 8.3.36 | 8.4.27 | 8.5.12        |\n'
printf '  |                                      by Kowalski  |\n'
printf "  '----------------------------------------------------'\n"

# ── 1. CLI binaries ──────────────────────────────────────────────────────────

echo
echo '  [CLI]'
check_bin php php
for v in 8.5 8.4 8.3 8.2 8.1 8.0 7.4 7.3 7.2; do
  check_bin "php${v}" "php${v}"
done

# ── 2. FPM binaries ──────────────────────────────────────────────────────────

echo
echo '  [FPM]'
check_bin php-fpm php-fpm
for v in 8.5 8.4 8.3 8.2 8.1 8.0 7.4; do
  check_bin "php${v}-fpm" "php${v}-fpm"
  check_bin "php-fpm${v}" "php-fpm${v}"
done

# ── 3. Package manager ───────────────────────────────────────────────────────
# One line per unique installed PHP version; package names deduplicated.

echo
echo '  [Packages]'
if command -v dpkg-query &>/dev/null; then
  while IFS= read -r ver; do
    report "pkg(apt)" "$ver"
  done < <(
    dpkg-query -W -f='${Version}\n' 'php*' 2>/dev/null \
      | sed 's/^[0-9]*://'                    \
      | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+'   \
      | sort -u
  )
elif command -v rpm &>/dev/null; then
  while IFS= read -r ver; do
    report "pkg(rpm)" "$ver"
  done < <(
    rpm -qa --queryformat '%{VERSION}\n' 'php*' 2>/dev/null \
      | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' \
      | sort -u
  )
elif command -v apk &>/dev/null; then
  while IFS= read -r ver; do
    report "pkg(apk)" "$ver"
  done < <(
    apk list --installed 2>/dev/null \
      | grep '^php'                        \
      | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' \
      | sort -u
  )
else
  echo '  no supported package manager detected'
fi

# ── 4. Running processes ─────────────────────────────────────────────────────
# Catches non-standard PHP binaries running as services.

echo
echo '  [Processes]'
proc_n=0
while IFS= read -r bin; do
  [[ -x "$bin" ]] || continue
  ver=$(parse_ver "$("$bin" -v 2>/dev/null)")
  [[ -z "$ver" ]] && continue
  report "proc" "$ver"
  proc_n=$(( proc_n + 1 ))
done < <(
  ps axo args= 2>/dev/null \
    | awk '{print $1}' \
    | grep -E '^/.*php' \
    | sort -u
)
(( proc_n == 0 )) && echo '  none detected'

# ── 5. HTTP response header (optional) ──────────────────────────────────────

if [[ -n "${1:-}" ]]; then
  echo
  echo "  [HTTP: $1]"
  if ! command -v curl &>/dev/null; then
    echo '  curl not found — skipping header check'
  else
    hdr=$(curl -sI --max-time 8 "$1" 2>/dev/null | grep -i 'x-powered-by:')
    ver=$(parse_ver "$hdr")
    if [[ -n "$ver" ]]; then
      report "x-powered-by" "$ver"
    else
      echo '  no PHP version in X-Powered-By header'
      echo '  note: suppress this header in production (expose_php = Off)'
    fi
  fi
fi

# ── summary ──────────────────────────────────────────────────────────────────

echo
hr
(( found == 0 )) && echo '  no PHP installations detected'
echo
