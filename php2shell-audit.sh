#!/usr/bin/env bash
# =============================================================================
# php2shell-audit.sh
# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) audit for ISPConfig /
# PHP-FPM / Apache / Nginx servers.
#
#  * READ-ONLY: it does not change anything.
#  * Run as root:      bash php2shell-audit.sh
#  * Without colors:   bash php2shell-audit.sh --no-color
#
# Exit codes:
#   0 = every running PHP is patched, nothing to do
#   1 = warnings: a vulnerable PHP is installed but not serving requests,
#       a non-web process still runs a replaced PHP binary, or a config
#       change is waiting for a reload
#   2 = a vulnerable (or unverifiable) PHP is serving requests, OR the package
#       is patched but the old (not restarted) process is still running
#
# Official fixed releases: 8.2.35, 8.3.36, 8.4.27, 8.5.12.
# Older branches (5.6, 7.x, 8.0, 8.1) can only be fixed by a distribution /
# sury.org backport: this is detected by looking for the CVE IDs in the
# package changelog.
# =============================================================================

set -u
export LC_ALL=C
shopt -s nullglob

CVE_RE='CVE-2026-109618|CVE-2026-109619'
EXIT_CODE=0
raise_exit() { [ "$1" -gt "$EXIT_CODE" ] && EXIT_CODE=$1; return 0; }

if [ -t 1 ] && [ "${1:-}" != "--no-color" ]; then
  C_RED=$'\e[31m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'; C_RESET=$'\e[0m'
else
  C_RED=''; C_GREEN=''; C_YELLOW=''; C_BOLD=''; C_DIM=''; C_RESET=''
fi
header() { printf '\n%s== %s ==%s\n' "$C_BOLD" "$1" "$C_RESET"; }
ok()     { printf '  %s[OK]%s    %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()   { printf '  %s[WARN]%s  %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
bad()    { printf '  %s[FAIL]%s  %s\n' "$C_RED" "$C_RESET" "$*"; }
info()   { printf '          %s\n' "$*"; }
advise() { printf '          %s-> %s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }

TIMEOUT_CMD=""; command -v timeout >/dev/null 2>&1 && TIMEOUT_CMD="timeout 15"
HAVE_DPKG=0; HAVE_RPM=0
command -v dpkg-query >/dev/null 2>&1 && HAVE_DPKG=1
[ "$HAVE_DPKG" = 0 ] && command -v rpm >/dev/null 2>&1 && HAVE_RPM=1

COUNT_VULN_RUNNING=0; COUNT_NEEDS_RESTART=0; COUNT_VULN_INSTALLED=0
COUNT_STALE_OTHER=0; COUNT_PENDING_CONFIG=0; COUNT_DOWN_POOLS=0

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# Status based on the upstream version: fixed | vuln | eol | pre54 | unknown
upstream_status() {
  local v=$1 major minor patch need=""
  v=${v#*:}                 # strip epoch
  v=${v%%[-~+ ]*}           # strip distribution suffix
  IFS=. read -r major minor patch _ <<<"$v"
  major=${major%%[!0-9]*}; minor=${minor%%[!0-9]*}; patch=${patch%%[!0-9]*}
  if [ -z "$major" ] || [ -z "$minor" ]; then echo unknown; return; fi
  patch=${patch:-0}
  case "$major.$minor" in
    8.2) need=35 ;; 8.3) need=36 ;; 8.4) need=27 ;; 8.5) need=12 ;;
  esac
  if [ -n "$need" ]; then
    if [ "$patch" -ge "$need" ]; then echo fixed; else echo vuln; fi
  elif [ "$major" -gt 8 ] || { [ "$major" -eq 8 ] && [ "$minor" -gt 5 ]; }; then echo fixed
  elif [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -lt 4 ]; }; then echo pre54
  else echo eol
  fi
}

package_of_file() {   # file -> package name (empty if not from a package)
  local f; f=$(readlink -f "$1" 2>/dev/null) || return 0
  if [ "$HAVE_DPKG" = 1 ]; then
    dpkg -S "$f" 2>/dev/null | grep -v '^diversion' | head -n1 | cut -d: -f1
  elif [ "$HAVE_RPM" = 1 ]; then
    rpm -qf "$f" --qf '%{NAME}\n' 2>/dev/null | grep -v 'not owned' | head -n1
  fi
}

package_version() {
  if [ "$HAVE_DPKG" = 1 ]; then dpkg-query -W -f='${Version}' "$1" 2>/dev/null
  elif [ "$HAVE_RPM" = 1 ]; then rpm -q --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null; fi
}

package_candidate() {   # newest version known to the local apt cache (dpkg only)
  [ "$HAVE_DPKG" = 1 ] && command -v apt-cache >/dev/null 2>&1 || return 0
  apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/ && $2 != "(none)" {print $2; exit}'
}

# 0 = changelog references the CVEs, 1 = it does not, 2 = no changelog available to check
changelog_has_fix() {
  local pkg=${1%%:*} base="" dir file seen=0 log
  if [ "$HAVE_DPKG" = 1 ]; then
    [[ $pkg =~ (php[0-9]+(\.[0-9]+)?) ]] && base=${BASH_REMATCH[1]}
    for dir in "/usr/share/doc/$pkg" ${base:+"/usr/share/doc/$base-common"}; do
      for file in "$dir/changelog.Debian.gz" "$dir/changelog.gz" "$dir/NEWS.Debian.gz"; do
        [ -r "$file" ] || continue
        seen=1
        zgrep -Eq "$CVE_RE" "$file" 2>/dev/null && return 0
      done
    done
    [ "$seen" = 1 ] && return 1
    return 2
  elif [ "$HAVE_RPM" = 1 ]; then
    log=$(rpm -q --changelog "$pkg" 2>/dev/null)
    [ -n "$log" ] || return 2
    grep -Eq "$CVE_RE" <<<"$log" && return 0
    return 1
  fi
  return 2
}

status_label() {
  case $1 in
    fixed)      printf '%sPATCHED%s' "$C_GREEN" "$C_RESET" ;;
    pre54)      printf '%sEOL (pre-5.4)%s' "$C_YELLOW" "$C_RESET" ;;
    unverified) printf '%sUNVERIFIED%s' "$C_YELLOW" "$C_RESET" ;;
    *)          printf '%sVULNERABLE%s' "$C_RED" "$C_RESET" ;;
  esac
}

to_bytes() {
  local v=${1// /} num unit
  [ "$v" = "-1" ] && { echo -1; return; }
  num=${v%%[!0-9]*}; unit=${v#"$num"}; num=${num:-0}
  case ${unit^^} in
    K*) echo $((num*1024)) ;; M*) echo $((num*1048576)) ;; G*) echo $((num*1073741824)) ;;
    *) echo "$num" ;;
  esac
}

is_on() { case ${1,,} in 1|on|yes|true) return 0 ;; *) return 1 ;; esac; }

process_start_time() {   # process start time (epoch seconds)
  local start_ticks boot_time hz
  start_ticks=$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}')
  boot_time=$(awk '/^btime/{print $2}' /proc/stat)
  hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
  [ -n "$start_ticks" ] && [ -n "$boot_time" ] && echo $(( boot_time + start_ticks / hz ))
}

parent_pid() { sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $2}'; }

# Prints the files (from $2...) modified after the epoch time in $1
changed_since() {
  local start=$1 file; shift
  for file in "$@"; do
    [ -e "$file" ] && [ "$(stat -c %Y "$file" 2>/dev/null || echo 0)" -gt "$start" ] && printf '%s ' "$file"
  done
  return 0
}

# Last effective assignment of a key in the given ini files
ini_get() {
  local key=$1; shift
  [ $# -gt 0 ] || return 0
  awk -v k="$key" '
    { line=$0; sub(/^[ \t]+/, "", line) }
    line ~ /^[;#\[]/ || index(line, "=") == 0 { next }
    { kk=substr(line, 1, index(line, "=")-1); gsub(/[ \t]+$/, "", kk) }
    kk == k { v=substr(line, index(line, "=")+1); sub(/[ \t]*;.*$/, "", v)
              gsub(/^[ \t"]+|[ \t"]+$/, "", v); val=v }
    END { if (val != "") print val }' "$@" 2>/dev/null
}

# -----------------------------------------------------------------------------
# Binary registry (key: resolved real path)
# -----------------------------------------------------------------------------
declare -A BIN_VERSION BIN_SAPI BIN_PKG BIN_PKG_VERSION BIN_STATUS BIN_NOTE BIN_INI_FILES
BIN_ORDER=()

classify_binary() {   # $1 = key; BIN_VERSION[$1] must already be set
  local key=$1 status pkg rc=1 candidate
  pkg=$(package_of_file "$key"); BIN_PKG[$key]=$pkg; BIN_PKG_VERSION[$key]=""
  [ -n "$pkg" ] && BIN_PKG_VERSION[$key]=$(package_version "$pkg")
  status=$(upstream_status "${BIN_VERSION[$key]}")
  case $status in
    fixed) BIN_STATUS[$key]=fixed; BIN_NOTE[$key]="official fixed release (or newer)" ;;
    pre54) BIN_STATUS[$key]=pre54
           BIN_NOTE[$key]="pre-5.4, EOL; the official advisory lists 5.4+ as affected, session.upload_progress does not exist here" ;;
    *)
      if [ -n "$pkg" ]; then changelog_has_fix "$pkg"; rc=$?; fi
      if [ "$rc" = 0 ]; then
        BIN_STATUS[$key]=fixed; BIN_NOTE[$key]="backported fix (package changelog references the CVEs)"
      elif [ -z "$pkg" ]; then
        BIN_STATUS[$key]=vuln; BIN_NOTE[$key]="not installed from a package (custom build?): patched only if it was patched manually"
      elif [ "$rc" = 2 ]; then
        BIN_STATUS[$key]=unverified
        if [ "$HAVE_DPKG" = 1 ]; then
          BIN_NOTE[$key]="cannot verify: the package changelog is not installed; check with: apt changelog $pkg | grep -E '$CVE_RE'"
        else
          BIN_NOTE[$key]="cannot verify: no changelog in the RPM database; check the vendor advisory for $pkg"
        fi
      elif [ "$status" = eol ]; then
        BIN_STATUS[$key]=vuln; BIN_NOTE[$key]="EOL branch, no CVE reference in the package changelog (no backport)"
      else
        BIN_STATUS[$key]=vuln; BIN_NOTE[$key]="below the fixed release, and no CVE reference in the changelog"
      fi ;;
  esac
  if [ "${BIN_STATUS[$key]}" != fixed ] && [ -n "$pkg" ]; then
    candidate=$(package_candidate "$pkg")
    if [ -n "$candidate" ] && [ "$candidate" != "${BIN_PKG_VERSION[$key]}" ]; then
      BIN_NOTE[$key]+="; newer package in the apt cache: $candidate"
    fi
  fi
}

# The binary's own php.ini and conf.d directory (parsed from -i output, HTML or text)
locate_ini_files() {
  local key=$1 output ini scan_dir file
  output=$($TIMEOUT_CMD "$key" -i 2>/dev/null)
  ini=$(grep -m1 'Loaded Configuration File' <<<"$output" | grep -oE '/[^ <]+' | head -n1)
  scan_dir=$(grep -m1 'Scan this dir' <<<"$output" | grep -oE '/[^ <]+' | head -n1)
  BIN_INI_FILES[$key]=""
  [ -n "$ini" ] && [ -r "$ini" ] && BIN_INI_FILES[$key]=$ini
  if [ -n "$scan_dir" ] && [ -d "$scan_dir" ]; then
    for file in "$scan_dir"/*.ini; do BIN_INI_FILES[$key]+="${BIN_INI_FILES[$key]:+|}$file"; done
  fi
}

probe_binary() {   # executable php / php-cgi / php-fpm
  local path=$1 key output version sapi
  [ -f "$path" ] && [ -x "$path" ] || return 1
  case $path in *config*|*phpize*|*phpdbg*) return 1 ;; esac
  key=$(readlink -f "$path") || return 1
  [ -n "${BIN_VERSION[$key]+x}" ] && return 0
  output=$($TIMEOUT_CMD "$key" -n -v 2>/dev/null | head -n1)
  version=$(sed -n 's/^PHP \([0-9][^ ]*\) .*/\1/p' <<<"$output")
  [ -n "$version" ] || return 1
  sapi=$(sed -n 's/^PHP [^ ]* (\([^)]*\)).*/\1/p' <<<"$output")
  BIN_VERSION[$key]=$version; BIN_SAPI[$key]=${sapi:-?}
  BIN_ORDER+=("$key")
  classify_binary "$key"
  locate_ini_files "$key"
  return 0
}

probe_module() {    # Apache mod_php module
  local so=$1 key pkg version dir file
  key=$(readlink -f "$so" 2>/dev/null) || key=$so
  [ -n "${BIN_VERSION[$key]+x}" ] && return 0
  pkg=$(package_of_file "$key"); version=""
  [ -n "$pkg" ] && version=$(package_version "$pkg")
  if [ -z "$version" ]; then   # last resort: version string embedded in the module
    version=$(grep -aoE 'PHP/[0-9]+\.[0-9]+\.[0-9]+' "$key" 2>/dev/null | head -n1); version=${version#PHP/}
  fi
  BIN_VERSION[$key]=${version:-unknown}; BIN_SAPI[$key]="apache2handler"
  BIN_ORDER+=("$key")
  classify_binary "$key"
  # mod_php ini: /etc/php/X.Y/apache2, /etc/php5/apache2 or /etc/php.ini
  BIN_INI_FILES[$key]=""
  if [[ $key =~ libphp([0-9]+\.[0-9]+)\.so ]]; then dir=/etc/php/${BASH_REMATCH[1]}/apache2
  elif [[ $key =~ libphp5\.so ]] && [ -d /etc/php5/apache2 ]; then dir=/etc/php5/apache2
  else dir=""; fi
  if [ -n "$dir" ]; then
    [ -r "$dir/php.ini" ] && BIN_INI_FILES[$key]="$dir/php.ini"
    for file in "$dir"/conf.d/*.ini; do BIN_INI_FILES[$key]+="${BIN_INI_FILES[$key]:+|}$file"; done
  elif [ -r /etc/php.ini ]; then
    BIN_INI_FILES[$key]=/etc/php.ini
    for file in /etc/php.d/*.ini; do BIN_INI_FILES[$key]+="|$file"; done
  fi
}

ini_files_of() {   # $1 binary key -> fills the global array INI_LIST
  local IFS='|'
  INI_LIST=()
  read -ra INI_LIST <<<"${BIN_INI_FILES[$1]:-}"
}

ini_of_binary() {  # $1 binary key, $2 ini key -> value (or empty)
  ini_files_of "$1"
  ini_get "$2" ${INI_LIST[@]+"${INI_LIST[@]}"}
}

# -----------------------------------------------------------------------------
# Evaluation + recommendations
#   evaluate_settings <status> <upload_progress> <upload_progress_source> <memory_limit>
#                     <memory_locked 0/1> <memory_source> <post_max_size> <mode: pool|modphp|cgi>
# -----------------------------------------------------------------------------
evaluate_settings() {
  local status=$1 upload=$2 upload_src=$3 mem=$4 mem_locked=$5 mem_src=$6 post=$7 mode=$8
  local post_bytes; post_bytes=$(to_bytes "$post")
  info "${C_DIM}session.upload_progress.enabled = $upload ($upload_src) | memory_limit = $mem ($mem_src) | post_max_size = $post${C_RESET}"

  if [ "$status" = fixed ]; then
    if [ "$mem" = "-1" ]; then
      advise "This version is patched: memory_limit = -1 is no longer needed, restore a finite value (e.g. 256M)."
    fi
    if [ "$upload" != "n/a" ] && is_on "$upload"; then
      info "(Optional hardening: session.upload_progress.enabled = 0, hardly any application uses it.)"
    fi
    return
  fi

  # --- vulnerable branch ---
  local fix_upload fix_mem fix_post
  case $mode in
    pool)   fix_upload="php_admin_flag[session.upload_progress.enabled] = off"
            fix_mem="php_admin_value[memory_limit] = -1"
            fix_post="php_admin_value[post_max_size] = 8M   (32M for sites with uploads)" ;;
    modphp) fix_upload="php_admin_flag session.upload_progress.enabled off   (Apache vhost / conf)"
            fix_mem="php_admin_value memory_limit -1"
            fix_post="php_admin_value post_max_size 8M   (32M for sites with uploads)" ;;
    *)      fix_upload="session.upload_progress.enabled = 0   (in the php.ini in use)"
            fix_mem="memory_limit = -1"
            fix_post="post_max_size = 8M   (32M for sites with uploads)" ;;
  esac

  if [ "$upload" = "n/a" ]; then
    info "session.upload_progress does not exist on this version; the only real fix is upgrading/migrating."
  elif is_on "$upload"; then
    bad "session.upload_progress.enabled is ON (known attack path of CVE-2026-109619)"
    advise "$fix_upload"
  else
    ok "session.upload_progress.enabled is off"
  fi

  if [ "$mem" != "-1" ]; then
    warn "memory_limit = $mem: hitting a finite limit is the trigger of CVE-2026-109618"
    advise "$fix_mem   (TEMPORARY until patched; add a cgroup/systemd MemoryMax as well)"
  elif [ "$mem_locked" != 1 ]; then
    warn "memory_limit = -1, but it is not locked at admin level: the application can reset it with ini_set() (WordPress does)"
    if [ "$mode" = cgi ]; then
      info "php-cgi/fcgid has no admin-level lock; upgrading or switching to PHP-FPM is the fix here."
    else
      advise "$fix_mem"
    fi
  else
    ok "memory_limit = -1 locked at admin level"
  fi

  if [ "$post_bytes" -gt $((32*1048576)) ] || [ "$post_bytes" = "-1" ] || [ "$post_bytes" = 0 ]; then
    warn "post_max_size = $post is too large"
    advise "$fix_post"
  fi
}

# =============================================================================
printf '%sPHP2Shell audit (CVE-2026-109618 / CVE-2026-109619)%s\n' "$C_BOLD" "$C_RESET"
printf 'Host: %s | Time: %s\n' "$(hostname -f 2>/dev/null || hostname)" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
[ "$(id -u)" -eq 0 ] || warn "Not running as root: some configs and processes will not be visible."
[ -r /etc/os-release ] && printf 'OS: %s\n' "$(. /etc/os-release; echo "${PRETTY_NAME:-?}")"
if [ -r /usr/local/ispconfig/server/lib/config.inc.php ]; then
  printf 'ISPConfig: %s\n' "$(grep -oE "ISPC_APP_VERSION'[^)]*" /usr/local/ispconfig/server/lib/config.inc.php | grep -oE "[0-9][0-9.p]*" | head -n1)"
fi

# =============================================================================
header "1. Installed core PHP packages"
PACKAGE_LINES=""
if [ "$HAVE_DPKG" = 1 ]; then
  PACKAGE_LINES=$(dpkg-query -W -f='${Status}\t${Package}\t${Version}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null \
    | awk -F'\t' '$1 ~ / installed$/ && $2 ~ /^(php[0-9][0-9.]*-(common|cli|fpm|cgi)|libapache2-mod-php[0-9][0-9.]*)$/ {print $2"\t"$3}')
elif [ "$HAVE_RPM" = 1 ]; then
  PACKAGE_LINES=$(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null \
    | grep -E '^(php|php[0-9]+-php)(-common|-cli|-fpm|-cgi)?'$'\t' | sort)
fi
if [ -z "$PACKAGE_LINES" ]; then
  info "No PHP installed from the package manager (may be a custom build, see section 2)."
else
  while IFS=$'\t' read -r pkg version; do
    status=$(upstream_status "$version"); origin=""
    [[ $version == *sury* ]] && origin=" [sury.org]"
    if [ "$status" != fixed ] && [ "$status" != pre54 ]; then
      changelog_has_fix "$pkg"
      case $? in 0) status=fixed ;; 2) status=unverified ;; esac
    fi
    printf '  %-30s %-38s %s%s\n' "$pkg" "$version" "$(status_label "$status")" "$origin"
  done <<<"$PACKAGE_LINES"
fi

# =============================================================================
header "2. PHP binaries and patch status"
for candidate in /usr/bin/php /usr/bin/php[0-9]* /usr/bin/php-cgi* /usr/sbin/php-fpm* /usr/sbin/php5-fpm \
         /usr/local/bin/php /usr/local/bin/php-cgi /usr/local/sbin/php-fpm \
         /opt/*/bin/php /opt/*/bin/php-cgi /opt/*/sbin/php-fpm \
         /opt/remi/*/root/usr/bin/php /opt/remi/*/root/usr/bin/php-cgi /opt/remi/*/root/usr/sbin/php-fpm \
         /usr/lib/cgi-bin/php*; do
  probe_binary "$candidate"
done
# mod_php modules (loaded ones also show up in section 3)
for so in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /usr/lib/httpd/modules/libphp*.so; do
  probe_module "$so"
done

if [ ${#BIN_ORDER[@]} -eq 0 ]; then
  info "No PHP binary found."
else
  for key in "${BIN_ORDER[@]}"; do
    printf '  %-42s %-15s %-12s %s\n' "$key" "${BIN_SAPI[$key]}" "${BIN_VERSION[$key]%%[-~+]*}" "$(status_label "${BIN_STATUS[$key]}")"
    info "${C_DIM}package: ${BIN_PKG[$key]:--} ${BIN_PKG_VERSION[$key]} | ${BIN_NOTE[$key]}${C_RESET}"
    [ "${BIN_STATUS[$key]}" != fixed ] && COUNT_VULN_INSTALLED=$((COUNT_VULN_INSTALLED+1))
  done
fi
[ "$COUNT_VULN_INSTALLED" -gt 0 ] && raise_exit 1

# =============================================================================
header "3. Running PHP processes (what actually serves requests)"
declare -A RUNNING_BIN RUNNING_START CHECKED_PIDS MASTER_CONF_BIN
MODPHP_LOADED=0

# $1 pid, $2 description, $3 binary/module path (may end in "(deleted)"), $4.. extra config files
check_running() {
  local pid=$1 desc=$2 path=$3 clean_path deleted=0 start mtime key; shift 3
  CHECKED_PIDS[$pid]=1
  clean_path=${path% (deleted)}; [ "$clean_path" != "$path" ] && deleted=1
  key=$(readlink -f "$clean_path" 2>/dev/null || echo "$clean_path")
  if [[ $key == *.so ]]; then probe_module "$key"; else probe_binary "$key" || true; fi
  RUNNING_BIN[$key]=1
  start=$(process_start_time "$pid"); mtime=$(stat -c %Y "$key" 2>/dev/null || echo 0)
  if [ -n "$start" ] && { [ -z "${RUNNING_START[$key]:-}" ] || [ "$start" -lt "${RUNNING_START[$key]}" ]; }; then
    RUNNING_START[$key]=$start
  fi
  local needs_restart=0
  { [ "$deleted" = 1 ] || { [ -n "$start" ] && [ "$mtime" -gt "$start" ]; }; } && needs_restart=1
  local status=${BIN_STATUS[$key]:-vuln} version=${BIN_VERSION[$key]:-?}
  version=${version%%[-~+]*}
  if [ "$status" = fixed ] && [ "$needs_restart" = 1 ]; then
    bad "$desc (PID $pid): patched $version is on disk, but the process still runs the OLD binary -> restart required"
    COUNT_NEEDS_RESTART=$((COUNT_NEEDS_RESTART+1)); raise_exit 2
  elif [ "$status" = fixed ]; then
    ok "$desc (PID $pid): $version $(status_label fixed)"
  else
    bad "$desc (PID $pid): $version $(status_label "$status") (${key})"
    COUNT_VULN_RUNNING=$((COUNT_VULN_RUNNING+1)); raise_exit 2
  fi

  # Config files changed after the process started are not active yet
  if [ -n "$start" ]; then
    ini_files_of "$key"
    local changed; changed=$(changed_since "$start" ${INI_LIST[@]+"${INI_LIST[@]}"} "$@")
    if [ -n "$changed" ]; then
      warn "  config changed after this process started, NOT active until reload/restart: $changed"
      COUNT_PENDING_CONFIG=$((COUNT_PENDING_CONFIG+1)); raise_exit 1
    fi
  fi
}

found_any=0
for pid in $(pgrep -f 'php-fpm: master process' 2>/dev/null); do
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
  conf=$(tr '\0' ' ' <"/proc/$pid/cmdline" | sed -n 's/.*(\(.*\)).*/\1/p')
  if [ -n "$conf" ]; then
    MASTER_CONF_BIN[$conf]=$(readlink -f "${exe% (deleted)}" 2>/dev/null || echo "${exe% (deleted)}")
    check_running "$pid" "PHP-FPM master [$conf]" "$exe" "$conf"
  else
    check_running "$pid" "PHP-FPM master" "$exe"
  fi
  found_any=1
done
for pid in $(pgrep -o -x 'apache2|httpd' 2>/dev/null); do
  CHECKED_PIDS[$pid]=1
  info "Apache is running (PID $pid)"
  while read -r so; do
    check_running "$pid" "Apache mod_php" "$so"; found_any=1; MODPHP_LOADED=1
  done < <(awk '$6 ~ /libphp/ {p=$6; for(i=7;i<=NF;i++) p=p" "$i; print p}' "/proc/$pid/maps" 2>/dev/null | sort -u)
done
declare -A CGI_SEEN
for pid in $(pgrep -f 'php-cgi|php[0-9.]*-cgi' 2>/dev/null); do
  CHECKED_PIDS[$pid]=1
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
  [ -n "${CGI_SEEN[$exe]+x}" ] && continue; CGI_SEEN[$exe]=1
  check_running "$pid" "php-cgi (FastCGI/fcgid)" "$exe"; found_any=1
done
pgrep -x nginx >/dev/null 2>&1 && info "Nginx is running"
[ "$found_any" = 0 ] && info "No PHP web process is running (PHP-FPM / mod_php / php-cgi)."

# Any other process (queue workers, supervisor jobs, long cron jobs, FPM workers
# of an unknown master...) that still runs a replaced PHP binary or extension
printf '\n'
SELF_PID=$$
for proc_dir in /proc/[0-9]*; do
  pid=${proc_dir#/proc/}
  [ "$pid" = "$SELF_PID" ] && continue
  [ -n "${CHECKED_PIDS[$pid]+x}" ] && continue
  ppid=$(parent_pid "$pid")
  [ -n "$ppid" ] && [ -n "${CHECKED_PIDS[$ppid]+x}" ] && continue   # workers of a master checked above
  stale=""
  exe=$(readlink "$proc_dir/exe" 2>/dev/null) || exe=""
  case $exe in *php*" (deleted)") stale=${exe% (deleted)} ;; esac
  if [ -z "$stale" ]; then
    stale=$(awk '$6 ~ /php/ && $NF == "(deleted)" {print $6; exit}' "$proc_dir/maps" 2>/dev/null)
  fi
  [ -n "$stale" ] || continue
  cmd=$(tr '\0' ' ' <"$proc_dir/cmdline" 2>/dev/null | cut -c1-100)
  warn "PID $pid still uses a replaced PHP file ($stale): ${cmd:-?}"
  COUNT_STALE_OTHER=$((COUNT_STALE_OTHER+1))
done
if [ "$COUNT_STALE_OTHER" -gt 0 ]; then
  advise "Restart these processes (supervisor / queue workers / services that own them)."
  raise_exit 1
else
  ok "No other process runs a replaced PHP binary or extension."
fi

# =============================================================================
# Collect vhosts: socket -> vhosts, fcgid starters, mod_php vhosts
declare -A SOCKET_VHOSTS
FCGID_ENTRIES=(); MODPHP_VHOSTS=()
normalize_listen() {
  local s=$1; s=${s#unix:}; s=${s#fcgi://}; s=${s%/}; s=${s%%|*}
  [[ $s =~ ^[0-9]+$ ]] && s="127.0.0.1:$s"
  s=${s/#localhost:/127.0.0.1:}
  echo "$s"
}
add_socket() {
  local k; k=$(normalize_listen "$1")
  [[ " ${SOCKET_VHOSTS[$k]:-} " == *" $2 "* ]] || SOCKET_VHOSTS[$k]+="${SOCKET_VHOSTS[$k]:+ }$2"
}

for conf_file in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
  [ -f "$conf_file" ] || continue
  vhost=$(grep -m1 -E '^[[:space:]]*server_name[[:space:]]' "$conf_file" | sed -E 's/^[[:space:]]*server_name[[:space:]]+//; s/[;[:space:]].*//')
  vhost=${vhost:-$(basename "$conf_file")}
  while read -r sock; do [ -n "$sock" ] && add_socket "$sock" "$vhost"; done < <(
    grep -E '^[^#]*fastcgi_pass' "$conf_file" | grep -oE 'fastcgi_pass[[:space:]]+[^;]+' | sed -E 's/fastcgi_pass[[:space:]]+//' | sort -u)
done

for conf_file in /etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf /etc/httpd/sites-enabled/*; do
  [ -f "$conf_file" ] || continue
  vhost=$(grep -m1 -iE '^[[:space:]]*ServerName[[:space:]]' "$conf_file" | awk '{print $2}')
  vhost=${vhost:-$(basename "$conf_file")}
  has_handler=0
  while read -r sock; do [ -n "$sock" ] && { add_socket "$sock" "$vhost"; has_handler=1; }; done < <(
    grep -vE '^[[:space:]]*#' "$conf_file" | grep -oE 'unix:[^|" ]+|-socket[[:space:]]+[^[:space:]]+|fcgi://[0-9.a-z]+:[0-9]+' \
      | sed -E 's/^-socket[[:space:]]+//' | sort -u)
  while read -r wrapper; do
    [ -n "$wrapper" ] || continue; has_handler=1
    FCGID_ENTRIES+=("$vhost|$wrapper")
  done < <(grep -vE '^[[:space:]]*#' "$conf_file" | grep -oE 'FcgidWrapper[[:space:]]+[^[:space:]]+' | awk '{print $2}' | sort -u)
  if [ "$has_handler" = 0 ] && [ "$MODPHP_LOADED" = 1 ]; then MODPHP_VHOSTS+=("$vhost|$conf_file"); fi
done

# =============================================================================
header "4. PHP-FPM pools, their vhosts and recommended settings"
declare -A SOCKET_MATCHED POOL_BINARY POOL_SEEN
POOL_FILES=()

# Pools included by the running FPM masters (covers custom paths, e.g. /opt builds)
for conf in "${!MASTER_CONF_BIN[@]}"; do
  [ -r "$conf" ] || continue
  POOL_BINARY[$(readlink -f "$conf")]=${MASTER_CONF_BIN[$conf]}
  POOL_FILES+=("$conf")
  while read -r pattern; do
    [ -n "$pattern" ] || continue
    [[ $pattern == /* ]] || pattern="$(dirname "$(dirname "$conf")")/$pattern"
    for pool_file in $pattern; do     # glob expansion is intended here
      [ -f "$pool_file" ] || continue
      POOL_BINARY[$(readlink -f "$pool_file")]=${MASTER_CONF_BIN[$conf]}
      POOL_FILES+=("$pool_file")
    done
  done < <(awk '/^[ \t]*include[ \t]*=/ { v=substr($0, index($0, "=")+1); gsub(/^[ \t"]+|[ \t"]+$/, "", v); print v }' "$conf")
done
# Well-known locations (also catches pools of FPM versions that are not running)
POOL_FILES+=(/etc/php/*/fpm/pool.d/*.conf /etc/php5/fpm/pool.d/*.conf /opt/*/etc/php-fpm.d/*.conf \
             /etc/php-fpm.d/*.conf /etc/opt/remi/*/php-fpm.d/*.conf)

fpm_binary_for_pool() {
  local f=$1 ver dir cand
  case $f in
    /etc/php/*/fpm/*) ver=${f#/etc/php/}; ver=${ver%%/*}; echo "/usr/sbin/php-fpm$ver" ;;
    /etc/php5/*)      echo /usr/sbin/php5-fpm ;;
    /opt/*/etc/*)     dir=${f#/opt/}; dir=${dir%%/*}
                      for cand in "/opt/$dir/sbin/php-fpm" "/opt/$dir/bin/php-fpm"; do
                        [ -x "$cand" ] && { echo "$cand"; return; }
                      done ;;
    /etc/opt/remi/*)  dir=${f#/etc/opt/remi/}; dir=${dir%%/*}; echo "/opt/remi/$dir/root/usr/sbin/php-fpm" ;;
    /etc/php-fpm.d/*) echo /usr/sbin/php-fpm ;;
  esac
}

parse_pool_file() {   # output: POOL\tname | LISTEN\tvalue | SET\tkey\tvalue\tadmin|user
  awk '
    { line=$0; sub(/^[ \t]+/, "", line) }
    line ~ /^[;#]/ { next }
    line ~ /^\[[^]]+\][ \t]*$/ { n=line; sub(/^\[/, "", n); sub(/\][ \t]*$/, "", n); print "POOL\t" n; next }
    line ~ /^listen[ \t]*=/ { v=substr(line, index(line, "=")+1); gsub(/^[ \t]+|[ \t]+$/, "", v); print "LISTEN\t" v; next }
    line ~ /^php_(admin_)?(value|flag)\[/ {
      kind = (line ~ /^php_admin_/) ? "admin" : "user"
      k=line; sub(/^[^[]*\[/, "", k); sub(/\].*$/, "", k)
      v=substr(line, index(line, "=")+1); gsub(/^[ \t"]+|[ \t"]+$/, "", v)
      print "SET\t" k "\t" v "\t" kind }' "$1"
}

report_pool() {
  local pool_file=$1 fpm_bin=$2 pool_name=$3 listen=$4; shift 4
  [ "$pool_name" = global ] && return 0
  local -A override=() override_kind=()
  local entry k v kind
  for entry in "$@"; do IFS=$'\t' read -r k v kind <<<"$entry"; override[$k]=$v; override_kind[$k]=$kind; done

  local key status version running vhosts norm
  key=$(readlink -f "$fpm_bin" 2>/dev/null || echo "$fpm_bin")
  status=${BIN_STATUS[$key]:-vuln}; version=${BIN_VERSION[$key]:-?}
  running="not running"; [ -n "${RUNNING_BIN[$key]+x}" ] && running="running"
  norm=$(normalize_listen "$listen"); SOCKET_MATCHED[$norm]=1
  vhosts=${SOCKET_VHOSTS[$norm]:-}

  printf '\n  %s[%s]%s %s\n' "$C_BOLD" "$pool_name" "$C_RESET" "$pool_file"
  printf '          PHP %s %s | FPM: %s | listen: %s\n' "${version%%[-~+]*}" "$(status_label "$status")" "$running" "$listen"
  info "vhosts: ${vhosts:-(no vhost in the web server config points here)}"

  if [ "$running" = "running" ] && [ -n "${RUNNING_START[$key]:-}" ]; then
    if [ -n "$(changed_since "${RUNNING_START[$key]}" "$pool_file")" ]; then
      warn "pool file changed after PHP-FPM started: the values below are NOT active until a reload"
      COUNT_PENDING_CONFIG=$((COUNT_PENDING_CONFIG+1)); raise_exit 1
    fi
  elif [ "$running" != "running" ] && [ -n "$vhosts" ]; then
    warn "vhosts point to this pool, but its PHP-FPM is not running (502 errors, or another FPM owns the socket?)"
    COUNT_DOWN_POOLS=$((COUNT_DOWN_POOLS+1)); raise_exit 1
  fi

  local upload upload_src mem mem_src mem_locked=0 post
  if [ "$status" = pre54 ]; then upload="n/a"; upload_src="-"
  elif [ -n "${override[session.upload_progress.enabled]+x}" ]; then
    upload=${override[session.upload_progress.enabled]}; upload_src="pool ${override_kind[session.upload_progress.enabled]}"
  else upload=$(ini_of_binary "$key" session.upload_progress.enabled); upload=${upload:-On}; upload_src="php.ini"; fi
  if [ -n "${override[memory_limit]+x}" ]; then
    mem=${override[memory_limit]}; mem_src="pool ${override_kind[memory_limit]}"
    [ "${override_kind[memory_limit]}" = admin ] && mem_locked=1
  else mem=$(ini_of_binary "$key" memory_limit); mem=${mem:-128M}; mem_src="php.ini"; fi
  if [ -n "${override[post_max_size]+x}" ]; then post=${override[post_max_size]}
  else post=$(ini_of_binary "$key" post_max_size); post=${post:-8M}; fi

  # Remember whether user-level overrides (.user.ini) could undo the mitigations
  if [ "$status" != fixed ] && [ "$running" = "running" ]; then
    [ "${override_kind[session.upload_progress.enabled]:-}" != admin ] || [ "$mem_locked" != 1 ] && USER_OVERRIDE_RISK=1
  fi

  evaluate_settings "$status" "$upload" "$upload_src" "$mem" "$mem_locked" "$mem_src" "$post" pool
  [ "$status" != fixed ] && [ "$running" = "running" ] && [ -n "$vhosts" ] && raise_exit 2
}

USER_OVERRIDE_RISK=0
pool_count=0
for pool_file in "${POOL_FILES[@]}"; do
  real_pool=$(readlink -f "$pool_file") || continue
  [ -n "${POOL_SEEN[$real_pool]+x}" ] && continue
  POOL_SEEN[$real_pool]=1
  fpm_bin=${POOL_BINARY[$real_pool]:-$(fpm_binary_for_pool "$pool_file")}
  [ -n "$fpm_bin" ] && probe_binary "$fpm_bin"
  current_pool=""; current_listen=""; pool_settings=()
  while IFS= read -r line; do
    case $line in
      POOL$'\t'*)   if [ -n "$current_pool" ]; then
                      report_pool "$pool_file" "$fpm_bin" "$current_pool" "$current_listen" ${pool_settings[@]+"${pool_settings[@]}"}
                      [ "$current_pool" != global ] && pool_count=$((pool_count+1))
                    fi
                    current_pool=${line#POOL$'\t'}; current_listen=""; pool_settings=() ;;
      LISTEN$'\t'*) current_listen=${line#LISTEN$'\t'} ;;
      SET$'\t'*)    pool_settings+=("${line#SET$'\t'}") ;;
    esac
  done < <(parse_pool_file "$pool_file")
  if [ -n "$current_pool" ]; then
    report_pool "$pool_file" "$fpm_bin" "$current_pool" "$current_listen" ${pool_settings[@]+"${pool_settings[@]}"}
    [ "$current_pool" != global ] && pool_count=$((pool_count+1))
  fi
done
[ "$pool_count" = 0 ] && info "No PHP-FPM pool configuration found."

unmatched=""
for sock in "${!SOCKET_VHOSTS[@]}"; do
  [ -z "${SOCKET_MATCHED[$sock]+x}" ] && unmatched+="    $sock  <-  ${SOCKET_VHOSTS[$sock]}"$'\n'
done
if [ -n "$unmatched" ]; then
  printf '\n'; warn "FastCGI addresses referenced by the web server but not matched to any pool file (check manually):"
  printf '%s' "$unmatched"
fi

# =============================================================================
header "5. Other PHP handlers: mod_php and FastCGI/fcgid"
if [ "$MODPHP_LOADED" = 1 ]; then
  for key in "${!RUNNING_BIN[@]}"; do
    [[ $key == *.so ]] || continue
    status=${BIN_STATUS[$key]:-vuln}
    printf '\n  %smod_php%s %s: PHP %s %s\n' "$C_BOLD" "$C_RESET" "$key" "${BIN_VERSION[$key]%%[-~+]*}" "$(status_label "$status")"
    if [ "$status" != fixed ]; then
      bad "mod_php is loaded: PHP parses the multipart body before the application runs, on every vhost that serves .php via mod_php."
      module_name=$(basename "$key" .so); module_name=${module_name#lib}
      advise "If every site runs on PHP-FPM, disable it: a2dismod ${module_name}  (then restart Apache)"
      USER_OVERRIDE_RISK=1
    fi
    ini_files_of "$key"
    upload=$(ini_get session.upload_progress.enabled ${INI_LIST[@]+"${INI_LIST[@]}"}); upload=${upload:-On}
    mem=$(ini_get memory_limit ${INI_LIST[@]+"${INI_LIST[@]}"}); mem=${mem:-128M}
    post=$(ini_get post_max_size ${INI_LIST[@]+"${INI_LIST[@]}"}); post=${post:-8M}
    info "global (${INI_LIST[0]:-php.ini not found}):"
    [ "$status" = pre54 ] && upload="n/a"
    evaluate_settings "$status" "$upload" "php.ini" "$mem" 0 "php.ini" "$post" modphp
  done
  if [ ${#MODPHP_VHOSTS[@]} -gt 0 ]; then
    apache_start=""
    for key in "${!RUNNING_BIN[@]}"; do [[ $key == *.so ]] && apache_start=${RUNNING_START[$key]:-}; done
    info ""
    info "Apache vhosts without an FPM/FastCGI handler (they use mod_php, or have no PHP):"
    for entry in "${MODPHP_VHOSTS[@]}"; do
      vhost=${entry%%|*}; conf_file=${entry#*|}
      directives=$(grep -iE 'php_(admin_)?(value|flag)[[:space:]]+(session\.upload_progress\.enabled|memory_limit|post_max_size)' "$conf_file" \
           | sed -E 's/^[[:space:]]+//' | tr '\n' ';')
      info "  - $vhost  ${C_DIM}${directives:+[$directives]}${C_RESET}"
      if [ -n "$apache_start" ] && [ -n "$(changed_since "$apache_start" "$conf_file")" ]; then
        warn "    $conf_file changed after Apache started: NOT active until an Apache reload"
        COUNT_PENDING_CONFIG=$((COUNT_PENDING_CONFIG+1)); raise_exit 1
      fi
    done
  fi
else
  info "mod_php is not loaded in a running Apache (or Apache is not running)."
fi

if [ ${#FCGID_ENTRIES[@]} -gt 0 ]; then
  printf '\n  %sFastCGI/fcgid vhosts (php-cgi)%s\n' "$C_BOLD" "$C_RESET"
  for entry in "${FCGID_ENTRIES[@]}"; do
    vhost=${entry%%|*}; wrapper=${entry#*|}
    cgi_bin=$(grep -m1 -oE 'exec[[:space:]]+[^[:space:]\\]+' "$wrapper" 2>/dev/null | awk '{print $2}')
    phprc=$(grep -m1 -oE 'PHPRC=[^[:space:]]+' "$wrapper" 2>/dev/null | cut -d= -f2 | tr -d '"'"'")
    if [ -z "$cgi_bin" ] || ! probe_binary "$cgi_bin"; then warn "$vhost: could not parse the starter script ($wrapper)"; continue; fi
    key=$(readlink -f "$cgi_bin"); status=${BIN_STATUS[$key]:-vuln}
    printf '\n  %s%s%s  starter: %s\n' "$C_BOLD" "$vhost" "$C_RESET" "$wrapper"
    printf '          PHP %s %s (%s)\n' "${BIN_VERSION[$key]%%[-~+]*}" "$(status_label "$status")" "$key"
    ini_files_of "$key"
    [ -n "$phprc" ] && [ -r "${phprc%/}/php.ini" ] && INI_LIST[0]="${phprc%/}/php.ini"
    upload=$(ini_get session.upload_progress.enabled ${INI_LIST[@]+"${INI_LIST[@]}"}); upload=${upload:-On}
    mem=$(ini_get memory_limit ${INI_LIST[@]+"${INI_LIST[@]}"}); mem=${mem:-128M}
    post=$(ini_get post_max_size ${INI_LIST[@]+"${INI_LIST[@]}"}); post=${post:-8M}
    [ "$status" = pre54 ] && upload="n/a"
    info "php.ini: ${INI_LIST[0]:-?}"
    evaluate_settings "$status" "$upload" "php.ini" "$mem" 0 "php.ini" "$post" cgi
    if [ "$status" != fixed ]; then raise_exit 2; USER_OVERRIDE_RISK=1; fi
  done
fi

# =============================================================================
header "6. Per-directory overrides (.user.ini / .htaccess)"
if [ "$USER_OVERRIDE_RISK" = 0 ]; then
  info "Skipped: no vulnerable PHP serves requests without admin-locked mitigations."
else
  info "A vulnerable PHP serves requests and some settings are not admin-locked: these files can undo the mitigations."
  override_files=0; override_shown=0
  for root in /var/www /srv/www /home; do
    [ -d "$root" ] || continue
    while IFS= read -r -d '' file; do
      case $file in
        */.user.ini) match=$(grep -E '^[[:space:]]*(session\.upload_progress\.enabled|memory_limit)[[:space:]]*=' "$file" 2>/dev/null) ;;
        *)           match=$(grep -E '^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]+(session\.upload_progress\.enabled|memory_limit)' "$file" 2>/dev/null) ;;
      esac
      [ -n "$match" ] || continue
      override_files=$((override_files+1))
      if [ "$override_shown" -lt 25 ]; then
        warn "$file: $(tr '\n' ';' <<<"$match" | sed -E 's/[[:space:]]+/ /g')"
        override_shown=$((override_shown+1))
      fi
    done < <($TIMEOUT_CMD find "$root" -xdev -maxdepth 8 \( -name .user.ini -o -name .htaccess \) -type f -size -1024k -print0 2>/dev/null)
  done
  if [ "$override_files" = 0 ]; then
    ok "No .user.ini / .htaccess overrides of session.upload_progress.enabled or memory_limit found."
  else
    [ "$override_files" -gt "$override_shown" ] && info "... and $((override_files-override_shown)) more file(s)."
    advise "Use php_admin_flag / php_admin_value (pool or Apache config): those cannot be overridden per directory."
    raise_exit 1
  fi
fi

# =============================================================================
header "7. Summary"
if [ "$EXIT_CODE" = 0 ]; then
  ok "Every PHP serving requests is patched, no restart or reload is pending. Nothing to do."
else
  [ "$COUNT_VULN_RUNNING" -gt 0 ]   && bad  "Vulnerable or unverifiable RUNNING PHP processes: $COUNT_VULN_RUNNING"
  [ "$COUNT_NEEDS_RESTART" -gt 0 ]  && bad  "Patched package, but restart pending: $COUNT_NEEDS_RESTART"
  [ "$COUNT_STALE_OTHER" -gt 0 ]    && warn "Other processes still running a replaced PHP binary: $COUNT_STALE_OTHER"
  [ "$COUNT_PENDING_CONFIG" -gt 0 ] && warn "Config changes waiting for a reload: $COUNT_PENDING_CONFIG"
  [ "$COUNT_DOWN_POOLS" -gt 0 ]     && warn "Pools used by vhosts whose PHP-FPM is not running: $COUNT_DOWN_POOLS"
  [ "$COUNT_VULN_INSTALLED" -gt 0 ] && warn "Vulnerable or unverifiable installed PHP binaries/modules in total: $COUNT_VULN_INSTALLED"

  cat <<'EOF'

  Recommended order of actions:
   1. Update: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; for old branches (5.6-8.1) use a
      backported package (Debian/Ubuntu: packages.sury.org). Then RESTART PHP-FPM
      (not reload), or Apache when using mod_php. Run this script again.
   2. Where no fix is available yet: temporary settings (see above, per pool). Apply
      both, as each narrows a different CVE, and neither is a complete protection.
      Reload the service afterwards, then re-run this script to confirm.
   3. ISPConfig: pool files are regenerated by ISPConfig, manual edits may be lost.
      - Per PHP version, in the FPM php.ini: session.upload_progress.enabled = 0
      - Per website: Website -> Options -> "Custom php.ini settings"
        (re-run this script to verify they ended up as php_admin_* lines in the pool)
      - Server-wide: a custom pool template at
        /usr/local/ispconfig/server/conf-custom/php_fpm_pool.conf.master
        (original: /usr/local/ispconfig/server/conf/), then Tools -> Resync.
   4. Web server limits (per site, ISPConfig "nginx/Apache Directives"):
        nginx:   client_max_body_size 8m;    (32m for sites with uploads)
        Apache:  LimitRequestBody 8388608
      If a site does not accept uploads at all, multipart requests can be blocked:
        nginx:   if ($content_type ~* "multipart/form-data") { return 403; }
        Apache:  <If "%{CONTENT_TYPE} =~ /multipart\/form-data/i">
                     Require all denied
                 </If>
   5. After patching: restore a finite memory_limit and look for signs of compromise
      (repeated 500 errors after multipart POSTs, unknown PHP files, new admin
      users, suspicious outbound connections).
EOF
fi

exit "$EXIT_CODE"
