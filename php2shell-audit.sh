#!/usr/bin/env bash
# =============================================================================
# php2shell-audit.sh
# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) audit for ISPConfig /
# PHP-FPM / Apache / Nginx servers.
#
#  * READ-ONLY: it does not change anything.
#  * Run as root:      bash php2shell-audit.sh
#  * Without colors:   bash php2shell-audit.sh --no-color
#  * Compromise checks look back to 2026-10-20 15:00 UTC (first public leak);
#    another start:    bash php2shell-audit.sh --since '2026-10-21 14:00 UTC'
#
# Exit codes:
#   0 = every running PHP is patched, nothing to do
#   1 = warnings: a vulnerable PHP is installed but not serving requests,
#       a non-web process still runs a replaced PHP binary, a config change
#       is waiting for a reload, or a vhost serving vulnerable PHP has no
#       multipart block
#   2 = a vulnerable (or unverifiable) PHP is serving requests, OR the package
#       is patched but the old (not restarted) process is still running,
#       OR a strong sign of compromise was found (section 9)
#  64 = invalid command line option
# "[CHECK]" lines (section 9) are items to review by hand; they do not change
# the exit code.
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

USE_COLOR=1
SINCE_ARG="2026-10-20 15:00 UTC"
while [ $# -gt 0 ]; do
  case $1 in
    --no-color) USE_COLOR=0 ;;
    --since)    shift; SINCE_ARG=${1:-} ;;
    --since=*)  SINCE_ARG=${1#--since=} ;;
    -h|--help)  awk 'NR > 2 && /^#/ {sub(/^# ?/, ""); print; next} NR > 2 {exit}' "$0"; exit 0 ;;
    *)          printf 'Unknown option: %s (see --help)\n' "$1" >&2; exit 64 ;;
  esac
  shift
done
SINCE_EPOCH=$(date -d "$SINCE_ARG" +%s 2>/dev/null) || SINCE_EPOCH=""
if [ -z "$SINCE_EPOCH" ]; then printf 'Invalid --since value: %s\n' "$SINCE_ARG" >&2; exit 64; fi
SINCE_STAMP=$(date -d "@$SINCE_EPOCH" +%Y%m%d%H%M%S)   # local time, for comparing log timestamps
SINCE_HUMAN=$(date -d "@$SINCE_EPOCH" '+%Y-%m-%d %H:%M %Z')

if [ -t 1 ] && [ "$USE_COLOR" = 1 ]; then
  C_RED=$'\e[31m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'; C_RESET=$'\e[0m'
else
  C_RED=''; C_GREEN=''; C_YELLOW=''; C_BOLD=''; C_DIM=''; C_RESET=''
fi
header() { printf '\n%s== %s ==%s\n' "$C_BOLD" "$1" "$C_RESET"; }
ok()     { printf '  %s[OK]%s    %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()   { printf '  %s[WARN]%s  %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
bad()    { printf '  %s[FAIL]%s  %s\n' "$C_RED" "$C_RESET" "$*"; }
check()  { printf '  %s[CHECK]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; COUNT_REVIEW=$((COUNT_REVIEW+1)); }
info()   { printf '          %s\n' "$*"; }
advise() { printf '          %s-> %s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }

TIMEOUT_CMD=""; command -v timeout >/dev/null 2>&1 && TIMEOUT_CMD="timeout 15"
HAVE_DPKG=0; HAVE_RPM=0
command -v dpkg-query >/dev/null 2>&1 && HAVE_DPKG=1
[ "$HAVE_DPKG" = 0 ] && command -v rpm >/dev/null 2>&1 && HAVE_RPM=1

COUNT_VULN_RUNNING=0; COUNT_NEEDS_RESTART=0; COUNT_VULN_INSTALLED=0
COUNT_STALE_OTHER=0; COUNT_PENDING_CONFIG=0; COUNT_DOWN_POOLS=0
COUNT_CONTAINER_VULN=0; COUNT_EXPOSED_FASTCGI=0; COUNT_EXPOSED_DB=0; COUNT_UNMATCHED=0
COUNT_NO_MULTIPART_BLOCK=0; COUNT_WRONG_BLOCK=0; COUNT_RLIMIT=0; COUNT_IOC=0; COUNT_REVIEW=0

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

# PHP-FPM and Apache keep their PID on reload (they re-exec themselves), so the process
# start time alone is not the time the current config was loaded. Look at the systemd
# journal ("Reloaded ...") and the FPM log ("ready to handle connections") as well.
# $1 pid, $2 optional php-fpm.conf -> prints the latest (re)load epoch time
effective_load_time() {
  local pid=$1 conf=${2:-} start unit t latest log line
  start=$(process_start_time "$pid"); latest=${start:-0}
  unit=$(grep -oE '[^/]+\.service' "/proc/$pid/cgroup" 2>/dev/null | head -n1)
  if [ -n "$unit" ] && [ -n "$start" ] && command -v journalctl >/dev/null 2>&1; then
    t=$(journalctl -u "$unit" --since "@$start" -o short-unix --no-pager -q 2>/dev/null \
        | awk '/Reloaded|Started/ {t=$1} END {if (t) print int(t)}')
    [ -n "$t" ] && [ "$t" -gt "$latest" ] && latest=$t
  fi
  if [ -n "$conf" ] && [ -r "$conf" ]; then
    log=$(awk '/^[ \t]*error_log[ \t]*=/ {v=substr($0, index($0, "=")+1); gsub(/^[ \t"]+|[ \t"]+$/, "", v); print v; exit}' "$conf")
    if [ -n "$log" ] && [ -r "$log" ]; then
      line=$(tail -n 2000 "$log" | grep -E 'ready to handle connections' | tail -n1 | sed -n 's/^\[\([^]]*\)\].*/\1/p')
      [ -n "$line" ] && t=$(date -d "$line" +%s 2>/dev/null) && [ -n "$t" ] && [ "$t" -gt "$latest" ] && latest=$t
    fi
  fi
  [ "$latest" -gt 0 ] && echo "$latest"
  return 0
}

HAVE_DOCKER=0
command -v docker >/dev/null 2>&1 && $TIMEOUT_CMD docker info >/dev/null 2>&1 && HAVE_DOCKER=1
declare -A CONTAINER_NAME_CACHE

container_of_pid() {   # prints the container name (or short id) a process runs in; empty on the host
  local id name=""
  id=$(grep -oE '[0-9a-f]{64}' "/proc/$1/cgroup" 2>/dev/null | head -n1)
  [ -n "$id" ] || return 0
  if [ -z "${CONTAINER_NAME_CACHE[$id]+x}" ]; then
    [ "$HAVE_DOCKER" = 1 ] && name=$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null)
    name=${name#/}
    CONTAINER_NAME_CACHE[$id]=${name:-${id:0:12}}
  fi
  echo "${CONTAINER_NAME_CACHE[$id]}"
}

container_php_version() {   # $1 container, $2 optional binary path inside it -> PHP version or empty
  local bin out
  [ "$HAVE_DOCKER" = 1 ] || return 0
  for bin in ${2:+"$2"} php php-cgi php-fpm; do
    out=$($TIMEOUT_CMD docker exec "$1" "$bin" -v 2>/dev/null | head -n1)
    if [[ $out == "PHP "* ]]; then sed -n 's/^PHP \([0-9][^ ]*\) .*/\1/p' <<<"$out"; return 0; fi
  done
}

container_php_status() {   # $1 version (may be empty) -> fixed | pre54 | vuln | unverified
  local st
  [ -n "$1" ] || { echo unverified; return; }
  st=$(upstream_status "$1")
  case $st in fixed|pre54) echo "$st" ;; *) echo vuln ;; esac
}

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

# Server-level php_admin_value / php_admin_flag in the Apache config (outside <VirtualHost>,
# <Directory>, <Location>, <Files>...). They apply to every mod_php vhost and win over
# php_value in vhosts and .htaccess. Output: "key<TAB>value" lines.
# APACHE_CONF_ROOT can point the functions to another directory (for testing).
apache_conf_root() {
  if [ -n "${APACHE_CONF_ROOT:-}" ]; then echo "$APACHE_CONF_ROOT"
  elif [ -d /etc/apache2 ]; then echo /etc/apache2
  elif [ -d /etc/httpd ]; then echo /etc/httpd; fi
}
apache_server_files() {   # server-level config files (not the vhost files), one per line
  local root f; root=$(apache_conf_root); [ -n "$root" ] || return 0
  for f in "$root/apache2.conf" "$root/conf/httpd.conf" "$root"/conf-enabled/*.conf \
           "$root"/mods-enabled/*.conf "$root"/conf.modules.d/*.conf; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done
}
apache_vhost_files() {    # enabled vhost files, one per line
  local root f; root=$(apache_conf_root); [ -n "$root" ] || return 0
  for f in "$root"/sites-enabled/* "$root"/conf.d/*.conf "$root"/vhosts.d/*.conf; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done
}
apache_global_admin_settings() {
  local files=() f
  while IFS= read -r f; do files+=("$f"); done < <(apache_server_files)
  [ ${#files[@]} -gt 0 ] || return 0
  awk '
    FNR == 1 { depth = 0 }
    { line=$0; sub(/^[ \t]+/, "", line); sub(/[ \t\r]+$/, "", line); low=tolower(line) }
    line == "" || line ~ /^#/ { next }
    low ~ /^<(virtualhost|directory|directorymatch|location|locationmatch|files|filesmatch|proxy|proxymatch)([ \t>]|$)/ { depth++; next }
    low ~ /^<\/(virtualhost|directory|directorymatch|location|locationmatch|files|filesmatch|proxy|proxymatch)[ \t]*>/ { if (depth > 0) depth--; next }
    depth == 0 && low ~ /^php_admin_(value|flag)[ \t]/ {
      n = split(line, a, /[ \t]+/)
      if (n >= 3) { v = a[3]; gsub(/"/, "", v); print a[2] "\t" v } }' "${files[@]}" 2>/dev/null
}

# Multipart blocks, RLimitMEM and wrong Content-Type checks in the Apache config.
# $@ = config files. Output (tab separated):
#   VHOST  file  servername  blocked(0/1)  redirect_only(0/1)
#   GLOBAL file  line                     <If> block outside any vhost/section: applies to every vhost
#   SCOPED file  line  section            block outside vhosts but inside <Directory>/<Location>/...
#   GLOBALRW file line                    mod_rewrite block outside vhosts: NOT inherited by vhosts
#   WRONG  file  line                     %{CONTENT_TYPE} is the RESPONSE type: this does not block anything
#   RLIMITMEM file line text
apache_multipart_scan() {
  [ $# -gt 0 ] || return 0
  awk '
    function mark(kind) {
      if (invh) { vhblocked = 1; return }
      if (kind == "rw") { print "GLOBALRW\t" FILENAME "\t" FNR; return }
      if (sect != "") print "SCOPED\t" FILENAME "\t" ifline "\t" sect
      else print "GLOBAL\t" FILENAME "\t" ifline
    }
    function flush_vh() {
      if (invh) print "VHOST\t" FILENAME "\t" (vhname != "" ? vhname : "(no ServerName)") "\t" vhblocked "\t" (vhredirect && !vhdocroot ? 1 : 0)
    }
    FNR == 1 { invh = 0; ifd = 0; rwpend = 0; sect = ""; sectd = 0 }
    { line = $0; sub(/^[ \t]+/, "", line); sub(/[ \t\r]+$/, "", line); low = tolower(line) }
    line == "" || line ~ /^#/ { next }
    low ~ /^<virtualhost[ \t>]/ { invh = 1; vhname = ""; vhblocked = 0; vhredirect = 0; vhdocroot = 0; next }
    low ~ /^<\/virtualhost[ \t]*>/ { flush_vh(); invh = 0; next }
    low ~ /^<if[ \t]/ {
      ifd++
      if (ifd == 1) {
        ifline = FNR; ifmp = (low ~ /multipart/); ifdeny = 0
        ifreq = (low ~ /req(_novary)?[ \t]*\(|http[ \t]*\(|%\{http:content-type\}/)
        ifwrong = (low ~ /%\{content_type\}/)
      }
      next
    }
    low ~ /^<\/if[ \t]*>/ {
      if (ifd == 1 && ifmp) {
        if (ifwrong && !ifreq) print "WRONG\t" FILENAME "\t" ifline
        else if (ifreq && ifdeny) mark("if")
      }
      if (ifd > 0) ifd--
      next
    }
    ifd >= 1 && (low ~ /^require[ \t]+all[ \t]+denied/ || low ~ /^deny[ \t]+from[ \t]+all/ || \
                 low ~ /^rewriterule[ \t].*\[([^]]*,)?(f|forbidden|g|gone|r=40[0-9])(,[^]]*)?\]/) { ifdeny = 1 }
    !invh && low ~ /^<(directory|directorymatch|location|locationmatch|files|filesmatch|proxy|proxymatch)[ \t>]/ {
      sectd++; if (sectd == 1) { sect = line; sub(/>.*/, ">", sect) }
      next
    }
    !invh && low ~ /^<\/(directory|directorymatch|location|locationmatch|files|filesmatch|proxy|proxymatch)[ \t]*>/ {
      if (sectd > 0) sectd--; if (sectd == 0) sect = ""
      next
    }
    low ~ /^rewritecond[ \t]+%\{http:content-type\}[ \t].*multipart/ { rwpend = 1; next }
    low ~ /^rewritecond[ \t]+%\{content_type\}[ \t].*multipart/ { print "WRONG\t" FILENAME "\t" FNR; next }
    low ~ /^rewriterule[ \t]/ {
      if (rwpend && low ~ /\[([^]]*,)?(f|forbidden|g|gone|r=40[0-9])(,[^]]*)?\]/) mark("rw")
      rwpend = 0
      if (invh && low ~ /^rewriterule[ \t]+[^ \t]+[ \t]+https?:\/\// && low ~ /\[([^]]*,)?r(=[a-z0-9]+)?(,[^]]*)?\]/) vhredirect = 1
    }
    low ~ /^rlimitmem[ \t]/ { print "RLIMITMEM\t" FILENAME "\t" FNR "\t" line }
    invh && vhname == "" && low ~ /^servername[ \t]/ { split(line, a, /[ \t]+/); vhname = a[2] }
    invh && low ~ /^documentroot[ \t]/ { vhdocroot = 1 }
    invh && low ~ /^redirect(permanent)?[ \t]+((permanent|temp|seeother|30[1278])[ \t]+)?\/[ \t]+https?:\/\// { vhredirect = 1 }
    invh && low ~ /^redirectmatch[ \t]+((permanent|temp|30[1278])[ \t]+)?"?\^?\/?\(?\.\*\)?\$?"?[ \t]+https?:\/\// { vhredirect = 1 }
  ' "$@" 2>/dev/null
}

# Variables set by an nginx "map $http_content_type $var { ... multipart ... }" block
nginx_multipart_map_vars() {
  [ $# -gt 0 ] || return 0
  awk '
    { line = $0; sub(/#.*/, "", line) }
    !inmap && line ~ /^[ \t]*map[ \t]+\$(http_content_type|content_type)[ \t]+\$[A-Za-z0-9_]+/ {
      v = line; sub(/^[ \t]*map[ \t]+\$[a-z_]+[ \t]+\$/, "", v); sub(/[^A-Za-z0-9_].*$/, "", v)
      inmap = 1; mp = 0
    }
    inmap && tolower(line) ~ /multipart/ { mp = 1 }
    inmap && line ~ /\}/ { if (mp) print v; inmap = 0 }' "$@" 2>/dev/null | sort -u
}

# Splits nginx files into server blocks: one output line per block,
# "file<TAB>first line number<TAB>block text with newlines replaced by \037"
nginx_server_blocks() {
  [ $# -gt 0 ] || return 0
  awk '
    FNR == 1 { depth = 0; insb = 0 }
    { line = $0; sub(/#.*/, "", line) }
    !insb && line ~ /(^|[ \t;}])server[ \t]*\{/ { insb = 1; sbdepth = depth; sbline = FNR; text = "" }
    {
      if (insb) text = text line "\037"
      tmp = line; opens = gsub(/\{/, "", tmp); tmp = line; closes = gsub(/\}/, "", tmp)
      depth += opens - closes
      if (insb && depth <= sbdepth) { print FILENAME "\t" sbline "\t" text; insb = 0 }
    }' "$@" 2>/dev/null
}

# 0 if the given nginx config text blocks multipart requests (if + return 4xx within 3 lines)
nginx_text_blocks_multipart() {   # $1 text, $2 space separated map variables
  awk -v vars=" $2 " '
    { low = tolower($0) }
    pending > 0 { if (low ~ /return[ \t]+(40[0-9]|41[0-9]|444)/) found = 1; pending-- }
    low ~ /if[ \t]*\(/ {
      cond = low; sub(/^.*if[ \t]*\(/, "", cond); sub(/\).*$/, "", cond)
      hit = 0
      if (cond ~ /\$(http_)?content_type/ && cond ~ /multipart/) hit = 1
      else {
        v = cond; sub(/=.*/, "", v); gsub(/[ \t!$]/, "", v)
        if (v != "" && index(vars, " " v " ") > 0 && cond !~ /!/) hit = 1
      }
      if (hit) { if (low ~ /return[ \t]+(40[0-9]|41[0-9]|444)/) found = 1; else pending = 3 }
    }
    END { exit found ? 0 : 1 }' <<<"$1"
}

# Soft RLIMIT_AS / RLIMIT_DATA of a process ("" if unlimited or unknown)
process_memory_rlimits() {
  awk '/^Max address space|^Max data size/ {
         soft = $(NF-2)
         if (soft != "unlimited") { name = substr($0, 1, 25); sub(/[ \t]+$/, "", name); printf "%s%s = %s", sep, name, soft; sep = ", " } }' \
    "/proc/$1/limits" 2>/dev/null
}

# Prints log lines dated at or after SINCE_STAMP. Understands the Apache 2.4/2.2 error log
# ("[Wed Oct 21 14:22:33.123456 2026]"), the PHP-FPM / PHP error log ("[21-Oct-2026 14:22:33]")
# and the nginx error log ("2026/10/21 14:22:33") formats. Lines without a date are skipped.
log_lines_since() {
  awk -v since="$SINCE_STAMP" '
    BEGIN { split("jan feb mar apr may jun jul aug sep oct nov dec", m, " "); for (i = 1; i <= 12; i++) mon[m[i]] = sprintf("%02d", i) }
    {
      stamp = ""
      if (substr($0, 1, 1) == "[") {
        s = substr($0, 2, index($0, "]") - 2); n = split(s, f, /[ \t]+/)
        if (n >= 5 && (tolower(f[2]) in mon)) {                     # Apache
          t = f[4]; sub(/\..*/, "", t); gsub(/:/, "", t)
          stamp = f[5] mon[tolower(f[2])] sprintf("%02d", f[3]) t
        } else if (n >= 2 && split(f[1], g, "-") == 3 && (tolower(g[2]) in mon)) {   # PHP / PHP-FPM
          t = f[2]; gsub(/:/, "", t)
          stamp = g[3] mon[tolower(g[2])] sprintf("%02d", g[1]) t
        }
      } else if ($1 ~ /^[0-9][0-9][0-9][0-9]\/[0-9][0-9]\/[0-9][0-9]$/ && $2 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/) {   # nginx
        d = $1; gsub(/\//, "", d); t = $2; gsub(/:/, "", t); stamp = d t
      }
      if (length(stamp) == 14 && stamp >= since) print
    }'
}

# cgroup memory limit of a process in bytes, "max" if unlimited, empty if unknown (cgroup v1 and v2)
cgroup_memory_limit() {
  local rel file v
  rel=$(awk -F: '$2 ~ /(^|,)memory(,|$)/ {print $3; exit}' "/proc/$1/cgroup" 2>/dev/null)
  if [ -n "$rel" ] && [ -r "/sys/fs/cgroup/memory$rel/memory.limit_in_bytes" ]; then
    file="/sys/fs/cgroup/memory$rel/memory.limit_in_bytes"
  else
    rel=$(awk -F: '$1 == "0" && $2 == "" {print $3; exit}' "/proc/$1/cgroup" 2>/dev/null)
    [ -n "$rel" ] && file="/sys/fs/cgroup$rel/memory.max"
  fi
  [ -n "${file:-}" ] && [ -r "$file" ] || return 0
  v=$(cat "$file" 2>/dev/null)
  # cgroup v1 reports "no limit" as a huge number (page-aligned LLONG_MAX)
  if [ "$v" = max ] || [ "${#v}" -ge 19 ]; then echo max; else echo "$v"; fi
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
      info "(memory_limit = -1: if you set this as a temporary PHP2Shell mitigation, restore the previous finite value;"
      info " if it was configured like this before (e.g. the ISPConfig panel pool), leave it as is.)"
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

declare -A CONTAINER_REPORTED
# A PHP process inside a container: its binary lives in the image, not on the host
report_container_process() {   # $1 pid, $2 description, $3 container, $4 binary path inside the container
  local pid=$1 desc=$2 cname=$3 exe=$4 version status image=""
  [ -n "${CONTAINER_REPORTED[$cname]+x}" ] && return 0
  CONTAINER_REPORTED[$cname]=1
  version=$(container_php_version "$cname" "$exe")
  status=$(container_php_status "$version")
  [ "$HAVE_DOCKER" = 1 ] && image=$(docker inspect -f '{{.Config.Image}}' "$cname" 2>/dev/null)
  if [ "$status" = fixed ]; then
    ok "$desc in container $cname${image:+ [$image]} (PID $pid): $version $(status_label fixed)"
  else
    bad "$desc in container $cname${image:+ [$image]} (PID $pid): ${version:-unknown} $(status_label "$status")"
    advise "Update the container image (see section 6); host package updates do not reach it."
    COUNT_CONTAINER_VULN=$((COUNT_CONTAINER_VULN+1)); raise_exit 2
  fi
}

# $1 pid, $2 description, $3 binary/module path (may end in "(deleted)"), $4.. extra config files
check_running() {
  local pid=$1 desc=$2 path=$3 clean_path deleted=0 start mtime key cname; shift 3
  CHECKED_PIDS[$pid]=1
  cname=$(container_of_pid "$pid")
  if [ -n "$cname" ]; then report_container_process "$pid" "$desc" "$cname" "${path% (deleted)}"; return 0; fi
  clean_path=${path% (deleted)}; [ "$clean_path" != "$path" ] && deleted=1
  key=$(readlink -f "$clean_path" 2>/dev/null || echo "$clean_path")
  if [[ $key == *.so ]]; then probe_module "$key"; else probe_binary "$key" || true; fi
  RUNNING_BIN[$key]=1
  if [[ $desc == PHP-FPM* ]]; then start=$(effective_load_time "$pid" "${1:-}")
  else start=$(effective_load_time "$pid"); fi
  mtime=$(stat -c %Y "$key" 2>/dev/null || echo 0)
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
for pid in $(pgrep -f '^php-fpm: master process' 2>/dev/null); do
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
  case ${exe##*/} in *php*) ;; *) continue ;; esac
  conf=$(tr '\0' ' ' <"/proc/$pid/cmdline" | sed -n 's/.*(\(.*\)).*/\1/p')
  if [ -n "$(container_of_pid "$pid")" ]; then
    check_running "$pid" "PHP-FPM master" "$exe"
  elif [ -n "$conf" ]; then
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
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
  case ${exe##*/} in *php*cgi*) ;; *) continue ;; esac   # not e.g. a grep for php-cgi
  CHECKED_PIDS[$pid]=1
  cgi_key="$(container_of_pid "$pid")|$exe"
  [ -n "${CGI_SEEN[$cgi_key]+x}" ] && continue; CGI_SEEN[$cgi_key]=1
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
  [ -n "$(container_of_pid "$pid")" ] && continue   # inside a container: handled by image updates
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
  s=${s/#\/var\/run\//\/run\/}
  echo "$s"
}
add_socket() {
  local k; k=$(normalize_listen "$1")
  [[ " ${SOCKET_VHOSTS[$k]:-} " == *" $2 "* ]] || SOCKET_VHOSTS[$k]+="${SOCKET_VHOSTS[$k]:+ }$2"
}

# All config files nginx actually loads (nginx -T follows every include); fallback: usual paths
NGINX_FILES=()
if command -v nginx >/dev/null 2>&1; then
  while IFS= read -r f; do [ -f "$f" ] && NGINX_FILES+=("$f"); done < <(
    $TIMEOUT_CMD nginx -T 2>/dev/null | sed -n 's/^# configuration file \(.*\):$/\1/p' | sort -u)
fi
[ ${#NGINX_FILES[@]} -gt 0 ] || NGINX_FILES=(/etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*)

# Files included by an nginx config file (active "include" directives only, 2 levels deep)
nginx_includes() {   # $1 file, $2 depth
  local file=$1 depth=${2:-0} pattern inc
  [ "$depth" -lt 2 ] || return 0
  while read -r pattern; do
    [ -n "$pattern" ] || continue
    [[ $pattern == /* ]] || pattern="/etc/nginx/$pattern"
    for inc in $pattern; do   # glob expansion is intended here
      [ -f "$inc" ] || continue
      echo "$inc"; nginx_includes "$inc" $((depth+1))
    done
  done < <(sed -E 's/#.*//' "$file" | grep -oE '(^|[[:space:];{])include[[:space:]]+[^;]+' | sed -E 's/^.*include[[:space:]]+//')
}

# nginx upstream blocks: name -> server addresses (e.g. "php-handler" -> 127.0.0.1:9000)
declare -A NGINX_UPSTREAM
while IFS=$'\t' read -r up_name up_server; do
  [ -n "$up_name" ] && NGINX_UPSTREAM[$up_name]+="${NGINX_UPSTREAM[$up_name]:+ }$up_server"
done < <(awk '
  { line=$0; sub(/#.*/, "", line) }
  line ~ /^[ \t]*upstream[ \t]+[^ \t{]+/ { name=line; sub(/^[ \t]*upstream[ \t]+/, "", name); sub(/[ \t{].*$/, "", name); inup=1 }
  inup { rest=line
         while (match(rest, /(^|[ \t;{])server[ \t]+[^; \t]+/)) {
           s=substr(rest, RSTART, RLENGTH); sub(/^.*server[ \t]+/, "", s); print name "\t" s
           rest=substr(rest, RSTART+RLENGTH) } }
  inup && line ~ /\}/ { inup=0 }' "${NGINX_FILES[@]}" 2>/dev/null)

for conf_file in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
  [ -f "$conf_file" ] || continue
  vhost=$(grep -m1 -E '^[[:space:]]*server_name[[:space:]]' "$conf_file" | sed -E 's/^[[:space:]]*server_name[[:space:]]+//; s/[;[:space:]].*//')
  vhost=${vhost:-$(basename "$conf_file")}
  while read -r sock; do
    [ -n "$sock" ] || continue
    if [ -n "${NGINX_UPSTREAM[$sock]:-}" ]; then
      for up_server in ${NGINX_UPSTREAM[$sock]}; do add_socket "$up_server" "$vhost"; done
    else
      add_socket "$sock" "$vhost"
    fi
  done < <(
    # the vhost file and the files it includes; comments are stripped before matching
    { cat "$conf_file"; nginx_includes "$conf_file" | sort -u | while read -r inc; do cat "$inc"; done; } \
      | sed -E 's/#.*//' | grep -oE '(^|[[:space:];{])fastcgi_pass[[:space:]]+[^;]+' \
      | sed -E 's/^.*fastcgi_pass[[:space:]]+//' | sort -u)
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
  if [ -z "${BIN_VERSION[$key]+x}" ]; then
    if [ -n "$vhosts" ]; then
      warn "leftover pool: its PHP-FPM binary ($fpm_bin) is not installed, but vhosts point here: $vhosts"
      COUNT_DOWN_POOLS=$((COUNT_DOWN_POOLS+1)); raise_exit 1
    else
      info "${C_DIM}leftover config: PHP-FPM binary $fpm_bin is not installed, nothing runs this pool (not a risk).${C_RESET}"
      info "${C_DIM}To clean up: dpkg -l | awk '/^rc/ && \$2 ~ /php/ {print \$2}'  then  apt purge <packages>${C_RESET}"
    fi
    return 0
  fi
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

# Host ports published by running containers: host port -> container name
declare -A CONTAINER_BY_HOSTPORT
if [ "$HAVE_DOCKER" = 1 ]; then
  while IFS=$'\t' read -r cname cports; do
    IFS=',' read -ra port_list <<<"$cports"
    for port in ${port_list[@]+"${port_list[@]}"}; do
      [[ $port == *"->"* ]] || continue
      host_port=${port%%->*}; host_port=${host_port##*:}
      CONTAINER_BY_HOSTPORT[$host_port]=$cname
    done
  done < <(docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null)
fi

for sock in "${!SOCKET_VHOSTS[@]}"; do
  [ -n "${SOCKET_MATCHED[$sock]+x}" ] && continue
  if [[ $sock =~ :([0-9]+)$ ]] && [ -n "${CONTAINER_BY_HOSTPORT[${BASH_REMATCH[1]}]:-}" ]; then
    printf '\n'
    info "$sock  <-  ${SOCKET_VHOSTS[$sock]}"
    info "${C_DIM}served by container ${CONTAINER_BY_HOSTPORT[${BASH_REMATCH[1]}]}: its PHP and ports are checked in section 6${C_RESET}"
    continue
  fi
  if [[ $sock == *fcgiwrap* ]]; then
    printf '\n'
    info "$sock  <-  ${SOCKET_VHOSTS[$sock]}"
    if [ -S "$sock" ]; then
      info "${C_DIM}fcgiwrap is a CGI wrapper (usually Perl/shell CGI), not PHP-FPM: not part of this audit.${C_RESET}"
    else
      info "${C_DIM}fcgiwrap (CGI wrapper, not PHP-FPM) socket does not exist: CGI on this site is not working.${C_RESET}"
    fi
    continue
  fi
  if [ "$COUNT_UNMATCHED" = 0 ]; then
    printf '\n'; warn "FastCGI addresses used by vhosts but not matched to any pool file: their PHP was NOT audited"
  fi
  COUNT_UNMATCHED=$((COUNT_UNMATCHED+1))
  info "$sock  <-  ${SOCKET_VHOSTS[$sock]}"
  owner=""
  if command -v ss >/dev/null 2>&1; then
    if [[ $sock == /* ]]; then
      owner=$(ss -lxpH 2>/dev/null | awk -v s="$sock" 'index($0, s) {print $NF; exit}')
    elif [[ $sock =~ :([0-9]+)$ ]]; then
      owner=$(ss -ltnpH "sport = :${BASH_REMATCH[1]}" 2>/dev/null | awk '{print $NF; exit}')
    fi
  fi
  info "${C_DIM}listening process: ${owner:-none found (nothing listens, or another host/container)}${C_RESET}"
  case $owner in
    *docker-proxy*|*containerd*|*conmon*)
      info "${C_DIM}served by a container: see section 6 for its PHP version and published ports${C_RESET}" ;;
  esac
done
[ "$COUNT_UNMATCHED" -gt 0 ] && raise_exit 1

# =============================================================================
header "5. Other PHP handlers: mod_php and FastCGI/fcgid"
if [ "$MODPHP_LOADED" = 1 ]; then
  declare -A APACHE_ADMIN=()
  while IFS=$'\t' read -r admin_key admin_value; do
    [ -n "$admin_key" ] && APACHE_ADMIN[$admin_key]=$admin_value
  done < <(apache_global_admin_settings)
  for key in "${!RUNNING_BIN[@]}"; do
    [[ $key == *.so ]] || continue
    status=${BIN_STATUS[$key]:-vuln}
    printf '\n  %smod_php%s %s: PHP %s %s\n' "$C_BOLD" "$C_RESET" "$key" "${BIN_VERSION[$key]%%[-~+]*}" "$(status_label "$status")"
    if [ "$status" != fixed ]; then
      bad "mod_php is loaded: PHP parses the multipart body before the application runs, on every vhost that serves .php via mod_php."
      module_name=$(basename "$key" .so); module_name=${module_name#lib}
      advise "If every site runs on PHP-FPM, disable it: a2dismod ${module_name}  (then restart Apache)"
    fi
    ini_files_of "$key"
    upload=$(ini_get session.upload_progress.enabled ${INI_LIST[@]+"${INI_LIST[@]}"}); upload=${upload:-On}; upload_src="php.ini"
    mem=$(ini_get memory_limit ${INI_LIST[@]+"${INI_LIST[@]}"}); mem=${mem:-128M}; mem_src="php.ini"; mem_locked=0
    post=$(ini_get post_max_size ${INI_LIST[@]+"${INI_LIST[@]}"}); post=${post:-8M}
    # Server-level php_admin_* in the Apache config wins over php.ini, vhosts and .htaccess
    upload_locked=0
    if [ -n "${APACHE_ADMIN[session.upload_progress.enabled]+x}" ]; then
      upload=${APACHE_ADMIN[session.upload_progress.enabled]}; upload_src="Apache config, admin"; upload_locked=1
    fi
    if [ -n "${APACHE_ADMIN[memory_limit]+x}" ]; then
      mem=${APACHE_ADMIN[memory_limit]}; mem_src="Apache config, admin"; mem_locked=1
    fi
    [ -n "${APACHE_ADMIN[post_max_size]+x}" ] && post=${APACHE_ADMIN[post_max_size]}
    # Without admin locks, .htaccess files could undo the mitigations (checked in section 7)
    if [ "$status" != fixed ] && { [ "$upload_locked" = 0 ] || [ "$mem_locked" = 0 ]; }; then USER_OVERRIDE_RISK=1; fi
    if [ ${#APACHE_ADMIN[@]} -gt 0 ]; then
      info "global (${INI_LIST[0]:-php.ini not found} + server-level php_admin_* in the Apache config):"
    else
      info "global (${INI_LIST[0]:-php.ini not found}):"
    fi
    [ "$status" = pre54 ] && upload="n/a"
    evaluate_settings "$status" "$upload" "$upload_src" "$mem" "$mem_locked" "$mem_src" "$post" modphp
  done
  if [ ${#MODPHP_VHOSTS[@]} -gt 0 ]; then
    apache_start=""
    for key in "${!RUNNING_BIN[@]}"; do [[ $key == *.so ]] && apache_start=${RUNNING_START[$key]:-}; done
    info ""
    info "Apache vhosts without an FPM/FastCGI handler (they use mod_php, or have no PHP):"
    for entry in "${MODPHP_VHOSTS[@]}"; do
      vhost=${entry%%|*}; conf_file=${entry#*|}
      directives=$(grep -vE '^[[:space:]]*#' "$conf_file" \
           | grep -iE '^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]+(session\.upload_progress\.enabled|memory_limit|post_max_size)[[:space:]]' \
           | sed -E 's/^[[:space:]]+//; s/[[:space:]]+/ /g' | sort -u | tr '\n' ';')
      info "  - $vhost  ${C_DIM}${directives:+[$directives]}${C_RESET}"
      # A vhost-level php_admin_* is stronger than the server-level one: it can undo the mitigation
      if [ "$status" != fixed ]; then
        while read -r undo_key undo_value; do
          case $undo_key in
            memory_limit) [ "$undo_value" = "-1" ] && continue ;;
            session.upload_progress.enabled) is_on "$undo_value" || continue ;;
          esac
          warn "    vhost-level php_admin_* overrides the mitigation here: $undo_key = $undo_value"
          USER_OVERRIDE_RISK=1; raise_exit 1
        done < <(grep -vE '^[[:space:]]*#' "$conf_file" \
                 | grep -ioE '^[[:space:]]*php_admin_(value|flag)[[:space:]]+(session\.upload_progress\.enabled|memory_limit)[[:space:]]+[^[:space:]]+' \
                 | awk '{gsub(/"/, "", $3); print $2, $3}' | sort -u)
      fi
      if [ -n "$apache_start" ] && [ -n "$(changed_since "$apache_start" "$conf_file")" ]; then
        warn "    $conf_file changed after Apache started: NOT active until an Apache reload"
        COUNT_PENDING_CONFIG=$((COUNT_PENDING_CONFIG+1)); raise_exit 1
      fi
    done
    admin_keys=""
    for admin_key in "${!APACHE_ADMIN[@]}"; do admin_keys+="${admin_keys:+, }$admin_key"; done
    [ -n "$admin_keys" ] && info "${C_DIM}(server-level php_admin_* for $admin_keys wins over the vhosts' php_value lines; a vhost-level php_admin_* would win over it)${C_RESET}"
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
header "6. Containers: published ports and PHP inside"
if [ "$HAVE_DOCKER" = 0 ]; then
  info "Docker is not installed or not running."
else
  container_count=0
  while IFS=$'\t' read -r cname cimage cports; do
    [ -n "$cname" ] || continue
    container_count=$((container_count+1))
    printf '\n  %s%s%s [%s]\n' "$C_BOLD" "$cname" "$C_RESET" "$cimage"
    # Ports published on all interfaces (Docker's own iptables rules bypass ufw)
    declare -A port_seen=()
    IFS=',' read -ra port_list <<<"$cports"
    for port in ${port_list[@]+"${port_list[@]}"}; do
      port=${port# }
      [[ $port == *"->"* ]] || continue
      case $port in 0.0.0.0:*|"[::]:"*|":::"*) ;; *) continue ;; esac
      host_port=${port%%->*}; host_port=${host_port##*:}
      container_port=${port##*->}
      [ -n "${port_seen[$host_port/$container_port]+x}" ] && continue
      port_seen[$host_port/$container_port]=1
      case ${container_port%%/*} in
        900[0-9])
          bad "FastCGI port published on ALL interfaces: $host_port -> $container_port (remote code execution, bypasses ufw)"
          advise "Bind it to localhost in the compose file: \"127.0.0.1:$host_port:${container_port%%/*}\", then recreate the container"
          COUNT_EXPOSED_FASTCGI=$((COUNT_EXPOSED_FASTCGI+1)); raise_exit 2 ;;
        3306|5432|6379|11211|27017|9200)
          bad "Database/cache port published on ALL interfaces: $host_port -> $container_port (bypasses ufw)"
          advise "Bind it to 127.0.0.1, or remove the mapping if only other containers use it"
          COUNT_EXPOSED_DB=$((COUNT_EXPOSED_DB+1)); raise_exit 1 ;;
        *)
          info "published on all interfaces: $host_port -> $container_port (bypasses ufw; make sure this is intended)" ;;
      esac
    done
    unset port_seen
    # PHP inside the container
    version=$(container_php_version "$cname")
    if [ -z "$version" ]; then
      info "${C_DIM}no PHP inside${C_RESET}"
    else
      status=$(container_php_status "$version")
      if [ "$status" = fixed ]; then
        ok "PHP $version inside: $(status_label fixed)"
      else
        bad "PHP $version inside: $(status_label "$status")"
        advise "Pull a patched image and recreate (docker compose pull && docker compose up -d), then verify: docker exec $cname php -v"
        [ "$status" = pre54 ] || [ "${version%%.*}" -lt 8 ] 2>/dev/null && \
          info "This PHP branch gets no fixes in official images: the application needs a newer PHP / image."
        if [ -z "${CONTAINER_REPORTED[$cname]+x}" ]; then
          CONTAINER_REPORTED[$cname]=1; COUNT_CONTAINER_VULN=$((COUNT_CONTAINER_VULN+1))
        fi
        raise_exit 2
      fi
    fi
  done < <(docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}' 2>/dev/null)
  [ "$container_count" = 0 ] && info "No running container."
fi

# =============================================================================
header "7. Per-directory overrides (.user.ini / .htaccess)"
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
header "8. Web server: multipart blocking and memory limits"
NEED_FILTER=0
[ $((COUNT_VULN_RUNNING + COUNT_CONTAINER_VULN)) -gt 0 ] && NEED_FILTER=1
if [ "$NEED_FILTER" = 1 ]; then
  info "A vulnerable PHP serves requests. PHP parses multipart/form-data bodies before any application code runs,"
  info "so rejecting multipart requests in the web server is the strongest temporary protection (it breaks uploads)."
  info "Request size limits, file_uploads = Off, disable_functions and application/WAF plugins do NOT protect."
else
  info "${C_DIM}No vulnerable PHP serves requests: multipart blocking is not needed (temporary blocks can be removed, they break uploads).${C_RESET}"
fi

print_name_list() {   # stdin: names -> wrapped info lines
  grep . | sort -u | tr '\n' ' ' | fold -s -w 96 | { while IFS= read -r wrapped || [ -n "$wrapped" ]; do info "  ${wrapped% }"; wrapped=""; done; }
}

# --- Apache ---
if pgrep -x 'apache2|httpd' >/dev/null 2>&1; then
  printf '\n  %sApache%s\n' "$C_BOLD" "$C_RESET"
  APACHE_FILES=()
  while IFS= read -r f; do APACHE_FILES+=("$f"); done < <(apache_server_files; apache_vhost_files)
  APACHE_SCAN=$(apache_multipart_scan ${APACHE_FILES[@]+"${APACHE_FILES[@]}"})
  apache_global=0
  while IFS=$'\t' read -r kind f1 f2 f3 f4; do
    case $kind in
      GLOBAL)   apache_global=1; ok "server-level multipart block, applies to every vhost: $f1 (line $f2)" ;;
      SCOPED)   info "multipart block outside the vhosts, limited to $f3: $f1 (line $f2)" ;;
      GLOBALRW) warn "mod_rewrite multipart rule outside the vhosts ($f1, line $f2): vhosts do NOT inherit it"
                advise "Use an <If> block instead (see below), or put the rule into every vhost." ;;
      WRONG)    bad "$f1 (line $f2): matches %{CONTENT_TYPE}, which is the RESPONSE type: this blocks nothing"
                advise "Use req('Content-Type') in <If>, or %{HTTP:Content-Type} in RewriteCond."
                COUNT_WRONG_BLOCK=$((COUNT_WRONG_BLOCK+1)); raise_exit 1 ;;
      RLIMITMEM) if [ "$NEED_FILTER" = 1 ]; then
                   warn "$f1 (line $f2): $f3 sets RLIMIT_DATA/AS for CGI children (php-cgi): PHP warns this can trigger CVE-2026-109618"
                   COUNT_RLIMIT=$((COUNT_RLIMIT+1)); raise_exit 1
                 fi ;;
    esac
  done <<<"$APACHE_SCAN"
  vh_total=0; vh_blocked=0; vh_redirect=0; vh_open=""
  while IFS=$'\t' read -r kind vh_file vh_name vh_is_blocked vh_is_redirect; do
    [ "$kind" = VHOST ] || continue
    # does this vhost hand requests to PHP? (mod_php: every vhost; otherwise a FastCGI/proxy handler)
    if [ "$MODPHP_LOADED" != 1 ] && ! grep -vE '^[[:space:]]*#' "$vh_file" 2>/dev/null \
         | grep -qiE 'proxy:(unix|fcgi)|fcgi://|FcgidWrapper|AddHandler[[:space:]].*php|SetHandler[[:space:]].*php'; then
      continue
    fi
    vh_total=$((vh_total+1))
    if [ "$vh_is_redirect" = 1 ]; then vh_redirect=$((vh_redirect+1))
    elif [ "$vh_is_blocked" = 1 ] || [ "$apache_global" = 1 ]; then vh_blocked=$((vh_blocked+1))
    else vh_open+="$vh_name"$'\n'; fi
  done <<<"$APACHE_SCAN"
  vh_open_count=$(grep -c . <<<"$vh_open")
  info "<VirtualHost> blocks serving PHP: $vh_total | multipart blocked: $vh_blocked | redirect only: $vh_redirect | NOT blocked: $vh_open_count"
  if [ "$vh_open_count" -gt 0 ]; then
    if [ "$NEED_FILTER" = 1 ]; then
      warn "vhosts serving vulnerable PHP without a multipart block:"
      COUNT_NO_MULTIPART_BLOCK=$((COUNT_NO_MULTIPART_BLOCK+vh_open_count)); raise_exit 1
    else
      info "${C_DIM}vhosts without a multipart block (fine, PHP is patched):${C_RESET}"
    fi
    print_name_list <<<"$vh_open"
    if [ "$NEED_FILTER" = 1 ]; then
      advise "In every vhost that does not need uploads (or server-wide in a conf-enabled file):"
      info "    <If \"req('Content-Type') =~ /multipart/i\">"
      info "        Require all denied"
      info "    </If>"
    fi
  fi
fi

# --- nginx ---
if pgrep -x nginx >/dev/null 2>&1; then
  printf '\n  %snginx%s\n' "$C_BOLD" "$C_RESET"
  MP_VARS=$(nginx_multipart_map_vars ${NGINX_FILES[@]+"${NGINX_FILES[@]}"} | tr '\n' ' ')
  [ -n "${MP_VARS// /}" ] && info "${C_DIM}multipart map variable(s): $MP_VARS${C_RESET}"
  NGINX_VHOST_FILES=()
  for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do [ -f "$f" ] && NGINX_VHOST_FILES+=("$f"); done
  sb_total=0; sb_blocked=0; sb_open=""
  while IFS=$'\t' read -r sb_file sb_line sb_text; do
    [ -n "$sb_file" ] || continue
    sb_text=${sb_text//$'\037'/$'\n'}
    sb_full=$sb_text
    while IFS= read -r inc; do
      [ -n "$inc" ] && sb_full+=$'\n'"$(sed -E 's/#.*//' "$inc" 2>/dev/null)"
    done < <(nginx_includes <(printf '%s\n' "$sb_text") | sort -u)
    grep -qE '(^|[[:space:];{])fastcgi_pass[[:space:]]' <<<"$sb_full" || continue
    sb_total=$((sb_total+1))
    sb_name=$(grep -m1 -E '^[[:space:]]*server_name[[:space:]]' <<<"$sb_text" | sed -E 's/^[[:space:]]*server_name[[:space:]]+//; s/[;[:space:]].*//')
    sb_name=${sb_name:-$(basename "$sb_file"):$sb_line}
    if nginx_text_blocks_multipart "$sb_full" "$MP_VARS"; then sb_blocked=$((sb_blocked+1))
    else sb_open+="$sb_name"$'\n'; fi
  done < <(nginx_server_blocks ${NGINX_VHOST_FILES[@]+"${NGINX_VHOST_FILES[@]}"})
  sb_open_count=$(grep -c . <<<"$sb_open")
  info "server blocks passing to PHP-FPM: $sb_total | multipart blocked: $sb_blocked | NOT blocked: $sb_open_count"
  if [ "$sb_open_count" -gt 0 ]; then
    if [ "$NEED_FILTER" = 1 ]; then
      warn "server blocks without a multipart block (the PHP behind them may be patched; see section 4):"
      COUNT_NO_MULTIPART_BLOCK=$((COUNT_NO_MULTIPART_BLOCK+sb_open_count)); raise_exit 1
    else
      info "${C_DIM}server blocks without a multipart block (fine, PHP is patched):${C_RESET}"
    fi
    print_name_list <<<"$sb_open"
    if [ "$NEED_FILTER" = 1 ]; then
      advise "In the http {} context:  map \$http_content_type \$php2shell_multipart { default 0; ~*multipart 1; }"
      advise "In every server {} that does not need uploads:  if (\$php2shell_multipart) { return 403; }"
    fi
  fi
fi
if [ "$NEED_FILTER" = 1 ] && [ "$((COUNT_NO_MULTIPART_BLOCK + COUNT_WRONG_BLOCK))" -lt 1 ] \
   && { pgrep -x 'apache2|httpd' >/dev/null 2>&1 || pgrep -x nginx >/dev/null 2>&1; }; then
  info "Verify from ANOTHER host (also directly on the IP): curl -sS -o /dev/null -w '%{http_code}\\n' -F t=1 --resolve NAME:443:IP https://NAME/  -> 403"
fi

# --- memory limits of the processes serving PHP ---
printf '\n  %sMemory limits of the processes serving PHP%s\n' "$C_BOLD" "$C_RESET"
limit_pids=$(pgrep -o -x 'apache2|httpd' 2>/dev/null; pgrep -f '^php-fpm: master process' 2>/dev/null)
limit_found=0
for pid in $limit_pids; do
  [ -r "/proc/$pid/limits" ] || continue
  [ -n "$(container_of_pid "$pid")" ] && continue
  comm=$(cat "/proc/$pid/comm" 2>/dev/null)
  cmdline=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | cut -c1-70)
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null); exe=$(readlink -f "${exe% (deleted)}" 2>/dev/null || echo "${exe% (deleted)}")
  serves_vuln=0
  if [[ $comm == apache2 || $comm == httpd ]]; then
    for key in "${!RUNNING_BIN[@]}"; do [[ $key == *.so ]] && [ "${BIN_STATUS[$key]:-vuln}" != fixed ] && serves_vuln=1; done
  else
    [ "${BIN_STATUS[$exe]:-vuln}" != fixed ] && serves_vuln=1
  fi
  rl=$(process_memory_rlimits "$pid")
  if [ -n "$rl" ]; then
    limit_found=1
    if [ "$serves_vuln" = 1 ]; then
      bad "PID $pid ($cmdline): $rl"
      advise "PHP warns that RLIMIT_AS / RLIMIT_DATA can trigger CVE-2026-109618: remove it, use a cgroup limit (MemoryMax / MemoryLimit)"
      COUNT_RLIMIT=$((COUNT_RLIMIT+1)); raise_exit 1
    else
      info "PID $pid ($cmdline): $rl (PHP is patched)"
    fi
  fi
  if [ "$serves_vuln" = 1 ]; then
    cg=$(cgroup_memory_limit "$pid")
    if [ "$cg" = max ]; then
      warn "PID $pid ($cmdline): no cgroup memory limit; with memory_limit = -1 one request can use all the RAM"
      advise "systemctl set-property <service> MemoryLimit=<size>   (MemoryMax= on cgroup v2)"
      raise_exit 1
    elif [ -n "$cg" ]; then
      ok "PID $pid ($cmdline): cgroup memory limit $((cg / 1048576)) MB"
    fi
  fi
done
[ "$limit_found" = 0 ] && ok "No RLIMIT_AS / RLIMIT_DATA on the web server and PHP-FPM master processes."

# =============================================================================
header "9. Signs of compromise since $SINCE_HUMAN"
info "${C_DIM}Heuristics. [FAIL] = strong sign of compromise; [CHECK] = review by hand (legitimate changes show up too).${C_RESET}"
info "${C_DIM}A clean result does not prove the server is clean: some exploit paths leave no trace.${C_RESET}"
LONG_TIMEOUT=""; command -v timeout >/dev/null 2>&1 && LONG_TIMEOUT="timeout 300"

show_limited() {   # $1 max lines; stdin: lines -> [CHECK]/info output handled by caller via $2 (check|info|bad)
  local max=$1 kind=$2 shown=0 total=0 l
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    total=$((total+1))
    if [ "$shown" -lt "$max" ]; then
      case $kind in check) check "$l" ;; bad) bad "$l" ;; *) info "$l" ;; esac
      shown=$((shown+1))
    fi
  done
  [ "$total" -gt "$shown" ] && info "... and $((total-shown)) more"
  return 0
}

# --- 9a. Crashes and memory exhaustion ---
printf '\n  %sCrashes and memory exhaustion (web server and PHP logs, kernel log)%s\n' "$C_BOLD" "$C_RESET"
CRASH_RE='exit signal|exited on signal|SIGSEGV|SIGBUS|SIGABRT|SIGILL|Segmentation fault|segfault'
MEMX_RE='Allowed memory size of [0-9]+ bytes exhausted|Out of memory \(allocated'
declare -A LOG_SEEN=()
log_hits=0
for f in /var/log/apache2/*error*.log* /var/log/httpd/*error_log* /var/log/nginx/*error*.log* \
         /var/log/ispconfig/httpd/*/error.log* /var/log/php*-fpm.log* /var/log/php*.log* /var/log/php/*.log* \
         /var/log/php-fpm/*.log*; do
  [ -f "$f" ] || continue
  real=$(readlink -f "$f"); [ -n "${LOG_SEEN[$real]+x}" ] && continue; LOG_SEEN[$real]=1
  [ "$(stat -c %Y "$f" 2>/dev/null || echo 0)" -ge "$SINCE_EPOCH" ] || continue
  hits=$(zcat -f "$f" 2>/dev/null | grep -aE "$CRASH_RE|$MEMX_RE" | log_lines_since)
  [ -n "$hits" ] || continue
  n_crash=$(grep -cE "$CRASH_RE" <<<"$hits"); n_memx=$(grep -cE "$MEMX_RE" <<<"$hits")
  check "$f: $n_crash crash line(s), $n_memx memory exhaustion line(s)"
  info "${C_DIM}last: $(tail -n1 <<<"$hits" | cut -c1-170)${C_RESET}"
  log_hits=$((log_hits+1))
done
[ "$log_hits" = 0 ] && ok "No PHP / web server crash or memory exhaustion lines in the error logs."
KERN=""; ksrc=""
if command -v journalctl >/dev/null 2>&1; then
  KERN=$($LONG_TIMEOUT journalctl _TRANSPORT=kernel --since "@$SINCE_EPOCH" -q --no-pager 2>/dev/null); ksrc="kernel journal"
fi
if [ -z "$KERN" ]; then KERN=$(dmesg 2>/dev/null); ksrc="dmesg (since boot, the journal is empty or not available)"; fi
kern_hits=$(grep -iE 'segfault|oom-kill|out of memory|killed process' <<<"$KERN" | grep -iE 'php|apache2|httpd|lsphp')
if [ -n "$kern_hits" ]; then
  check "$ksrc: $(grep -c . <<<"$kern_hits") segfault / OOM line(s) for PHP or the web server (cgroup OOM kills are expected if an attack hits memory_limit = -1)"
  tail -n 5 <<<"$kern_hits" | cut -c1-170 | while IFS= read -r l; do info "${C_DIM}$l${C_RESET}"; done
else
  ok "No PHP / web server segfault or OOM kill in the $ksrc."
fi

# --- 9b. Files in the web roots ---
printf '\n  %sFiles in the web roots%s\n' "$C_BOLD" "$C_RESET"
WEB_ROOTS=()
for r in /var/www /srv/www /srv/http /home; do [ -d "$r" ] && WEB_ROOTS+=("$r"); done
# document roots outside those directories
while IFS= read -r d; do
  [ -d "$d" ] || continue
  case "$d/" in /var/www/*|/srv/www/*|/srv/http/*|/home/*) continue ;; esac
  WEB_ROOTS+=("$d")
done < <( { for f in $(apache_vhost_files); do grep -vE '^[[:space:]]*#' "$f" | awk 'tolower($1) == "documentroot" {gsub(/"/, "", $2); print $2}'; done
            for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do [ -f "$f" ] && sed -E 's/#.*//' "$f" | awk '$1 == "root" {sub(/;.*/, "", $2); gsub(/"/, "", $2); print $2}'; done; } 2>/dev/null | sort -u)
WEBSHELL_RE='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|\$_(POST|GET|REQUEST|COOKIE|SERVER))|assert[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|(system|passthru|shell_exec|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE|SERVER)|[^_a-z]exec[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|create_function[[:space:]]*\(.*\$_(POST|GET|REQUEST|COOKIE)'
if [ ${#WEB_ROOTS[@]} -eq 0 ]; then
  info "No web root found."
else
  info "${C_DIM}searched: ${WEB_ROOTS[*]}${C_RESET}"
  PHP_NAME=( \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.pht' -o -iname '*.phtml' -o -iname '*.phar' \) )
  FIND_OUT=$($LONG_TIMEOUT find "${WEB_ROOTS[@]}" -xdev -maxdepth 12 -type f \
      \( \( "${PHP_NAME[@]}" -o -name .user.ini -o -name .htaccess \) -newermt "@$SINCE_EPOCH" -printf 'NEW\t%TY-%Tm-%Td %TH:%TM\t%u\t%p\n' \) , \
      \( -path '*/uploads/*' "${PHP_NAME[@]}" -printf 'UPL\t%TY-%Tm-%Td %TH:%TM\t%u\t%p\n' \) , \
      \( \( -name .user.ini -o -name .htaccess \) -size -1024k -printf 'CFG\t-\t-\t%p\n' \) 2>/dev/null)
  find_rc=$?
  [ "$find_rc" = 124 ] && warn "The file search timed out (300 s): the lists below are incomplete."
  new_list=$(awk -F'\t' '$1 == "NEW"' <<<"$FIND_OUT" | sort -t$'\t' -k2,2r)
  upl_list=$(awk -F'\t' '$1 == "UPL"' <<<"$FIND_OUT")
  # webshell patterns in new PHP files and in PHP files under uploads/
  shell_hits=$( { cut -f4 <<<"$new_list"; cut -f4 <<<"$upl_list"; } | grep -iE '\.(php[0-9]?|pht|phtml|phar)$' | sort -u | head -n 5000 \
               | while IFS= read -r p; do [ -f "$p" ] && grep -qiE "$WEBSHELL_RE" "$p" 2>/dev/null && echo "$p"; done)
  if [ -n "$shell_hits" ]; then
    bad "Webshell-like code in new PHP files or in uploads/ (eval/assert/system on request data):"
    show_limited 25 info <<<"$shell_hits"
    COUNT_IOC=$((COUNT_IOC+$(grep -c . <<<"$shell_hits"))); raise_exit 2
  else
    ok "No webshell pattern in new PHP files or in PHP files under uploads/."
  fi
  new_count=$(grep -c . <<<"$new_list")
  if [ "$new_count" -gt 0 ]; then
    check "$new_count PHP / .htaccess / .user.ini file(s) created or modified since $SINCE_HUMAN (newest first):"
    awk -F'\t' '{print $2 "  " $3 "  " $4}' <<<"$new_list" | show_limited 30 info
  else
    ok "No PHP / .htaccess / .user.ini file created or modified since $SINCE_HUMAN."
  fi
  # PHP files under uploads/ (any age); tiny "Silence is golden" placeholders are skipped
  upl_real=$(cut -f2,3,4 <<<"$upl_list" | while IFS=$'\t' read -r t u p; do
               [ -n "$p" ] || continue
               if [ "$(stat -c %s "$p" 2>/dev/null || echo 0)" -lt 200 ] && grep -qi 'silence is golden' "$p" 2>/dev/null; then continue; fi
               echo "$t  $u  $p"; done)
  if [ -n "$upl_real" ]; then
    check "PHP file(s) under an uploads/ directory (uploads should never contain PHP):"
    show_limited 25 info <<<"$upl_real"
  fi
  # handlers and auto_prepend in .htaccess / .user.ini (any age)
  cfg_hits=$(awk -F'\t' '$1 == "CFG" {print $4}' <<<"$FIND_OUT" | while IFS= read -r p; do
               grep -vE '^[[:space:]]*[#;]' "$p" 2>/dev/null \
                 | grep -iE 'auto_(prepend|append)_file|(AddHandler|AddType|SetHandler)[[:space:]].*(php|x-httpd)' \
                 | grep -viE 'auto_(prepend|append)_file[[:space:]=]+("|none|$)' \
                 | head -n 2 | sed "s|^|$p: |"; done)
  if [ -n "$cfg_hits" ]; then
    check ".htaccess / .user.ini with auto_prepend_file or a PHP handler (legitimate e.g. for Wordfence or a PHP version switch):"
    cut -c1-170 <<<"$cfg_hits" | show_limited 25 info
  fi
fi

# --- 9c. auto_prepend_file / auto_append_file in the server config ---
printf '\n  %sauto_prepend_file / auto_append_file in the server config%s\n' "$C_BOLD" "$C_RESET"
prepend_hits=$(grep -RIsE 'auto_(prepend|append)_file' /etc/php /etc/php5 /etc/php.ini /etc/php.d /etc/php-fpm.d /etc/opt/remi \
                 /etc/apache2 /etc/httpd /etc/nginx 2>/dev/null \
               | grep -vE '^[^:]+:[[:space:]]*[#;]' \
               | grep -viE 'auto_(prepend|append)_file[^=]*=[[:space:]]*("[[:space:]]*"|none)?[[:space:]]*$' \
               | grep -viE 'auto_(prepend|append)_file[[:space:]]+(none|"")[[:space:]]*$')
if [ -n "$prepend_hits" ]; then
  check "auto_prepend_file / auto_append_file is set (a classic persistence trick; legitimate for e.g. Wordfence):"
  cut -c1-170 <<<"$prepend_hits" | show_limited 20 info
else
  ok "auto_prepend_file / auto_append_file is not set in the PHP, Apache or nginx config."
fi

# --- 9d. Persistence: cron, systemd, SSH keys, accounts ---
printf '\n  %sPersistence: cron, systemd, SSH keys, accounts%s\n' "$C_BOLD" "$C_RESET"
if [ -s /etc/ld.so.preload ]; then
  bad "/etc/ld.so.preload exists and is not empty (rootkit technique): $(tr '\n' ' ' </etc/ld.so.preload | cut -c1-120)"
  COUNT_IOC=$((COUNT_IOC+1)); raise_exit 2
fi
uid0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
if [ -n "$uid0" ]; then
  bad "Accounts with UID 0 besides root: $uid0"
  COUNT_IOC=$((COUNT_IOC+1)); raise_exit 2
fi
persist_files() {
  local f h
  for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* \
           /var/spool/cron/crontabs/* /var/spool/cron/* /etc/rc.local /etc/passwd /etc/shadow /etc/group \
           /etc/sudoers /etc/sudoers.d/* /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /etc/ld.so.preload \
           /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/init.d/*; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done
  # SSH keys and shell startup files of local accounts and of /home/*
  while IFS= read -r h; do
    [ -d "$h" ] || continue
    for f in "$h"/.ssh/authorized_keys* "$h"/.bashrc "$h"/.profile "$h"/.bash_profile; do [ -f "$f" ] && printf '%s\n' "$f"; done
  done < <( { cut -d: -f6 /etc/passwd 2>/dev/null; for h in /home/*; do echo "$h"; done; } | sort -u)
  find /etc/systemd/system /usr/local/lib/systemd/system /etc/systemd/user -xdev \( -type f -o -type l \) 2>/dev/null
}
persist_hits=""
while IFS= read -r f; do
  m=$(stat -c %Y "$f" 2>/dev/null || echo 0)
  [ "$m" -ge "$SINCE_EPOCH" ] || continue
  # a package file changed by an upgrade and still matching the package is not interesting
  if [ "$HAVE_DPKG" = 1 ]; then
    pkg=$(dpkg -S "$f" 2>/dev/null | grep -v '^diversion' | head -n1 | cut -d: -f1)
    if [ -n "$pkg" ] && ! dpkg --verify "$pkg" 2>/dev/null | grep -qF " $f"; then continue; fi
  fi
  persist_hits+="$(date -d "@$m" '+%Y-%m-%d %H:%M')  $f"$'\n'
done < <(persist_files | sort -u)
if [ -n "${persist_hits//$'\n'/}" ]; then
  check "Changed since $SINCE_HUMAN (cron, systemd units, SSH keys, accounts, sudo, shell startup files):"
  sort -r <<<"$persist_hits" | show_limited 30 info
  info "${C_DIM}Your own changes (e.g. systemctl set-property drop-ins, fstab, apt) appear here too.${C_RESET}"
else
  ok "No cron job, systemd unit, SSH key, account or sudo file changed since $SINCE_HUMAN (package files excluded)."
fi

# --- 9e. Processes started by the web server / PHP, and other processes of the web users ---
printf '\n  %sProcesses of the web server and PHP users%s\n' "$C_BOLD" "$C_RESET"
PROC_HITS=$(ps -eo pid=,ppid=,user:32=,comm=,args= 2>/dev/null | awk '
  BEGIN { web = "^(apache2|httpd|php-fpm.*|php[0-9.]+-fpm.*|php5-fpm|php-cgi.*|php[0-9.]*-cgi.*|lsphp.*)$"
          mailer = "sendmail|msmtp|postdrop|exim" }
  { p = $1; ppid[p] = $2; user[p] = $3; comm[p] = $4; a = $0
    sub(/^[ \t]*[0-9]+[ \t]+[0-9]+[ \t]+[^ \t]+[ \t]+[^ \t]+[ \t]*/, "", a); args[p] = a; order[++n] = p }
  END {
    for (i = 1; i <= n; i++) { p = order[i]; if (comm[p] ~ web && user[p] != "root") wu[user[p]] = 1 }
    for (i = 1; i <= n; i++) {
      p = order[i]; pc = comm[ppid[p]]
      if (comm[p] ~ web || comm[p] ~ /^(ps|awk)$/ || args[p] ~ mailer) continue
      if (pc ~ web) print "CHILD\t" p "\t" user[p] "\t" pc "\t" substr(args[p], 1, 120)
      else if ((user[p] in wu) && comm[p] !~ /^php/ && comm[p] !~ /^(nginx|cron|CRON)$/) print "WEBUSER\t" p "\t" user[p] "\t" pc "\t" substr(args[p], 1, 120)
    } }')
child_hits=$(awk -F'\t' '$1 == "CHILD" {print "PID " $2 " (" $3 ", parent " $4 "): " $5}' <<<"$PROC_HITS")
webuser_hits=$(awk -F'\t' '$1 == "WEBUSER" {print "PID " $2 " (" $3 ", parent " $4 "): " $5}' <<<"$PROC_HITS")
if [ -n "$child_hits" ]; then
  check "Processes started by the web server or PHP-FPM (shells, interpreters or download tools are suspicious):"
  show_limited 20 info <<<"$child_hits"
fi
if [ -n "$webuser_hits" ]; then
  check "Other processes running as a web server / PHP user:"
  show_limited 20 info <<<"$webuser_hits"
fi
[ -z "$child_hits$webuser_hits" ] && ok "No process started by the web server or PHP-FPM, and no other process of the web users."

# --- 9f. Outbound connections of the web server / PHP ---
printf '\n  %sOutbound connections of the web server and PHP%s\n' "$C_BOLD" "$C_RESET"
if command -v ss >/dev/null 2>&1; then
  listen_ports=" $(ss -tln 2>/dev/null | awk 'NR > 1 {n = split($4, a, ":"); print a[n]}' | sort -u | tr '\n' ' ') "
  local_addrs=" $(ip -o addr 2>/dev/null | awk '{split($4, a, "/"); print a[1]}' | tr '\n' ' ') "
  out_hits=$(ss -tnp state established 2>/dev/null | awk -v lp="$listen_ports" -v la="$local_addrs" '
    NR == 1 { next }
    /users:\(\("(apache2|httpd|php|lsphp)/ {
      n = split($3, l, ":"); lport = l[n]
      peer = $4; n = split(peer, r, ":"); pport = r[n]; host = substr(peer, 1, length(peer) - length(pport) - 1)
      gsub(/[\[\]]/, "", host); sub(/^::ffff:/, "", host)
      if (index(lp, " " lport " ") > 0) next                     # inbound to a listening port
      if (host ~ /^127\./ || host == "::1" || index(la, " " host " ") > 0) next
      proc = $0; sub(/^.*users:\(\("/, "", proc); sub(/".*$/, "", proc)
      print proc " -> " host ":" pport }' | sort | uniq -c | sort -rn | awk '{c = $1; $1 = ""; sub(/^ /, ""); print $0 "  (" c "x)"}')
  if [ -n "$out_hits" ]; then
    check "Outbound connections (legitimate: databases, LDAP, SMTP, APIs; unknown hosts are suspicious):"
    show_limited 25 info <<<"$out_hits"
  else
    ok "No outbound connection of the web server or PHP right now."
  fi
else
  info "ss is not installed: skipped."
fi

# =============================================================================
header "10. Summary"
if [ "$EXIT_CODE" = 0 ]; then
  ok "Every PHP serving requests is patched, no restart or reload is pending. Nothing to do."
  [ "$COUNT_REVIEW" -gt 0 ] && info "[CHECK] items to review by hand in section 9: $COUNT_REVIEW"
else
  [ "$COUNT_IOC" -gt 0 ]            && bad  "Strong signs of compromise (section 9): $COUNT_IOC"
  [ "$COUNT_VULN_RUNNING" -gt 0 ]   && bad  "Vulnerable or unverifiable RUNNING PHP processes: $COUNT_VULN_RUNNING"
  [ "$COUNT_EXPOSED_FASTCGI" -gt 0 ] && bad "Container FastCGI ports published on all interfaces: $COUNT_EXPOSED_FASTCGI"
  [ "$COUNT_CONTAINER_VULN" -gt 0 ]  && bad "Running containers with vulnerable or unknown PHP: $COUNT_CONTAINER_VULN"
  [ "$COUNT_EXPOSED_DB" -gt 0 ]      && warn "Container database/cache ports published on all interfaces: $COUNT_EXPOSED_DB"
  [ "$COUNT_NEEDS_RESTART" -gt 0 ]  && bad  "Patched package, but restart pending: $COUNT_NEEDS_RESTART"
  [ "$COUNT_STALE_OTHER" -gt 0 ]    && warn "Other processes still running a replaced PHP binary: $COUNT_STALE_OTHER"
  [ "$COUNT_PENDING_CONFIG" -gt 0 ] && warn "Config changes waiting for a reload: $COUNT_PENDING_CONFIG"
  [ "$COUNT_DOWN_POOLS" -gt 0 ]     && warn "Pools used by vhosts whose PHP-FPM is not running: $COUNT_DOWN_POOLS"
  [ "${COUNT_UNMATCHED:-0}" -gt 0 ] && warn "FastCGI addresses whose PHP could not be audited: $COUNT_UNMATCHED"
  [ "$COUNT_VULN_INSTALLED" -gt 0 ] && warn "Vulnerable or unverifiable installed PHP binaries/modules in total: $COUNT_VULN_INSTALLED"
  [ "$COUNT_NO_MULTIPART_BLOCK" -gt 0 ] && warn "vhosts / server blocks serving vulnerable PHP without a multipart block: $COUNT_NO_MULTIPART_BLOCK"
  [ "$COUNT_WRONG_BLOCK" -gt 0 ]    && warn "Multipart blocks that do not work (%{CONTENT_TYPE}): $COUNT_WRONG_BLOCK"
  [ "$COUNT_RLIMIT" -gt 0 ]         && warn "RLIMIT_AS / RLIMIT_DATA memory limits on vulnerable PHP: $COUNT_RLIMIT"
  [ "$COUNT_REVIEW" -gt 0 ]         && info "[CHECK] items to review by hand in section 9: $COUNT_REVIEW"

  # Only the actions that belong to the problems found in this run
  printf '\n  %sRecommended actions:%s\n' "$C_BOLD" "$C_RESET"
  step=0
  action() { step=$((step+1)); printf '   %d. %s\n' "$step" "$1"; shift; local line; for line in "$@"; do printf '      %s\n' "$line"; done; }

  if [ "$COUNT_IOC" -gt 0 ]; then
    action "FIRST: treat the server as compromised (section 9). Preserve the logs, isolate it, review the files found," \
           "rebuild if confirmed, and rotate every secret the web users could read (DB passwords, API keys, LDAP binds)."
  fi
  if [ "$COUNT_EXPOSED_FASTCGI" -gt 0 ] || [ "$COUNT_EXPOSED_DB" -gt 0 ]; then
    action "FIRST: bind the container ports flagged in section 6 to 127.0.0.1 (compose: \"127.0.0.1:HOST:CONTAINER\")," \
           "recreate the containers, and verify from another host that the port is closed (nc -vz -w3 <ip> <port>)." \
           "An exposed FastCGI port allows code execution without any PHP bug: check the mounted volumes for webshells."
  fi
  if [ "$COUNT_CONTAINER_VULN" -gt 0 ]; then
    action "Update the container images with vulnerable PHP (section 6): docker compose pull && docker compose up -d," \
           "then verify with: docker exec <container> php -v. EOL PHP branches need a newer application image."
  fi
  if [ "$COUNT_VULN_RUNNING" -gt 0 ]; then
    action "Update PHP: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; for old branches (5.6-8.1) a backported" \
           "package (Debian/Ubuntu: packages.sury.org). Package-only upgrade (Debian/Ubuntu):" \
           "apt-get install --only-upgrade \$(dpkg-query -W -f='\${db:Status-Abbrev}\${Package}\\n' 'php*' 'libapache2-mod-php*' | awk '/^ii/{print substr(\$0,4)}' | grep -E '^(php[0-9]|libapache2-mod-php[0-9])')" \
           "Then RESTART PHP-FPM (not reload), or Apache when using mod_php, and re-run this script."
    action "Until the update is done: apply the temporary settings shown above per pool / handler" \
           "(both of them: each narrows a different CVE, neither is a complete protection), then reload." \
           "ISPConfig regenerates pool files: use the FPM php.ini per PHP version, \"Custom php.ini settings\"" \
           "per website, or a custom template in /usr/local/ispconfig/server/conf-custom/php_fpm_pool.conf.master."
    if [ "$((COUNT_NO_MULTIPART_BLOCK + COUNT_WRONG_BLOCK))" -gt 0 ]; then
      action "Block multipart/form-data requests on every vhost that does not need uploads (section 8):" \
             "Apache: <If \"req('Content-Type') =~ /multipart/i\"> Require all denied </If>" \
             "nginx:  map \$http_content_type \$php2shell_multipart { default 0; ~*multipart 1; }  +  if (\$php2shell_multipart) { return 403; }" \
             "Restrict the sites that need uploads (admin tools, webmail) by IP where possible, and test from another host."
    fi
  elif [ "$COUNT_VULN_INSTALLED" -gt 0 ]; then
    action "Vulnerable PHP is installed but does not serve web requests (CLI / cron / unused version)." \
           "Update it anyway (scripts and cron jobs run it), or remove the versions you no longer use."
  fi
  if [ "$COUNT_RLIMIT" -gt 0 ]; then
    action "Remove the RLIMIT_AS / RLIMIT_DATA limits (RLimitMEM, LimitAS=, LimitDATA=, ulimit -v / -d) listed in" \
           "section 8; limit memory with a cgroup instead: systemctl set-property <service> MemoryLimit=<size>."
  fi
  if [ "$COUNT_NEEDS_RESTART" -gt 0 ]; then
    action "Restart the PHP services marked 'restart required' in section 3, e.g.:" \
           "systemctl restart 'php*-fpm.service'   (and Apache, if mod_php is used)"
  fi
  if [ "$COUNT_STALE_OTHER" -gt 0 ]; then
    action "Restart the processes listed at the end of section 3 (queue workers, supervisor jobs, ...)."
  fi
  if [ "$COUNT_PENDING_CONFIG" -gt 0 ]; then
    action "Reload the services whose config changed after they started (section 3-5), e.g.:" \
           "systemctl reload phpX.Y-fpm   /   systemctl reload apache2"
  fi
  if [ "$COUNT_DOWN_POOLS" -gt 0 ]; then
    action "Some vhosts point to a pool whose PHP-FPM is not running or not installed (section 4):" \
           "start / reinstall that PHP-FPM, move the site to another PHP version, or disable the site."
  fi
  if [ "${COUNT_UNMATCHED:-0}" -gt 0 ]; then
    action "Check the FastCGI addresses listed in section 4: find what serves them (another host, a stopped" \
           "container...) and verify that PHP separately, or disable the site if nothing should serve it."
  fi
  if [ "${override_files:-0}" -gt 0 ]; then
    action "Remove or neutralise the .user.ini / .htaccess overrides listed in section 7, and lock the" \
           "settings with php_admin_flag / php_admin_value."
  fi
  if [ "$COUNT_VULN_RUNNING" -gt 0 ] || [ "$COUNT_NEEDS_RESTART" -gt 0 ] || [ "$COUNT_CONTAINER_VULN" -gt 0 ] || [ "$COUNT_EXPOSED_FASTCGI" -gt 0 ]; then
    action "Review the [CHECK] items of section 9 (crashes, new PHP files, persistence, processes, connections)," \
           "and check the applications for new admin users. Re-run after patching: bash $0 --since '<date>'."
  fi
fi

exit "$EXIT_CODE"
