#!/bin/sh
###
# integrity-watch.sh - lightweight host integrity monitor with mail alerts
#
# Collects a text "state" of security-relevant parts of the system (config
# files, keys, accounts, scheduled jobs, listening ports, package file
# checksums, ...) and compares it to a saved baseline. Any difference is
# mailed to root. It is a tripwire, not a protection: a root-level attacker
# can disable it. The daily heartbeat mail makes that visible: if it stops
# arriving, the monitor or mail delivery is broken.
#
# Target: Debian 11 (bullseye), 12 (bookworm), 13 (trixie). POSIX sh (dash).
# Required: only Debian base system tools; checked at start, see REQUIRED_TOOLS.
# If one is missing, nothing is compared and a single error mail is sent.
# Optional: ss (iproute2), nft (nftables), getcap (libcap2-bin), dig
# (bind9-dnsutils / dnsutils). Missing ones only skip their section; their
# presence is part of the state, so installing one later is reported as such.
#
# Usage (as root):
#   integrity-watch.sh init [-y]  Show the difference from the current baseline,
#                                 then save a new baseline after confirmation.
#                                 Run after every intentional change.
#                                 -y: no confirmation (for scripts).
#   integrity-watch.sh check      Compare with the baseline and mail the
#                                 difference. Mails only when the state changes,
#                                 not on every run (cron: every 5 minutes).
#   integrity-watch.sh show       Print the difference from the baseline, no mail.
#   integrity-watch.sh heartbeat  Daily "alive" mail with the current status and
#                                 a full package checksum verification.
#   integrity-watch.sh webcheck   Report PHP-like files created or changed under
#                                 WEB_ROOTS since the previous run (cron: hourly).
#                                 Does nothing if WEB_ROOTS is empty.
#
# Install:
#   install -o root -g root -m 750 integrity-watch.sh /usr/local/sbin/integrity-watch.sh
#   install -o root -g root -m 644 integrity-watch.cron /etc/cron.d/integrity-watch
#   Optional host settings: copy integrity-watch.default to
#   /etc/default/integrity-watch (root-owned, not group/world writable).
#   Then run: integrity-watch.sh init
#
# Design notes:
#   - Every state line is self-describing ("file ...", "port ...", "account ..."),
#     so a single diff line in a mail is understandable without context.
#   - Mails contain hashes, paths and metadata only, never file contents.
#   - Package-owned binaries, libraries and PAM modules are verified against
#     the dpkg checksum database (dpkg --verify) instead of being hashed.
#     This way package updates (e.g. unattended-upgrades) do not cause alerts,
#     but a replaced binary does. Limitation: an attacker with root can also
#     edit the dpkg database; rkhunter or debsums with external reference
#     data cover that case better.
#   - The state advances only after a successful mail. If sending fails, the
#     alert is retried on the next run and the failure is logged to syslog
#     (auth.warning, tag integrity-watch): journalctl -t integrity-watch
#   - Volatile data is excluded on purpose: firewall counters, dynamic set
#     elements (blocklists), ephemeral UDP ports, ~/.ssh/known_hosts, and the
#     content of ~/.google_authenticator (rewritten on every TOTP login when
#     code reuse is disallowed; only its owner and mode are tracked).
###

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
export LC_ALL=C
umask 077

# ---- Defaults (override in /etc/default/integrity-watch) ----

# Directory for baseline and state files
STATE_DIR=/var/lib/integrity-watch
# Mail recipient (local alias or full address)
MAIL_TO=root
# sendmail-compatible program (msmtp-mta, postfix, exim4 all provide this)
SENDMAIL=/usr/sbin/sendmail
# Packages whose files are verified on every check (dpkg --verify).
# Not installed packages are skipped silently.
VERIFY_PACKAGES="openssh-server openssh-client openssh-sftp-server sudo login passwd
 util-linux procps coreutils findutils grep sed mawk gawk bash dash
 libc6 libc-bin libpam0g libpam-modules libpam-modules-bin libpam-runtime
 libpam-google-authenticator libkeyutils1 cron systemd systemd-sysv
 iproute2 net-tools kmod lsof msmtp msmtp-mta nftables iptables"
# Extra files and directories to hash (space separated, no spaces in paths)
EXTRA_FILES=""
EXTRA_DIRS=""
# Extended regex; matching state lines are dropped (host-specific noise)
IGNORE_RE=""
# Web roots for "webcheck" (space separated, empty = disabled)
WEB_ROOTS=""
# Extended regex of paths excluded from the web scan (e.g. caches)
WEB_EXCLUDE_RE=""
# Known bad IPs, extended regex with escaped dots (empty = disabled).
# Any TCP/UDP connection to them is reported.
IOC_IPS=""
# DNS zones whose SOA serial is tracked (empty = disabled), and the server
# to ask. Useful on DNS servers: an unexpected zone change shows up.
DNS_ZONES=""
DNS_SERVER=127.0.0.1

CONF=/etc/default/integrity-watch
if [ -f "$CONF" ]; then
    # Source the config only if it cannot be modified by non-root users
    if [ "$(stat -c '%u' "$CONF")" = 0 ] && [ -z "$(find "$CONF" -perm /022 2>/dev/null)" ]; then
        . "$CONF"
    else
        logger -p auth.warning -t integrity-watch "ignoring unsafe config $CONF (not root-owned or writable by others)" 2>/dev/null
    fi
fi

BASELINE=$STATE_DIR/baseline.txt
BASELINE_PREV=$STATE_DIR/baseline.prev.txt
LAST_ALERTED=$STATE_DIR/last_alerted.txt
CURRENT=$STATE_DIR/current.txt
WEB_MARKER=$STATE_DIR/web_marker
WEB_NEW=$STATE_DIR/web_new.txt
HOST=$(hostname -f 2>/dev/null || hostname)
SELF=$(readlink -f "$0")

[ "$(id -u)" = 0 ] || { echo "Must run as root." >&2; exit 1; }
mkdir -p "$STATE_DIR" || exit 1

# ---- Dependencies ----
#
# Required tools: without them a part of the state would silently be empty,
# which hides changes. All of them are in the Debian base system
# (coreutils, findutils, diffutils, mawk, grep, sed, util-linux, bsdutils,
# dpkg, hostname, libc-bin). If one is missing, the script does not compare
# anything; it reports the problem once (and again only if the list of
# missing tools changes) and exits.
#
# Optional tools: their sections are skipped if the tool is missing. Each
# one's presence is recorded in the state as "tool <name> present|absent",
# so installing one later shows up in the alert with the reason.
REQUIRED_TOOLS="awk cat cmp cp cut date diff dpkg dpkg-query find getent grep head hostname id
 ionice logger mv nice readlink sed sha256sum sort stat timeout wc"
OPTIONAL_TOOLS="ss nft getcap dig"

missing=""
for t in $REQUIRED_TOOLS; do
    command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
done
[ -x "$SENDMAIL" ] || missing="$missing $SENDMAIL"
MISSING_FILE=$STATE_DIR/missing_tools.txt
if [ -n "$missing" ]; then
    echo "Missing required tools:$missing" >&2
    logger -p auth.err -t integrity-watch "missing required tools:$missing" 2>/dev/null
    if [ "$(cat "$MISSING_FILE" 2>/dev/null)" != "$missing" ] && [ -x "$SENDMAIL" ]; then
        { printf 'To: %s\nSubject: [INTEGRITY ERROR] %s: missing tools\n\n' "$MAIL_TO" "$(hostname)"
          echo "integrity-watch cannot run, required tools are missing:$missing"
          echo "No integrity check is done until this is fixed."
        } | timeout 30 "$SENDMAIL" -t >/dev/null 2>&1 && echo "$missing" > "$MISSING_FILE"
    fi
    exit 1
fi
rm -f "$MISSING_FILE"

have() { command -v "$1" >/dev/null 2>&1; }

# ---- Helpers ----

# Send a mail; subject in $1, body on stdin. Returns non-zero on failure.
send_mail() {
    if { printf 'To: %s\nSubject: %s\n\n' "$MAIL_TO" "$1"; cat; } \
        | timeout 30 "$SENDMAIL" -t >/dev/null 2>&1; then
        return 0
    fi
    logger -p auth.warning -t integrity-watch "mail FAILED: $1" 2>/dev/null
    return 1
}

# "file <sha256> <mode> <owner:group> <path>", or "link <path> -> <target>"
hash_file() {
    if [ -L "$1" ]; then
        echo "link $1 -> $(readlink "$1")"
    elif [ -f "$1" ]; then
        echo "file $(sha256sum < "$1" | cut -c1-64) $(stat -c '%a %U:%G' "$1") $1"
    fi
}

# Owner and mode only, for files whose content changes legitimately
meta_file() {
    [ -e "$1" ] && echo "meta $(stat -c '%a %U:%G' "$1") $1"
}

# Hash every file and symlink below the given directories
hash_dirs() {
    for d in "$@"; do
        [ -d "$d" ] || continue
        find "$d" \( -type f -o -type l \) 2>/dev/null | while IFS= read -r f; do
            hash_file "$f"
        done
    done
}

# Print each existing directory once, with symlinks resolved.
# Needed because /bin, /sbin and /lib are symlinks into /usr on merged-/usr
# systems (Debian 12/13, and new Debian 11 installs) but real directories on
# older installs.
real_dirs() {
    for d in "$@"; do
        [ -d "$d" ] && readlink -f "$d"
    done | sort -u
}

# ---- State collection ----

collect_files() {
    for f in \
        /etc/passwd /etc/shadow /etc/group /etc/gshadow \
        /etc/sudoers /etc/sudo.conf \
        /etc/ld.so.preload /etc/ld.so.conf \
        /etc/crontab /etc/rc.local \
        /etc/environment /etc/profile /etc/bash.bashrc \
        /etc/hosts /etc/hosts.allow /etc/hosts.deny /etc/nsswitch.conf /etc/resolv.conf \
        /etc/aliases /etc/msmtprc /etc/modules /etc/sysctl.conf \
        /etc/nftables.conf /etc/rkhunter.conf /etc/rkhunter.conf.local \
        /etc/network/interfaces \
        "$CONF" "$SELF" \
        $EXTRA_FILES
    do
        hash_file "$f"
    done

    # Directories where a new or changed file means new code running as root
    # or changed authentication / network behavior:
    #   ssh, pam.d, security, sudoers.d  - authentication
    #   ld.so.conf.d                     - library loading
    #   cron.*, /var/spool/cron          - scheduled jobs (crontabs, at jobs)
    #   systemd, init.d                  - services, timers, enabled units
    #   profile.d, update-motd.d         - run on every login
    #   logrotate.d                      - postrotate scripts run as root
    #   apt/apt.conf.d                   - APT hooks run as root on updates
    #   apt sources and keyrings         - new package sources
    #   kernel, modprobe.d, modules-load.d, sysctl.d, udev/rules.d
    #   network, dhcp                    - interface hook scripts
    #   apparmor.d/local, apparmor.d/disable - profile extensions / disabled profiles
    #   docker, ufw, iptables, fail2ban  - container and firewall config
    #   /usr/local/bin, /usr/local/sbin  - local, non-packaged programs
    hash_dirs \
        /etc/ssh /etc/pam.d /etc/security /etc/sudoers.d \
        /etc/ld.so.conf.d \
        /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
        /var/spool/cron \
        /etc/systemd /etc/init.d \
        /etc/profile.d /etc/update-motd.d /etc/logrotate.d \
        /etc/apt/apt.conf.d /etc/apt/sources.list.d /etc/apt/trusted.gpg.d /etc/apt/keyrings \
        /etc/kernel /etc/modprobe.d /etc/modules-load.d /etc/sysctl.d /etc/udev/rules.d \
        /etc/network /etc/dhcp \
        /etc/apparmor.d/local /etc/apparmor.d/disable \
        /etc/docker /etc/ufw /etc/iptables /etc/fail2ban \
        /usr/local/bin /usr/local/sbin \
        /root/.config/systemd \
        $EXTRA_DIRS
    for f in /etc/apt/sources.list /etc/apt/trusted.gpg \
             /root/.bashrc /root/.profile /root/.bash_profile /root/.bash_login; do
        hash_file "$f"
    done

    # Per-user SSH files that grant access or run code at login.
    # known_hosts is skipped on purpose (changes on every new outgoing host).
    getent passwd | cut -d: -f6 | sort -u | while IFS= read -r h; do
        [ -d "$h" ] || continue
        for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2" \
                 "$h/.ssh/rc" "$h/.ssh/environment"; do
            hash_file "$f"
        done
        meta_file "$h/.google_authenticator"
    done

    # Shared libraries in /usr/local/lib (not covered by dpkg verification)
    find /usr/local/lib -name '*.so*' \( -type f -o -type l \) 2>/dev/null | while IFS= read -r f; do
        hash_file "$f"
    done
}

collect_packages() {
    # Changed package files (checksum only; conffiles are tracked above).
    # dpkg --verify line format: 9 flag characters, attribute, path;
    # flag 3 = "5" means checksum mismatch, attribute "c" means conffile.
    installed=$(dpkg-query -W -f='${Package} ${db:Status-Abbrev}\n' $VERIFY_PACKAGES 2>/dev/null \
                | awk '$2 ~ /^ii/ {print $1}')
    [ -n "$installed" ] && dpkg --verify $installed 2>/dev/null \
        | grep -E '^..5' | grep -vE '^.{9} c ' | sed 's/^/pkgfile-changed /'

    # Files in PAM module directories that are not owned by any package.
    # dpkg --verify cannot see a newly added module, only changed ones.
    # Paths are compared without the /usr prefix, because packages list them
    # as /lib/... (Debian 11/12) or /usr/lib/... (Debian 13).
    owned=$STATE_DIR/pam_owned.tmp
    cat /var/lib/dpkg/info/*.list 2>/dev/null | grep -E '/security/[^/]+\.so$' \
        | sed 's#^/usr##' | sort -u > "$owned"
    for d in $(real_dirs /lib/security /lib/*/security /usr/lib/security /usr/lib/*/security); do
        for f in "$d"/*.so; do
            [ -f "$f" ] || continue
            grep -qxF "${f#/usr}" "$owned" || hash_file "$f" | sed 's/^/pam-unpackaged /'
        done
    done
    rm -f "$owned"
}

collect_accounts() {
    getent passwd | awk -F: '$3 == 0 {print "account uid0 " $1}'
    # Accounts that can log in interactively
    getent passwd | awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print "account shell " $1 " " $7}'
    # Accounts with a usable password (hash field is not locked or empty)
    awk -F: '$2 != "" && $2 !~ /^[!*]/ {print "account password " $1}' /etc/shadow
    # Members of groups that grant root-level access
    for g in sudo adm docker wheel lxd libvirt disk shadow; do
        m=$(getent group "$g" | cut -d: -f4)
        [ -n "$m" ] && echo "group $g $m"
    done
}

collect_runtime() {
    # Which optional tools are available (see Dependencies)
    for t in $OPTIONAL_TOOLS; do
        if have "$t"; then echo "tool $t present"; else echo "tool $t absent"; fi
    done

    # Listening sockets with the owning program (pids removed, they change).
    # UDP sockets in the ephemeral port range are clients, not services.
    eph=$(cut -f1 /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null)
    [ -n "$eph" ] || eph=32768
    have ss && ss -tulnpH 2>/dev/null | awk -v eph="$eph" '{
        addr = $5; port = addr; sub(/.*:/, "", port)
        if ($1 == "udp" && port + 0 >= eph) next
        prog = "?"
        if (match($0, /users:\(\("[^"]+"/)) prog = substr($0, RSTART + 9, RLENGTH - 10)
        print "port " $1 " " addr " " prog
    }' | sort -u

    # SUID/SGID files in system directories and in world-writable places
    for d in $(real_dirs /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
                         /lib /usr/lib /usr/libexec /home /tmp /var/tmp /dev/shm); do
        find "$d" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null
    done | sort -u | while IFS= read -r f; do
        echo "suid $(stat -c '%a %U:%G' "$f") $f"
    done

    # File capabilities (e.g. cap_setuid on a copied interpreter)
    if have getcap; then
        for d in $(real_dirs /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/lib); do
            getcap -r "$d" 2>/dev/null
        done | sort -u | sed 's/^/cap /'
    fi

    # Loaded kernel modules (read directly, no kmod/lsmod needed) and the
    # kernel taint flags
    awk '{print "module " $1}' /proc/modules 2>/dev/null | sort
    echo "kernel tainted $(cat /proc/sys/kernel/tainted 2>/dev/null)"

    # Processes running from writable temp dirs or from memory (fileless)
    for p in /proc/[0-9]*; do
        e=$(readlink "$p/exe" 2>/dev/null) || continue
        case "$e" in
            /tmp/*|/var/tmp/*|/dev/shm/*|/memfd:*|memfd:*) echo "process-exe $e" ;;
        esac
    done | sort -u

    # Firewall: active ruleset without counters and without set elements
    # (dynamic blocklists change constantly; their definitions still count).
    # Only if nf_tables is already loaded: running nft would load the kernel
    # module itself, and the monitor must not change what it measures.
    if have nft && grep -q '^nf_tables ' /proc/modules 2>/dev/null; then
        nft -s list ruleset 2>/dev/null \
            | awk '/elements = \{/ {skip = 1} skip && /\}/ {skip = 0; next} !skip' \
            | sed 's/^[[:space:]]*//' | grep -v '^$' | sed 's/^/nft /'
    fi

    # Connections to known bad IPs
    if [ -n "$IOC_IPS" ] && have ss; then
        ss -tunH 2>/dev/null | grep -E "$IOC_IPS" | awk '{print "ioc-conn " $1 " " $6}' | sort -u
    fi

    # SOA serials of watched DNS zones.
    # A failed query (timeout, server restarting) must not look like a
    # change, so the value from the previous run is reused in that case.
    if [ -n "$DNS_ZONES" ] && have dig; then
        for z in $DNS_ZONES; do
            serial=$(dig +short +time=3 +tries=2 SOA "$z" @"$DNS_SERVER" 2>/dev/null | awk 'NF >= 7 {print $3; exit}')
            if [ -n "$serial" ]; then
                echo "dns-soa $z $serial"
            else
                prev=$(grep -m1 "^dns-soa $z " "$CURRENT" 2>/dev/null)
                if [ -n "$prev" ]; then echo "$prev"; else echo "dns-soa $z unavailable"; fi
                logger -p auth.notice -t integrity-watch "SOA query failed for $z at $DNS_SERVER" 2>/dev/null
            fi
        done
    fi
}

collect_state() {
    {
        collect_files
        collect_packages
        collect_accounts
        collect_runtime
    } | if [ -n "$IGNORE_RE" ]; then grep -vE "$IGNORE_RE"; else cat; fi | sort -u
}

# Full package checksum verification (all packages), for the daily heartbeat
verify_all_packages() {
    nice -n 19 ionice -c 3 dpkg --verify 2>/dev/null | grep -E '^..5' | grep -vE '^.{9} c '
}

# ---- Commands ----

case "${1:-check}" in
    init)
        collect_state > "$CURRENT.new" && mv "$CURRENT.new" "$CURRENT" || exit 1
        if [ -s "$BASELINE" ]; then
            if diff "$BASELINE" "$CURRENT" > "$STATE_DIR/init.diff"; then
                echo "No difference from the current baseline."
            else
                echo "Difference from the current baseline (< old, > new):"
                cat "$STATE_DIR/init.diff"
            fi
            if [ "$2" != "-y" ]; then
                printf 'Save this as the new baseline? [y/N] '
                read -r answer
                case "$answer" in y|Y|yes) ;; *) echo "Not saved."; exit 1 ;; esac
            fi
            cp -p "$BASELINE" "$BASELINE_PREV"
        fi
        cp "$CURRENT" "$BASELINE" && cp "$CURRENT" "$LAST_ALERTED" || exit 1
        echo "Baseline saved: $BASELINE ($(wc -l < "$BASELINE") lines)"
        printf 'New baseline saved at %s by %s.\nPrevious baseline: %s\n' \
            "$(date '+%F %T')" "${SUDO_USER:-$(id -un)}" "$BASELINE_PREV" \
            | send_mail "[INTEGRITY] $HOST: new baseline"
        ;;

    check)
        if [ ! -s "$BASELINE" ]; then
            echo "No baseline found ($BASELINE). Run: $SELF init" \
                | send_mail "[INTEGRITY ALERT] $HOST: no baseline"
            exit 1
        fi
        collect_state > "$CURRENT.new" && mv "$CURRENT.new" "$CURRENT" || exit 1
        # Alert only when the state differs from what was last reported
        cmp -s "$CURRENT" "$LAST_ALERTED" && exit 0
        n=$(diff "$BASELINE" "$CURRENT" | grep -c '^[<>]')
        if [ "$n" -eq 0 ]; then
            msg="The state is back to the baseline."
            subject="[INTEGRITY] $HOST: back to baseline"
        else
            msg="Difference from the baseline (< baseline, > now):"
            subject="[INTEGRITY ALERT] $HOST: $n changed line(s)"
        fi
        if { echo "$msg"; echo
             diff "$BASELINE" "$CURRENT" | grep '^[<>]' | head -n 400
             [ "$n" -gt 400 ] && echo "... $n changed lines in total, run: $SELF show"
             echo
             echo "If the change is intentional, run: $SELF init"
           } | send_mail "$subject"; then
            cp "$CURRENT" "$LAST_ALERTED"
        fi
        ;;

    show)
        [ -s "$BASELINE" ] || { echo "No baseline found."; exit 1; }
        collect_state | diff "$BASELINE" - && echo "No difference."
        ;;

    heartbeat)
        if [ -s "$BASELINE" ] && collect_state | cmp -s - "$BASELINE"; then
            status="no difference"
        else
            status="DIFFERENCE FOUND"
        fi
        verify_all_packages > "$STATE_DIR/verify_all.txt"
        nv=$(wc -l < "$STATE_DIR/verify_all.txt")
        absent=""
        for t in $OPTIONAL_TOOLS; do have "$t" || absent="$absent $t"; done
        { echo "The integrity monitor is running."
          echo "Baseline: $status"
          [ -n "$absent" ] && echo "Optional tools not installed (their checks are skipped):$absent"
          echo "Package files with changed checksum (all packages, conffiles excluded): $nv"
          if [ "$nv" -gt 0 ]; then
              echo; head -n 50 "$STATE_DIR/verify_all.txt"
              echo; echo "Check with: dpkg --verify <package>; reinstall with: apt install --reinstall <package>"
          fi
          [ "$status" = "no difference" ] || { echo; echo "Details: $SELF show"; }
        } | send_mail "[INTEGRITY] $HOST daily heartbeat: $status, $nv changed package file(s)"
        ;;

    webcheck)
        [ -n "$WEB_ROOTS" ] || exit 0
        if [ ! -e "$WEB_MARKER" ]; then
            touch "$WEB_MARKER"
            echo "Web marker created; the next run reports changes from now on."
            exit 0
        fi
        touch "$WEB_MARKER.new"
        # ctime is used because it cannot be backdated with touch
        nice -n 19 ionice -c 3 find $WEB_ROOTS -type f \
            \( -iname '*.ph*' -o -name '.htaccess' -o -name '.user.ini' \) \
            -cnewer "$WEB_MARKER" -printf '%CY-%Cm-%Cd %CH:%CM %u %s %p\n' 2>/dev/null \
            | if [ -n "$WEB_EXCLUDE_RE" ]; then grep -vE "$WEB_EXCLUDE_RE"; else cat; fi \
            | sort > "$WEB_NEW"
        if [ -s "$WEB_NEW" ]; then
            n=$(wc -l < "$WEB_NEW")
            { echo "PHP-like files created or changed (by ctime) since the previous scan:"
              echo "(ctime, owner, size, path)"; echo
              head -n 200 "$WEB_NEW"
              [ "$n" -gt 200 ] && echo "... $n files in total, see $WEB_NEW"
            } | send_mail "[INTEGRITY WEB] $HOST: $n new/changed file(s)" || exit 1
        fi
        mv "$WEB_MARKER.new" "$WEB_MARKER"
        ;;

    *)
        echo "Usage: $0 init [-y] | check | show | heartbeat | webcheck" >&2
        exit 2
        ;;
esac
