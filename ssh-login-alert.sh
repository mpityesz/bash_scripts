#!/bin/sh
###
# ssh-login-alert.sh - mail root on every SSH session open
#
# Called by pam_exec in the session phase of sshd's PAM stack. For each new
# SSH session it sends a short mail with user, source address, TTY and time
# to root (forwarded to a real address via /etc/aliases).
#
# Install:
#   install -o root -g root -m 755 ssh-login-alert.sh /usr/local/sbin/ssh-login-alert.sh
#
#   Then append to /etc/pam.d/sshd (make a backup first):
#     # Mail root on every SSH session open (optional: never blocks login)
#     session    optional     pam_exec.so quiet /usr/local/sbin/ssh-login-alert.sh
#
#   No sshd reload is needed: PAM config is read for every new session.
#   Keep an existing root session open while testing.
#
# Requirements:
#   - a working sendmail interface (/usr/sbin/sendmail), e.g. msmtp + msmtp-mta
#   - root mail forwarded to an external address in /etc/aliases
#   - UsePAM yes in sshd (Debian default)
#
# Behavior:
#   - Runs only on session open (PAM_TYPE=open_session), not on close.
#   - Always exits 0. Together with "optional" in the PAM line, a failure
#     of this script can never block a login.
#   - The mail is sent in the background, so a slow or unreachable relay
#     never delays the login.
#   - A failed send is logged to syslog (auth.warning, tag ssh-login-alert).
#     This matters with queueless senders like msmtp, where a failed mail
#     is lost. Check with:
#       journalctl -t ssh-login-alert
#   - ProxyJump / ssh -W connections (port forwarding without a shell) also
#     trigger the alert: sshd opens the PAM session for them too
#     (verified on Debian 13, OpenSSH 10.0). The tty field shows "ssh".
#   - With SSH connection multiplexing (ControlMaster) only the first
#     connection opens a PAM session; later channels reuse it.
#
# Manual test (as root, without PAM):
#   PAM_TYPE=open_session PAM_USER=test PAM_RHOST=192.0.2.1 PAM_SERVICE=sshd \
#     /usr/local/sbin/ssh-login-alert.sh
#
# Rollback:
#   Remove the pam_exec line from /etc/pam.d/sshd (or restore the backup),
#   then delete /usr/local/sbin/ssh-login-alert.sh.
#
# Target: Debian 12 (bookworm), Debian 13 (trixie).
###

# PAM sets PAM_TYPE; anything other than session open is ignored
[ "${PAM_TYPE:-}" = "open_session" ] || exit 0

HOST=$(hostname -f 2>/dev/null || hostname)
SUBJECT="[SSH LOGIN] $HOST: ${PAM_USER:-?} <- ${PAM_RHOST:-?}"

# Build and send the mail in a detached background subshell.
# timeout: do not leave a hanging sendmail process if the relay stalls.
(
    {
        printf 'To: root\n'
        printf 'Subject: %s\n\n' "$SUBJECT"
        printf 'time:    %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
        printf 'host:    %s\n' "$HOST"
        printf 'user:    %s\n' "${PAM_USER:-?}"
        printf 'from:    %s\n' "${PAM_RHOST:-?}"
        printf 'tty:     %s\n' "${PAM_TTY:-?}"
        printf 'service: %s\n' "${PAM_SERVICE:-?}"
    } | timeout 30 /usr/sbin/sendmail -t >/dev/null 2>&1 \
        || logger -p auth.warning -t ssh-login-alert "mail FAILED: $SUBJECT" 2>/dev/null
) >/dev/null 2>&1 &

exit 0
