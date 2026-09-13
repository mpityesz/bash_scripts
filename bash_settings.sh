#!/bin/bash

###
# Copy this file to /usr/local/sbin and
# and link at the end of ~/.bashrc
# '. /usr/local/sbin/bash_settings.sh'
###


###
# HISTORY
###

echo "Changing history settings..."

# Append history immediately
shopt -s histappend
#export PROMPT_COMMAND="history -a;$PROMPT_COMMAND"
# Save new commands immediately, then reload new entries from other terminals
# DON'T use 'history -c' as it clears the in-memory history list for this
# shell; without a matching 'history -r' to reload from file right after,
# you'd temporarily lose access to earlier commands in this session.
# Guard against duplication: if this file gets sourced more than once in
# the same shell (e.g. manually re-running 'source ~/.bashrc'), appending
# unconditionally would keep stacking "history -a; history -n;" onto
# PROMPT_COMMAND forever. The case check below only adds it once.
case "$PROMPT_COMMAND" in
    *"history -a; history -n;"*) ;;
    *) export PROMPT_COMMAND="history -a; history -n; ${PROMPT_COMMAND}" ;;
esac

# Make "history" queries in THIS shell immediately reflect commands run
# in OTHER open terminals. The PROMPT_COMMAND above already writes each
# finished command to ~/.bash_history right away (history -a) and pulls
# in new entries once per prompt cycle (history -n) - but that read only
# happens right before a prompt is shown, so running "history" as your
# very first action in a freshly drawn prompt can still miss something
# another terminal wrote a moment earlier. Wrapping the "history" command
# itself to force one more fresh read closes that gap: in bash, a shell
# function takes priority over a builtin of the same name, so this
# transparently overrides plain "history" - and the h/hg aliases further
# down, which just expand to the word "history" and pick this up too.
history() {
    builtin history -n    # pull in anything other terminals wrote since our last read
    builtin history "$@"  # then run the actually requested history command
}

# Make multi-line commandsline in history
shopt -q -s cmdhist

# History time format
export HISTTIMEFORMAT="%Y-%m-%d %T "

# Store 50000 commands in history buffer
export HISTSIZE=50000

# Store 50000 commands in history FILE
export HISTFILESIZE=50000

# Avoid duplicates in history
#export HISTIGNORE='&:[ ]*'
# Avoid saving specific commands from history.
# NOTE: per the Bash manual, each HISTIGNORE pattern is anchored and must
# match the COMPLETE line - Bash does not implicitly append a wildcard.
# So this only hides bare "history", "ls" and "pwd" with no arguments;
# "ls -la" or "pwd -P" still get saved. If you want to also hide those
# with arguments, use "ls*:pwd*" instead.
export HISTIGNORE="history:ls:pwd:"
# ignorespace – eliminates commands that begin with a space history list.
# ignoredups – eliminate duplicate commands.
# ignoreboth – Enable both ignoredups and ignorespace
# erasedups- eliminate duplicates from the whole list
export HISTCONTROL=ignoreboth:erasedups

# Ensure history file exists
touch ~/.bash_history 2>/dev/null


###
# SHELL OPTIONS
###

echo "Shell options..."

# Don't want my shell to warn me of incoming mail.
# NOTE: "shopt -u mailwarn" (the previous version of this line) does NOT
# do this - per the Bash manual, mailwarn only controls the separate
# "The mail in mailfile has been read" notice, and it is already off by
# default in every bash. The actual mail-check mechanism is driven by
# the MAIL/MAILPATH/MAILCHECK variables, so that is what needs clearing:
unset MAILCHECK MAILPATH MAIL

# Correct dir spellings
shopt -q -s cdspell

# Make sure display get updated when terminal window get resized
shopt -q -s checkwinsize

# Turn on the extended pattern matching features
shopt -q -s extglob

# Get immediate notification of background job termination
set -o notify

# Disable [CTRL-D] which is used to exit the shell
#set -o ignoreeof

# Disable core files
#ulimit -S -c 0 > /dev/null 2>&1


###
# TERMINAL & SCREEN SETTINGS
###

echo "Terminal settings..."

# Better terminal support for screen and tmux
# Note: inside a screen session using the accompanying screenrc (which
# sets "term screen-256color"), $TERM typically already arrives here as
# "screen-256color", so the first branch below is mainly a fallback for
# cases where that config isn't in effect (different account, no
# .screenrc, etc). tmux's default TERM is "tmux" unless configured
# otherwise in tmux.conf.
if [[ $TERM == "screen" ]]; then
    export TERM=screen-256color
elif [[ $TERM == "tmux" ]]; then
    export TERM=tmux-256color
elif [[ $TERM == "xterm" ]]; then
    export TERM=xterm-256color
fi

# Enable colors in less
export LESS="-R -M -i -j10"
export LESS_TERMCAP_mb=$'\E[1;31m'     # begin bold
export LESS_TERMCAP_md=$'\E[1;36m'     # begin blink
export LESS_TERMCAP_me=$'\E[0m'        # reset bold/blink
export LESS_TERMCAP_so=$'\E[01;44;33m' # begin reverse video
export LESS_TERMCAP_se=$'\E[0m'        # reset reverse video
export LESS_TERMCAP_us=$'\E[1;32m'     # begin underline
export LESS_TERMCAP_ue=$'\E[0m'        # reset underline


###
# ALIASES + VARIABLES
###

echo "Aliases, other options..."

# Helper: check whether a command exists, without printing anything.
# Used below so we only define an alias/variable for an optional
# (non-essential) tool if it's actually installed - instead of defining
# an alias that fails with "command not found" the moment it's used.
_have() { command -v "$1" >/dev/null 2>&1; }

# Collects one short note per alias/variable skipped below because its
# command isn't installed. Printed once as a summary near the end
# instead of one warning per missing tool, then cleared.
_bs_missing=()

# Use less as pager if available, else fall back to "more" (util-linux,
# effectively always present).
if _have less; then
    export PAGER=less
elif _have more; then
    export PAGER=more
    _bs_missing+=("PAGER: 'less' not found, using 'more' instead (apt install less)")
fi

# Preferred editor, tried in this order. mcedit needs the "mc" package
# (Midnight Commander), which is NOT installed by default on Debian -
# nano/vim/vi are much safer bets if mc isn't there.
for _bs_editor in mcedit nano vim vi; do
    if _have "$_bs_editor"; then
        export EDITOR="$_bs_editor"
        export VISUAL="$_bs_editor"
        break
    fi
done
unset _bs_editor
if [ -n "$VISUAL" ]; then
    export SVN_EDITOR="$VISUAL"
else
    _bs_missing+=("EDITOR/VISUAL: none of mcedit/nano/vim/vi found - set manually")
fi

# MS-DOS / XP cmd like stuff
[ -n "$VISUAL" ] && alias edit="$VISUAL"
alias copy='cp'
alias cls='clear'
alias del='rm'
alias md='mkdir'
alias move='mv'
alias rd='rmdir'
alias ren='mv'
if _have ifconfig; then
    alias ipconfig='ifconfig'
elif _have ip; then
    alias ipconfig='ip addr'
    _bs_missing+=("ipconfig: 'ifconfig' (net-tools) not found, using 'ip addr' instead")
else
    _bs_missing+=("ipconfig: neither ifconfig nor ip found")
fi

# Other Linux stuff
if _have bc; then
    alias bc='bc -l'
else
    _bs_missing+=("bc: not installed (apt install bc)")
fi
_have diff && alias diff='diff -u'

# force colorful grep output
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

# ls stuff
# Note: "dir" and "vdir" here are the actual GNU coreutils dir/vdir
# binaries (separate from ls, with slightly different default formatting),
# not the earlier DOS-style "dir" alias - this is the only "dir" alias
# left in the file, since an earlier "alias dir='ls'" would have been
# silently overridden by this one anyway (last definition wins).
alias l.='ls -d .* --color=auto'
alias ll='ls -lh --color=auto'
alias la='ls -lha --color=auto'
alias ls='ls --color=auto'

alias dir='dir --color=auto'
alias vdir='vdir --color=auto'

# Useful navigation aliases
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'

# History shortcuts
alias h='history'
alias hg='history | grep'

# Process shortcuts
alias psg='ps aux | grep'

# Network
# net-tools (netstat/ifconfig) has NOT been installed by default on
# Debian since version 9 - fall back to the always-present iproute2
# equivalent (ss) if netstat is missing.
if _have netstat; then
    alias ports='netstat -tulanp'
elif _have ss; then
    alias ports='ss -tulanp'
    _bs_missing+=("ports: 'netstat' (net-tools) not found, using 'ss -tulanp' instead")
else
    _bs_missing+=("ports: neither netstat nor ss found")
fi

# System info improvements
alias df='df -h'
alias du='du -h'
alias free='free -h'
alias meminfo='free -h -l -t'
alias cpuinfo='lscpu'
# "column" ships in bsdmainutils (Debian 9-10) / bsdextrautils (11+) -
# usually present, but missing on a --no-install-recommends install or
# a minimal debootstrap. Without this check, "mount" itself would fail
# every time (the alias runs "mount | column -t" as one pipeline, so a
# missing column breaks even plain mount).
if _have column; then
    alias mount='mount | column -t'
else
    _bs_missing+=("mount: 'column' not found, left unaliased so plain mount still works (apt install bsdextrautils)")
fi

# Directory size
alias dud='du -d 1 -h'
alias duf='du -sh *'

# Safety aliases
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'

# Make directory and cd into it
mkcd() {
    mkdir -p "$1" && cd "$1"
}

# Shared by extract() and compress(): checks whether the external tool
# needed for one archive format is installed; if not, prints which
# package provides it and returns 1, instead of letting the raw command
# fail with a bare "command not found".
_archive_need() {
    # $1 = command to check, $2 = package name to suggest installing
    if ! _have "$1"; then
        echo "'$1' is required for this but is not installed (apt install $2)" >&2
        return 1
    fi
}

# Extract almost any common archive format.
# Usage: extract <archive> [destination-directory]
#   destination-directory defaults to the current directory, and is
#   created automatically if it doesn't exist yet.
#
# External dependencies - tar/gzip/bzip2/xz-utils are Debian essential/
# base packages and normally need nothing extra, but every format below
# is still checked at runtime rather than assumed, since the following
# are NOT guaranteed to be pre-installed:
#   .zip           -> unzip
#   .Z             -> ncompress (uncompress)
#   .rar           -> unrar (or unrar-free)
#   .7z            -> p7zip-full
#   .tar.zst/.zst  -> zstd
# .tar.zst is piped through 'zstd -dc' rather than tar's own "--zstd"
# flag, because that flag needs GNU tar 1.31+, which Debian 9 (tar
# 1.29) does not have - piping works on every version.
extract() {
    if [[ "$1" == "-h" || "$1" == "--help" || -z "$1" ]]; then
        cat <<'EOF'
Usage: extract <archive> [destination-directory]

Extracts <archive> into [destination-directory] (default: current
directory; created automatically if it does not exist).

Supported formats:
  .tar  .tar.gz/.tgz  .tar.bz2/.tbz2  .tar.xz/.txz  .tar.zst
  .gz  .bz2  .xz  .Z  .zip  .rar  .7z  .zst
EOF
        return 0
    fi

    local file="$1"
    local dest="${2:-.}"

    if [ ! -f "$file" ]; then
        echo "'$file' is not a valid file" >&2
        return 1
    fi
    mkdir -p "$dest" || return 1

    local base
    base="$(basename "$file")"

    case "$file" in
        *.tar.bz2|*.tbz2) _archive_need tar tar || return 1
                           tar xjf "$file" -C "$dest" ;;
        *.tar.gz|*.tgz)   _archive_need tar tar || return 1
                           tar xzf "$file" -C "$dest" ;;
        *.tar.xz|*.txz)   _archive_need tar tar || return 1
                           tar xJf "$file" -C "$dest" ;;
        *.tar.zst)        _archive_need zstd zstd || return 1
                           zstd -dc "$file" | tar xf - -C "$dest" ;;
        *.tar)            tar xf "$file" -C "$dest" ;;
        *.bz2)            _archive_need bunzip2 bzip2 || return 1
                           bunzip2 -c "$file" > "$dest/${base%.bz2}" ;;
        *.gz)             gunzip -c "$file" > "$dest/${base%.gz}" ;;
        *.xz)             _archive_need unxz xz-utils || return 1
                           unxz -c "$file" > "$dest/${base%.xz}" ;;
        *.Z)              _archive_need uncompress ncompress || return 1
                           uncompress -c "$file" > "$dest/${base%.Z}" ;;
        *.zst)            _archive_need unzstd zstd || return 1
                           unzstd -c "$file" > "$dest/${base%.zst}" ;;
        *.zip)            _archive_need unzip unzip || return 1
                           unzip -d "$dest" "$file" ;;
        *.rar)            _archive_need unrar unrar || return 1
                           unrar x "$file" "$dest/" ;;
        *.7z)             _archive_need 7z p7zip-full || return 1
                           7z x "$file" -o"$dest" ;;
        *) echo "'$file' cannot be extracted via extract() - unrecognised format" >&2
           return 1 ;;
    esac
}

# Create an archive - companion to extract().
# Usage: compress <output-archive> <file-or-directory> [more...]
#   The archive type is inferred from <output-archive>'s extension,
#   mirroring how extract() infers the format from the input filename.
#
# .rar is intentionally NOT supported here: the open-source "unrar"
# tool can only extract RAR archives, not create them - creating one
# needs the proprietary "rar" tool, which isn't in Debian's repos.
compress() {
    if [[ "$1" == "-h" || "$1" == "--help" || $# -lt 2 ]]; then
        cat <<'EOF'
Usage: compress <output-archive> <file-or-directory> [more...]

The archive type is picked from the extension of output-archive.

Supported: .tar  .tar.gz/.tgz  .tar.bz2/.tbz2  .tar.xz/.txz  .tar.zst
           .zip  .7z

Example: compress backup.tar.gz ~/project

(.rar is not supported for creation: the unrar tool can only extract
RAR archives, it cannot create them.)
EOF
        return 0
    fi

    local out="$1"
    shift

    case "$out" in
        *.tar.bz2|*.tbz2) _archive_need tar tar || return 1
                           tar cjf "$out" "$@" ;;
        *.tar.gz|*.tgz)   _archive_need tar tar || return 1
                           tar czf "$out" "$@" ;;
        *.tar.xz|*.txz)   _archive_need tar tar || return 1
                           tar cJf "$out" "$@" ;;
        *.tar.zst)        _archive_need zstd zstd || return 1
                           tar cf - "$@" | zstd -q > "$out" ;;
        *.tar)            tar cf "$out" "$@" ;;
        *.zip)            _archive_need zip zip || return 1
                           zip -r "$out" "$@" ;;
        *.7z)             _archive_need 7z p7zip-full || return 1
                           7z a "$out" "$@" ;;
        *) echo "'$out': unrecognised or unsupported archive extension" >&2
           return 1 ;;
    esac
}

# Root prompt
if [ "$EUID" -eq 0 ]; then
    echo "Root prompt set."
    export PS1="> \[\e[1;32m\]\t\[\e[0m\] [ \[\e[1;34m\]\u\[\e[0m\]@\[\e[1;31m\]\H\[\e[0m\] ] > \[\e[1;32m\]\W\[\e[0m\]\$: "
else
    # User prompt with different colors
    export PS1="> \[\e[1;32m\]\t\[\e[0m\] [ \[\e[1;36m\]\u\[\e[0m\]@\[\e[1;33m\]\H\[\e[0m\] ] > \[\e[1;32m\]\W\[\e[0m\]\$: "
fi

if [ "${#_bs_missing[@]}" -gt 0 ]; then
    echo "Note: some optional tools were missing, so a few aliases/vars"
    echo "were skipped or use a fallback:"
    for _bs_note in "${_bs_missing[@]}"; do
        echo "  - $_bs_note"
    done
    unset _bs_note
fi
unset _bs_missing

echo "Bash settings done."
