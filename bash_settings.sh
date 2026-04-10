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
# DON'T use 'history -c' as it clears and rewrites timestamps!
export PROMPT_COMMAND="history -a; history -n; ${PROMPT_COMMAND}"

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
# Avoid save special commands
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
#unset MAILCHECK
shopt -u mailwarn

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
if [[ $TERM == "screen" ]]; then
    export TERM=screen-256color
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

# Use less command as a pager
export PAGER=less

# Set vim as default text editor
export EDITOR=mcedit
export VISUAL=mcedit
export SVN_EDITOR="$VISUAL"

# MS-DOS / XP cmd like stuff
alias edit=$VISUAL
alias copy='cp'
alias cls='clear'
alias del='rm'
alias dir='ls'
alias md='mkdir'
alias move='mv'
alias rd='rmdir'
alias ren='mv'
alias ipconfig='ifconfig'

# Other Linux stuff
alias bc='bc -l'
alias diff='diff -u'

# force colorful grep output
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

# ls stuff
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
alias ports='netstat -tulanp'

# System info improvements
alias df='df -h'
alias du='du -h'
alias free='free -h'
alias meminfo='free -h -l -t'
alias cpuinfo='lscpu'
alias mount='mount | column -t'

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

# Extract various archive formats
extract() {
    if [ -f "$1" ]; then
        case "$1" in
            *.tar.bz2)   tar xjf "$1"     ;;
            *.tar.gz)    tar xzf "$1"     ;;
            *.bz2)       bunzip2 "$1"     ;;
            *.rar)       unrar x "$1"     ;;
            *.gz)        gunzip "$1"      ;;
            *.tar)       tar xf "$1"      ;;
            *.tbz2)      tar xjf "$1"     ;;
            *.tgz)       tar xzf "$1"     ;;
            *.zip)       unzip "$1"       ;;
            *.Z)         uncompress "$1"  ;;
            *.7z)        7z x "$1"        ;;
            *)           echo "'$1' cannot be extracted via extract()" ;;
        esac
    else
        echo "'$1' is not a valid file"
    fi
}

# root prompt
#if [ $(id -u) = 0 ]; then
if [ "$EUID" -eq 0 ]; then
    echo "Root prompt setted..."
    export PS1="> \[\e[1;32m\]\t\[\e[0m\] [ \[\e[1;34m\]\u\[\e[0m\]@\[\e[1;31m\]\H\[\e[0m\] ] > \[\e[1;32m\]\W\[\e[0m\]\$: "
else
    # User prompt with different colors
    export PS1="> \[\e[1;32m\]\t\[\e[0m\] [ \[\e[1;36m\]\u\[\e[0m\]@\[\e[1;33m\]\H\[\e[0m\] ] > \[\e[1;32m\]\W\[\e[0m\]\$: "
fi

echo "Bash settings done."
