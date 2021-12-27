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
# Save and reload the history after each command finishes
export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"

# Make multi-line commandsline in history
shopt -q -s cmdhist

# History time format
export HISTTIMEFORMAT="%y-%m-%d %T "

# Store 5000 commands in history buffer
export HISTSIZE=5000

# Store 5000 commands in history FILE
export HISTFILESIZE=5000

# Avoid duplicates in hisotry
#export HISTIGNORE='&:[ ]*'
# Avoid save special commands
export HISTIGNORE="history:ls:pwd:"
# ignorespace – eliminates commands that begin with a space history list.
# ignoredups – eliminate duplicate commands.
# ignoreboth – Enable both ignoredups and ignorespace
# erasedups- eliminate duplicates from the whole list
export HISTCONTROL=ignoreboth

echo HISTSIZE is $HISTSIZE
echo HISTFILESIZE is $HISTFILESIZE


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
# ALIASES + VA
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
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

# ls stuff
alias l.='ls -d .* --color=auto'
alias ll='ls -l --color=auto'
alias ls='ls --color=auto'

alias dir='dir --color=auto'
alias vdir='vdir --color=auto'

# root prompt
if [ $(id -u) = 0 ]; then
    echo "Root prompt setted..."
    export PS1="> \[\e[1;32m\]\t\[\e[0m\] [ \[\e[1;34m\]\u\[\e[0m\]@\[\e[1;31m\]\H\[\e[0m\] ] > \[\e[1;32m\]\W\[\e[0m\]\$: "
fi

echo "Bash settings done."
