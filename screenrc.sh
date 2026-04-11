# GNU Screen configuration file
# Usage: Copy this file to ~/.screenrc
# cp screenrc.sh ~/.screenrc
# Alternative: Copy to /usr/local/sbin and create a symlink to this file

###
# COLORS AND TERMINAL SETTINGS
###

# Enable 256 color support
term screen-256color
attrcolor b ".I"
termcapinfo xterm 'Co#256:AB=\E[48;5;%dm:AF=\E[38;5;%dm'
defbce on

###
# SCROLLBACK AND SCROLLING
###

# Scrollback buffer size (10000 lines)
# This determines how much previous output you can scroll back through
defscrollback 10000

# Enable mouse scrolling in xterm
# With this setting the scroll wheel will work
termcapinfo xterm* ti@:te@

###
# STATUS BAR
###

# Display status bar at the bottom
hardstatus alwayslastline
hardstatus string '%{= kG}[ %{G}%H %{g}][%= %{= kw}%?%-Lw%?%{r}(%{W}%n*%f%t%?(%u)%?%{r})%{w}%?%+Lw%?%?%= %{g}][%{B} %m-%d %{W}%c %{g}]'

###
# GENERAL SETTINGS
###

# UTF-8 support
defutf8 on

# Automatic detach on hangup
autodetach on

# Disable startup message
startup_message off

# Visual bell (instead of audio notification)
vbell on
vbell_msg "Bell!"

###
# KEYBOARD COMMANDS
###

# Show help: Ctrl+a then ?
bind ? command -c help
bind -c help h command -c help
bind -c help ? other

###
# USING SCROLLING
###
# 1. Press Ctrl+A then Esc - enters "copy mode"
# 2. Scrolling: arrows, PgUp/PgDn, cursor movement
# 3. Exit: Esc key
###