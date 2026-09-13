###
# GNU Screen configuration file
# Usage: Copy this file to ~/.screenrc
# cp screenrc.sh ~/.screenrc
# Alternative: Copy to /usr/local/sbin and create a symlink to this file
#
# IMPORTANT: GNU Screen only auto-loads a config file from ~/.screenrc
# (a hidden file directly in the user's home directory) unless started
# with 'screen -c /path/to/file' or with the SCREENRC env var set.
# For a system-wide config that applies to every user, use /etc/screenrc
# instead (loaded in addition to, not instead of, the per-user file).
#
# Target environment: Debian 9 through 13. Screen version differs a lot
# across this range (roughly 4.4 on Debian 9 up to 4.9.x on Debian 13),
# so settings below are chosen to degrade gracefully on the older end.
###

###
# COLORS AND TERMINAL SETTINGS
###

# Enable 256 color support
# Using 256-color (not 24-bit truecolor) as the actual terminal capability
# on purpose: GNU Screen 4.4.x (Debian 9) cannot reliably pass through
# 24-bit color codes, so 256-color is the safest baseline across 9-13.
term screen-256color

# Treat bold text as an instruction to use bright colors instead of a
# separate bold font weight. Per the GNU Screen manual (Attrcolor
# command): "attrcolor b '.I' - Use bright colors for bold text. Most
# terminal emulators do this already." - i.e. this mainly matters for
# terminals that don't already do this substitution on their own.
attrcolor b ".I"

# Tell screen how to translate 256-color escape sequences for the
# outer terminal (xterm) and for screen's own virtual terminals
termcapinfo xterm 'Co#256:AB=\E[48;5;%dm:AF=\E[38;5;%dm'
termcapinfo screen* 'Co#256:AB=\E[48;5;%dm:AF=\E[38;5;%dm'

# Use Background Color Erase so backgrounds fill correctly when
# clearing lines/screen (needed for consistent colored status bar)
defbce on

# MC (Midnight Commander) color support
setenv TERM screen-256color

# NOTE (verified against the GNU Screen manual): the officially released
# 4.x branch of screen - which is what ships in Debian 9 through 13
# (versions 4.4.x up to 4.9.1) - has no 24-bit truecolor support at all.
# It is only present in the unreleased git master / future 5.x branch via
# a "truecolor on" directive, which does not exist in any 4.x release and
# would error out if used here. There is no version- or terminal-dependent
# fallback to describe: on every Debian version in this range, screen is
# hard-limited to the 256-color palette configured above, regardless of
# how capable the outer terminal emulator is.

###
# SCROLLBACK AND SCROLLING
###

# Scrollback buffer size (10000 lines)
# This determines how much previous output you can scroll back through
# Applies per window; increasing this raises memory use per open window
defscrollback 10000

# Enable mouse scrolling in xterm
# xterm normally switches to its own "alternate screen" buffer when an
# app like less/vim runs, which disables the host terminal's own
# scrollback and mouse wheel. Clearing ti (terminal init) and te
# (terminal end) here stops that switch, so the mouse wheel keeps
# scrolling screen's own buffer instead. Trade-off: some full-screen
# apps may leave visible artifacts behind on exit without altscreen
# (see GENERAL SETTINGS below) to compensate.
termcapinfo xterm* ti@:te@

###
# STATUS BAR
###

# Display status bar at the bottom
# alwayslastline reserves the terminal's last line for the status bar
# so it never scrolls away with regular output
hardstatus alwayslastline

# Status bar layout, left to right: hostname (%H), then the list of
# open windows (%-Lw ... %+Lw, with the active one highlighted via
# %n*%f%t), then the date (%m-%d) and clock (%c) on the right.
# %{= kG} etc. are color codes: k=black, G=bright green, g=green,
# w=white, r=red, W=bright white, B=bright blue background
hardstatus string '%{= kG}[ %{G}%H %{g}][%= %{= kw}%?%-Lw%?%{r}(%{W}%n*%f%t%?(%u)%?%{r})%{w}%?%+Lw%?%?%= %{g}][%{B} %m-%d %{W}%c %{g}]'

###
# GENERAL SETTINGS
###

# UTF-8 support
# Ensures new windows start in UTF-8 mode; needed for correct display
# of non-ASCII characters (accented Hungarian letters, box-drawing, etc.)
defutf8 on

# Automatic detach on hangup
# If the connection drops (SSH disconnect, terminal closed), the
# session keeps running detached instead of killing all windows.
# Per the GNU Screen manual this is already "on" by default on every
# build - this line just makes that reliance explicit and self-documenting,
# it does not change behavior versus a stock installation.
autodetach on

# Disable startup message
# Skips the GNU Screen version/copyright splash shown on first launch
startup_message off

# Enables "alternate screen" terminal capability support in screen's
# virtual terminals (per the GNU Screen manual, Redisplay section) -
# the same mechanism xterm uses so full-screen apps (vim, less, mc,
# htop) draw on a separate buffer and restore the prior screen content
# on exit, instead of leaving their output mixed into the scrollback.
altscreen on

# Record window creation/attach/detach events in /etc/utmp so tools
# like 'who' and 'w' show the correct user session info - useful when
# several people share a multi-user Debian host. Per the GNU Screen
# manual this defaults to "on" already on builds compiled with utmp
# support (which is the case for Debian's screen package) - this line
# documents the intent rather than changing the default.
deflogin on

# Per default, screen removes a window from the list as soon as its
# process exits. With "zombie kr" defined, a dead window is kept
# instead: pressing the first key (k) removes it like the kill
# command would, pressing the second key (r) makes screen relaunch
# the original command in that window. (Source: GNU Screen manual,
# Zombie command.)
zombie kr

# Visual bell (instead of audio notification)
# Flashes the screen instead of beeping when an event needs attention
vbell on
vbell_msg "Bell!"

###
# KEYBOARD COMMANDS
###

# Help is available with: Ctrl+a then ?
# Reload config: Ctrl+a then r
# Re-reads and applies ~/.screenrc live, without restarting the whole
# session (existing windows keep running) - handy after editing this file
bind r source ~/.screenrc

###
# USAGE NOTES
###
# Scrolling:
# 1. Press Ctrl+A then Esc (enters "copy mode")
# 2. Use arrows, PgUp/PgDn for scrolling
# 3. Press Esc to exit
#
# Important: Do not start screen from within MC or while MC is running
# Start screen first, then run MC inside screen sessions
###
