###
# tmux configuration file
# Usage: Copy this file to ~/.tmux.conf
# cp tmux.conf ~/.tmux.conf
# Alternative: /etc/tmux.conf for a system-wide config, loaded first for
# every user, IN ADDITION TO (not instead of) their own ~/.tmux.conf.
#
# IMPORTANT: like GNU Screen's ~/.screenrc, tmux only auto-loads this
# file from ~/.tmux.conf (a hidden file directly in the home directory)
# unless started with 'tmux -f /path/to/file'.
#
# Target environment: Debian 9 through 13. tmux's version differs a lot
# across this range (2.3 on Debian 9, 2.8 on 10, 3.1c on 11, 3.3a on 12,
# 3.5a on 13), so every setting below was checked against that whole
# range - same approach as the accompanying .screenrc.
#
# Prefix key: left at the tmux default (Ctrl+b), intentionally NOT
# unified with screen's Ctrl+a - by request, so screen and tmux keep
# their own separate, well-known muscle memory instead of one
# overriding the other.
###

###
# COLORS AND TERMINAL SETTINGS
###

# Base terminal type tmux advertises to programs running inside it.
# Unlike GNU Screen 4.x (which has no truecolor support at all in any
# released version), tmux CAN do real 24-bit color - but the more
# "correct"-looking value "tmux-256color" needs a terminfo entry that
# may be missing on the older end of this range (Debian 9's ncurses
# dates from 2016 and may not ship it, which produces a confusing
# "missing or unsuitable terminal" error). "screen-256color" is the
# same universally-present terminfo entry already relied on in the
# .screenrc, and is the standard, well-documented safe default for tmux
# across old and new systems alike.
set -g default-terminal "screen-256color"

# Layer real 24-bit color support on top via the "Tc" terminal-override,
# rather than the newer "terminal-features" option - the latter only
# exists from tmux 3.2 onward, so it isn't available on Debian 9-11's
# tmux (2.3 / 2.8 / 3.1c). The "Tc" override has worked since tmux 2.2,
# i.e. on every version in the 9-13 range, and is harmless to leave in
# place even on newer tmux that also has terminal-features.
set -ga terminal-overrides ",*:Tc"

###
# SCROLLBACK
###

# Scrollback buffer size (lines kept per pane) - tmux's equivalent of
# screen's defscrollback. Same 10000-line value as the .screenrc, for
# consistency between the two tools.
set -g history-limit 10000

###
# STATUS BAR
###

# Refresh the status bar (for the clock) every 5 seconds instead of the
# 15-second default.
set -g status-interval 5

# Status bar layout, styled to resemble the accompanying .screenrc:
# hostname on the left, window list in the middle, date/time on the
# right. #h/#H and the strftime-style %-codes are standard tmux/format
# specifiers, stable across the whole 9-13 tmux version range.
set -g status-left "#[fg=green,bold][ #h ]#[default]"
set -g status-left-length 20
set -g status-right "#[fg=blue,bold][ %m-%d %H:%M ]#[default]"
set -g status-right-length 20
set -g status-justify centre

# Highlight the active window in the window list
setw -g window-status-current-style "fg=white,bold,bg=red"

###
# GENERAL SETTINGS
###

# UTF-8 handling is automatic from the locale since tmux 2.2+ (Debian
# 9's 2.3 already has this) - unlike screen, no separate "defutf8"-style
# directive is needed here.

# Mouse support: click to select panes/windows, drag borders to resize,
# wheel to scroll through history. The unified "mouse" option needs
# tmux >= 2.1, so it works everywhere in the 9-13 range (Debian 9 has
# 2.3, just above that threshold).
set -g mouse on

# Remove the ~500ms delay tmux waits after Escape by default (it's
# trying to distinguish a bare Escape from the start of a function/
# arrow-key sequence). Without this, vim and similar programs feel
# laggy leaving insert mode inside tmux.
set -s escape-time 10

# Start window and pane numbering at 1 instead of 0 - keys 1-9 on a
# normal keyboard then map naturally to "first, second, third..."
# window, instead of the first window being an outlier at position 0.
set -g base-index 1
setw -g pane-base-index 1

# Automatically renumber the remaining windows when one is closed, so
# numbering stays contiguous instead of leaving gaps.
set -g renumber-windows on

###
# KEYBINDINGS
###

# Reload this config without restarting the session: prefix + r
# (mirrors "bind r source ~/.screenrc" in the accompanying .screenrc)
bind r source-file ~/.tmux.conf \; display-message "tmux.conf reloaded"

###
# USAGE NOTES
###
# Prefix key: Ctrl+b (tmux default - intentionally NOT unified with
# screen's Ctrl+a, see note at the top of this file).
#
# Common keys (all preceded by the prefix):
#   c        new window
#   n / p    next / previous window
#   0-9      jump directly to window by number
#   %        split pane vertically
#   "        split pane horizontally
#   arrow    move between panes
#   d        detach (session keeps running in the background)
#   [        enter copy/scroll mode (q to exit - the tmux equivalent of
#            screen's Ctrl+a Esc)
#
# Reattach to a running session from another terminal or SSH login:
#   tmux attach
###
