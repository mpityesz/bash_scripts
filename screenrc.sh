# GNU Screen configuration file
# Használat: Másold ezt a fájlt a ~/.screenrc helyre
# cp screenrc.sh ~/.screenrc

###
# SZÍNEK ÉS TERMINAL BEÁLLÍTÁSOK
###

# 256 színes támogatás engedélyezése
term screen-256color
attrcolor b ".I"
termcapinfo xterm 'Co#256:AB=\E[48;5;%dm:AF=\E[38;5;%dm'
defbce on

###
# SCROLLBACK ÉS GÖRGETÉS
###

# Scrollback buffer mérete (10000 sor)
# Ez határozza meg, hogy mennyi korábbi kimenetet tudsz visszagörgetni
defscrollback 10000

# Egér görgetés engedélyezése xterm-ben
# Ezzel a beállítással működni fog a scroll wheel
termcapinfo xterm* ti@:te@

###
# STÁTUSZ SOR
###

# Státusz sor megjelenítése az alsó részen
hardstatus alwayslastline
hardstatus string '%{= kG}[ %{G}%H %{g}][%= %{= kw}%?%-Lw%?%{r}(%{W}%n*%f%t%?(%u)%?%{r})%{w}%?%+Lw%?%?%= %{g}][%{B} %m-%d %{W}%c %{g}]'

###
# ÁLTALÁNOS BEÁLLÍTÁSOK
###

# UTF-8 támogatás
defutf8 on

# Automatikus leválasztás (detach) hangup esetén
autodetach on

# Indulási üzenet kikapcsolása
startup_message off

# Vizuális csengő (hangjelzés helyett)
vbell on
vbell_msg "Bell!"

###
# BILLENTYŰPARANCSOK
###

# Súgó megjelenítése: Ctrl+a majd ?
bind ? command -c help
bind -c help h command -c help
bind -c help ? other

###
# GÖRGETÉS HASZNÁLATA
###
# 1. Nyomj Ctrl+A majd Esc-et - belép a "copy mode"-ba
# 2. Görgetés: nyilak, PgUp/PgDn, kurzor mozgatás
# 3. Kilépés: Esc gomb
###
