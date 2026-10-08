###
## Logrotate config for the msmtp logfile
##
## Install as: /etc/logrotate.d/msmtp
## Check with: logrotate --debug /etc/logrotate.d/msmtp
##
## Notes:
## - msmtp opens the logfile on every send and does not run as a daemon,
##   so no postrotate action (signal or service restart) is needed.
## - Previous versions called `invoke-rc.d rsyslog rotate` in postrotate.
##   That is unnecessary for msmtp, and fresh Debian 12 / 13 installs do not
##   include rsyslog at all (journald only); it was removed here.
## - Ownership and mode must match the setup in msmtprc_config (section 4).
###
/var/log/msmtp/msmtp.log
{
	rotate 7
	weekly
	missingok
	notifempty
	compress
	delaycompress
	create 0640 root adm
}
