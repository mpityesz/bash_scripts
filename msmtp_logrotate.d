###
## To check: logrotate --debug /etc/logrotate.d/msmtp
###
/var/log/msmtp/msmtp.log
{
	rotate 7
	weekly
	missingok
	notifempty
	compress
	delaycompress
    sharedscripts
	create 0640 root adm
	postrotate
		invoke-rc.d rsyslog rotate >/dev/null 2>&1 || true
	endscript
}
