#!/bin/bash

###
## Certbot renewal deploy hook
##
## Passed variables:
## RENEWED_DOMAINS contains the list of domain names in the renewed certificate
## RENEWED_LINEAGE refers to the live folder where the certificate material is stored.
###

FQDN=$(hostname -f)

restart_nginx () {
    systemctl restart nginx.service
    return 0
}

restart_postfix () {
    systemctl restart postfix.service
    return 0
}

restart_dovecot () {
    systemctl restart dovecot.service
    return 0
}

restart_pure_ftpd_mysql () {
    cp /etc/ssl/private/pure-ftpd.pem /etc/ssl/private/pure-ftpd.pem.bak
    cat "/etc/letsencrypt/live/$FQDN/privkey.pem" "/etc/letsencrypt/live/$FQDN/fullchain.pem" > "/etc/ssl/private/pure-ftpd.pem"
    systemctl restart pure-ftpd-mysql.service
    return 0
}

case $RENEWED_DOMAINS in

    "$FQDN")
        restart_nginx
        restart_postfix
        restart_dovecot
        restart_pure_ftpd_mysql
    ;;

  *)
        restart_pure_ftpd_mysql
    ;;

esac

exit 0
