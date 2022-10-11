#!/bin/bash

###
# Certbot renewal deploy hook
#
# Passed variables:
# RENEWED_DOMAINS contains the list of domain names in the renewed certificate
# RENEWED_LINEAGE refers to the live folder where the certificate material is stored.
###

fqdn=$(hostname -f)

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
    cat /etc/letsencrypt/live/$fqdn/privkey.pem /etc/letsencrypt/live/$fqdn/fullchain.pem > /etc/ssl/private/pure-ftpd.pem
    systemctl restart pure-ftpd-mysql.service
    return 0
}

case $RENEWED_DOMAINS in

    "$fqdn")
        restart_nginx
        restart_postfix
        restart_dovecot
        restart_pure_ftpd_mysql
    ;;

  *)
    ;;

esac

exit 0
