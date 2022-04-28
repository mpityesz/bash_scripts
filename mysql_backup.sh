#!/bin/bash

SQL_CRED="-u #BACKUPUSERNAME# -p#BACKUPUSERPASSWD#"

EXPORT_DIR="/mnt/backup/mysql_bkp"

#BACKUP_URI="remotebackup@dexter.fixnet.hu::/mnt/backup/fixnet.hu/database/mysql"

DOW=$(date "+%u")

echo "show databases;"|mysql $SQL_CRED|grep -v "Database"|grep -v "information_schema"|grep -v "performance_schema"| while read DB; do
  echo  -n "Backing up $DB ... "
  mysqldump $SQL_CRED $DB | gzip > $EXPORT_DIR/$DB.$DOW.sql.gz
  echo "done."
done
