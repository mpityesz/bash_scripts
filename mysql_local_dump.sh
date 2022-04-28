#!/bin/bash

SQL_CRED="-u #BACKUPUSERNAME# -p#BACKUPUSERPASSWD#"

## TODO: Export dir from argument
EXPORT_DIR="/mnt/backup/mysql_bkp"

## BACKUP_URI="REMOTEBACKUPUSER@REMOTEHOST::/mnt/backup/storage"

## Day of the week
DOW=$(date "+%u")

echo "show databases;"|mysql $SQL_CRED|grep -v "Database"|grep -v "information_schema"|grep -v "performance_schema"| while read DB; do
  echo  -n "Backing up $DB ... "
  mysqldump $SQL_CRED $DB | gzip > $EXPORT_DIR/$DB.$DOW.sql.gz
  echo "done."
done
