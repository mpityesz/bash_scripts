#!/bin/bash

BASE_BACKUP_PATH="/mnt/storage/woody_data/_export/slapd"
BACKUP_FILE="fixnet.hu.ldif"

DOW=$(date "+%u")
DOW_DIR_NAME="slapd-bkp-dow-${DOW}"
DOW_BACKUP_PATH="${BASE_BACKUP_PATH}/${DOW_DIR_NAME}"

mkdir -p "${DOW_BACKUP_PATH}"

## Slapd
slapcat -l "${BASE_BACKUP_PATH}/${BACKUP_FILE}" > /dev/null 2>&1

## Week daily full backup
## Config
/usr/bin/nice /usr/sbin/slapcat -n 0 -l "${DOW_BACKUP_PATH}/config.ldif" > /dev/null 2>&1
## Full
/usr/bin/nice /usr/sbin/slapcat -l "${DOW_BACKUP_PATH}/full.ldif" > /dev/null 2>&1

#/usr/bin/nice /usr/sbin/slapcat -n 1 > ${DOW_BACKUP_PATH}/domain.ldif
#/usr/bin/nice /usr/sbin/slapcat -n 2 > ${DOW_BACKUP_PATH}/access.ldif
#chmod -R 640 "${DOW_BACKUP_PATH}/"

tar cpzf "${DOW_BACKUP_PATH}/etc_ldap.tgz" /etc/ldap > /dev/null 2>&1
tar cpzf "${DOW_BACKUP_PATH}/var_lib_ldap.tgz" /var/lib/ldap > /dev/null 2>&1
