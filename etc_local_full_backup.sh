#!/bin/bash

### Directory where the backups will be stored
BACKUP_DIR="/root"

### Day of the week
DOW=$(date "+%u")

### Define the backup file name
BACKUP_FILE="$BACKUP_DIR/etc_backup_$DOW.tar.gz"

### Create a backup of the /etc directory
tar -czf "$BACKUP_FILE" /etc

### Log the backup operation
echo "Backup of /etc completed on $(date) and stored in $BACKUP_FILE" >> /var/log/backup_etc.log
