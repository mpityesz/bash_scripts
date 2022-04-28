#!/bin/bash

## @TODO: Directory names from argument
STORAGE_DIR="/mnt/storage/wwwroot/"
BACKUP_DIR="/mnt/backup/wwwroot_bkp/"

## BACKUP_URI="REMOTEBACKUPUSER@REMOTEHOST::/mnt/backup/storage"

## Backup
rdiff-backup \
    --force \
    $STORAGE_DIR \
    $BACKUP_DIR

## Cleanup
#& @TODO: Time from argument
rdiff-backup \
    --force \
    --remove-older-than 4W \
    $BACKUP_DIR
