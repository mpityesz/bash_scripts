#!/bin/bash

### Day of the week
DOW=$(date "+%u")

### @TODO: Export file from argument
EXPORT_FILE="/mnt/backup/packages/installed_packages_list_${DOW}.txt"

### Backup packages
dpkg-query -f '${binary:Package}\n' -W > "${EXPORT_FILE}"

### Reinstall packages
#xargs -a packages_list.txt apt install
