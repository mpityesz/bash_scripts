#!/bin/bash

EXPORT_FILE="/root/packages_list.txt"

# Backup packages
dpkg-query -f '${binary:Package}\n' -W > "${EXPORT_FILE}"

# Reinstall packages
#xargs -a packages_list.txt apt install
