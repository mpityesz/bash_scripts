#!/bin/bash

## @TODO: Source URI from argument
SOURCE_URI="https://github.com/mpityesz/bash_scripts/raw/main"

## @TODO: Download dir from argument
DOWNLOAD_DIR="/root/bash_scripts"

mkdir -p "${DOWNLOAD_DIR}"

## @TODO: Select scripts from argument
declare -a DOWNLOAD_SCRIPTS

DOWNLOAD_SCRIPTS=(
    "backup_crontab"
    "bash_settings.sh"
    "config_mc_mcedit_ini"
    "hdsentinel_daily_report.sh"
    "ispconfig_php_sessionclean.sh"
    "mail_local_rdiff_backup.sh"
    "msmtprc_config"
    "mysql_local_dump.sh"
    "packages_local_backup.sh"
    "slapd_local_full_backup.sh"
    "www_local_rdiff_backup.sh"
)

## Wget selected scripts to download folder
for SCRIPT_NAME in "${DOWNLOAD_SCRIPTS[@]}"; do
    DOWNLOAD_SCRIPT_NAME="${SOURCE_URI}/${SCRIPT_NAME}"
    echo "Downloading ${SCRIPT_NAME} from ${DOWNLOAD_SCRIPT_NAME}..."
    wget --directory-prefix="${DOWNLOAD_DIR}" "${DOWNLOAD_SCRIPT_NAME}"
    echo "Done."
    echo ""
done

## Set execution flag on scripts
cd "${DOWNLOAD_DIR}"
chmod +x *.sh
cd ..
