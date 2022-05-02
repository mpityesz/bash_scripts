#!/bin/bash


## Hdsentinel daily report
##
## Download link: https://www.hdsentinel.com/hdslin/hdsentinel-019c-x64.gz
##
## Arguments:
## --report-file /path/to/report.txt : specify report file (default: ~/hdsentinel_daily_reports/hdsentinel_daily_report_DAY.txt)
## If file exist, backing up the original, and ovewrite it.
##
## --block-device /dev/sda : define selected block device, if not exist, reporting all device


## @TODO
## - email address in argument
## - hdsentinel '-r' option to extended report


## Starting
echo ""
echo "+ -- HD SENTINEL DAILY REPORT------------------------------------ -- +"
echo ""
echo "Arguments:"
echo "--report-file /path/to/report.txt : specify report file (default: /root/hdsentinel_daily_reports/hdsentinel_daily_report_DAY.txt)"
echo "If file exist, backing up the original, and ovewrite it."
echo ""
echo "--block-device /dev/sda : define selected block device, if not exist, reporting all device"
echo ""


## Hdsentinel path
HDSENTINEL_PATH="/opt/hdsentinel/hdsentinel-019c-x64"
echo "Predefined hdsentinel path: ${HDSENTINEL_PATH}"


## Check if hdsentinel exist and executable
## @TODO Auto download hdsentinel...
if [[ ! -x "${HDSENTINEL_PATH}" ]]; then { echo "Hdsentinel is not exist or not executable. Aborting, no report generated."; echo ""; exit 1; } fi


## Default parameters
SELECTED_BLOCK_DEVICE=""
if [[ ${UID} -eq 0 ]]; then { SELECTED_REPORT_FILE_DIRECTORY="/root/hdsentinel_daily_reports"; } else { SELECTED_REPORT_FILE_DIRECTORY="~/hdsentinel_daily_reports"; } fi
SELECTED_REPORT_FILE="${SELECTED_REPORT_FILE_DIRECTORY}/hdsentinel_daily_report_$(date +%d).txt"


## Report email
REPORTING_EMAIL="morar.istvan@gmail.com"
echo "Reporting email: ${REPORTING_EMAIL}"


## Processing argument list, if any exist
ALL_ARGUMENTS="$@"
declare -A SCRIPT_PARAMETERS

for ARG in ${ALL_ARGUMENTS[@]}; do

    ## Check that argument is key or value
    ## Argument key starts with '--'
    PREFIX="${ARG:0:2}"
    if [[ "${PREFIX}" == "--" ]]; then
	TMP_LAST_KEY="${ARG:2}"

    ## If key exist (from the previous loop of the for-cycle) then add the value to script arguments array
    else
	if [[ ! -z "${TMP_LAST_KEY}" ]]; then
	    SCRIPT_PARAMETERS["${TMP_LAST_KEY}"]="${ARG}"
	    TMP_LAST_KEY=""
	fi
    fi
done


## Processing argument
## @TODO: parameter processing with functions
for KEY in ${!SCRIPT_PARAMETERS[@]}; do
    VALUE="${SCRIPT_PARAMETERS[${KEY}]}"

    case "${KEY}" in

	## Selected block device
	"block-device")
	    BLK_DEVICE="${VALUE}"
	    echo "Given block device: ${BLK_DEVICE}"

	    ## If parameter empty, select all
	    if [[ -z "${BLK_DEVICE}" ]]; then
		echo "No block device selected or parameter is empty. All devices will be checked."

	    ## If selected device not exist, select all
	    elif [[ ! -b "${BLK_DEVICE}" ]]; then
		echo "Given block device is not a block device. All devices will be checked."
	    else
		SELECTED_BLOCK_DEVICE="-dev ${BLK_DEVICE}"
	    fi
	;;

	## Report file
	"report-file")
	    REPORT_FILE="${VALUE}"
	    echo "Given report file: ${REPORT_FILE}"
	    REPORT_FILE_DIRECTORY=$(dirname "${REPORT_FILE}")
	    echo "Given report file directory: ${REPORT_FILE_DIRECTORY}"

	    ## If parameter empty, select default
	    if [[ -z "${REPORT_FILE}" ]]; then
		echo "No report file selected or parameter is empty. Default report file will be used."
	    else

		## Check given report file directory is exist and/or writable
		mkdir -p "${REPORT_FILE_DIRECTORY}"
		RETURN_VALUE=$?
		if [[ $RETURN_VALUE -ne 1 ]] && [[ ! -w "${REPORT_FILE_DIRECTORY}" ]]; then
		    echo "Given report file directory not writable. Default report file will be used."
		else

		    ## If given report file not exist, the given report file will be used
		    if [[ ! -e "${REPORT_FILE}" ]]; then
			SELECTED_REPORT_FILE="${REPORT_FILE}"
		    else

			## If given report file is readable-writable, create a copy, the given report file will be used
			if [[ -r "${REPORT_FILE}" && -w "${REPORT_FILE}" ]]; then
			    cp "${REPORT_FILE}" "${REPORT_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
			    SELECTED_REPORT_FILE="${REPORT_FILE}"
			else
			    echo "Given report file not readable or writable. Default report file will be used."
			fi

		    fi ## Given report file not exist else branch end
		fi ## Directory writable else branch end
	    fi ## Parameter empty else branch end
	;;

    esac
done


## Summary of processed parameters
echo ""
echo "+ -- SUMMARIZING PARAMETERS-------------------------------------- -- +"
echo ""
echo "Selected block device (empty value -> all block device will be inspected): ${SELECTED_BLOCK_DEVICE}"
echo "Selected report file: ${SELECTED_REPORT_FILE}"
echo ""


## Execute program
echo ""
echo "+ -- STARTING PROGRAM-------------------------------------------- -- +"
echo ""

## Try to create report directory
SELECTED_REPORT_FILE_DIRECTORY=$(dirname "${SELECTED_REPORT_FILE}")
mkdir -p "${SELECTED_REPORT_FILE_DIRECTORY}"
"${HDSENTINEL_PATH}" "${SELECTED_BLOCK_DEVICE}" > "${SELECTED_REPORT_FILE}"


## Sending report in email
echo ""
echo "+ -- SENDING EMAIL----------------------------------------------- -- +"
echo ""

mail -s "HDsentinel report - ${HOSTNAME} - $(date +%Y-%m-%d)" "${REPORTING_EMAIL}" < "${SELECTED_REPORT_FILE}"

exit 0
