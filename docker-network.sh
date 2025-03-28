#!/bin/bash

### Parse arguments
for arg in "$@"; do
    case $arg in
        --action=*)
            ACTION="${arg#*=}"
            shift
            ;;
        --network=*)
            DOCKER_NETWORK="${arg#*=}"
            shift
            ;;
        --subnet=*)
            DOCKER_SUBNET="${arg#*=}"
            shift
            ;;
        --gateway=*)
            DOCKER_GATEWAY="${arg#*=}"
            shift
            ;;
        *)
            echo "Unknown parameter: $arg"
            exit 1
            ;;
    esac
done


### Default values
: "${DOCKER_NETWORK:=vowifi_ikev2_net}"
: "${DOCKER_SUBNET:=172.35.0.0/24}"
: "${DOCKER_GATEWAY:=172.35.0.1}"


### Validate action
if [[ -z "$ACTION" ]]; then
    echo "Missing --action parameter (must be 'enable' or 'disable')"
    exit 1
fi
if [[ "$ACTION" != "enable" && "$ACTION" != "disable" ]]; then
    echo "Invalid action: $ACTION (must be 'enable' or 'disable')"
    exit 1
fi


### Perform action
if [[ "$ACTION" == "enable" ]]; then
    ### Check if network exists
    if docker network inspect "$DOCKER_NETWORK" > /dev/null 2>&1; then
        echo "Docker network '$DOCKER_NETWORK' already exists."
    else
        ### Create Docker bridge network with subnet and gateway
        docker network create \
            --driver=bridge \
            --subnet="$DOCKER_SUBNET" \
            --gateway="$DOCKER_GATEWAY" \
            "$DOCKER_NETWORK"
        echo "Docker network '$DOCKER_NETWORK' created with subnet $DOCKER_SUBNET and gateway $DOCKER_GATEWAY."
    fi
elif [[ "$ACTION" == "disable" ]]; then
    ### Check if network exists
    if docker network inspect "$DOCKER_NETWORK" > /dev/null 2>&1; then
        docker network rm "$DOCKER_NETWORK"
        echo "Docker network '$DOCKER_NETWORK' removed."
    else
        echo "Docker network '$DOCKER_NETWORK' does not exist."
    fi
fi
