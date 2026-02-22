# comment settings
MOUNT_DIR=/mnt/nvme
NVME_DEV=/dev/nvme0n1

get_nvme_model() {
    local device_path="$1"
    
    # Check if parameter is provided
    if [ -z "$device_path" ]; then
        echo "Error: Please provide NVMe device path" >&2
        return 1
    fi
    
    # Check device path format
    if [[ ! "$device_path" =~ ^/dev/nvme ]]; then
        echo "Error: '$device_path' is not an NVMe device path" >&2
        return 1
    fi
    
    # Check if device exists
    if [ ! -e "$device_path" ]; then
        echo "Error: Device '$device_path' does not exist" >&2
        return 1
    fi
    
    # Extract device name (remove /dev/ prefix)
    local device_name="${device_path#/dev/}"
    
    # Read model number directly from sys filesystem
    if [ -f "/sys/block/$device_name/device/model" ]; then
        local model=$(cat "/sys/block/$device_name/device/model" | sed 's/ *$//')
        echo "$model"
        return 0
    else
        echo "Error: Cannot get model number for device '$device_path'" >&2
        return 1
    fi
}

get_nvme_serial() {
    local device_path="$1"
    
    # Check if parameter is provided
    if [ -z "$device_path" ]; then
        echo "Error: Please provide NVMe device path" >&2
        return 1
    fi
    
    # Check device path format
    if [[ ! "$device_path" =~ ^/dev/nvme ]]; then
        echo "Error: '$device_path' is not an NVMe device path" >&2
        return 1
    fi
    
    # Check if device exists
    if [ ! -e "$device_path" ]; then
        echo "Error: Device '$device_path' does not exist" >&2
        return 1
    fi
    
    # Extract device name (remove /dev/ prefix)
    local device_name="${device_path#/dev/}"
    
    # Read serial number directly from sys filesystem
    if [ -f "/sys/block/$device_name/device/serial" ]; then
        local serial=$(cat "/sys/block/$device_name/device/serial" | sed 's/ *$//')
        echo "$serial"
        return 0
    else
        echo "Error: Cannot get serial number for device '$device_path'" >&2
        return 1
    fi
}

NVME_DEV_NAME=$(get_nvme_model $NVME_DEV)
NVME_DEV_SERIAL=$(get_nvme_serial $NVME_DEV)

# These two SSDs are used for experiments.
if [ "$NVME_DEV_NAME" != "INTEL SSDPFR1Q400GBF" ] && [ "$NVME_DEV_NAME" != "ZHITAI Ti600 1TB" ] && [ "$NVME_DEV_NAME" != "Samsung SSD 990 EVO Plus 1TB" ]; then
    
    # These two SSDs are used for experiments.
    if [ "$NVME_DEV_NAME" == "KINGSTON SNV3S1000G" ] && [ "$NVME_DEV_SERIAL" != "50026B768741AC41" ]; then
        echo "Warning: Unsupported NVMe device model detected: $NVME_DEV_NAME with serial $NVME_DEV_SERIAL"
        exit 1
    fi
fi

echo "Detected NVMe device model: $NVME_DEV_NAME with serial $NVME_DEV_SERIAL"

TARGET_SSD="optane"
if [ "$NVME_DEV_NAME" == "ZHITAI Ti600 1TB" ]; then
TARGET_SSD="consumer"
fi


