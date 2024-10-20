#!/bin/bash

# Check if the correct number of arguments are provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <parameter_file.json>"
    exit 1
fi

# Get the directory of the script
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# Assign argument to variable
PARAM_FILENAME="$1"
PARAM_FILE="$SCRIPT_DIR/$1"

# Display the provided parameter file
echo "-------------------------------------------"
echo "Parameter filename: ${PARAM_FILENAME}"
echo "Parameter fullpath: ${PARAM_FILE}"
echo "Script directory  : ${SCRIPT_DIR}"
echo "-------------------------------------------"
echo ""

# Check if the parameter file exists
if [ ! -f "$PARAM_FILE" ]; then
    echo "Error: Parameter file '${PARAM_FILE}' does not exist."
    exit 1
fi

# Validate JSON structure
./json_validate_structure.py "$PARAM_FILENAME"
if [ $? -ne 0 ]; then
    exit 1
fi

# Validate JSON values
./json_validate_values.py "$PARAM_FILENAME"
if [ $? -ne 0 ]; then
    exit 1
fi

# Check SSH login
./proxmox_check_ssh_login.py "$PARAM_FILENAME"
if [ $? -ne 0 ]; then
    exit 1
fi

# Check SSH login
./proxmox_add_snippets_folder.py "$PARAM_FILENAME"
if [ $? -ne 0 ]; then
    exit 1
fi

# Check hostname on PVE host
./proxmox_check_hostname.py "$PARAM_FILENAME"
if [ $? -ne 0 ]; then
    exit 1
fi

# Disable SSH password login
./proxmox_disable_password_login.py "$PARAM_FILENAME"
if [ $? -ne 0 ]; then
    exit 1
fi

# Disable SSH password login
./proxmox_set_no_subcribtion_and_remove_warning.py "$PARAM_FILENAME"
if [ $? -ne 0 ]; then
    exit 1
fi

# Disable SSH password login
./proxmox_import_iso_images.py "$PARAM_FILENAME"
if [ $? -ne 0 ]; then
    exit 1
fi

# Disable SSH password login
./proxmox_update_root_password.py "$PARAM_FILENAME"
if [ $? -ne 0 ]; then
    exit 1
fi

# Disable SSH password login
./proxmox_reboot.py "$PARAM_FILENAME"
if [ $? -ne 0 ]; then
    exit 1
fi
