#!/bin/bash

clear

# Check if the correct number of arguments are provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <parameter_file.json>"
    exit 1
fi

# Get the directory of the script
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# Assign argument to variable
PARAM_FILE="$1"

# Display the provided parameter file
echo "-------------------------------------------"
echo "Parameter filename: ${PARAM_FILE}"
echo "Script directory  : ${SCRIPT_DIR}"
echo "-------------------------------------------"
echo ""

# Check if the parameter file exists
if [ ! -f "$PARAM_FILE" ]; then
    echo "Error: Parameter file '${PARAM_FILE}' does not exist."
    exit 1
fi

# Validate JSON structure
./json_validate_structure.py "$PARAM_FILE"
if [ $? -ne 0 ]; then
    exit 1
fi

# Validate JSON values
./json_validate_values.py "$PARAM_FILE"
if [ $? -ne 0 ]; then
    exit 1
fi

# Check SSH login
./proxmox_validate_and_build_linux_template.py "$PARAM_FILE"
if [ $? -ne 0 ]; then
    exit 1
fi