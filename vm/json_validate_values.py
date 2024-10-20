#!/usr/bin/env python3

import json
import sys
import re

print("-------------------------------------------")
print("--          Validate JSON values         --")
print("-------------------------------------------")

def end_output_to_shell():
    print("\033[0m-------------------------------------------")
    print("")

def load_config(config_file):
    """Load configuration from a JSON file."""
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config
    except Exception as e:
        print(f"\033[91m[ERROR]           : Error reading the configuration file: {e}")
        sys.exit(1)

def is_valid_hostname(name):
    """
    Validate a hostname according to DNS naming rules:
    - It must consist of alphanumeric characters or hyphens.
    - Labels cannot start or end with a hyphen.
    - The length of the entire hostname cannot exceed 253 characters.
    - Labels are separated by periods and must be between 1 and 63 characters.
    """
    name_regex = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')

    # Check if the overall hostname is too long
    if len(name) > 253:
        return False

    # Split the hostname into labels by periods
    labels = name.split('.')

    # Validate each label in the hostname
    for label in labels:
        if not name_regex.match(label):
            return False

    # If all labels are valid, return True
    return True

def check_values(config):
    errors = []

    for key, obj in config.items():
        first_key = next(iter(obj))
        first_value = obj[first_key]

        # Check if allow_blank is false and the value is empty (only for strings)
        if obj["allow_blank"] is False and isinstance(first_value, str) and first_value == "":
            errors.append(f"\033[91m[ERROR]           : the key '{first_key}' is blank but cannot be blank.")

        # Check if allow_spaces is false and the value contains spaces (only for strings)
        if obj["allow_spaces"] is False and isinstance(first_value, str) and " " in first_value:
            errors.append(f"\033[91m[ERROR]           : the key '{first_key}' contains spaces but cannot have spaces.")

        # Check for correct types (e.g., integers for cores/memory)
        if key in ["TEMPLATE", "ID", "CORES", "MEM" "VLAN", "CLOUDINIT_UPGRADE" "CLOUDINIT_MASK"] and not isinstance(first_value, int):
            errors.append(f"\033[91m[ERROR]           : the key '{first_key}' should be an integer, but found {type(first_value).__name__}.")

        # Check if specific keys have valid DNS names (e.g., NAME, HOST)
        if key in ["NAME"]:
            if not is_valid_hostname(first_value):
                errors.append(f"\033[91m[ERROR]           : the key '{first_key}' does not adhere to DNS naming rules.")


    if errors:
        for error in errors:
            print(f"\033[91m[ERROR]           : {error}")
        sys.exit(1)

    print("\033[92m[SUCCESS]         : All values are valid")
    end_output_to_shell()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("[ERROR]           : Usage: validate_json.py <config.json>")
        sys.exit(1)

    config_file = sys.argv[1]
    config = load_config(config_file)
    check_values(config)
