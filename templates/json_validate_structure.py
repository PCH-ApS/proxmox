#!/usr/bin/env python3

import json
import sys

print("-------------------------------------------")
print("--        Validate JSON structure        --")
print("-------------------------------------------")

# Dictionary of mandatory keys and their required first sub-keys
MANDATORY_KEYS = {
    "USER": "username",
    "HOST": "host_ip",
    "ID": "id",
    "NAME": "name",
    "OS_TYPE": "os",
    "CORES": "cores",
    "MEMORY": "mem",
    "STORAGE_CONTROLLER": "storage_ctrl",
    "LOCAL_STORAGE": "local_storage",
    "NETWORK_CONTROLLER": "nic",
    "NETWORK_BRIDGE": "bridge",
    "DISKIMAGE": "image"
}

# Dictionary of optional keys and their required first sub-keys
OPTIONAL_KEYS = {}

def validate_boolean(value, field_name):
    if not isinstance(value, bool):
        print(f"\033[91m[ERROR]           : '{field_name}' must be a boolean (true/false)")
        return False
    return True

def end_output_to_shell():
    print("\033[0m-------------------------------------------")
    print("")

def check_parameters(config_file):
    errors = []
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)

        allowed_keys = set(MANDATORY_KEYS.keys()).union(OPTIONAL_KEYS.keys())

        # Check for invalid keys
        for key in config.keys():
            if key not in allowed_keys:
                errors.append(f"\033[91m[ERROR]           : Invalid key '{key}' found in JSON configuration.")
        # Check for mandatory keys and sub-keys
        for key, sub_key in MANDATORY_KEYS.items():
            if key not in config:
                errors.append(f"\033[91m[ERROR]           : Missing mandatory key '{key}' in JSON configuration.")
            elif sub_key not in config[key]:
                errors.append(f"\033[91m[ERROR]           : Missing mandatory sub-key '{sub_key}' in '{key}' object.")
            elif not validate_boolean(config[key].get("allow_blank", None), f"{key}.allow_blank") or not validate_boolean(config[key].get("allow_spaces", None), f"{key}.allow_spaces"):
                errors.append(f"\033[91m[ERROR]           : Invalid boolean value in {key}")
        # Check for 'comment' key
        for key, obj in config.items():
            if "comment" not in obj:
                print(f"\033[91m[ERROR]           : E'{key}' is missing 'comment' key.")
        if errors:
            for error in errors:
                print(f"\033[91m{error}")
            sys.exit(1)

        print("\033[92m[SUCCESS]         : All parameters are structured correctly")
        end_output_to_shell()

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error reading the configuration file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("[ERROR]           : Usage: validate_json.py <config.json>")
        sys.exit(1)

    config_file = sys.argv[1]
    check_parameters(config_file)
