#!/usr/bin/env python3

import json
import sys

print("-------------------------------------------")
print("--        Validate JSON structure        --")
print("-------------------------------------------")

# Dictionary of mandatory keys and their required first sub-keys
MANDATORY_KEYS = {
    "PVE_USER": "username",
    "PVE_HOST": "host_ip",
    "PVE_NAME": "hostname",
    "PVE_DOMAIN": "domain_string",
    "PVE_SSHKEY": "publickey"


}

# Dictionary of optional keys and their required first sub-keys
OPTIONAL_KEYS = {
    # Example of possible optional keys and their first sub-keys
    "PVE_ISO": "urls"
}

def validate_boolean(value, field_name):
    if value.lower() not in ["true", "false"]:
        print(f"\033[91m[ERROR]           : '{field_name}' must be 'true' or 'false'")
        return False
    return True

def end_output_to_shell():
    print("\033[0m-------------------------------------------")
    print("")

def check_parameters(config_file):
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)

        # Combine all allowed keys (mandatory + optional)
        allowed_keys = set(MANDATORY_KEYS.keys()).union(OPTIONAL_KEYS.keys())

        # Check for invalid keys in the JSON
        for key in config.keys():
            if key not in allowed_keys:
                print(f"\033[91m[ERROR]           : Invalid key '{key}' found in JSON configuration.")
                end_output_to_shell()
                sys.exit(1)

        # Check for mandatory keys and their first sub-keys
        for key, sub_key in MANDATORY_KEYS.items():
            if key not in config:
                print(f"\033[91m[ERROR]           : Missing mandatory key '{key}' in JSON configuration.")
                end_output_to_shell()
                sys.exit(1)

            if sub_key not in config[key]:
                print(f"\033[91m[ERROR]           : Missing mandatory sub-key '{sub_key}' in '{key}' object.")
                end_output_to_shell()
                sys.exit(1)

        # Check for optional keys and their first sub-keys
        for key, sub_key in OPTIONAL_KEYS.items():
            if key in config:  # Only check if the optional key is present
                if sub_key not in config[key]:
                    print(f"\033[91m[ERROR]           : Missing optional sub-key '{sub_key}' in '{key}' object.")
                    end_output_to_shell()
                    sys.exit(1)

        # Iterate through each key in the JSON
        for key, obj in config.items():
            if not isinstance(obj, dict):
                print(f"\033[91m[ERROR]           : {key} is not a valid object.")
                end_output_to_shell()
                sys.exit(1)

            # Check for required keys and validate boolean values
            for sub_key in ["allow_blank", "allow_spaces"]:
                if sub_key not in obj:
                    print(f"\033[91m[ERROR]           : {key} is missing '{sub_key}' key.")
                    end_output_to_shell()
                    sys.exit(1)
                if not validate_boolean(obj[sub_key], f"{key}.{sub_key}"):
                    end_output_to_shell()
                    sys.exit(1)

            # Check for 'comment' key
            if "comment" not in obj:
                print(f"\033[91m[ERROR]           : {key} is missing 'comment' key.")
                end_output_to_shell()
                sys.exit(1)

            # Success message for keys
            key_type = "mandatory" if key in MANDATORY_KEYS else "optional"
            print(f"\033[92m[SUCCESS]         : {key_type.capitalize()} key '{key}' is valid, with sub-key '{MANDATORY_KEYS.get(key, OPTIONAL_KEYS.get(key))}' present.")

        print("\033[92m[SUCCESS]         : All parameters are structured correctly")
        end_output_to_shell()
    except Exception as e:
        print(f"\033[91m[ERROR]           : Error reading the configuration file: {e}")
        end_output_to_shell()
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("[ERROR]           : Usage: validate_json.py <config.json>")
        end_output_to_shell()
        sys.exit(1)

    config_file = sys.argv[1]
    check_parameters(config_file)
