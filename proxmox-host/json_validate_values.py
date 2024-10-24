#!/usr/bin/env python3

import json
import sys

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
        end_output_to_shell()
        sys.exit(1)

def get_json_values(config):
    # Extract needed variables from JSON file
    return {
        "pve_user": config.get("PVE_USER").get("username"),
        "pve_host": config.get("PVE_HOST").get("host_ip"),
        "pve_name": config.get("PVE_NAME").get("hostname"),
        "pve_domain": config.get("PVE_DOMAIN").get("domain_string"),
        "pve_sshkey": config.get("PVE_SSHKEY").get("publickey"),
        "pve_iso": config.get("PVE_ISO").get("urls")
    }


def check_spaces(config_file):
    errors = []
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)

        for key, obj in config.items():
            # Get the first key and its value
            first_key = next(iter(obj))
            first_value = obj[first_key]

            # Check if allow_spaces is false and the value contains spaces
            if obj["allow_spaces"].lower() == "false" and " " in first_value:
                errors.append(f"\033[91m[ERROR]           : '{first_key}' contains blank space. Spaces are not allowed! Please change the value and remove spaces")

        if not errors:
            print("\033[92m[SUCCESS]         : No spaces found in restricted fields")
        else:
            for error in errors:
                print(error)
                end_output_to_shell()
            sys.exit(1)

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error reading the configuration file: {e}")
        end_output_to_shell()
        sys.exit(1)

def check_empty_values(config_file):
    errors = []
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)

        for key, obj in config.items():
            # Get the first key and its value
            first_key = next(iter(obj))
            first_value = obj[first_key]

            # Check if allow_blank is false and the value is empty
            if obj["allow_blank"].lower() == "false" and first_value == "":
                errors.append(f"\033[91m[ERROR]           : '{first_key}' is blank. This key is not optional! Please enter a value in the JSON file")

        if not errors:
            print("\033[92m[SUCCESS]         : No mandatory fields are empty")
        else:
            for error in errors:
                print(error)
                end_output_to_shell()
            sys.exit(1)

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error reading the configuration file: {e}")
        end_output_to_shell()
        sys.exit(1)

def check_valid_ip_address(value_string):
    value_string = values.get("pve_host")
    parts = value_string.split('.')

    if len(parts) != 4:
        print(f"\033[91m[ERROR]           : Invalid IP address '{value_string}'. IP address should have exactly four parts.")
        end_output_to_shell()
        sys.exit(1)

    for part in parts:
        try:
            part_int = int(part)
            if not 0 <= part_int <= 255:
                print(f"\033[91m[ERROR]           : Invalid IP address '{value_string}'. Each part should be between 0 and 255.")
                end_output_to_shell()
                sys.exit(1)
        except ValueError:
            print(f"\033[91m[ERROR]           : Invalid IP address '{value_string}'. Each part should be an integer.")
            end_output_to_shell()
            sys.exit(1)

    print(f"\033[92m[INFO]            : IP address '{value_string}' is a valid ip-address.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\033[91m[ERROR]           : Usage: check_spaces.py <config.json>")
        end_output_to_shell()
        sys.exit(1)

    config_file = sys.argv[1]
    config = load_config(config_file)
    values = get_json_values(config)
    check_spaces(config_file)
    check_empty_values(config_file)
    check_valid_ip_address(values)
    end_output_to_shell()